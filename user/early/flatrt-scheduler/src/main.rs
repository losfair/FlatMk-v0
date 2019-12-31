//! flatrt-scheduler is a usermode task scheduler running on FlatMk.
//! 
//! Each scheduler instance listens on timer interrupts on one CPU core, but
//! can accept yield/add requests from any core.
//! 
//! Implemented with a simple round-robin policy.

#![no_std]
#![no_main]
#![feature(naked_functions, asm, new_uninit)]

#[macro_use]
extern crate lazy_static;

extern crate alloc;

#[macro_use]
mod debug;
mod caps;

use flatmk_sys::spec;
use flatrt_thread::{Thread, ThreadCapSet};
use flatrt_fastipc::FastIpcPayload;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::{
    collections::{
        btree_set::BTreeSet,
        vec_deque::VecDeque,
    },
    boxed::Box,
};
use spin::Mutex;

/// Start address for heap allocation.
const HEAP_START: usize = 0x7fff00000000;

/// Start address for dynamic capability allocation.
const DYN_CAP_START: u64 = 0x100000;

/// 903 = 902 + 1.
/// 
/// Divides the PIT clock (1193181.6666 Hz) by 902.
/// So we get 1193181.6666 / 902 = 1322.817812195122 interrupts per second,
/// and every cycle is 755962.0007993173 nanoseconds.
const PIT_DIV: u16 = 903;
const PIC_NANOSECS_PER_CYCLE: u64 = 755962;

/// The maximum time in nanoseconds that a task is allowed to execute before being preempted out.
const MAX_TIME_SLICE_NS: u64 = 1_000_000_0; // 10 milliseconds

/// The tag applied to the idle task during initialization.
const IDLE_TAG: u64 = core::u64::MAX;

/// Current timestamp in nanoseconds.
static NANOSEC: AtomicU64 = AtomicU64::new(0);

/// Reentrancy counter. See `ReentrancyGuard`.
static REENTRANCY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The timestamp at which the current task started executing.
static CURRENT_BEGIN: AtomicU64 = AtomicU64::new(0);

lazy_static! {
    /// The scheduling queue. Tasks get pushed to the back and popped from the front.
    static ref SCHED_QUEUE: Mutex<VecDeque<SchedEntity>> = Mutex::new(VecDeque::new());

    /// Sleeping tasks.
    static ref TIMED_TASKS: Mutex<BTreeSet<TimedTask>> = Mutex::new(BTreeSet::new());
}

/// A sleeping task.
#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct TimedTask {
    /// The deadline after which this task should be put into the scheduling queue.
    deadline: u64,

    /// The scheduling entity of the task.
    entity: Option<SchedEntity>, // None for comparison
}

/// A scheduling entity. Contains its task endpoint and extended context that is not saved by the kernel.
struct SchedEntity {
    /// Task endpoint whose CPtr is allocated by `flatrt_capalloc`.
    endpoint: spec::TaskEndpoint,

    /// x86-64 xsave area.
    xsave: Box<Xsave>,
}

impl Drop for SchedEntity {
    /// The task endpoint needs to be manually dropped.
    fn drop(&mut self) {
        unsafe {
            spec::to_result(caps::CAPSET.drop_cap(self.endpoint.cptr())).unwrap();
        }
        flatrt_capalloc::release(*self.endpoint.cptr());
    }
}

impl PartialEq for SchedEntity {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint.cptr().index().eq(&other.endpoint.cptr().index())
    }
}

impl Eq for SchedEntity {}

impl PartialOrd for SchedEntity {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.endpoint.cptr().index().partial_cmp(&other.endpoint.cptr().index())
    }
}

impl Ord for SchedEntity {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.endpoint.cptr().index().cmp(&other.endpoint.cptr().index())
    }
}

/// x86-64 xsave region.
#[repr(C, align(64))]
struct Xsave {
    fxsave: [u8; 512],
    xsave_header: [u8; 64],
    ymmh: [u128; 16],
}

impl Default for Xsave {
    #[inline(always)]
    fn default() -> Xsave {
        unsafe {
            core::mem::zeroed()
        }
    }
}

/// A guard type that prevents reentering the scheduler.
struct ReentrancyGuard { _unused: u64 }

impl ReentrancyGuard {
    fn new() -> Option<ReentrancyGuard> {
        if REENTRANCY_COUNTER.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return None;
        }
        Some(ReentrancyGuard {
            _unused: 1,
        })
    }
}

impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        assert_eq!(self._unused, 1);
        assert!(REENTRANCY_COUNTER.fetch_sub(1, Ordering::SeqCst) == 1);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        caps::init();

        flatrt_allocator::init(HEAP_START, caps::RPT);
        flatrt_capalloc::init(caps::CAPSET, DYN_CAP_START);

        spec::to_result(caps::IDLE_REPLY.set_tag(IDLE_TAG)).expect("Cannot set idle tag");
        init_pit();

        setup_interrupt_handler();
        setup_sched_api();
    }

    debug!("scheduler: Initialized.");

    unsafe {
        caps::ME.ipc_return();
    }
    unreachable!()
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    debug!("scheduler panic: {:#?}", info);
    loop {}
}

unsafe fn init_pit() {
    spec::to_result(caps::PIT_MODE_COMMAND.outb(0b00110100)).unwrap(); // channel 0, lobyte/hibyte, rate generator
    spec::to_result(caps::PIT_CHANNEL_0.outb(PIT_DIV as u64)).unwrap(); // low byte
    spec::to_result(caps::PIT_CHANNEL_0.outb((PIT_DIV >> 8) as u64)).unwrap(); // high byte
}

unsafe fn setup_interrupt_handler() {
    let mut th_timer = Thread::new(ThreadCapSet {
        owner_task: caps::ME,
        owner_capset: caps::CAPSET,
        new_task: caps::THREAD_TIMER,
    });
    let (entry, index) = th_timer.make_ipc_endpoint_raw(on_timer);
    spec::to_result(caps::TIMER_INTERRUPT.bind(
        &caps::THREAD_TIMER,
        entry,
        index,
    )).expect("setup_interrupt_handler: Cannot bind interrupt.");
}

unsafe fn setup_sched_api() {
    let mut th_sched_api = Thread::new(ThreadCapSet {
        owner_task: caps::ME,
        owner_capset: caps::CAPSET,
        new_task: caps::THREAD_SCHED_API,
    });
    th_sched_api.make_ipc_endpoint(
        spec::TaskEndpointFlags::CAP_TRANSFER,
        false,
        caps::THREAD_SCHED_CREATE_ENDPOINT.cptr(),
        on_sched_create,
    );
    th_sched_api.make_ipc_endpoint(
        spec::TaskEndpointFlags::TAGGABLE,
        false,
        caps::THREAD_SCHED_YIELD_ENDPOINT.cptr(),
        on_sched_yield,
    );
}

fn on_sched_create(this_task: spec::BasicTask, tag: u64) {
    let guard = try_take_guard_or_return(this_task);

    let mut ipc_payload = FastIpcPayload::read();
    let command = ipc_payload.data[0];

    unsafe {
        match command {
            0 => {
                let backing_cptr = flatrt_capalloc::allocate();
                spec::to_result(this_task.fetch_ipc_cap(&backing_cptr, 1)).unwrap();
                let incoming_task = spec::TaskEndpoint::new(backing_cptr);

                // Validate that the incoming capability is actually a `TaskEndpoint` with `reply` property.
                if
                    caps::CAPSET.get_cap_type(incoming_task.cptr()) != spec::CapType::TaskEndpoint as i64 ||
                    incoming_task.is_reply() != 1 {
                        debug!(
                            "scheduler: on_sched_create: Invalid incoming task. is_reply = {}, cptr = {:016x}",
                            incoming_task.is_reply(),
                            backing_cptr.index(),
                        );
                        flatrt_capalloc::release(backing_cptr);
                        ipc_payload.data[0] = -1i64 as _;
                        ipc_payload.write();
                        return_or_idle(this_task, guard);
                }

                SCHED_QUEUE.try_lock().unwrap().push_back(SchedEntity {
                    endpoint: incoming_task,
                    xsave: Box::new(Xsave::default()),
                });
                return_or_idle(this_task, guard);
            }
            _ => {
                ipc_payload.data[0] = -1i64 as _;
                ipc_payload.write();
                return_or_idle(this_task, guard);
            }
        }
        
    }
}

fn on_sched_yield(this_task: spec::BasicTask, tag: u64) {
    let guard = try_take_guard_or_return(this_task);

    let mut ipc_payload = FastIpcPayload::read();
    let command = ipc_payload.data[0];

    // TODO: Use automatic binding generation for these commands?
    match command {
        0 => {
            // Busy yield. Allow the scheduler to switch to the next task.
            let backing_cptr = flatrt_capalloc::allocate();
            unsafe {
                spec::to_result(this_task.fetch_ipc_cap(&backing_cptr, 0)).unwrap();
            }
            let incoming_task = unsafe {
                spec::TaskEndpoint::new(backing_cptr)
            };
            SCHED_QUEUE.try_lock().unwrap().push_back(SchedEntity {
                endpoint: incoming_task,
                xsave: Box::new(Xsave::default()),
            });
            resched(this_task, guard);
        }
        1 => {
            // Sleep for a given period of time.
            let nanosecs = ipc_payload.data[1];
            let current = NANOSEC.load(Ordering::SeqCst);

            // Check for overflow.
            let end = match current.checked_add(nanosecs as _) {
                Some(x) => x,
                None => {
                    ipc_payload.data[0] = -1i64 as _;
                    ipc_payload.write();
                    return_or_idle(this_task, guard);
                }
            };

            let backing_cptr = flatrt_capalloc::allocate();
            unsafe {
                spec::to_result(this_task.fetch_ipc_cap(&backing_cptr, 0)).unwrap();
            }
            let incoming_task = unsafe {
                spec::TaskEndpoint::new(backing_cptr)
            };
            TIMED_TASKS.try_lock().unwrap().insert(TimedTask {
                deadline: end,
                entity: Some(SchedEntity {
                    endpoint: incoming_task,
                    xsave: Box::new(Xsave::default()),
                }),
            });
            resched(this_task, guard);
        }
        _ => {
            ipc_payload.data[0] = -1i64 as _;
            ipc_payload.write();
            return_or_idle(this_task, guard);
        }
    }
}

/// Timer interrupt handler.
fn on_timer(this_task: spec::BasicTask, tag: u64) {
    // Update timestamp before trying to take guard to keep the time accurate.
    let nanosecs = NANOSEC.fetch_add(PIC_NANOSECS_PER_CYCLE, Ordering::SeqCst);

    let guard = try_take_guard_or_return(this_task);

    let begin = CURRENT_BEGIN.load(Ordering::SeqCst);

    if (nanosecs + PIC_NANOSECS_PER_CYCLE) / 1000000000 > nanosecs / 1000000000 {
        debug!("scheduler: timer tick: {}, tag = {}", nanosecs, tag);
    }

    // A switch from the idle task should trigger an immediate resched.
    if tag == IDLE_TAG {
        resched(this_task, guard);
    }

    // Do not reschedule if the task hasn't used up its time slice.
    if nanosecs - begin < MAX_TIME_SLICE_NS {
        return_or_idle(this_task, guard);
    }

    // Take the previous task.
    let backing_cptr = flatrt_capalloc::allocate();
    unsafe {
        spec::to_result(this_task.fetch_ipc_cap(&backing_cptr, 0)).unwrap();
    }
    let incoming_task = unsafe {
        spec::TaskEndpoint::new(backing_cptr)
    };

    // Save extended context.
    let mut xsave: Box<Xsave> = unsafe {
        Box::new_uninit().assume_init()
    };
    do_xsave(&mut *xsave);

    // Push into scheduling queue.
    SCHED_QUEUE.try_lock().unwrap().push_back(SchedEntity {
        endpoint: incoming_task,
        xsave: xsave,
    });

    // Resched.
    resched(this_task, guard);
}

/// Tries returning to the previous task.
/// 
/// If fails, switches to the idle task.
fn return_or_idle(this_task: spec::BasicTask, guard: ReentrancyGuard) -> ! {
    drop(guard);
    _do_return_or_idle(this_task);
}

/// Tries returning to the previous task, assuming we have dropped the reentrancy guard.
/// 
/// If fails, switches to the idle task.
fn _do_return_or_idle(this_task: spec::BasicTask) -> ! {
    unsafe {
        this_task.ipc_return();
        caps::IDLE_REPLY.invoke();
        panic!("_do_return_or_idle: Cannot invoke idle task.");
    }
}

/// Picks a next task and switches to it.
fn resched(this_task: spec::BasicTask, guard: ReentrancyGuard) -> ! {
    update_timed_tasks();

    let task = SCHED_QUEUE.try_lock().unwrap().pop_front();
    if let Some(task) = task {
        // Update task begin time.
        CURRENT_BEGIN.store(NANOSEC.load(Ordering::SeqCst), Ordering::SeqCst);

        // Restore extended context.
        do_xrstor(&*task.xsave);

        unsafe {
            // We cannot assume the return endpoint is still valid after dropping the guard.
            // So here we use IPC cap and ipc_return to switch tasks.
            spec::to_result(this_task.put_ipc_cap(task.endpoint.cptr(), 0)).unwrap();
        }

        drop(task);

        // Switch task.
        return_or_idle(this_task, guard);
    } else {
        // No pending task is available.
        // Drop the guard and directly invoke the idle task.
        drop(guard);
        unsafe {
            caps::IDLE_REPLY.invoke();
        }
        panic!("resched: Cannot invoke idle task.");
    }
}

/// Pushes expired timed tasks into `SCHED_QUEUE`.
fn update_timed_tasks() {
    let mut tasks = TIMED_TASKS.try_lock().unwrap();
    let mut expired = tasks.split_off(&TimedTask {
        deadline: NANOSEC.load(Ordering::SeqCst),
        entity: None,
    });

    // split_off returns values after the given key
    core::mem::swap(&mut *tasks, &mut expired);

    let mut sched_queue = SCHED_QUEUE.try_lock().unwrap();
    for task in expired {
        sched_queue.push_back(task.entity.unwrap());
    }
}

/// Tries taking the reentrancy guard. If fails, calls `_do_return_or_idle`.
fn try_take_guard_or_return(this_task: spec::BasicTask) -> ReentrancyGuard {
    match ReentrancyGuard::new() {
        Some(x) => x,
        None => {
            _do_return_or_idle(this_task);
        }
    }
}

// FIXME: Enable xsave/xrstor
fn do_xsave(area: &mut Xsave) {
    unsafe {
        asm!(
            r#"
                fxsave ($0)
            "# :: "r"(area) :: "volatile"
        );
    }
}

// FIXME: Enable xsave/xrstor
fn do_xrstor(area: &Xsave) {
    unsafe {
        asm!(
            r#"
                fxrstor ($0)
            "# :: "r"(area) :: "volatile"
        );
    }
}
