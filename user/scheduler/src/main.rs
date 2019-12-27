#![no_main]
#![no_std]
#![feature(core_intrinsics, asm, naked_functions, new_uninit, panic_info_message)]

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate flatruntime_user;

use flatruntime_user::{
    syscall::CPtr,
    io::Port,
    interrupt::{Interrupt},
    ipc::*,
    task::*,
    thread::{Thread, this_task, this_user_base},
    capset::CapType,
};
use alloc::boxed::Box;
use alloc::collections::btree_set::BTreeSet;
use core::mem::{ManuallyDrop, MaybeUninit};
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::collections::vec_deque::VecDeque;

static PIC_INTERRUPT_TIMER: Interrupt = unsafe { Interrupt::new(CPtr::new(1)) };
static IDLE_TASK: TaskEndpoint = unsafe { TaskEndpoint::new(CPtr::new(2)) };
static PIT_CHANNEL_0: Port = unsafe { Port::new(CPtr::new(3)) };
static PIT_MODE_COMMAND: Port = unsafe { Port::new(CPtr::new(4)) };

/// 903 = 902 + 1.
/// 
/// Divides the PIT clock (1193181.6666 Hz) by 902.
/// So we get 1193181.6666 / 902 = 1322.817812195122 interrupts per second,
/// and every cycle is 755962.0007993173 nanoseconds.
const PIT_DIV: u16 = 903;
const PIC_NANOSECS_PER_CYCLE: u64 = 755962;
const MAX_TIME_SLICE_NS: u64 = 1_000_000_0; // 10 milliseconds
const IDLE_TAG: u64 = core::u64::MAX;

static NANOSEC: AtomicU64 = AtomicU64::new(0);
static REENTRANCY_COUNTER: AtomicU64 = AtomicU64::new(0);
static CURRENT_BEGIN: AtomicU64 = AtomicU64::new(0);

lazy_static! {
    static ref SCHED_QUEUE: Mutex<VecDeque<SchedEntity>> = Mutex::new(VecDeque::new());
    static ref TIMED_TASKS: Mutex<BTreeSet<TimedTask>> = Mutex::new(BTreeSet::new());
}

#[repr(C, align(64))]
struct Xsave {
    fxsave: [u8; 512],
    xsave_header: [u8; 64],
    ymmh: [u128; 16],
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct TimedTask {
    deadline: u64,
    entity: Option<SchedEntity>, // None for comparison
}

struct SchedEntity {
    endpoint: CPtr,
    xsave: Box<Xsave>,
}

impl PartialEq for SchedEntity {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint.index().eq(&other.endpoint.index())
    }
}

impl Eq for SchedEntity {}

impl PartialOrd for SchedEntity {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.endpoint.index().partial_cmp(&other.endpoint.index())
    }
}

impl Ord for SchedEntity {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.endpoint.index().cmp(&other.endpoint.index())
    }
}

struct ReentrancyGuard { _unused: u64 }
impl ReentrancyGuard {
    fn new() -> ReentrancyGuard {
        REENTRANCY_COUNTER.fetch_add(1, Ordering::SeqCst);
        ReentrancyGuard {
            _unused: 1,
        }
    }
}
impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        assert_eq!(self._unused, 1);
        REENTRANCY_COUNTER.fetch_sub(1, Ordering::SeqCst);
    }
}

#[no_mangle]
pub unsafe extern "C" fn user_start() -> ! {
    this_task().put_ipc_cap(1, ROOT_TASK.fetch_task_endpoint(handle_yield as u64, 0, TaskEndpointFlags::empty(), false).unwrap().into_cptr()).unwrap();
    this_task().put_ipc_cap(2, ROOT_TASK.fetch_task_endpoint(handle_add as u64, 0, TaskEndpointFlags::CAP_TRANSFER, false).unwrap().into_cptr()).unwrap();
    init_pit();

    let interrupt_handler_thread = Thread::new();
    interrupt_handler_thread.task().fetch_task_endpoint(interrupt_handler_thread_init as u64, 0, TaskEndpointFlags::empty(), false).unwrap().call(&mut FastIpcPayload::default()).unwrap();
    
    PIC_INTERRUPT_TIMER.bind(interrupt_handler_thread.task(), handle_timer_interrupt as u64, 0).unwrap();
    core::mem::forget(interrupt_handler_thread);

    ipc_return();
    panic!("user_start: ipc_return failed");
}

unsafe fn wfi() -> ! {
    ipc_return_to_unowned(ManuallyDrop::new(CPtr::new(IDLE_TASK.cptr().index())));
    unreachable!()
}

ipc_entry!(interrupt_handler_thread_init, __interrupt_handler_thread_init, {
    IDLE_TASK.set_tag(IDLE_TAG).unwrap();
    ipc_return();
    unreachable!()
});

ipc_entry_with_context_result_fastipc!(handle_timer_interrupt, __handle_timer_interrupt, _payload, _context, tag, {
    unsafe {
        let begin = CURRENT_BEGIN.load(Ordering::SeqCst);
        let nanosecs = NANOSEC.fetch_add(PIC_NANOSECS_PER_CYCLE, Ordering::SeqCst);

        // allocator, locks, etc. aren't reentrant.
        if REENTRANCY_COUNTER.load(Ordering::SeqCst) != 0 {
            ipc_return();
            panic!("timer_interrupt: ipc_return failed");
        }

        if tag != IDLE_TAG {
            // Do not reschedule if the current task hasn't used up its time slice.
            if nanosecs - begin < MAX_TIME_SLICE_NS {
                ipc_return();
                unreachable!();
            }
            save_sched_entity();
        }

        update_timed_tasks(nanosecs);
        try_resched();
        wfi();
    }
});

ipc_entry!(handle_yield, __handle_yield, {
    unsafe {
        let guard = ReentrancyGuard::new();
        let mut payload = FastIpcPayload::default();
        fastipc_read(&mut payload);

        match payload.data[0] {
            1 => {
                save_sched_entity();
            }
            2 => { // sleep
                let current = NANOSEC.load(Ordering::Relaxed);
                let duration = payload.data[1] as u64;
                let deadline = match current.checked_add(duration) {
                    Some(x) => x,
                    None => {
                        payload.data[0] = -1i64 as _;
                        drop(guard);
                        ipc_return();
                        panic!("yield: ipc_return failed");
                    }
                };
                let task = TimedTask {
                    deadline,
                    entity: Some(take_sched_entity()),
                };
                TIMED_TASKS.lock().insert(task);
            }
            _ => {}
        }
        drop(guard);
        try_resched();
        wfi();
    }
});

ipc_entry!(handle_add, __handle_add, {
    unsafe {
        let guard = ReentrancyGuard::new();
        let mut payload = FastIpcPayload::default();

        let incoming_cap = this_task().fetch_ipc_cap(1).unwrap();
        if ROOT_CAPSET.get_cap_type(&incoming_cap).unwrap() != CapType::TaskEndpoint as u32
            || !ipc_endpoint_is_reply(&incoming_cap)
            || !ipc_endpoint_is_taggable(&incoming_cap) {

            drop(incoming_cap);
            
            payload.data[0] = -1i64 as u64;
            fastipc_write(&payload);

            drop(guard);
            ipc_return();
            panic!("add: ipc_return failed (1)");
        }

        push_sched_queue(core::iter::once(SchedEntity {
            endpoint: incoming_cap,
            xsave: Box::new(core::mem::zeroed()),
        }));

        drop(guard);
        ipc_return();
        panic!("add: ipc_return failed (2)");
    }
});

unsafe fn update_timed_tasks(nanosecs: u64) {
    let mut tasks = TIMED_TASKS.lock();
    let mut expired = tasks.split_off(&TimedTask {
        deadline: nanosecs,
        entity: None,
    });

    // split_off returns values after the given key
    core::mem::swap(&mut *tasks, &mut expired);
    push_sched_queue(expired.into_iter().map(|x| x.entity.unwrap()));
}

unsafe fn init_pit() {
    PIT_MODE_COMMAND.outb(0b00110100).unwrap(); // channel 0, lobyte/hibyte, rate generator
    PIT_CHANNEL_0.outb(PIT_DIV as u8).unwrap(); // low byte
    PIT_CHANNEL_0.outb((PIT_DIV >> 8) as u8).unwrap(); // high byte
}

fn push_sched_queue(entity: impl Iterator<Item = SchedEntity>) {
    let mut q = SCHED_QUEUE.lock();
    for entity in entity {
        q.push_back(entity);
    }
}

fn pop_sched_queue() -> Option<SchedEntity> {
    SCHED_QUEUE.lock().pop_front()
}

unsafe fn take_ipc_source() -> CPtr {
    this_task().fetch_ipc_cap(0).unwrap()
}

unsafe fn take_sched_entity() -> SchedEntity {
    let from = take_ipc_source();
    let mut area: Box<MaybeUninit<Xsave>> = Box::new_uninit();
    do_xsave(&mut *(area.as_mut_ptr()));
    SchedEntity {
        endpoint: from,
        xsave: area.assume_init(),
    }
}

unsafe fn save_sched_entity() {
    let entity = take_sched_entity();
    push_sched_queue(core::iter::once(entity));
}

unsafe fn try_resched() {
    let guard = ReentrancyGuard::new();
    let entity = pop_sched_queue();

    if let Some(entity) = entity {
        do_xrstor(&*entity.xsave);
        drop(entity.xsave);

        CURRENT_BEGIN.store(NANOSEC.load(Ordering::SeqCst), Ordering::SeqCst);

        let tlcap = this_user_base();
        ROOT_CAPSET.trivial_move_cap(entity.endpoint.index(), tlcap).unwrap();
        drop(entity.endpoint);
        drop(guard);

        ipc_return_to_unowned(ManuallyDrop::new(CPtr::new(tlcap)));
        unreachable!()
    }
}

// FIXME: Enable xsave/xrstor
unsafe fn do_xsave(area: &mut Xsave) {
    asm!(
        r#"
            mov $$0, %edx
            mov $$7, %eax
            fxsave ($0)
        "# :: "r"(area) : "rax", "rdx": "volatile"
    );
}

// FIXME: Enable xsave/xrstor
unsafe fn do_xrstor(area: &Xsave) {
    asm!(
        r#"
            mov $$0, %edx
            mov $$7, %eax
            fxrstor ($0)
        "# :: "r"(area) : "rax", "rdx": "volatile"
    );
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    /*let mut b = Box::new([0u8; 65536]);
    unsafe {
        asm!("nop" : "=r"(&*b) ::: "volatile");
        asm!("nop" :: "r"(&mut *b) :: "volatile");
        * (0xa0301010 as *mut u8) = 42;
    }*/
    let fmt = format!("{}", info.message().unwrap());
    unsafe {
        let val = fmt.as_bytes().as_ptr().offset(0);
        asm!(
            r#"
                mov ($0), %rax
                mov $$0xffffffffff, %rbx
                and %rbx, %rax
                mov $$0xffff800000000000, %rbx
                or %rbx, %rax
                mov (%rax), %rax
                ud2
            "# :: "r"(val) :: "volatile"
        );
    }
    loop {}
}
