//! flatrt-scheduler is the usermode task scheduler running on FlatMk.
//! 
//! Each scheduler instance listens on timer interrupts on one CPU core, but
//! can accept yield/add requests from any core.

#![no_std]
#![no_main]
#![feature(naked_functions, asm)]

#[macro_use]
mod debug;
mod caps;

use flatmk_sys::spec;
use flatrt_thread::{Thread, ThreadCapSet};
use core::sync::atomic::{AtomicU64, Ordering};

/// Start address for heap allocation.
const HEAP_START: usize = 0x7fff00000000;

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

#[repr(C, align(64))]
struct Xsave {
    fxsave: [u8; 512],
    xsave_header: [u8; 64],
    ymmh: [u128; 16],
}

struct ReentrancyGuard { _unused: u64 }
impl ReentrancyGuard {
    fn new() -> ReentrancyGuard {
        assert_eq!(REENTRANCY_COUNTER.fetch_add(1, Ordering::SeqCst), 0);
        ReentrancyGuard {
            _unused: 1,
        }
    }
}
impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        assert_eq!(self._unused, 1);
        assert!(REENTRANCY_COUNTER.fetch_sub(1, Ordering::SeqCst) > 0);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        caps::init();
        flatrt_allocator::init(HEAP_START, caps::RPT);
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
    let mut th_sched_create = Thread::new(ThreadCapSet {
        owner_task: caps::ME,
        owner_capset: caps::CAPSET,
        new_task: caps::THREAD_SCHED_CREATE,
    });
    th_sched_create.make_ipc_endpoint(
        spec::TaskEndpointFlags::CAP_TRANSFER,
        false,
        caps::THREAD_SCHED_CREATE_ENDPOINT.cptr(),
        on_sched_create,
    );
}

fn on_sched_create(this_task: spec::BasicTask, tag: u64) {

}

fn on_timer(this_task: spec::BasicTask, tag: u64) {
    let begin = CURRENT_BEGIN.load(Ordering::SeqCst);
    let nanosecs = NANOSEC.fetch_add(PIC_NANOSECS_PER_CYCLE, Ordering::SeqCst);

    if (nanosecs + PIC_NANOSECS_PER_CYCLE) / 1000000000 > nanosecs / 1000000000 {
        debug!("scheduler: timer tick: {}, tag = {}", nanosecs, tag);
    }

    // allocator, locks, etc. aren't reentrant.
    if REENTRANCY_COUNTER.load(Ordering::SeqCst) != 0 {
        unsafe {
            this_task.ipc_return(); // ignore error
        }
        unreachable!()
    } else {
        unsafe {
            this_task.ipc_return(); // ignore error
        }
        unreachable!()
    }
    /*

    if tag != IDLE_TAG {
        // Try not to reschedule if the current task hasn't used up its time slice.
        if nanosecs - begin < MAX_TIME_SLICE_NS {
            ipc_return();
            // Ignore ipc_return error and reschedule.
        } else {
            save_sched_entity();
        }
    }

    try_resched();
    wfi();
    debug!("Timer")*/
}

// FIXME: Enable xsave/xrstor
unsafe fn do_xsave(area: &mut Xsave) {
    asm!(
        r#"
            fxsave ($0)
        "# :: "r"(area) :: "volatile"
    );
}

// FIXME: Enable xsave/xrstor
unsafe fn do_xrstor(area: &Xsave) {
    asm!(
        r#"
            fxrstor ($0)
        "# :: "r"(area) :: "volatile"
    );
}
