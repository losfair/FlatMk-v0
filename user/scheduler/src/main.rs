#![no_main]
#![no_std]
#![feature(core_intrinsics, asm, naked_functions, new_uninit)]

#[macro_use]
extern crate lazy_static;

extern crate alloc;
extern crate flatruntime_user;

use flatruntime_user::{
    syscall::CPtr,
    io::Port,
    interrupt::{Interrupt, WaitForInterrupt},
    ipc::{TaskEndpoint, FastIpcPayload, ipc_return, ipc_return_to, fastipc_read},
    task::{ROOT_TASK, ROOT_CAPSET},
    thread::ROOT_IPC_BASE,
};
use alloc::boxed::Box;
use core::mem::MaybeUninit;
use spin::Mutex;
use alloc::collections::vec_deque::VecDeque;

static PIC_INTERRUPT_TIMER: Interrupt = unsafe { Interrupt::new(CPtr::new(1)) };
static WFI: WaitForInterrupt = unsafe { WaitForInterrupt::new(CPtr::new(2)) };

lazy_static! {
    static ref SCHED_QUEUE: Mutex<VecDeque<SchedEntity>> = Mutex::new(VecDeque::new());
}

#[repr(C, align(64))]
struct Xsave {
    fxsave: [u8; 512],
    xsave_header: [u8; 64],
    ymmh: [u128; 16],
}

struct SchedEntity {
    endpoint: CPtr,
    xsave: Box<Xsave>,
}

#[no_mangle]
pub unsafe extern "C" fn user_start() -> ! {
    PIC_INTERRUPT_TIMER.bind(&*ROOT_TASK, handle_timer_interrupt_begin as u64, 0).unwrap();
    ipc_return();
}

#[naked]
unsafe extern "C" fn handle_timer_interrupt_begin() -> ! {
    asm!(
        r#"
            mov %gs:8, %rsp
            jmp handle_timer_interrupt
        "# :::: "volatile"
    );
    loop {}
}

#[no_mangle]
unsafe extern "C" fn handle_timer_interrupt() -> ! {
    save_sched_entity();
    resched();
}

#[naked]
unsafe extern "C" fn handle_yield_begin() -> ! {
    asm!(
        r#"
            mov %gs:8, %rsp
            jmp handle_yield
        "# :::: "volatile"
    );
    loop {}
}

#[no_mangle]
unsafe extern "C" fn handle_yield() -> ! {
    let mut payload = FastIpcPayload::default();
    fastipc_read(&mut payload);

    match payload.data[0] {
        1 => {
            save_sched_entity();
        }
        _ => {}
    }
    resched();
}

unsafe fn save_sched_entity() {
    let from = ROOT_CAPSET.take_ipc_cap(ROOT_IPC_BASE).unwrap();
    let mut area: Box<MaybeUninit<Xsave>> = Box::new_uninit();
    do_xsave(&mut *(area.as_mut_ptr()));

    SCHED_QUEUE.lock().push_back(
        SchedEntity {
            endpoint: from,
            xsave: area.assume_init(),
        }
    );
}

unsafe fn resched() -> ! {
    let entity = SCHED_QUEUE.lock().pop_front();
    if let Some(entity) = entity {
        do_xrstor(&*entity.xsave);
        drop(entity.xsave);
        ipc_return_to(entity.endpoint);
    } else {
        WFI.wait();
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
    unsafe {
        * (0xa0300000 as *mut u8) = 42;
    }
    loop {}
}
