#![no_main]
#![no_std]
#![feature(core_intrinsics)]

#[macro_use]
extern crate lazy_static;

extern crate alloc;

mod serial;
mod vga;

use crate::serial::SerialPort;
use alloc::boxed::Box;
use core::arch::x86_64::_rdtsc;
use core::fmt::Write;
use flatruntime_user::{
    io::Port,
    ipc::*,
    mm::{Mmio, RootPageTable},
    syscall::Delegation,
};

lazy_static! {
    static ref SERIAL_PORT: SerialPort = {
        unsafe {
            use core::intrinsics::abort;
            let serial_ports: [Port; 8] = [
                flatruntime_user::root::new_x86_io_port(0x3f8).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3f9).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fa).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fb).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fc).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fd).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fe).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3ff).unwrap_or_else(|_| abort()),
            ];
            SerialPort::new(serial_ports)
        }
    };
    static ref PT: RootPageTable = flatruntime_user::task::THIS_TASK.fetch_rpt().unwrap();
    static ref VGA_MMIO: Mmio = flatruntime_user::root::new_mmio(0xb8000).unwrap();
}

#[repr(align(4096))]
struct Stack([u8; 1048576]);

#[repr()]
static mut STACK_AFTER_SWITCH: Stack = Stack([0; 1048576]);

unsafe fn resource_init() {
    PT.map_page(0x1b8000).unwrap();
    VGA_MMIO.alloc_at(0x1b8000).unwrap();
}

#[no_mangle]
pub unsafe extern "C" fn user_start() -> ! {
    writeln!(SERIAL_PORT.handle(), "Init process started.");
    resource_init();
    println!("init: FlatMK init task started.");

    benchmark(1000000, "simple capability invocation", || {
        flatruntime_user::task::THIS_TASK.call_invalid();
    });

    let cloned = flatruntime_user::task::THIS_TASK.deep_clone().unwrap();
    println!("init: Cloned task.");

    cloned.reset_caps(Box::new(Delegation::new())).unwrap();
    unsafe {
        cloned
            .make_first_level_endpoint(0, Box::new(Delegation::new()))
            .unwrap();
        cloned.put_cap(cloned.get_cptr(), 0).unwrap();
    }
    println!("init: Initialized capabilities on clone.");
    cloned.unblock_ipc().unwrap();

    cloned
        .set_register(16, 0)
        .unwrap();

    benchmark(1000000, "complex capability invocation", || {
        assert_eq!(
            cloned.get_register(16).unwrap(),
            0
        );
    });

    let cloned_endpoint = unsafe { IpcEndpoint::new(cloned.fetch_ipc_endpoint(
        after_switch as _,
        unsafe {
            let stack_begin = STACK_AFTER_SWITCH.0.as_mut_ptr();
            stack_begin.offset(STACK_AFTER_SWITCH.0.len() as isize) as u64
        }
    ).unwrap()) };

    let mut payload = FastIpcPayload::default();

    benchmark(1000000, "IPC call", || {
        payload.0[0] = 1;
        payload.0[1] = 2;
        cloned_endpoint.call(&mut payload).unwrap();
        assert_eq!(payload.0[0], 3);
    });

    cloned.reset_caps(Box::new(Delegation::new())).unwrap();

    drop(cloned_endpoint);
    drop(cloned);

    println!("init: Dropped clone.");

    benchmark(1000000, "task deep clone", || {
        flatruntime_user::task::THIS_TASK.deep_clone().unwrap();
    });

    loop {}
}

fn benchmark<F: FnMut()>(n: usize, msg: &str, mut f: F) {
    let begin = unsafe { _rdtsc() } as usize;
    for _ in 0..n {
        f();
    }
    let end = unsafe { _rdtsc() } as usize;
    let result = (end - begin) / n;
    println!("init: benchmark: {} cycles per {}.", result, msg);
}

extern "C" fn after_switch() -> ! {
    flatruntime_user::ipc::handle_ipc();
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    println!("panic(): {:#?}", info);
    //writeln!(SERIAL_PORT.handle(), "panic(): {:#?}", info);
    loop {}
}
