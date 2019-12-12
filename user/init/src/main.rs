#![no_main]
#![no_std]
#![feature(core_intrinsics)]

#[macro_use]
extern crate lazy_static;

mod serial;
mod vga;

use crate::serial::SerialPort;
use core::fmt::Write;
use flatruntime_user::{
    io::Port,
    mm::{Mmio, Vmap},
};
use core::arch::x86_64::_rdtsc;

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
    static ref VMAP: Vmap = flatruntime_user::task::new_vmap().unwrap();
    static ref VGA_MMIO: Mmio = flatruntime_user::root::new_mmio(0xb8000).unwrap();
}

unsafe fn resource_init() {
    VMAP.map_page(0x1b8000).unwrap();
    VGA_MMIO.alloc_at(0x1b8000).unwrap();
}

#[no_mangle]
pub unsafe extern "C" fn user_start() -> ! {
    writeln!(SERIAL_PORT.handle(), "Init process started.");
    resource_init();
    println!("init: FlatMK init task started.");

    benchmark_cap_invoke(1000000);

    loop {}
}

fn benchmark_cap_invoke(n: usize) {
    let begin = unsafe {
        _rdtsc()
    };
    for i in 0..n {
        flatruntime_user::task::call_invalid();
    }
    let end = unsafe {
        _rdtsc()
    };
    writeln!(SERIAL_PORT.handle(), "Benchmark: {} cycles per capability invocation.", (end - begin) / (n as u64));
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    writeln!(SERIAL_PORT.handle(), "panic(): {:#?}", info);
    loop {}
}
