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
    syscall::{Delegation, RootCap, RootResources},
};

lazy_static! {
    static ref RESOURCES: RootResources = {
        unsafe {
            let root_cap = RootCap::init();
            root_cap.into_resources()
        }
    };
    static ref SERIAL_PORT: SerialPort = {
        unsafe {
            use core::intrinsics::abort;
            let serial_ports: [Port; 8] = [
                Port::new(RESOURCES.x86_port.get_port(0x3f8).unwrap_or_else(|| abort())),
                Port::new(RESOURCES.x86_port.get_port(0x3f9).unwrap_or_else(|| abort())),
                Port::new(RESOURCES.x86_port.get_port(0x3fa).unwrap_or_else(|| abort())),
                Port::new(RESOURCES.x86_port.get_port(0x3fb).unwrap_or_else(|| abort())),
                Port::new(RESOURCES.x86_port.get_port(0x3fc).unwrap_or_else(|| abort())),
                Port::new(RESOURCES.x86_port.get_port(0x3fd).unwrap_or_else(|| abort())),
                Port::new(RESOURCES.x86_port.get_port(0x3fe).unwrap_or_else(|| abort())),
                Port::new(RESOURCES.x86_port.get_port(0x3ff).unwrap_or_else(|| abort())),
            ];
            SerialPort::new(serial_ports)
        }
    };
}

unsafe fn resource_init() {
    RESOURCES.local_mapper.map_page(0x1b8000).unwrap();
    RESOURCES.local_mmio.alloc_at(0x1b8000, 0xb8000).unwrap();
}

#[no_mangle]
pub unsafe extern "C" fn user_start() -> ! {
    writeln!(SERIAL_PORT.handle(), "Init process started.");
    resource_init();
    println!("init: FlatRuntime init task started.");
    loop {}
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    writeln!(SERIAL_PORT.handle(), "panic(): {:#?}", info);
    loop {}
}
