#![no_main]
#![no_std]

mod serial;
mod vga;

use crate::serial::SerialPort;
use core::fmt::Write;
use flatruntime_user::{
    io::Port,
    syscall::{Delegation, RootCap},
};

static mut ANY_PORT_DELEGATION: Delegation = Delegation::new();

#[no_mangle]
pub unsafe extern "C" fn user_start() -> ! {
    let root_cap = RootCap::init();
    let any_port = root_cap
        .make_any_x86_port(&mut ANY_PORT_DELEGATION)
        .unwrap();
    let serial_ports: [Port; 8] = [
        Port::new(any_port.get_port(0x3f8).unwrap()),
        Port::new(any_port.get_port(0x3f9).unwrap()),
        Port::new(any_port.get_port(0x3fa).unwrap()),
        Port::new(any_port.get_port(0x3fb).unwrap()),
        Port::new(any_port.get_port(0x3fc).unwrap()),
        Port::new(any_port.get_port(0x3fd).unwrap()),
        Port::new(any_port.get_port(0x3fe).unwrap()),
        Port::new(any_port.get_port(0x3ff).unwrap()),
    ];
    let mut serial = SerialPort::new(serial_ports);
    writeln!(serial, "Hello, world!");
    println!("Hello, world!");
    loop {}
}
