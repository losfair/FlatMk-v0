use core::fmt::{self, Write};
use flatruntime_user::io::Port;

pub struct SerialPort {
    ports: [Port; 8],
}

impl SerialPort {
    pub const unsafe fn new(ports: [Port; 8]) -> SerialPort {
        SerialPort {
            ports,
        }
    }

    pub fn get_lsts(&mut self) -> u8 {
        unsafe {
            self.ports[5].inb() // line status register is on port 5.
        }
    }
    
    pub fn send(&mut self, data: u8) {
        unsafe {
            match data {
                8 | 0x7F => {
                    while (!self.get_lsts() & 1) == 0 {}
                    self.ports[0].outb(8);
                    while (!self.get_lsts() & 1) == 0 {}
                    self.ports[0].outb(b' ');
                    while (!self.get_lsts() & 1) == 0 {}
                    self.ports[0].outb(8);
                }
                _ => {
                    while (!self.get_lsts() & 1) == 0 {}
                    self.ports[0].outb(data);
                }
            }
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send(byte);
        }
        Ok(())
    }
}