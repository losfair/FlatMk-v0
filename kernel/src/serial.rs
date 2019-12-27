use core::fmt::{self, Write};
use spin::{Mutex, Once};
use x86::io::{inb, outb};

static SERIAL_PORT: Once<Mutex<SerialPort>> = Once::new();

pub fn with_serial_port<F: FnOnce(&mut SerialPort) -> T, T>(f: F) -> T {
    let sp = SERIAL_PORT.call_once(|| unsafe {
        let mut sp = SerialPort::new(0x3f8);
        sp.init();
        Mutex::new(sp)
    });
    let mut sp = sp.lock();
    f(&mut *sp)
}

pub struct SerialPort {
    base_port: u16,
}

impl SerialPort {
    pub const unsafe fn new(base_port: u16) -> SerialPort {
        SerialPort { base_port }
    }

    pub unsafe fn init(&mut self) {
        outb(self.base_port + 1, 0x00); // Disable interrupts
        outb(self.base_port + 3, 0x00); // Set baud rate divisor
        outb(self.base_port + 0, 0x00); // Set baud rate to 38400 baud
        outb(self.base_port + 1, 0x00); //
        outb(self.base_port + 3, 0x00); // 8 bits, no parity, one stop bit
        outb(self.base_port + 2, 0x00); // Enable FIFO, clear them, with 14-byte threshold
        outb(self.base_port + 4, 0x00); // Enable IRQs, RTS/DSR set
        outb(self.base_port + 1, 0x00); // Disable Interrupts
    }

    pub fn get_lsts(&mut self) -> u8 {
        unsafe {
            inb(self.base_port + 5) // line status register is on port 5.
        }
    }

    pub fn send(&mut self, data: u8) {
        unsafe {
            match data {
                8 | 0x7F => {
                    while (!self.get_lsts() & 1) == 0 {}
                    outb(self.base_port, 8);
                    while (!self.get_lsts() & 1) == 0 {}
                    outb(self.base_port, b' ');
                    while (!self.get_lsts() & 1) == 0 {}
                    outb(self.base_port, 8);
                }
                _ => {
                    while (!self.get_lsts() & 1) == 0 {}
                    outb(self.base_port, data);
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

macro_rules! println {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        $crate::serial::with_serial_port(|p| writeln!(p, "{}", format_args!($($arg)*))).unwrap();
    }};
}
