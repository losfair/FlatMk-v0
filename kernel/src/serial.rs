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
        outb(self.base_port + 1, 0x00); // Disable all interrupts
        outb(self.base_port + 3, 0x80); // Enable DLAB (set baud rate divisor)
        outb(self.base_port + 0, 0x01); // Set baud rate to 115200 baud
        outb(self.base_port + 1, 0x00); // (hi byte)
        outb(self.base_port + 3, 0x03); // 8 bits, no parity, one stop bit
        outb(self.base_port + 2, 0xc7); // Enable FIFO, clear them, with 14-byte threshold
        outb(self.base_port + 4, 0x0b); // Enable IRQs, RTS/DSR set
    }

    fn is_transmit_empty(&mut self) -> bool {
        unsafe {
            inb(self.base_port + 5) & 0x20 != 0
        }
    }

    pub fn send(&mut self, data: u8) {
        unsafe {
            while !self.is_transmit_empty() {}
            outb(self.base_port, data);
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
