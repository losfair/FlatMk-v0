//! Debugging utilities.

use crate::caps::PUTCHAR;
use core::marker::PhantomData;
use core::fmt::Write;

/// A debug port.
pub struct DebugPort(PhantomData<()>);

/// The global instance of `DebugPort` that can be written to.
pub static mut DEBUG: DebugPort = DebugPort(PhantomData);

impl Write for DebugPort {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            unsafe {
                PUTCHAR.putchar(byte as u64);
            }
        }
        Ok(())
    }
}

macro_rules! debug {
    ($($arg:tt)*) => { #[allow(unused_unsafe)] unsafe {
        use core::fmt::Write;
        writeln!(&mut $crate::debug::DEBUG, "{}", format_args!($($arg)*)).unwrap();
    }};
}
