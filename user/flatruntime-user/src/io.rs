use crate::error::*;
use crate::syscall::CPtr;
use core::convert::TryFrom;

const PORT_READ: i64 = 0;
const PORT_WRITE: i64 = 1;

pub struct Port {
    cap: CPtr,
}

impl Port {
    pub unsafe fn new(cap: CPtr) -> Port {
        Port { cap }
    }

    pub unsafe fn outb(&self, x: u8) -> KernelResult<()> {
        self.cap.call_result(PORT_WRITE, 1, x as _, 0).map(|_| ())
    }

    pub unsafe fn inb(&self) -> KernelResult<u8> {
        self.cap.call_result(PORT_READ, 1, 0, 0).map(|x| x as u8)
    }
}
