use crate::syscall::CPtr;

const PORT_READ: i64 = 0;
const PORT_WRITE: i64 = 1;

pub struct Port {
    cap: CPtr,
}

impl Port {
    pub unsafe fn new(cap: CPtr) -> Port {
        Port { cap }
    }

    pub unsafe fn outb(&self, x: u8) {
        if self.cap.call(PORT_WRITE, 1, x as _, 0) < 0 {
            panic!("PORT_WRITE failed");
        }
    }

    pub unsafe fn inb(&self) -> u8 {
        match self.cap.call(PORT_READ, 1, 0, 0) {
            x if x >= 0 => x as u8,
            _ => panic!("PORT_READ failed"),
        }
    }
}
