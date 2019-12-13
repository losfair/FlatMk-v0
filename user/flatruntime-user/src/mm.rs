use crate::error::*;
use crate::syscall::{CPtr, Delegation};
use alloc::boxed::Box;
use core::convert::TryFrom;

pub struct RootPageTable {
    cap: CPtr,
}

impl RootPageTable {
    pub unsafe fn new(cap: CPtr) -> RootPageTable {
        RootPageTable { cap }
    }

    pub unsafe fn map_page(&self, vaddr: u64) -> Result<(), i64> {
        loop {
            let mut del = Box::new(Delegation::new());
            let ret = self
                .cap
                .call(vaddr as i64, &mut *del as *mut Delegation as i64, 0, 0);
            if ret < 0 {
                return Err(ret);
            }
            if ret == 0 {
                break;
            }

            Box::leak(del);
            if ret == 1 {
                break;
            }
        }
        Ok(())
    }
}

pub struct Mmio {
    cap: CPtr,
}

impl Mmio {
    pub unsafe fn new(cap: CPtr) -> Mmio {
        Mmio { cap }
    }

    pub unsafe fn alloc_at(&self, vaddr: u64) -> KernelResult<()> {
        let result = self.cap.call(vaddr as i64, 0, 0, 0);
        if result < 0 {
            Err(KernelError::try_from(result as i32).unwrap())
        } else {
            Ok(())
        }
    }
}
