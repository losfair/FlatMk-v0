use crate::syscall::{Delegation, CPtr};
use alloc::boxed::Box;

pub struct LocalMapper {
    cap: CPtr,
}

impl LocalMapper {
    pub unsafe fn new(cap: CPtr) -> LocalMapper {
        LocalMapper {
            cap,
        }
    }

    pub unsafe fn map_page(&self, vaddr: u64) -> Result<(), i64> {
        loop {
            let mut del = Box::new(Delegation::new());
            let ret = self.cap.call(vaddr as i64, &mut *del as *mut Delegation as i64, 0, 0);
            if ret <= 0  {
                return Err(ret);
            }
            Box::leak(del);
            if ret == 1 {
                break;
            }
        }
        Ok(())
    }
}

pub struct LocalMmio {
    cap: CPtr,
}

impl LocalMmio {
    pub unsafe fn new(cap: CPtr) -> LocalMmio {
        LocalMmio {
            cap,
        }
    }

    pub unsafe fn alloc_at(&self, vaddr: u64, paddr: u64) -> Result<(), i64> {
        let ret = self.cap.call(vaddr as i64, paddr as i64, 0, 0);
        if ret != 0  {
            Err(ret)
        } else {
            Ok(())
        }
    }
}