use crate::error::*;
use crate::syscall::CPtr;
use crate::task::allocate_cptr;
use core::convert::TryFrom;

pub struct RootPageTable {
    cap: CPtr,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum RootPageTableRequest {
    MakeLeaf = 0,
    AllocLeaf = 1,
    FetchDeepClone = 2,
}

impl RootPageTable {
    pub unsafe fn new(cap: CPtr) -> RootPageTable {
        RootPageTable { cap }
    }

    pub fn cptr(&self) -> &CPtr {
        &self.cap
    }

    pub fn deep_clone(&self) -> KernelResult<RootPageTable> {
        let (cptr, _) = allocate_cptr(|cptr| {
            unsafe {
                self.cap.call_result(
                    RootPageTableRequest::FetchDeepClone as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )?;
            }
            Ok(())
        })?;
        Ok(unsafe { RootPageTable::new(cptr) })
    }

    pub fn make_leaf(&self, vaddr: u64) -> KernelResult<()> {
        unsafe {
            self.cap
                .call_result(
                    RootPageTableRequest::MakeLeaf as u32 as i64,
                    vaddr as i64,
                    0,
                    0,
                )
                .map(|_| ())
        }
    }

    pub fn alloc_leaf(&self, vaddr: u64) -> KernelResult<()> {
        unsafe {
            self.cap
                .call_result(
                    RootPageTableRequest::AllocLeaf as u32 as i64,
                    vaddr as i64,
                    0,
                    0,
                )
                .map(|_| ())
        }
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
        self.cap.call_result(vaddr as i64, 0, 0, 0).map(|_| ())
    }
}
