use crate::error::*;
use crate::syscall::CPtr;
use alloc::boxed::Box;
use core::convert::TryFrom;

pub struct RootPageTable {
    cap: CPtr,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum RootPageTableRequest {
    MakeLeaf = 0,
    AllocLeaf = 1,
}

impl RootPageTable {
    pub unsafe fn new(cap: CPtr) -> RootPageTable {
        RootPageTable { cap }
    }

    pub unsafe fn make_leaf(&self, vaddr: u64) -> KernelResult<()> {
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
