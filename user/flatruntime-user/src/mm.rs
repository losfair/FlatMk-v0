use crate::error::*;
use crate::syscall::CPtr;
use crate::task::{ROOT_CAPSET, allocate_cptr};
use core::convert::TryFrom;
use crate::capset::CapType;

pub struct RootPageTable {
    cap: CPtr,
}

bitflags! {
    pub struct UserPteFlags: u64 {
        const WRITABLE = 1 << 0;
        const EXECUTABLE = 1 << 1;
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum RootPageTableRequest {
    MakeLeaf = 0,
    AllocLeaf = 1,
    FetchDeepClone = 2,
    PutPage = 3,
    FetchPage = 4,
    DropPage = 5,
    SetProtection = 6,
}

impl RootPageTable {
    pub unsafe fn new(cap: CPtr) -> RootPageTable {
        RootPageTable { cap }
    }

    pub fn checked_new(cap: CPtr) -> KernelResult<RootPageTable> {
        if ROOT_CAPSET.get_cap_type(&cap)? == CapType::RootPageTable as u32 {
            Ok(unsafe { RootPageTable::new(cap) })
        } else {
            Err(KernelError::InvalidArgument)
        }
    }

    pub fn cptr(&self) -> &CPtr {
        &self.cap
    }

    pub fn into_cptr(self) -> CPtr {
        self.cap
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

    pub fn alloc_leaf(&self, vaddr: u64, prot: UserPteFlags) -> KernelResult<()> {
        unsafe {
            self.cap
                .call_result(
                    RootPageTableRequest::AllocLeaf as u32 as i64,
                    vaddr as i64,
                    prot.bits() as i64,
                    0,
                )
                .map(|_| ())
        }
    }

    pub unsafe fn put_page(&self, src: u64, dst: u64, prot: UserPteFlags) -> KernelResult<()> {
        self.cap.call_result(
            RootPageTableRequest::PutPage as u32 as i64,
            src as _,
            dst as _,
            prot.bits() as i64,
        ).map(|_| ())
    }

    pub unsafe fn fetch_page(&self, src: u64, dst: u64, prot: UserPteFlags) -> KernelResult<()> {
        self.cap.call_result(
            RootPageTableRequest::FetchPage as u32 as i64,
            src as _,
            dst as _,
            prot.bits() as i64,
        ).map(|_| ())
    }

    pub fn drop_page(&self, target: u64) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(
                RootPageTableRequest::DropPage as u32 as i64,
                target as _,
                0,
                0,
            ).map(|_| ())
        }
    }

    pub fn set_protection(&self, target: u64, prot: UserPteFlags) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(
                RootPageTableRequest::SetProtection as u32 as i64,
                target as _,
                prot.bits() as i64,
                0,
            ).map(|_| ())
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

    pub unsafe fn alloc_at(&self, vaddr: u64, prot: UserPteFlags) -> KernelResult<()> {
        self.cap.call_result(vaddr as i64, prot.bits() as i64, 0, 0).map(|_| ())
    }
}
