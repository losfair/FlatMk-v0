use crate::error::*;
use crate::syscall::*;
use crate::task::allocate_cptr;

pub struct CapSet {
    cap: CPtr,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum CapSetRequest {
    MakeLeafSet = 0,
    CloneCap = 1,
    DropCap = 2,
    FetchCap = 3,
    PutCap = 4,
    FetchDeepClone = 5,
    MoveCap = 6,
}

impl CapSet {
    pub const unsafe fn new(cptr: CPtr) -> CapSet {
        CapSet { cap: cptr }
    }

    pub fn cptr(&self) -> &CPtr {
        &self.cap
    }

    pub fn deep_clone(&self) -> KernelResult<CapSet> {
        let (cptr, _) = allocate_cptr(|cptr| {
            unsafe {
                self.cap.call_result(
                    CapSetRequest::FetchDeepClone as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )?;
            }
            Ok(())
        })?;
        Ok(unsafe { CapSet::new(cptr) })
    }

    pub fn make_leaf(&self, ptr: u64) -> KernelResult<()> {
        unsafe {
            self.cap
                .call_result(CapSetRequest::MakeLeafSet as u32 as i64, ptr as i64, 0, 0)?;
        }
        Ok(())
    }

    pub fn trivial_clone_cap(&self, src: u64, dst: u64) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(
                CapSetRequest::CloneCap as u32 as i64,
                src as i64,
                dst as i64,
                0,
            )?;
        }
        Ok(())
    }

    pub fn trivial_drop_cap(&self, cap: u64) -> KernelResult<()> {
        unsafe {
            self.cap
                .call_result(CapSetRequest::DropCap as u32 as i64, cap as i64, 0, 0)?;
        }
        Ok(())
    }

    pub fn put_cap(&self, src: &CPtr, dst: u64) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(
                CapSetRequest::PutCap as u32 as i64,
                src.index() as i64,
                dst as i64,
                0,
            )?;
        }
        Ok(())
    }

    pub fn fetch_cap(&self, src: u64) -> KernelResult<CPtr> {
        let (cptr, _) = allocate_cptr(|cptr| {
            unsafe {
                self.cap.call_result(
                    CapSetRequest::FetchCap as u32 as i64,
                    src as i64,
                    cptr.index() as i64,
                    0,
                )?;
            }
            Ok(())
        })?;
        Ok(cptr)
    }

    pub fn trivial_move_cap(&self, src: u64, dst: u64) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(
                CapSetRequest::MoveCap as u32 as i64,
                src as i64,
                dst as i64,
                0,
            )?;
        }
        Ok(())
    }

    pub fn take_ipc_cap(&self, src: u64) -> KernelResult<CPtr> {
        let (cptr, _) = allocate_cptr(|cptr| {
            self.trivial_move_cap(src, cptr.index())
        })?;
        Ok(cptr)
    }
}
