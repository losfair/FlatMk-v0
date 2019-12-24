use crate::capset::CapSet;
use crate::error::*;
use crate::mm::RootPageTable;
use crate::syscall::*;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::convert::TryFrom;
use spin::Mutex;

pub const LOCAL_CAP_INDEX_CAPSET: u64 = 4;

lazy_static! {
    pub static ref ROOT_TASK: Task = Task {
        cap: unsafe { CPtr::new(0) },
    };
    pub static ref ROOT_CAPSET: Mutex<CapSet> = {
        unsafe {
            ROOT_TASK
                .cap
                .call_result(
                    BasicTaskRequest::FetchCapSet as u32 as i64,
                    LOCAL_CAP_INDEX_CAPSET as i64,
                    0,
                    0,
                )
                .unwrap();
        }
        Mutex::new(unsafe { CapSet::new(CPtr::new(LOCAL_CAP_INDEX_CAPSET)) })
    };
    static ref CAP_ALLOC_STATE: Mutex<CapAllocState> = Mutex::new(CapAllocState::new());
}

pub struct Task {
    cap: CPtr,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum BasicTaskRequest {
    FetchDeepClone = 1,
    FetchCapSet = 2,
    FetchRootPageTable = 3,
    GetRegister = 4,
    SetRegister = 5,
    FetchNewUserPageSet = 6,
    FetchTaskEndpoint = 7,
    UnblockIpc = 8,
    SetIpcBase = 9,
    PutCapSet = 10,
    IpcIsBlocked = 11,
    MakeCapSet = 12,
}

struct CapAllocState {
    current_level0: u64,
    current_level1: u8,
    release_pool: VecDeque<u64>,
}

pub const BASE_LEVEL0: u64 = 0x600000;

pub const MAX_LEVEL0: u64 = core::u32::MAX as u64;
pub const MAX_LEVEL1: u8 = 31;

pub const LEAF_BITS: usize = 8;

impl CapAllocState {
    fn new() -> CapAllocState {
        CapAllocState {
            current_level0: BASE_LEVEL0 - 1,
            current_level1: 31,
            release_pool: VecDeque::new(),
        }
    }
}

impl Task {
    pub fn cptr(&self) -> &CPtr {
        &self.cap
    }

    pub fn fetch_capset(&self) -> KernelResult<CapSet> {
        let (cptr, _) = allocate_cptr(|cptr| {
            unsafe {
                self.cap.call_result(
                    BasicTaskRequest::FetchCapSet as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )
            }
            .map(|_| ())
        })?;
        Ok(unsafe { CapSet::new(cptr) })
    }

    pub fn fetch_rpt(&self) -> KernelResult<RootPageTable> {
        let (cptr, _) = allocate_cptr(|cptr| {
            unsafe {
                self.cap.call_result(
                    BasicTaskRequest::FetchRootPageTable as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )
            }
            .map(|_| ())
        })?;
        Ok(unsafe { RootPageTable::new(cptr) })
    }

    /// Invokes an invalid operation on CAP_TASK.
    /// Useful for benchmarking.
    pub fn call_invalid(&self) {
        unsafe {
            self.cap.call(-1, 0, 0, 0);
        }
    }

    pub fn set_register(&self, index: u32, value: u64) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(
                BasicTaskRequest::SetRegister as u32 as i64,
                index as i64,
                value as i64,
                0,
            )?;
        }
        Ok(())
    }

    pub fn get_register(&self, index: u32) -> KernelResult<u64> {
        let mut result: u64 = 0;
        match unsafe {
            self.cap.call(
                BasicTaskRequest::GetRegister as u32 as i64,
                index as i64,
                &mut result as *mut _ as i64,
                0,
            )
        } {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            _ => Ok(result),
        }
    }

    pub fn deep_clone(&self) -> KernelResult<Task> {
        let (cptr, _) = allocate_cptr(|cptr| {
            unsafe {
                self.cap.call_result(
                    BasicTaskRequest::FetchDeepClone as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )
            }
            .map(|_| ())
        })?;
        Ok(Task { cap: cptr })
    }

    pub fn set_ipc_base(&self, base: u64) -> KernelResult<()> {
        unsafe {
            self.cap
                .call_result(BasicTaskRequest::SetIpcBase as u32 as i64, base as _, 0, 0)
                .map(|_| ())
        }
    }

    pub fn fetch_task_endpoint(&self, pc: u64) -> KernelResult<CPtr> {
        let (cptr, _) = allocate_cptr(|cptr| unsafe {
            self.cap
                .call_result(
                    BasicTaskRequest::FetchTaskEndpoint as u32 as i64,
                    cptr.index() as _,
                    pc as _,
                    0,
                )
                .map(|_| ())
        })?;
        Ok(cptr)
    }

    pub fn unblock_ipc(&self) -> KernelResult<()> {
        unsafe {
            self.cap
                .call_result(BasicTaskRequest::UnblockIpc as u32 as i64, 0, 0, 0).map(|_| ())
        }
    }

    pub fn put_capset(&self, capset: &CapSet) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(
                BasicTaskRequest::PutCapSet as u32 as i64,
                capset.cptr().index() as i64,
                0,
                0,
            )?;
        }
        Ok(())
    }

    pub fn make_capset(&self) -> KernelResult<CapSet> {
        unsafe {
            let (cptr, _) = allocate_cptr(|cptr| {
                self.cap.call_result(
                    BasicTaskRequest::MakeCapSet as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )?;
                Ok(())
            })?;
            Ok(CapSet::new(cptr))
        }
    }

    pub fn ipc_is_blocked(&self) -> KernelResult<bool> {
        unsafe {
            self.cap
                .call_result(BasicTaskRequest::IpcIsBlocked as u32 as i64, 0, 0, 0).map(|x| x != 0)
        }
    }
}

#[inline]
pub fn allocate_cptr<T, F: FnOnce(&CPtr) -> KernelResult<T>>(
    initializer: F,
) -> KernelResult<(CPtr, T)> {
    let mut state = CAP_ALLOC_STATE.lock();

    let cptr = if let Some(x) = state.release_pool.pop_front() {
        unsafe { CPtr::new(x) }
    } else {
        if state.current_level0 == MAX_LEVEL0 && state.current_level1 == MAX_LEVEL1 {
            panic!("allocate_cptr: out of space");
        }

        if state.current_level1 == MAX_LEVEL1 {
            let new_base = (state.current_level0 + 1) << LEAF_BITS;
            ROOT_CAPSET.lock().make_leaf(new_base)?;
            state.current_level0 += 1;
            state.current_level1 = 0;
        } else {
            state.current_level1 += 1;
        }

        unsafe { CPtr::new((state.current_level0 << LEAF_BITS) | (state.current_level1 as u64)) }
    };

    match initializer(&cptr) {
        Ok(x) => Ok((cptr, x)),
        Err(e) => {
            // Don't run destructors.
            push_release_pool(&mut state, &cptr);
            core::mem::forget(cptr);
            Err(e)
        }
    }
}

/// Called by the Drop implementation for CPtr.
#[inline]
pub(crate) unsafe fn release_cptr(cptr: &mut CPtr) {
    let mut state = CAP_ALLOC_STATE.lock();
    ROOT_CAPSET
        .lock()
        .trivial_drop_cap(cptr.index())
        .expect("trivial_drop_cap failed");
    push_release_pool(&mut state, cptr);
}

#[inline]
fn push_release_pool(state: &mut CapAllocState, cptr: &CPtr) {
    state.release_pool.push_back(cptr.index());
}
