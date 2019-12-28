use crate::capset::CapSet;
use crate::error::*;
use crate::mm::RootPageTable;
use crate::syscall::*;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::convert::TryFrom;
use spin::Mutex;
use crate::ipc::TaskEndpoint;

pub const LOCAL_CAP_INDEX_CAPSET: u64 = 31;
pub const LOCAL_CAP_INDEX_RPT: u64 = 30;

lazy_static! {
    pub static ref ROOT_TASK: Task = Task {
        cap: unsafe { CPtr::new(0) },
    };
    pub static ref ROOT_CAPSET: CapSet = {
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
        unsafe { CapSet::new(CPtr::new(LOCAL_CAP_INDEX_CAPSET)) }
    };
    pub static ref ROOT_PAGE_TABLE: RootPageTable = {
        unsafe {
            ROOT_TASK
                .cap
                .call_result(
                    BasicTaskRequest::FetchRootPageTable as u32 as i64,
                    LOCAL_CAP_INDEX_RPT as i64,
                    0,
                    0,
                )
                .unwrap();
        }
        unsafe { RootPageTable::new(CPtr::new(LOCAL_CAP_INDEX_RPT)) }
    };
    static ref CAP_ALLOC_STATE: Mutex<CapAllocState> = Mutex::new(CapAllocState::new());
}

pub struct Task {
    cap: CPtr,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum BasicTaskRequest {
    Ping = 0,
    FetchShallowClone = 1,
    FetchCapSet = 2,
    FetchRootPageTable = 3,
    GetRegister = 4,
    SetRegister = 5,
    FetchTaskEndpoint = 7,
    FetchIpcCap = 8,
    PutIpcCap = 9,
    PutCapSet = 10,
    MakeCapSet = 12,
    MakeRootPageTable = 13,
    PutRootPageTable = 14,
    IpcReturn = 15,
    FetchWeak = 16,
    HasWeak = 17,
}

bitflags! {
    pub struct TaskEndpointFlags: u16 {
        /// Whether capability transfer is performed for this endpoint.
        const CAP_TRANSFER = 1 << 0;

        /// Whether this endpoint can be used to add tags.
        const TAGGABLE = 1 << 1;
    }
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

    pub fn into_cptr(self) -> CPtr {
        self.cap
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

    pub fn fetch_root_page_table(&self) -> KernelResult<RootPageTable> {
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

    pub fn ping(&self) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(
                BasicTaskRequest::Ping as u32 as i64,
                0, 0, 0,
            )?;
        }
        Ok(())
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

    pub fn shallow_clone(&self) -> KernelResult<Task> {
        let (cptr, _) = allocate_cptr(|cptr| {
            unsafe {
                self.cap.call_result(
                    BasicTaskRequest::FetchShallowClone as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )
            }
            .map(|_| ())
        })?;
        Ok(Task { cap: cptr })
    }

    pub fn fetch_weak(&self) -> KernelResult<Task> {
        let (cptr, _) = allocate_cptr(|cptr| {
            unsafe {
                self.cap.call_result(
                    BasicTaskRequest::FetchWeak as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )
            }
            .map(|_| ())
        })?;
        Ok(Task { cap: cptr })
    }

    pub fn has_weak(&self) -> KernelResult<bool> {
        unsafe {
            self.cap.call_result(
                BasicTaskRequest::HasWeak as u32 as i64,
                0,
                0,
                0,
            )
        }
        .map(|x| x == 1)
    }

    pub fn fetch_ipc_cap(&self, index: u8) -> KernelResult<CPtr> {
        let (cptr, _) = allocate_cptr(|cptr| unsafe {
            self.cap
                .call_result(
                    BasicTaskRequest::FetchIpcCap as u32 as i64,
                    cptr.index() as _,
                    index as _,
                    0,
                )
                .map(|_| ())
        })?;
        Ok(cptr)
    }

    pub fn put_ipc_cap(&self, index: u8, cptr: CPtr) -> KernelResult<()> {
        unsafe {
            self.cap
                .call_result(
                    BasicTaskRequest::PutIpcCap as u32 as i64,
                    cptr.index() as _,
                    index as _,
                    0,
                )
                .map(|_| ())
        }
    }

    pub fn fetch_task_endpoint(&self, pc: u64, context: u64, flags: TaskEndpointFlags, reply: bool) -> KernelResult<TaskEndpoint> {
        let (cptr, _) = allocate_cptr(|cptr| unsafe {
            let mixed_arg1 = cptr.index() | ((flags.bits() as u64) << 48) | ((if reply { 1u64 } else { 0u64 }) << 63);
            self.cap
                .call_result(
                    BasicTaskRequest::FetchTaskEndpoint as u32 as i64,
                    mixed_arg1 as _,
                    pc as _,
                    context as _,
                )
                .map(|_| ())
        })?;
        Ok(unsafe { TaskEndpoint::new(cptr) })
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

    pub fn put_root_page_table(&self, rpt: &RootPageTable) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(
                BasicTaskRequest::PutRootPageTable as u32 as i64,
                rpt.cptr().index() as i64,
                0,
                0,
            )?;
        }
        Ok(())
    }

    pub fn make_root_page_table(&self) -> KernelResult<RootPageTable> {
        unsafe {
            let (cptr, _) = allocate_cptr(|cptr| {
                self.cap.call_result(
                    BasicTaskRequest::MakeRootPageTable as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )?;
                Ok(())
            })?;
            Ok(RootPageTable::new(cptr))
        }
    }

    pub fn ipc_return(&self) -> KernelError {
        unsafe {
            match self.cap.call_result(
                BasicTaskRequest::IpcReturn as u32 as i64,
                0, 0, 0
            ) {
                Ok(_) => KernelError::InvalidState,
                Err(e) => e,
            }
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
            ROOT_CAPSET.make_leaf(new_base)?;
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
        .trivial_drop_cap(cptr.index())
        .expect("trivial_drop_cap failed");
    push_release_pool(&mut state, cptr);
}

#[inline]
fn push_release_pool(state: &mut CapAllocState, cptr: &CPtr) {
    state.release_pool.push_back(cptr.index());
}
