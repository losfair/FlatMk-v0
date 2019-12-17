use crate::error::*;
use crate::mm::RootPageTable;
use crate::syscall::*;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::convert::TryFrom;
use spin::Mutex;
use core::mem::ManuallyDrop;

lazy_static! {
    pub static ref THIS_TASK: Task = Task {
        cap: ManuallyDrop::new(unsafe { CPtr::new_twolevel(0, 0) }),
        backing: None,
    };
    static ref CAP_ALLOC_STATE: Mutex<CapAllocState> = Mutex::new(CapAllocState::new());
}

pub struct Task {
    cap: ManuallyDrop<CPtr>,
    backing: Option<Box<Delegation>>,
}

impl Drop for Task {
    fn drop(&mut self) {
        let is_unique = match unsafe {
            self.cap.call(
                BasicTaskRequest::IsUnique as u32 as i64,
                0,
                0,
                0,
            )
        } {
            x if x < 0 => panic!("Error calling IsUnique on task: {:?}", KernelError::try_from(x as i32).unwrap()),
            0 => false,
            1 => true,
            _ => panic!("Unexpected result from IsUnique"),
        };
        unsafe {
            ManuallyDrop::drop(&mut self.cap);
        }
        if !is_unique {
            core::mem::forget(self.backing.take());
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum BasicTaskRequest {
    CloneCap = 0,
    DropCap = 1,
    FetchCap = 2,
    PutCap = 3,
    SwitchTo = 4,
    FetchDeepClone = 5,
    MakeFirstLevelEndpoint = 6,
    FetchRootPageTable = 7,
    GetRegister = 8,
    SetRegister = 9,
    FetchNewUserPageSet = 10,
    FetchIpcEndpoint = 11,
    UnblockIpc = 12,
    FetchIpcCap = 13,
    ResetCaps = 14,
    IpcIsBlocked = 15,
    IsUnique = 16,
}

struct CapAllocState {
    current_level0: u8,
    current_level1: u8,
    release_pool: VecDeque<(u8, u8)>,
}

pub const MAX_LEVEL0: u8 = 255;
pub const MAX_LEVEL1: u8 = 31;

impl CapAllocState {
    fn new() -> CapAllocState {
        CapAllocState {
            current_level0: 0,
            current_level1: 7,
            release_pool: VecDeque::new(),
        }
    }
}

impl Task {
    pub fn get_cptr(&self) -> &CPtr {
        &self.cap
    }

    pub fn fetch_rpt(&self) -> KernelResult<RootPageTable> {
        let (cptr, _) = allocate_cptr(|cptr| {
            let result = unsafe {
                self.cap.call(
                    BasicTaskRequest::FetchRootPageTable as u32 as i64,
                    cptr.index() as i64,
                    0,
                    0,
                )
            };
            if result < 0 {
                Err(KernelError::try_from(result as i32).unwrap())
            } else {
                Ok(())
            }
        })?;
        Ok(unsafe { RootPageTable::new(cptr) })
    }

    /// Invokes an invalid operation on CAP_TASK.
    /// Useful for benchmarking.
    pub fn call_invalid(&self) {
        unsafe {
            self.cap.call(-2, 0, 0, 0); // -1 is INVALID_CAP
        }
    }

    pub fn set_register(&self, index: u32, value: u64) -> KernelResult<()> {
        match unsafe {
            self.cap.call(
                BasicTaskRequest::SetRegister as u32 as i64,
                index as i64,
                value as i64,
                0,
            )
        } {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            _ => Ok(()),
        }
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

    pub fn switch_to(&self) {
        unsafe {
            self.cap
                .call(BasicTaskRequest::SwitchTo as u32 as i64, 0, 0, 0);
        }
    }

    pub fn deep_clone(&self) -> KernelResult<Task> {
        let mut backing = unsafe { Delegation::new_uninitialized_boxed() };
        let backing_ptr: *mut Delegation = &mut *backing;

        let (cptr, _) = allocate_cptr(|cptr| {
            match unsafe {
                self.cap.call(
                    BasicTaskRequest::FetchDeepClone as u32 as i64,
                    cptr.index() as i64,
                    backing_ptr as i64,
                    0,
                )
            } {
                x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
                _ => Ok(()),
            }
        })?;
        Ok(Task {
            cap: ManuallyDrop::new(cptr),
            backing: Some(backing),
        })
    }

    pub fn fetch_ipc_cap(&self, index: usize) -> KernelResult<CPtr> {
        let (cptr, _) = allocate_cptr(|cptr| {
            match unsafe {
                self.cap.call(
                    BasicTaskRequest::FetchIpcCap as u32 as i64,
                    cptr.index() as _,
                    index as _,
                    0,
                )
            } {
                x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
                _ => Ok(()),
            }
        })?;
        Ok(cptr)
    }

    pub fn fetch_ipc_endpoint(&self, pc: u64, sp: u64) -> KernelResult<CPtr> {
        let (cptr, _) = allocate_cptr(|cptr| {
            match unsafe {
                self.cap.call(
                    BasicTaskRequest::FetchIpcEndpoint as u32 as i64,
                    cptr.index() as _,
                    pc as _,
                    sp as _,
                )
            } {
                x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
                _ => Ok(()),
            }
        })?;
        Ok(cptr)
    }

    pub fn unblock_ipc(&self) -> KernelResult<()> {
        match unsafe {
            self.cap
                .call(BasicTaskRequest::UnblockIpc as u32 as i64, 0, 0, 0)
        } {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            _ => Ok(()),
        }
    }

    pub fn reset_caps(&self, delegation: Box<Delegation>) -> KernelResult<()> {
        let raw = Box::into_raw(delegation);
        match unsafe {
            self.cap
                .call(BasicTaskRequest::ResetCaps as u32 as i64, raw as i64, 0, 0)
        } {
            x if x < 0 => {
                unsafe {
                    Box::from_raw(raw);
                }
                Err(KernelError::try_from(x as i32).unwrap())
            }
            _ => Ok(()),
        }
    }

    pub unsafe fn trivial_clone_cap(&self, src: u64, dst: u64) -> KernelResult<()> {
        match self.cap.call(
            BasicTaskRequest::CloneCap as u32 as i64,
            src as i64,
            dst as i64,
            0,
        ) {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            _ => Ok(()),
        }
    }

    pub unsafe fn trivial_drop_cap(&self, cap: u64) -> KernelResult<()> {
        match self
            .cap
            .call(BasicTaskRequest::DropCap as u32 as i64, cap as i64, 0, 0)
        {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            _ => Ok(()),
        }
    }

    pub unsafe fn fetch_cap(&self, src: u64) -> KernelResult<CPtr> {
        let (cptr, _) = allocate_cptr(|cptr| {
            match self.cap.call(
                BasicTaskRequest::FetchCap as u32 as i64,
                src as i64,
                cptr.index() as i64,
                0,
            ) {
                x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
                _ => Ok(()),
            }
        })?;
        Ok(cptr)
    }

    pub unsafe fn put_cap(&self, src: &CPtr, dst: u64) -> KernelResult<()> {
        match self.cap.call(
            BasicTaskRequest::PutCap as u32 as i64,
            src.index() as i64,
            dst as i64,
            0,
        ) {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            _ => Ok(()),
        }
    }

    pub fn ipc_is_blocked(&self) -> KernelResult<bool> {
        match unsafe {
            self.cap
                .call(BasicTaskRequest::IpcIsBlocked as u32 as i64, 0, 0, 0)
        } {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            0 => Ok(false),
            1 => Ok(true),
            _ => panic!("ipc_is_blocked: unexpected result from kernel"),
        }
    }

    pub unsafe fn make_first_level_endpoint(
        &self,
        index: usize,
        delegation: Box<Delegation>,
    ) -> KernelResult<()> {
        let delegation = Box::into_raw(delegation);
        let ret = self.cap.call(
            BasicTaskRequest::MakeFirstLevelEndpoint as u32 as i64,
            index as i64,
            delegation as i64,
            0,
        );
        match ret {
            x if x < 0 => {
                Box::from_raw(delegation);
                Err(KernelError::try_from(x as i32).unwrap())
            }
            _ => Ok(()),
        }
    }
}

#[inline]
pub fn allocate_cptr<T, F: FnOnce(&CPtr) -> KernelResult<T>>(
    initializer: F,
) -> KernelResult<(CPtr, T)> {
    let mut state = CAP_ALLOC_STATE.lock();

    let cptr = if let Some(x) = state.release_pool.pop_front() {
        unsafe { CPtr::new_twolevel(x.0, x.1) }
    } else {
        if state.current_level0 == MAX_LEVEL0 && state.current_level1 == MAX_LEVEL1 {
            panic!("allocate_cptr: out of space");
        }

        if state.current_level1 == MAX_LEVEL1 {
            let delegation = Box::into_raw(unsafe { Delegation::new_uninitialized_boxed() });
            let ret = unsafe {
                THIS_TASK.cap.call(
                    BasicTaskRequest::MakeFirstLevelEndpoint as u32 as i64,
                    (state.current_level0 + 1) as i64,
                    delegation as i64,
                    0,
                )
            };
            if ret != 0 {
                panic!("unable to allocate first level endpoint");
            }
            state.current_level0 += 1;
            state.current_level1 = 0;
        } else {
            state.current_level1 += 1;
        }

        unsafe { CPtr::new_twolevel(state.current_level0, state.current_level1) }
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
    if THIS_TASK.cap.call(
        BasicTaskRequest::DropCap as u32 as i64,
        cptr.index() as i64,
        0,
        0,
    ) != 0
    {
        panic!("DropCap failed");
    }
    push_release_pool(&mut state, cptr);
}

#[inline]
pub(crate) unsafe fn release_cptr_no_dropcap(cptr: &mut CPtr) {
    let mut state = CAP_ALLOC_STATE.lock();
    push_release_pool(&mut state, cptr);
}

#[inline]
fn push_release_pool(state: &mut CapAllocState, cptr: &CPtr) {
    state
        .release_pool
        .push_back(((cptr.index() >> 56) as u8, (cptr.index() >> 48) as u8));
}
