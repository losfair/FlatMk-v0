use crate::error::*;
use crate::mm::Vmap;
use crate::syscall::*;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::convert::TryFrom;
use spin::Mutex;

lazy_static! {
    static ref CAP_ALLOC_STATE: Mutex<CapAllocState> = Mutex::new(CapAllocState::new());
}

static CAP_TASK: CPtr = unsafe { CPtr::new_twolevel(0, 0) };

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum BasicTaskRequest {
    MakeFirstLevelEndpoint = 0,
    CapVmap = 1,
}

pub const MAX_LEVEL0: u8 = 255;
pub const MAX_LEVEL1: u8 = 31;

struct CapAllocState {
    current_level0: u8,
    current_level1: u8,
    release_pool: VecDeque<(u8, u8)>,
}

impl CapAllocState {
    fn new() -> CapAllocState {
        CapAllocState {
            current_level0: 0,
            current_level1: 7,
            release_pool: VecDeque::new(),
        }
    }
}

pub fn allocate_cptr() -> CPtr {
    let mut state = CAP_ALLOC_STATE.lock();

    if let Some(x) = state.release_pool.pop_front() {
        return unsafe { CPtr::new_twolevel(x.0, x.1) };
    }

    if state.current_level0 == MAX_LEVEL0 && state.current_level1 == MAX_LEVEL1 {
        panic!("allocate_cptr: out of space");
    }

    if state.current_level1 == MAX_LEVEL1 {
        let delegation = Box::into_raw(Box::new(Delegation::new()));
        let ret = unsafe {
            CAP_TASK.call(
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
}

/// Called by the Drop implementation for CPtr.
pub(crate) unsafe fn release_cptr(cptr: &mut CPtr) {
    let mut state = CAP_ALLOC_STATE.lock();
    state
        .release_pool
        .push_back(((cptr.index() >> 56) as u8, (cptr.index() >> 48) as u8));
}

pub fn new_vmap() -> KernelResult<Vmap> {
    let cptr = allocate_cptr();
    let result = unsafe {
        CAP_TASK.call(
            BasicTaskRequest::CapVmap as u32 as i64,
            cptr.index() as i64,
            0,
            0,
        )
    };
    if result < 0 {
        Err(KernelError::try_from(result as i32).unwrap())
    } else {
        Ok(unsafe { Vmap::new(cptr) })
    }
}

/// Invokes an invalid operation on CAP_TASK.
/// Useful for benchmarking.
pub fn call_invalid() {
    unsafe {
        CAP_TASK.call(-1, 0, 0, 0);
    }
}
