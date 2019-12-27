use crate::error::*;
use core::convert::TryFrom;
use core::intrinsics::abort;
use core::mem::MaybeUninit;

unsafe fn _do_syscall(p0: i64, p1: i64, p2: i64, p3: i64, p4: i64, p5: i64) -> i64 {
    let result: i64;
    asm!(
        "mov $$0, %rax\nsyscall" :
            "={rax}"(result) :
            "{rdi}"(p0), "{rsi}"(p1), "{rdx}"(p2), "{r10}"(p3), "{r8}"(p4), "{r9}"(p5) :
            "rcx", "r11"
    );
    result
}

pub const INVALID_CAP: u64 = core::u64::MAX;

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum RootTaskCapRequest {
    AnyX86IoPort = 0,
    LocalMap = 1,
    LocalMmio = 2,
}

#[repr(transparent)]
pub struct CPtr(u64);

impl CPtr {
    pub const unsafe fn new(inner: u64) -> CPtr {
        CPtr(inner)
    }

    #[inline(never)]
    pub unsafe fn call(&self, p0: i64, p1: i64, p2: i64, p3: i64) -> i64 {
        _do_syscall(self.0 as _, p0, p1, p2, p3, 0)
    }

    pub unsafe fn call_result(&self, p0: i64, p1: i64, p2: i64, p3: i64) -> KernelResult<i64> {
        match self.call(p0, p1, p2, p3) {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            x => Ok(x),
        }
    }

    #[inline]
    pub unsafe fn leaky_call(mut self, p0: i64, p1: i64, p2: i64, p3: i64) -> i64 {
        let raw = self.0;
        core::mem::forget(self);
        _do_syscall(raw as _, p0, p1, p2, p3, 0)
    }

    pub fn index(&self) -> u64 {
        self.0
    }
}

impl Drop for CPtr {
    fn drop(&mut self) {
        unsafe {
            crate::task::release_cptr(self);
        }
    }
}
