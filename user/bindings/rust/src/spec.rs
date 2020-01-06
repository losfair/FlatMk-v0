use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use core::convert::TryFrom;

pub const PAGE_SIZE: usize = 4096;

#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct CPtr(u64);

impl CPtr {
    pub const fn new(inner: u64) -> Self {
        CPtr(inner)
    }

    pub fn index(&self) -> u64 {
        self.0
    }

    pub unsafe fn call(&self, p0: i64, p1: i64, p2: i64, p3: i64) -> i64 {
        _do_syscall(self.0 as i64, p0, p1, p2, p3, 0)
    }
}

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

pub fn to_result(code: i64) -> Result<u64, KernelError> {
    if code < 0 {
        Err(match KernelError::try_from(code) {
            Ok(x) => x,
            Err(_) => KernelError::InvalidArgument,
        })
    } else {
        Ok(code as u64)
    }
}

include!("../generated/flatmk_spec.rs");

pub static CAP_TRIVIAL_SYSCALL: TrivialSyscallEntry = unsafe { TrivialSyscallEntry::new(CPtr::new(core::u64::MAX)) };
