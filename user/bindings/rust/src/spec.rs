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

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "riscv32")]
unsafe fn _do_syscall(p0: i64, p1: i64, p2: i64, p3: i64, p4: i64, p5: i64) -> i64 {
    let result_lo: i32;
    let result_hi: i32;
    asm!(
        "ecall" :
            "={x10}"(result_lo), "={x11}"(result_hi) :
            "{x10}"(p0 as i32), "{x11}"((p0 >> 32) as i32),
            "{x12}"(p1 as i32), "{x13}"((p1 >> 32) as i32),
            "{x14}"(p2 as i32), "{x15}"((p2 >> 32) as i32),
            "{x16}"(p3 as i32), "{x17}"((p3 >> 32) as i32),
            "{x5}"(p4 as i32), "{x6}"((p4 >> 32) as i32),
            "{x7}"(p5 as i32), "{x28}"((p5 >> 32) as i32)
    );
    ((result_lo as u32 as u64) | ((result_hi as u32 as u64) << 32)) as i64
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
