use bitflags::bitflags;
use num_enum::TryFromPrimitive;

pub struct CPtr(u64);

impl CPtr {
    pub const unsafe fn new(inner: u64) -> Self {
        CPtr(inner)
    }

    pub fn index(&self) -> u64 {
        self.0
    }

    pub unsafe fn call(&self, p0: i64, p1: i64, p2: i64, p3: i64) -> i64 {
        _do_syscall(p0, p1, p2, p3, 0, 0)
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

include!("../generated/flatmk_spec.rs");
