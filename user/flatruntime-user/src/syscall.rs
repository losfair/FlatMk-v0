use alloc::boxed::Box;
use core::intrinsics::abort;

mod syscall_impl {
    #[naked]
    #[inline(never)]
    #[no_mangle]
    unsafe extern "C" fn _do_syscall() {
        asm!(
            r#"
            movq %rcx, %r10
            syscall
            retq
        "#
        );
    }
}

extern "C" {
    fn _do_syscall(p0: i64, p1: i64, p2: i64, p3: i64, p4: i64, p5: i64) -> i64;
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum RootTaskCapRequest {
    AnyX86IoPort = 0,
    LocalMap = 1,
    LocalMmio = 2,
}

#[repr(align(4096))]
pub struct Delegation([u8; 4096]);

impl Delegation {
    pub const fn new() -> Delegation {
        Delegation([0; 4096])
    }
}

pub struct CPtr(u64);

impl CPtr {
    pub const unsafe fn new_twolevel(level0: u8, level1: u8) -> CPtr {
        CPtr(((level0 as u64) << 56) | ((level1 as u64) << 48))
    }

    pub unsafe fn call(&self, p0: i64, p1: i64, p2: i64, p3: i64) -> i64 {
        _do_syscall(
            self.0 as _,
            p0,
            p1,
            p2,
            p3,
            0,
        )
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
