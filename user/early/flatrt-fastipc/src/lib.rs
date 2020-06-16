//! Implementation of fast IPC message passing with direct task switch
//! on FlatMk.

#![no_std]
#![feature(llvm_asm)]

use core::mem::MaybeUninit;

#[repr(C)]
#[derive(Default, Clone, Debug)]
pub struct FastIpcPayload {
    pub data: [u64; 8],
}

impl FastIpcPayload {
    pub fn read() -> FastIpcPayload {
        unsafe {
            let mut result: MaybeUninit<FastIpcPayload> = MaybeUninit::uninit();
            llvm_asm!(
                r#"
                mov %xmm0, 0($0)
                mov %xmm1, 8($0)
                mov %xmm2, 16($0)
                mov %xmm3, 24($0)
                mov %xmm4, 32($0)
                mov %xmm5, 40($0)
                mov %xmm6, 48($0)
                mov %xmm7, 56($0)
            "# : : "r"(result.as_mut_ptr()) : : "volatile");
            result.assume_init()
        }
    }

    pub fn write(&self) {
        unsafe {
            llvm_asm!(
                r#"
                mov 0($0), %xmm0
                mov 8($0), %xmm1
                mov 16($0), %xmm2
                mov 24($0), %xmm3
                mov 32($0), %xmm4
                mov 40($0), %xmm5
                mov 48($0), %xmm6
                mov 56($0), %xmm7
            "# : : "r"(self) : : "volatile");
        }
    }
}
