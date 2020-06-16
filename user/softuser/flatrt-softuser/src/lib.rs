#![no_std]
#![feature(llvm_asm, global_asm)]

use flatmk_sys::spec::{self, KernelError};

#[repr(align(16))]
struct Stack([u8; 65536]);

#[no_mangle]
static mut SOFTUSER_STACK: Stack = Stack([0; 65536]);

global_asm!(r#"

.globl _start
_start:
lui t0, %hi(SOFTUSER_STACK)
lui t1, 16
add sp, t0, t1
jal user_start
ebreak

.globl abort
abort:
ebreak

"#);

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe {
            llvm_asm!("ebreak" :::: "volatile");
        }
    }
}
