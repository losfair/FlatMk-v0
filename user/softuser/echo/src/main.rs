#![no_std]
#![no_main]
#![feature(naked_functions, asm)]

use flatmk_sys::spec::{self, KernelError};

union StackPtrToU32 {
    from: *mut Stack,
    to: u32,
}

#[repr(align(16))]
struct Stack([u8; 65536]);

#[no_mangle]
static mut STACK: Stack = Stack([0; 65536]);

#[naked]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    asm!(r#"
        lui a0, %hi(STACK)
        lui a1, 16
        add sp, a0, a1
        j user_start
    "# :::: "volatile");
    loop {}
}

#[no_mangle]
extern "C" fn user_start() -> ! {
    unsafe {
        spec::CAP_TRIVIAL_SYSCALL.softuser_leave();
        unreachable!()
    }
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe {
            asm!("ebreak" :::: "volatile");
        }
    }
}

#[no_mangle]
extern "C" fn abort() {
    loop {
        unsafe {
            asm!("ebreak" :::: "volatile");
        }
    }
}