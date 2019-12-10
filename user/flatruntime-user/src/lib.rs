#![no_std]
#![feature(asm, naked_functions, lang_items, core_intrinsics, alloc_error_handler)]

extern crate alloc;

pub mod io;
pub mod syscall;
pub mod mm;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[lang = "eh_personality"]
fn eh_personality() -> ! {
    loop {}
}

#[repr(align(4096))]
struct Stack([u8; 1048576]);

#[no_mangle]
static mut STACK: Stack = Stack([0; 1048576]);

#[no_mangle]
#[naked]
#[inline(never)]
pub unsafe extern "C" fn _start() -> ! {
    asm!(r#"
        leaq STACK, %rsp
        addq $$1048576, %rsp
        pushq %rax
        jmp user_start
    "# :::: "volatile");
    loop {}
}

#[alloc_error_handler]
fn on_alloc_error(_: core::alloc::Layout) -> ! {
    loop {}
}
