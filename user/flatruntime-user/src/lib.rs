#![no_std]
#![feature(
    asm,
    naked_functions,
    lang_items,
    core_intrinsics,
    alloc_error_handler,
    new_uninit
)]

extern crate alloc;

#[macro_use]
extern crate lazy_static;

pub mod allocator;
pub mod capset;
pub mod error;
pub mod io;
pub mod ipc;
pub mod mm;
pub mod root;
pub mod syscall;
pub mod task;
pub mod thread;

extern "C" {
    fn user_start() -> !;
}

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
        jmp early_start
    "# :::: "volatile");
    loop {}
}

#[no_mangle]
#[inline(never)]
unsafe extern "C" fn early_start() -> ! {
    crate::allocator::init();
    crate::thread::init_startup_thread();
    user_start();
}

#[alloc_error_handler]
fn on_alloc_error(_: core::alloc::Layout) -> ! {
    loop {}
}
