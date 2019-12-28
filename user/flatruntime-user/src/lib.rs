#![no_std]
#![feature(
    asm,
    naked_functions,
    lang_items,
    core_intrinsics,
    alloc_error_handler,
    new_uninit,
    try_trait
)]

extern crate alloc;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate bitflags;

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
pub mod interrupt;
pub mod elf;
pub mod layout;

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
#[cfg(feature = "static_stack")]
struct Stack([u8; 1048576]);

#[no_mangle]
#[cfg(feature = "static_stack")]
static mut STACK: Stack = Stack([0; 1048576]);

#[no_mangle]
#[naked]
#[inline(never)]
#[cfg(feature = "static_stack")]
pub unsafe extern "C" fn _start() -> ! {
    asm!(r#"
        leaq STACK, %rsp
        addq $$1048576, %rsp
        jmp early_start
    "# :::: "volatile");
    loop {}
}

#[no_mangle]
#[naked]
#[inline(never)]
#[cfg(not(feature = "static_stack"))]
pub unsafe extern "C" fn _start() -> ! {
    asm!(r#"
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
    unsafe {
        asm!("mov $$0xffff8000000a110c, %rax\nmov (%rax), %rax" :::: "volatile");
    }
    loop {}
}
