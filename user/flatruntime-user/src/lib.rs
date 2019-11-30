#![no_std]
#![feature(asm, naked_functions, lang_items, core_intrinsics)]

pub mod syscall;
pub mod io;

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[lang = "eh_personality"]
fn eh_personality() -> ! {
    loop {}
}

#[no_mangle]
static mut STACK: [u8; 1048576] = [0; 1048576];

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
