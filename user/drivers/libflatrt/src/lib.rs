#![no_std]
#![feature(llvm_asm, new_uninit, maybe_uninit_extra)]

extern crate alloc;

pub mod elfloader;
pub mod malloc;
pub mod linux_mm;
pub mod capalloc;

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        llvm_asm!("ud2" :::: "volatile");
    }
    loop {}
}
