#![no_std]
#![feature(asm, new_uninit, maybe_uninit_extra)]

extern crate alloc;

pub mod elfloader;
pub mod malloc;
pub mod linux_mm;
pub mod capalloc;

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        asm!("ud2" :::: "volatile");
    }
    loop {}
}
