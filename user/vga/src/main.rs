#![no_main]
#![no_std]
#![feature(lang_items, asm, naked_functions)]

#[macro_use]
extern crate flatruntime_user;

mod vga;

use flatruntime_user::{
    ipc::*,
    syscall::*,
};
use scheduler_api::*;

static SCHED_YIELD: SchedYield = unsafe { SchedYield::new(TaskEndpoint::new(CPtr::new(1))) };

#[no_mangle]
unsafe extern "C" fn user_start() -> ! {
    println!("vga: Server started.");
    loop {
        SCHED_YIELD.sleep(1_000_000_0);
        print!(".");
    }
}

ipc_entry!(ipc_vga_get_metadata, __ipc_vga_get_metadata, {
    panic!("ipc_vga_get_metadata");
});

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    println!("vga: panic(): {:#?}", info);
    loop {}
}
