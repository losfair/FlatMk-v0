#![no_main]
#![no_std]
#![feature(
    asm,
    naked_functions,
    lang_items,
    abi_x86_interrupt,
    core_intrinsics,
    const_fn
)]

#[macro_use]
extern crate bitflags;

mod boot;
mod capability;
mod elf;
mod exception;
mod paging;
mod serial;
mod syscall;
mod task;

use bootloader::BootInfo;
use capability::CapabilitySet;
use core::fmt::Write;
use core::ptr::NonNull;
use serial::with_serial_port;
use task::{Task, TaskRegisters};
use x86_64::structures::paging::PageTable;

static mut ROOT_TASK: Option<Task> = None;
static mut ROOT_PAGE_TABLE: Option<PageTable> = None;
static mut ROOT_CAPSET: Option<CapabilitySet> = None;

#[no_mangle]
pub extern "C" fn kstart(boot_info: &'static BootInfo) -> ! {
    with_serial_port(|p| {
        writeln!(p, "Starting FlatRuntime Microkernel.").unwrap();
    });
    unsafe {
        boot::set_boot_info(boot_info);
        exception::init_gdt();
        exception::init_idt();
        paging::init();
        task::init();
        syscall::init();
        exception::init_interrupts();

        ROOT_TASK = Some(Task::new(exception::KERNEL_STACK_END));
        ROOT_PAGE_TABLE = Some(PageTable::new());
        ROOT_CAPSET = Some(CapabilitySet::default());

        let root_capset = ROOT_CAPSET.as_mut().unwrap();
        root_capset.init_for_root_task();

        let rt = ROOT_TASK.as_mut().unwrap();
        rt.init_as_root(ROOT_PAGE_TABLE.as_mut().unwrap(), root_capset);
        let rt = &*rt;
        task::switch_to(NonNull::new(rt as *const _ as *mut _).unwrap());
        let initial_ip = rt.load_root_image();
        (*rt.registers.get()).rip = initial_ip;
        with_serial_port(|p| {
            writeln!(p, "Dropping to user mode at {:p}.", initial_ip as *mut u8).unwrap();
        });
        task::schedule();
    }
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    with_serial_port(|p| {
        writeln!(p, "Kernel panic: {:#?}", info).unwrap();
    });
    loop {
        x86_64::instructions::hlt();
    }
}

#[lang = "eh_personality"]
fn eh_personality() -> ! {
    loop {}
}
