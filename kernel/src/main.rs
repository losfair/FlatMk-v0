#![no_main]
#![no_std]
#![feature(
    asm,
    naked_functions,
    lang_items,
    abi_x86_interrupt,
    core_intrinsics,
    const_fn,
    maybe_uninit_extra
)]

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate lazy_static;

mod boot;
mod capability;
mod debug;
mod elf;
mod error;
mod exception;
mod kobj;
mod paging;
mod serial;
mod syscall;
mod task;
mod user;

use crate::kobj::*;
use crate::paging::PageTableObject;
use bootloader::BootInfo;
use capability::CapabilitySet;
use core::cell::UnsafeCell;
use core::fmt::Write;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use kobj::KernelObject;
use serial::with_serial_port;
use task::{Task, TaskRegisters};
use x86_64::{structures::paging::PageTable, VirtAddr};

lazy_static! {
    // These values can only be used after paging is initialized.
    static ref ROOT_KOBJ: RootKernelObject = RootKernelObject;
    static ref ROOT_CAPSET: KernelObjectRef<CapabilitySet> = {
        static mut KOBJ: MaybeUninit<KernelObject<CapabilitySet>> = MaybeUninit::uninit();
        let kobj = unsafe {
            (*KOBJ.as_mut_ptr()).write(CapabilitySet::default());
            (*KOBJ.as_mut_ptr()).init(&*ROOT_KOBJ, false).unwrap();
            &*KOBJ.as_ptr()
        };
        kobj.get_ref()
    };
    static ref ROOT_PT_OBJECT: KernelObjectRef<PageTableObject> = {
        static mut PT: MaybeUninit<PageTable> = MaybeUninit::uninit();
        let pt = unsafe {
            PT.write(PageTable::new());
            &mut *PT.as_mut_ptr()
        };

        static mut KOBJ: MaybeUninit<KernelObject<PageTableObject>> = MaybeUninit::uninit();
        let kobj = unsafe {
            (*KOBJ.as_mut_ptr()).write(PageTableObject::new(pt));
            (*KOBJ.as_mut_ptr()).init(&*ROOT_KOBJ, false).unwrap();
            &*KOBJ.as_ptr()
        };
        kobj.get_ref()
    };
    static ref ROOT_TASK: KernelObjectRef<Task> = {
        static mut TASK: MaybeUninit<KernelObject<Task>> = MaybeUninit::uninit();
        let task = unsafe {
            (*TASK.as_mut_ptr()).write(Task::new(VirtAddr::new(exception::KERNEL_STACK_END), ROOT_PT_OBJECT.clone(), ROOT_CAPSET.clone()));
            (*TASK.as_mut_ptr()).init(&*ROOT_KOBJ, false).unwrap();
            &*TASK.as_ptr()
        };
        task.get_ref()
    };

}

#[no_mangle]
pub extern "C" fn kstart(boot_info: &'static BootInfo) -> ! {
    with_serial_port(|p| {
        writeln!(p, "Starting FlatRuntime Microkernel.").unwrap();
    });

    // Early init.
    unsafe {
        boot::set_boot_info(boot_info);
        exception::init_gdt();
        exception::init_idt();
        paging::init();
        task::init();
        syscall::init();
        exception::init_interrupts();
    }

    //ROOT_CAPSET.init_for_root_task();
    ROOT_PT_OBJECT.with(|x| {
        crate::paging::make_page_table(unsafe { crate::paging::active_level_4_table() }, x);
    });

    task::switch_to(ROOT_TASK.clone());
    let initial_ip = ROOT_TASK.load_root_image();
    unsafe {
        (*ROOT_TASK.local_state.unsafe_deref().registers.get()).rip = initial_ip;
    }
    with_serial_port(|p| {
        writeln!(p, "Dropping to user mode at {:p}.", initial_ip as *mut u8).unwrap();
    });
    unsafe {
        task::enter_user_mode();
    }
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    use x86_64::instructions::interrupts;
    interrupts::without_interrupts(|| {
        with_serial_port(|p| {
            writeln!(p, "Kernel panic: {:#?}", info).unwrap();
        });
        loop {
            x86_64::instructions::hlt();
        }
    })
}

#[lang = "eh_personality"]
fn eh_personality() -> ! {
    loop {}
}
