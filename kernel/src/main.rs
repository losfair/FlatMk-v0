#![no_main]
#![no_std]
#![feature(
    asm,
    naked_functions,
    lang_items,
    abi_x86_interrupt,
    core_intrinsics,
    const_fn,
    maybe_uninit_extra,
    const_generics,
    untagged_unions,
    const_if_match,
    const_panic,
    try_trait
)]

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate bitflags;

#[macro_use]
mod serial;

mod addr;
mod arch;
mod boot;
mod capability;
mod debug;
mod error;
mod kobj;
mod multilevel;
mod pagealloc;
mod paging;
mod syscall;
mod task;
mod user;
mod spec;

use crate::arch::{arch_early_init, arch_late_init};
use crate::kobj::*;
use crate::pagealloc::*;
use crate::paging::{PageTableMto, PageTableObject};
use crate::task::StateRestoreMode;
use bootloader::BootInfo;
use capability::{CapabilityEndpointObject, CapabilityEndpointSet, CapabilitySet, CapabilityTable};
use task::Task;

lazy_static! {
    // These values can only be used after paging is initialized.
    static ref ROOT_CAPSET: KernelObjectRef<CapabilitySet> = KernelObjectRef::new(CapabilitySet(
        CapabilityTable::new().unwrap()
    )).unwrap();
    static ref ROOT_PT_OBJECT: KernelObjectRef<PageTableObject> = KernelObjectRef::new(
        PageTableObject(PageTableMto::new().unwrap())
    ).unwrap();
    static ref ROOT_TASK: KernelObjectRef<Task> = KernelObjectRef::new(Task::new_initial(
        ROOT_PT_OBJECT.clone(),
        ROOT_CAPSET.clone(),
    )).unwrap();
}

#[no_mangle]
pub extern "C" fn kstart(boot_info: &'static BootInfo) -> ! {
    println!("Starting FlatMK.");

    // Early init.
    unsafe {
        boot::set_boot_info(boot_info);
        arch_early_init();
        paging::init();
        task::init();
        syscall::init();
        arch_late_init();

        ROOT_PT_OBJECT.copy_kernel_range_from_level(&mut *crate::paging::_active_level_4_table());
        setup_initial_caps();
    }

    task::switch_to(ROOT_TASK.clone(), None).unwrap();
    let initial_ip = ROOT_TASK.load_root_image();
    ROOT_TASK.registers.lock().rip = initial_ip;
    println!("Dropping to user mode at {:p}.", initial_ip as *mut u8);
    task::enter_user_mode(StateRestoreMode::Full);
}

unsafe fn setup_initial_caps() {
    ROOT_CAPSET.0.make_leaf_entry(0).unwrap();
    ROOT_CAPSET
        .0
        .attach_leaf(0, KernelPageRef::new(CapabilityEndpointSet::new()).unwrap())
        .unwrap();
    ROOT_CAPSET
        .0
        .lookup(0, |set| {
            set.endpoints[0].object = CapabilityEndpointObject::BasicTask(ROOT_TASK.clone());
            set.endpoints[1].object = CapabilityEndpointObject::RootTask;
        })
        .unwrap();
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    println!("Kernel panic: {:#?}", info);

    // Print task id in another println in case the current task is null.
    println!("Task ID = {}", Task::current().id);
    loop {}
}

#[lang = "eh_personality"]
fn eh_personality() -> ! {
    loop {}
}
