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

mod arch;
mod boot;
mod capability;
mod debug;
mod elf;
mod error;
mod exception;
mod kobj;
mod multilevel;
mod paging;
mod serial;
mod syscall;
mod task;
mod user;

use crate::kobj::*;
use crate::multilevel::*;
use crate::paging::{PageTableObject, RootPageTable};
use bootloader::BootInfo;
use capability::{
    CapabilityEndpointObject, CapabilitySet, CapabilityTable, CapabilityTableNode,
    LockedCapabilityEndpointSet,
};
use core::fmt::Write;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr::NonNull;
use kobj::KernelObject;
use serial::with_serial_port;
use task::Task;
use x86_64::{structures::paging::PageTable, VirtAddr};

lazy_static! {
    // These values can only be used after paging is initialized.
    static ref ROOT_KOBJ: RootKernelObject = RootKernelObject;
    static ref ROOT_CAPSET: KernelObjectRef<CapabilitySet> = {
        static mut KOBJ: MaybeUninit<KernelObject<CapabilitySet>> = MaybeUninit::uninit();
        static mut CAP_ROOT: MaybeUninit<Level<LockedCapabilityEndpointSet, CapabilityTableNode, 128>> = MaybeUninit::uninit();

        let kobj = unsafe {
            CAP_ROOT.write(Level {
                table: ManuallyDrop::new(CapabilityTableNode::new_table()),
            });
            let cap_table = CapabilityTable::new(NonNull::new(CAP_ROOT.as_mut_ptr()).unwrap(), VirtAddr::new(0));
            (*KOBJ.as_mut_ptr()).write(CapabilitySet(cap_table));
            (*KOBJ.as_mut_ptr()).init(&*ROOT_KOBJ, VirtAddr::new(0), false).unwrap();
            &*KOBJ.as_ptr()
        };
        kobj.get_ref()
    };
    static ref ROOT_PT_OBJECT: KernelObjectRef<PageTableObject> = {
        static mut PT: MaybeUninit<RootPageTable> = MaybeUninit::uninit();
        let pt = unsafe {
            PT.write(RootPageTable::new(PageTable::new()));
            &mut *PT.as_mut_ptr()
        };

        static mut KOBJ: MaybeUninit<KernelObject<PageTableObject>> = MaybeUninit::uninit();
        let kobj = unsafe {
            (*KOBJ.as_mut_ptr()).write(PageTableObject::new(pt));
            (*KOBJ.as_mut_ptr()).init(&*ROOT_KOBJ, VirtAddr::new(0), false).unwrap();
            &*KOBJ.as_ptr()
        };
        kobj.get_ref()
    };
    static ref ROOT_TASK: KernelObjectRef<Task> = {
        static mut TASK: MaybeUninit<KernelObject<Task>> = MaybeUninit::uninit();
        let task = unsafe {
            (*TASK.as_mut_ptr()).write(Task::new_initial(VirtAddr::new(exception::KERNEL_STACK_END), ROOT_PT_OBJECT.clone(), ROOT_CAPSET.clone()));
            (*TASK.as_mut_ptr()).init(&*ROOT_KOBJ, VirtAddr::new(0), false).unwrap();
            &*TASK.as_ptr()
        };
        task.get_ref()
    };
}

#[no_mangle]
pub extern "C" fn kstart(boot_info: &'static BootInfo) -> ! {
    with_serial_port(|p| {
        writeln!(p, "Starting FlatMK.").unwrap();
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

    ROOT_PT_OBJECT.with(|x| {
        crate::paging::make_root_page_table(unsafe { crate::paging::active_level_4_table() }, x);
    });

    unsafe {
        setup_initial_caps();
    }

    task::switch_to(ROOT_TASK.clone()).unwrap();
    let initial_ip = ROOT_TASK.load_root_image();
    ROOT_TASK.registers.lock().rip = initial_ip;
    with_serial_port(|p| {
        writeln!(p, "Dropping to user mode at {:p}.", initial_ip as *mut u8).unwrap();
    });
    task::enter_user_mode();
}

unsafe fn setup_initial_caps() {
    static mut INITIAL_CAP_TABLE_NODES: MaybeUninit<
        [Level<LockedCapabilityEndpointSet, CapabilityTableNode, 128>; 4],
    > = MaybeUninit::uninit();
    INITIAL_CAP_TABLE_NODES.write([
        Level {
            table: ManuallyDrop::new(CapabilityTableNode::new_table()),
        },
        Level {
            table: ManuallyDrop::new(CapabilityTableNode::new_table()),
        },
        Level {
            table: ManuallyDrop::new(CapabilityTableNode::new_table()),
        },
        Level {
            table: ManuallyDrop::new(CapabilityTableNode::new_table()),
        },
    ]);

    let mut expected: u8 = 0;
    while ROOT_CAPSET.0.lookup_entry(0, |level, entry| {
        let nodes = &mut *INITIAL_CAP_TABLE_NODES.as_mut_ptr();
        entry.next = Some(NonNull::from(&mut nodes[level as usize]));
        assert_eq!(level, expected);
        expected += 1;
        if level == 3 {
            let mut entry = entry.as_level().unwrap();
            let entry = entry.as_mut();
            let set = LockedCapabilityEndpointSet::new();
            {
                let mut endpoints = set.endpoints.lock();
                endpoints[0].object = CapabilityEndpointObject::BasicTask(ROOT_TASK.clone());
                endpoints[1].object = CapabilityEndpointObject::RootTask;
            }
            entry.value = ManuallyDrop::new(set);
            return true;
        }

        false
    }) != true
    {}
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
