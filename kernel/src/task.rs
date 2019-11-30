use crate::capability::{Capability, CapabilitySet};
use crate::paging::phys_to_virt;
use crate::serial::with_serial_port;
use bootloader::bootinfo::MemoryRegionType;
use core::cell::{Cell, UnsafeCell};
use core::fmt::Write;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;
use x86_64::{
    registers::{
        control::{Cr3, Cr3Flags},
        model_specific::{GsBase, Msr},
        rflags::RFlags,
    },
    structures::paging::{frame::PhysFrame, page_table::PageTableFlags, PageTable},
    PhysAddr, VirtAddr,
};

pub const ROOT_TASK_FULL_MAP_BASE: u64 = 0x20000000u64;
pub const PAGE_SIZE: u64 = 4096;

static ROOT_IMAGE: &'static [u8] =
    include_bytes!("../../user/init/target/x86_64-flatmk/debug/init");
static mut IA32_KERNEL_GS_BASE: Msr = Msr::new(0xc0000102);

/// A task must not be larger than 4096 bytes.
#[repr(C, align(4096))]
pub struct Task {
    pub kernel_stack: u64,
    pub user_stack: u64,
    pub prev: UnsafeCell<Option<NonNull<Task>>>,
    pub next: UnsafeCell<Option<NonNull<Task>>>,
    pub page_table_root: *mut PageTable,
    pub registers: UnsafeCell<TaskRegisters>,
    pub capabilities: *const CapabilitySet,
    pub pending_page_fault: Cell<bool>,
}

#[repr(C)]
#[derive(Default, Copy, Clone, Debug)]
pub struct TaskRegisters {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rip: u64,
    pub rflags: u64,
}

pub trait Retype: Sized {
    unsafe fn retype_in_place(&mut self) -> bool;
}

pub fn get_current_task() -> Option<NonNull<Task>> {
    unsafe { core::mem::transmute(GsBase::read()) }
}

pub fn set_current_task(t: Option<NonNull<Task>>) {
    GsBase::write(unsafe { core::mem::transmute(t) });
}

pub unsafe fn init() {
    set_current_task(None);
}

impl TaskRegisters {
    pub fn new() -> TaskRegisters {
        TaskRegisters {
            rflags: RFlags::INTERRUPT_FLAG.bits(),
            ..Default::default()
        }
    }
}

unsafe fn recursively_map_region<I: Iterator<Item = u64>>(
    region: &mut I,
    levels: &mut [(u64, *mut PageTable)],
    count: &mut u64,
) -> *mut PageTable {
    if levels.len() == 1 && levels[0].0 >= 256 {
        panic!("recursively_map_region: Attempting to map into kernel range");
    }
    if levels[0].1.is_null() {
        let new_pt = recursively_map_region(region, &mut levels[1..], count);
        if new_pt.is_null() {
            return new_pt;
        }
        levels[0].1 = new_pt;
    }
    let region_addr = match region.next() {
        Some(x) => x,
        None => return core::ptr::null_mut(),
    };
    let phys = PhysAddr::new(region_addr);

    (*levels[0].1)[levels[0].0 as usize].set_addr(
        phys,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
    );
    if levels[0].0 == 511 {
        levels[0].0 = 0;
        levels[0].1 = core::ptr::null_mut();
    } else {
        levels[0].0 += 1;
    }
    let pt = phys_to_virt(phys).as_mut_ptr::<PageTable>();
    (*pt).zero();
    *count += 1;
    pt
}

unsafe fn make_continuous_map<I: Iterator<Item = u64>>(
    mut region: I,
    start: u64,
    root: *mut PageTable,
) -> u64 {
    let mut levels: [(u64, *mut PageTable); 4] = [
        ((start >> 12) & 511, core::ptr::null_mut()),
        ((start >> 21) & 511, core::ptr::null_mut()),
        ((start >> 30) & 511, core::ptr::null_mut()),
        ((start >> 39) & 511, root),
    ];
    let mut count: u64 = 0;
    while !recursively_map_region(&mut region, &mut levels, &mut count).is_null() {
        //with_serial_port(|p| writeln!(p, "mapped: ({}, {}, {}, {})", levels[3].0, levels[2].0, levels[1].0, levels[0].0).unwrap());
    }
    count
}

impl Task {
    pub fn new(kernel_stack: u64) -> Task {
        Task {
            kernel_stack: kernel_stack,
            user_stack: 0,
            prev: UnsafeCell::new(None),
            next: UnsafeCell::new(None),
            page_table_root: core::ptr::null_mut(),
            registers: UnsafeCell::new(TaskRegisters::new()),
            capabilities: core::ptr::null(),
            pending_page_fault: Cell::new(false),
        }
    }
    pub unsafe fn init_as_root(
        &mut self,
        page_table_root: *mut PageTable,
        cap_root: *const CapabilitySet,
    ) {
        *self.prev.get() = NonNull::new(self as *mut _);
        *self.next.get() = NonNull::new(self as *mut _);
        self.page_table_root = page_table_root;
        self.capabilities = cap_root;
        crate::paging::make_page_table(&mut *self.page_table_root);
    }
    pub unsafe fn load_root_image(&self) -> u64 {
        assert_eq!(get_current_task(), NonNull::new(self as *const _ as *mut _));

        // Map all available physical memory into root task's address space.
        let num_pages_mapped = {
            let phys_mappings = &crate::boot::boot_info().memory_map;

            make_continuous_map(
                phys_mappings
                    .iter()
                    .filter_map(|x| match x.region_type {
                        MemoryRegionType::Usable | MemoryRegionType::Bootloader => {
                            Some((x.range.start_addr()..x.range.end_addr()).step_by(PAGE_SIZE as _))
                        }
                        _ => None,
                    })
                    .flatten(),
                ROOT_TASK_FULL_MAP_BASE,
                self.page_table_root,
            )
        };
        x86_64::instructions::tlb::flush_all();
        with_serial_port(|p| writeln!(p, "Mapped {} pages.", num_pages_mapped).unwrap());

        let user_view = core::slice::from_raw_parts_mut(
            ROOT_TASK_FULL_MAP_BASE as *mut u8,
            (num_pages_mapped * PAGE_SIZE) as usize,
        );
        match crate::elf::load(ROOT_IMAGE, user_view, ROOT_TASK_FULL_MAP_BASE) {
            Some(x) => x,
            None => {
                panic!("Unable to load root image");
            }
        }
    }
    pub fn kill(&self) {
        // FIXME: Task leaked
        unsafe {
            assert_eq!(get_current_task(), NonNull::new(self as *const _ as *mut _));
            if *self.prev.get() == NonNull::new(self as *const _ as *mut _) {
                set_current_task(None);
            } else {
                *(*self.prev.get()).unwrap().as_ref().next.get() = *self.next.get();
                *(*self.next.get()).unwrap().as_ref().prev.get() = *self.prev.get();
                set_current_task(*self.next.get());
            }
        }
    }
    pub fn current() -> Option<NonNull<Task>> {
        unsafe { get_current_task() }
    }
}

pub fn retype_user<T: Retype>(vaddr: VirtAddr) -> Option<*mut T> {
    assert!(core::mem::size_of::<T>() <= 4096);

    if !vaddr.is_aligned(PAGE_SIZE) {
        return None;
    }

    let mut kvaddr = match crate::paging::take_from_user(vaddr) {
        Some(x) => x,
        None => return None,
    };
    let maybe_value = kvaddr.as_mut_ptr::<T>();
    if !unsafe { (*maybe_value).retype_in_place() } {
        None
    } else {
        Some(maybe_value)
    }
}

pub unsafe fn switch_to(task: NonNull<Task>) {
    set_current_task(Some(task));
    Cr3::write(
        PhysFrame::from_start_address(
            crate::paging::virt_to_phys(VirtAddr::new(task.as_ref().page_table_root as u64))
                .unwrap(),
        )
        .unwrap(),
        Cr3Flags::empty(),
    );
}

pub unsafe fn enter_user_mode() -> ! {
    #[naked]
    #[inline(never)]
    unsafe extern "C" fn __enter_user_mode(
        _unused: u64,
        _registers: *const TaskRegisters,
        user_code_selector: u32,
        user_data_selector: u32,
    ) {
        asm!(
            r#"
                mov %cx, %ds
                mov %cx, %es
                pushq %rcx // ds
                pushq %rcx // ss
                pushq 112(%rsi) // rsp
                pushq 136(%rsi) // rflags
                pushq %rdx
                pushq 128(%rsi) // rip
                mov 0(%rsi), %r15
                mov 8(%rsi), %r14
                mov 16(%rsi), %r13
                mov 24(%rsi), %r12
                mov 32(%rsi), %r11
                mov 40(%rsi), %r10
                mov 48(%rsi), %r9
                mov 56(%rsi), %r8
                mov 64(%rsi), %rax
                mov 72(%rsi), %rbx
                mov 80(%rsi), %rcx
                mov 88(%rsi), %rdx
                mov 104(%rsi), %rdi
                mov 120(%rsi), %rbp
                mov 96(%rsi), %rsi
                swapgs
                iretq
            "# :::: "volatile"
        );
    }
    assert_eq!(core::mem::size_of::<TaskRegisters>(), 144);
    let selectors = crate::exception::get_selectors();
    let task = get_current_task().unwrap();
    __enter_user_mode(
        0,
        task.as_ref().registers.get(),
        selectors.user_code_selector.0 as u32,
        selectors.user_data_selector.0 as u32,
    );
    loop {}
}

pub unsafe fn schedule() -> ! {
    switch_to(
        (*(get_current_task().expect("All processes exited"))
            .as_ref()
            .next
            .get())
        .expect("empty next pointer"),
    );
    enter_user_mode();
}

pub unsafe fn switch_task_mode() {
    asm!("swapgs" :::: "volatile");
}
