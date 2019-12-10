use crate::capability::{Capability, CapabilitySet};
use crate::kobj::KernelObject;
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
    structures::paging::{
        frame::PhysFrame,
        page_table::{PageTableEntry, PageTableFlags},
        PageTable,
    },
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
    /// Address of the kernel syscall stack.
    pub kernel_stack: u64,

    /// Saved address of the user stack.
    pub user_stack: Cell<u64>,

    /// Previous task in a circular task list.
    pub prev: UnsafeCell<NonNull<Task>>,

    /// Next task in a circular task list.
    pub next: UnsafeCell<NonNull<Task>>,

    /// Page table of this task.
    pub page_table_root: KernelObject<UnsafeCell<PageTable>>,

    /// Saved registers when scheduled out.
    pub registers: UnsafeCell<TaskRegisters>,

    /// Root capability set.
    pub capabilities: KernelObject<CapabilitySet>,

    /// Is there a pending page fault on this task?
    pub pending_page_fault: Cell<bool>,

    /// Number of (KernelObject + Task + SchedQueue) that refer to this task.
    pub kobj_refcount: Cell<usize>,

    /// Parent task of this task. Can be null.
    pub parent: *const Task,
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

unsafe fn make_continuous_map<I: Iterator<Item = u64>>(
    mut region: I,
    mut vaddr: u64,
    root: &mut PageTable,
) -> u64 {
    let mut count: u64 = 0;
    for page_phys in region {
        let page_phys = PhysAddr::new(page_phys);
        let page_virt = VirtAddr::new(vaddr);

        let mut entry = &mut root[u16::from(page_virt.p4_index()) as usize];
        let mut reached_leaf = false;
        {
            if !entry.is_unused() {
                entry = &mut (*crate::paging::phys_to_virt(entry.addr()).as_mut_ptr::<PageTable>())
                    [u16::from(page_virt.p3_index()) as usize];
                if !entry.is_unused() {
                    entry = &mut (*crate::paging::phys_to_virt(entry.addr())
                        .as_mut_ptr::<PageTable>())
                        [u16::from(page_virt.p2_index()) as usize];
                    if !entry.is_unused() {
                        entry = &mut (*crate::paging::phys_to_virt(entry.addr())
                            .as_mut_ptr::<PageTable>())
                            [u16::from(page_virt.p1_index()) as usize];
                        reached_leaf = true;
                    }
                }
            }
        }
        entry.set_addr(
            page_phys,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );
        {
            let page = &mut *crate::paging::phys_to_virt(page_phys)
                .as_mut_ptr::<[u8; PAGE_SIZE as usize]>();
            for b in page.iter_mut() {
                *b = 0;
            }
        }
        if reached_leaf {
            vaddr += PAGE_SIZE;
            count += 1;
        }
    }
    count
}

impl Default for Task {
    fn default() -> Task {
        unsafe { core::mem::zeroed() }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if !self.parent.is_null() {
            unsafe {
                Task::dec_ref(self.parent);
                self.detach();
            }
        } else {
            panic!("Attempting to drop root task");
        }
    }
}

impl Task {
    pub fn inc_ref(&self) {
        self.kobj_refcount.set(self.kobj_refcount.get() + 1);
    }

    pub unsafe fn detach(&self) {
        let next_ptr = *self.next.get();
        if next_ptr.as_ptr() != self as *const Task as *mut Task {
            let prev = (*self.prev.get()).as_ref();
            let next = (*self.next.get()).as_ref();
            *prev.next.get() = *self.next.get();
            *next.prev.get() = *self.prev.get();
            *self.prev.get() = NonNull::new(self as *const Task as *mut Task).unwrap();
            *self.next.get() = NonNull::new(self as *const Task as *mut Task).unwrap();

            if get_current_task().unwrap().as_ptr() == self as *const Task as *mut Task {
                set_current_task(Some(next_ptr));
            }
        } else {
            if get_current_task().unwrap().as_ptr() == self as *const Task as *mut Task {
                set_current_task(None);
            }
        }
    }

    pub unsafe fn attach(&self, that: &Task) {
        *self.prev.get() = NonNull::new(that as *const Task as *mut Task).unwrap();
        *self.next.get() = *that.next.get();

        let prev = (*self.prev.get()).as_ref();
        let next = (*self.next.get()).as_ref();

        *prev.next.get() = NonNull::new(self as *const Task as *mut Task).unwrap();
        *next.prev.get() = NonNull::new(self as *const Task as *mut Task).unwrap();
    }

    pub unsafe fn dec_ref(me: *const Task) {
        let prev = (*me).kobj_refcount.get();
        assert!(prev >= 1);
        (*me).kobj_refcount.set(prev - 1);
        if (prev == 1) {
            core::ptr::drop_in_place(&mut *(me as *mut Task));
        }
    }

    /// Initializes an empty Task.
    pub fn init(
        &mut self,
        parent: Option<&Task>,
        kernel_stack: u64,
        page_table_root: KernelObject<UnsafeCell<PageTable>>,
        cap_root: KernelObject<CapabilitySet>,
    ) {
        if let Some(parent) = parent {
            parent.inc_ref();
        }

        {
            let me = self as *mut _;
            unsafe {
                core::ptr::write(
                    me,
                    Task {
                        kernel_stack: kernel_stack,
                        user_stack: Cell::new(0),
                        prev: UnsafeCell::new(NonNull::new(me).unwrap()),
                        next: UnsafeCell::new(NonNull::new(me).unwrap()),
                        page_table_root: page_table_root,
                        registers: UnsafeCell::new(TaskRegisters::new()),
                        capabilities: cap_root,
                        pending_page_fault: Cell::new(false),
                        parent: parent
                            .map(|x| x as *const Task)
                            .unwrap_or(core::ptr::null()),
                        kobj_refcount: Cell::new(1),
                    },
                );
            }
        }
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
                &mut *self.page_table_root.get(),
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
    pub unsafe fn release(&self) {
        Task::dec_ref(self);
    }
    pub fn current() -> Option<NonNull<Task>> {
        unsafe { get_current_task() }
    }
}

pub fn retype_user<T: Retype>(current: &mut PageTable, vaddr: VirtAddr) -> Option<*mut T> {
    assert!(core::mem::size_of::<T>() <= PAGE_SIZE as usize);

    if !vaddr.is_aligned(PAGE_SIZE) {
        return None;
    }

    let mut kvaddr = match crate::paging::take_from_user(current, vaddr) {
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

impl Retype for PageTable {
    unsafe fn retype_in_place(&mut self) -> bool {
        core::ptr::write(self, core::mem::zeroed());
        true
    }
}

/// This function is unsafe because the caller needs to guarantee that `pt` is an L4 page table.
unsafe fn lookup_pt_entry<'a, 'b>(
    mut pt: &'a mut PageTable,
    vaddr: VirtAddr,
) -> Option<&'a mut PageTableEntry> {
    let indexes: [usize; 3] = [
        u16::from(vaddr.p4_index()) as usize,
        u16::from(vaddr.p3_index()) as usize,
        u16::from(vaddr.p2_index()) as usize,
    ];
    for &index in indexes.iter() {
        if pt[index].is_unused() {
            return None;
        }
        let virt = crate::paging::phys_to_virt(pt[index].addr());
        pt = &mut *virt.as_mut_ptr::<PageTable>();
    }
    return Some(&mut pt[u16::from(vaddr.p1_index()) as usize]);
}

pub unsafe fn map_physical_page_into_user(
    current_root: &mut PageTable,
    target_vaddr: VirtAddr,
    phys: PhysAddr,
    flags: PageTableFlags,
) -> bool {
    if u16::from(target_vaddr.p4_index()) >= 256 || !target_vaddr.is_aligned(PAGE_SIZE) {
        return false;
    }
    let entry = if let Some(x) = lookup_pt_entry(current_root, target_vaddr) {
        x
    } else {
        return false;
    };
    entry.set_addr(phys, flags);
    true
}

pub fn retype_page_table_from_user(
    current_root: &mut PageTable,
    target_vaddr: VirtAddr,
    user_page: VirtAddr,
) -> Option<u8> {
    if u16::from(target_vaddr.p4_index()) >= 256 || !target_vaddr.is_aligned(PAGE_SIZE) {
        return None;
    }

    unsafe {
        let current = Task::current().unwrap();
        let current = current.as_ref();
        let mut pt = current.page_table_root.get();

        let indexes: [usize; 4] = [
            u16::from(target_vaddr.p4_index()) as usize,
            u16::from(target_vaddr.p3_index()) as usize,
            u16::from(target_vaddr.p2_index()) as usize,
            u16::from(target_vaddr.p1_index()) as usize,
        ];
        for (i, &index) in indexes.iter().enumerate() {
            if (*pt)[index].is_unused() {
                let kvaddr: *mut PageTable = match retype_user(current_root, user_page) {
                    Some(x) => x,
                    None => return None,
                };
                let phys = crate::paging::virt_to_phys(current_root, VirtAddr::new(kvaddr as u64))
                    .expect("retype_user returned invalid address");
                (*pt)[index].set_addr(
                    phys,
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::USER_ACCESSIBLE,
                );
                return Some((4 - i) as u8); // in range 1..=4
            } else {
                let virt = crate::paging::phys_to_virt((*pt)[index].addr());
                pt = virt.as_mut_ptr::<PageTable>();
            }
        }
        Some(0)
    }
}

pub fn switch_to(task: &Task) {
    set_current_task(Some(
        NonNull::new(task as *const Task as *mut Task).unwrap(),
    ));
    unsafe {
        Cr3::write(
            PhysFrame::from_start_address(
                crate::paging::virt_to_phys(
                    crate::paging::active_level_4_table(),
                    VirtAddr::new(task.page_table_root.get() as u64),
                )
                .unwrap(),
            )
            .unwrap(),
            Cr3Flags::empty(),
        )
    };
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
    let task = loop {
        if let Some(t) = get_current_task() {
            break t;
        } else {
            x86_64::instructions::hlt();
        }
    };
    switch_to((*task.as_ref().next.get()).as_ref());
    enter_user_mode();
}
