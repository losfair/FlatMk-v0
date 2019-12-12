use crate::capability::{Capability, CapabilitySet};
use crate::error::*;
use crate::kobj::*;
use crate::kobj::{KernelObject, LikeKernelObjectRef, Retype};
use crate::paging::{phys_to_virt, PageFaultState, PageTableObject, RootPageTable};
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
    include_bytes!("../../user/init/target/x86_64-flatmk/release/init");
static mut IA32_KERNEL_GS_BASE: Msr = Msr::new(0xc0000102);

/// LocalState is NOT thread safe and should only be accessed on the task's
/// own thread.
#[repr(C)]
pub struct LocalState {
    /// Address of the kernel syscall stack.
    pub kernel_stack: Cell<VirtAddr>,

    /// Saved address of the user stack.
    pub user_stack: Cell<VirtAddr>,

    /// Is there a pending page fault on this task?
    pub pending_page_fault: Cell<PageFaultState>,

    /// Saved registers when scheduled out.
    pub registers: UnsafeCell<TaskRegisters>,
}

#[repr(transparent)]
pub struct LocalStateWrapper(UnsafeCell<LocalState>);

impl LocalStateWrapper {
    pub unsafe fn unsafe_deref(&self) -> &LocalState {
        &*self.0.get()
    }
}

unsafe impl Send for LocalStateWrapper {}
unsafe impl Sync for LocalStateWrapper {}

#[repr(C)]
pub struct Task {
    /// Thread-unsafe local state.
    pub local_state: LocalStateWrapper,

    /// Page table of this task.
    pub page_table_root: KernelObjectRef<PageTableObject>,

    /// Root capability set.
    pub capabilities: KernelObjectRef<CapabilitySet>,
}

#[repr(C)]
#[derive(Default, Clone, Debug)]
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

pub fn get_current_task() -> Option<KernelObjectRef<Task>> {
    // Clone the current reference, if any.
    let ptr = GsBase::read().as_ptr::<KernelObject<Task>>();
    if ptr.is_null() {
        None
    } else {
        let obj = unsafe { KernelObjectRef::from_raw(ptr) };
        let ret = obj.clone();
        // We should not drop the old reference here.
        KernelObjectRef::into_raw(obj);
        Some(ret)
    }
}

pub fn set_current_task(t: Option<KernelObjectRef<Task>>) {
    // Drop the old reference.
    let old = GsBase::read().as_ptr::<KernelObject<Task>>();
    if !old.is_null() {
        unsafe {
            KernelObjectRef::from_raw(old);
        }
    }

    // Write the new reference.
    match t {
        Some(x) => {
            let raw = KernelObjectRef::into_raw(x);
            GsBase::write(VirtAddr::new(raw as u64));
        }
        None => {
            GsBase::write(VirtAddr::new(0));
        }
    }
}

pub unsafe fn init() {
    GsBase::write(VirtAddr::new(0));
}

impl TaskRegisters {
    pub fn new() -> TaskRegisters {
        TaskRegisters {
            rflags: RFlags::INTERRUPT_FLAG.bits(),
            ..Default::default()
        }
    }
}

/// The caller needs to ensure that `root` is a root page table.
unsafe fn make_user_continuous_map<I: Iterator<Item = PhysFrame>>(
    mut region: I,
    mut vaddr: VirtAddr,
    root: &mut PageTable,
) -> u64 {
    let mut count: u64 = 0;
    for page_phys in region {
        let page_phys = page_phys.start_address();
        let page_virt = vaddr;

        // Kernel memory should not be remapped.
        if u16::from(page_virt.p4_index()) >= 256 {
            return count;
        }

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

impl Retype for Task {
    unsafe fn retype_in_place(&mut self) -> KernelResult<()> {
        Err(KernelError::NotImplemented)
    }
}

impl Notify for Task {}

impl Task {
    /*
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
    */

    /// Creates a new task.
    pub fn new(
        kernel_stack: VirtAddr,
        page_table_root: KernelObjectRef<PageTableObject>,
        cap_root: KernelObjectRef<CapabilitySet>,
    ) -> Task {
        Task {
            local_state: LocalStateWrapper(UnsafeCell::new(LocalState {
                kernel_stack: Cell::new(kernel_stack),
                user_stack: Cell::new(VirtAddr::new(0)),
                pending_page_fault: Cell::new(PageFaultState::NoPageFault),
                registers: UnsafeCell::new(TaskRegisters::new()),
            })),
            page_table_root: page_table_root,
            capabilities: cap_root,
        }
    }

    pub fn load_root_image(&self) -> u64 {
        // Map all available physical memory into root task's address space.
        let num_pages_mapped = {
            let phys_mappings = &crate::boot::boot_info().memory_map;

            self.page_table_root.with(|pt_root| {
                let phys_iterator = phys_mappings
                    .iter()
                    .filter_map(|x| match x.region_type {
                        MemoryRegionType::Usable | MemoryRegionType::Bootloader => Some(
                            (x.range.start_addr()..x.range.end_addr())
                                .step_by(PAGE_SIZE as _)
                                .map(|x| PhysFrame::from_start_address(PhysAddr::new(x)).unwrap()),
                        ),
                        _ => None,
                    })
                    .flatten();
                unsafe {
                    make_user_continuous_map(
                        phys_iterator,
                        VirtAddr::new(ROOT_TASK_FULL_MAP_BASE),
                        pt_root,
                    )
                }
            })
        };
        x86_64::instructions::tlb::flush_all();
        with_serial_port(|p| writeln!(p, "Mapped {} pages.", num_pages_mapped).unwrap());

        let user_view = unsafe {
            core::slice::from_raw_parts_mut(
                ROOT_TASK_FULL_MAP_BASE as *mut u8,
                (num_pages_mapped * PAGE_SIZE) as usize,
            )
        };
        match crate::elf::load(ROOT_IMAGE, user_view, ROOT_TASK_FULL_MAP_BASE) {
            Some(x) => x,
            None => {
                panic!("Unable to load root image");
            }
        }
    }
    pub fn current() -> Option<KernelObjectRef<Task>> {
        get_current_task()
    }
}

pub fn retype_user<T: Retype + Notify + Send + Sync + 'static, K: Into<LikeKernelObjectRef>>(
    current: &mut RootPageTable,
    owner: K,
    vaddr: VirtAddr,
) -> KernelResult<KernelObjectRef<T>> {
    if !vaddr.is_aligned(PAGE_SIZE) {
        return Err(KernelError::InvalidDelegation);
    }

    let mut kvaddr = crate::paging::take_from_user(current, vaddr)?;
    let maybe_value = kvaddr.as_mut_ptr::<KernelObject<T>>();
    let owner = owner.into();

    unsafe {
        match (*maybe_value).init(owner.get(), true) {
            Ok(_) => Ok((*maybe_value).get_ref()),
            Err(e) => {
                match crate::paging::put_to_user(current, kvaddr) {
                    _ => {}
                }
                Err(e)
            }
        }
    }
}

impl Retype for PageTable {
    unsafe fn retype_in_place(&mut self) -> KernelResult<()> {
        core::ptr::write(self, core::mem::zeroed());
        Ok(())
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
) -> KernelResult<()> {
    if u16::from(target_vaddr.p4_index()) >= 256 || !target_vaddr.is_aligned(PAGE_SIZE) {
        return Err(KernelError::InvalidArgument);
    }
    let entry = if let Some(x) = lookup_pt_entry(current_root, target_vaddr) {
        x
    } else {
        return Err(KernelError::InvalidAddress);
    };
    entry.set_addr(phys, flags);
    Ok(())
}

/// Takes a page from userspace and uses it as the "next"
/// level of page table needed for `target_vaddr`.
pub fn retype_page_table_from_user(
    current_root: &mut RootPageTable,
    target_vaddr: VirtAddr,
    user_page: VirtAddr,
) -> KernelResult<u8> {
    if u16::from(target_vaddr.p4_index()) >= 256 || !target_vaddr.is_aligned(PAGE_SIZE) {
        return Err(KernelError::InvalidArgument);
    }

    let kvaddr = crate::paging::take_from_user(current_root, user_page)?;
    let kmap = kvaddr.as_mut_ptr::<[u8; PAGE_SIZE as usize]>();
    let phys = crate::paging::virt_to_phys(current_root, VirtAddr::new(kvaddr.as_u64()))?;

    let mut pt = &mut **current_root;
    let indexes: [usize; 3] = [
        u16::from(target_vaddr.p4_index()) as usize,
        u16::from(target_vaddr.p3_index()) as usize,
        u16::from(target_vaddr.p2_index()) as usize,
    ];
    for (i, &index) in indexes.iter().enumerate() {
        if pt[index].is_unused() {
            unsafe {
                for b in (*kmap).iter_mut() {
                    *b = 0;
                }
            }
            pt[index].set_addr(
                phys,
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE,
            );
            return Ok((3 - i) as u8); // in range 1..=3
        } else {
            let virt = crate::paging::phys_to_virt(pt[index].addr());
            pt = unsafe { &mut *virt.as_mut_ptr::<PageTable>() };
        }
    }
    unsafe {
        crate::paging::put_to_user(current_root, kvaddr)?;
    }
    Ok(0)
}

pub fn switch_to(task: KernelObjectRef<Task>) {
    let pt_root: *const PageTable = task.page_table_root.with(|x| x as *mut _ as *const _);

    set_current_task(Some(task));
    unsafe {
        Cr3::write(
            PhysFrame::from_start_address(
                crate::paging::virt_to_phys(
                    crate::paging::active_level_4_table(),
                    VirtAddr::new(pt_root as u64),
                )
                .unwrap(),
            )
            .unwrap(),
            Cr3Flags::empty(),
        )
    };
}

/// Switches out of kernel mode and enters user mode.
/// Unsafe because the kernel stack is immediately invalidated after entering user mode.
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
    let registers: *const TaskRegisters = task.local_state.unsafe_deref().registers.get();
    // Here we won't get a dangling `registers` pointer after drop because we know that
    // `GsBase` won't be dropped now.
    drop(task);

    __enter_user_mode(
        0,
        registers,
        selectors.user_code_selector.0 as u32,
        selectors.user_data_selector.0 as u32,
    );
    loop {}
}
