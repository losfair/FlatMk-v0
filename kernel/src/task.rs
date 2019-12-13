use crate::capability::{CapabilityEndpoint, CapabilitySet};
use crate::error::*;
use crate::kobj::*;
use crate::kobj::{KernelObject, LikeKernelObject, LikeKernelObjectRef, Retype};
use crate::paging::{PageTableObject, RootPageTable};
use crate::serial::with_serial_port;
use bootloader::bootinfo::MemoryRegionType;
use core::cell::{Cell, UnsafeCell};
use core::fmt::Write;
use spin::Mutex;
use x86_64::{
    registers::{
        control::{Cr3, Cr3Flags},
        model_specific::GsBase,
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

#[derive(Copy, Clone, Debug)]
pub enum TaskFaultState {
    NoFault,
    PageFault,
}

/// LocalState is NOT thread safe and should only be accessed on the task's
/// own thread.
#[repr(C)]
pub struct LocalState {
    /// Address of the kernel syscall stack.
    pub kernel_stack: Cell<VirtAddr>,

    /// Saved address of the user stack.
    pub user_stack: Cell<VirtAddr>,

    /// Is there a pending page fault on this task?
    pub pending_fault: Cell<TaskFaultState>,

    /// Saved registers when scheduled out.
    pub registers: UnsafeCell<TaskRegisters>,
}

impl LocalState {
    pub fn new() -> LocalState {
        let current = Task::current().unwrap();
        LocalState {
            kernel_stack: Cell::new(
                unsafe { current.local_state.unsafe_deref() }
                    .kernel_stack
                    .get(),
            ),
            user_stack: Cell::new(VirtAddr::new(0)),
            pending_fault: Cell::new(TaskFaultState::NoFault),
            registers: UnsafeCell::new(TaskRegisters::new()),
        }
    }
}

#[repr(transparent)]
pub struct LocalStateWrapper(UnsafeCell<LocalState>);

impl LocalStateWrapper {
    pub fn new(inner: LocalState) -> LocalStateWrapper {
        LocalStateWrapper(UnsafeCell::new(inner))
    }

    pub unsafe fn unsafe_deref(&self) -> &LocalState {
        &*self.0.get()
    }
}

unsafe impl Send for LocalStateWrapper {}
unsafe impl Sync for LocalStateWrapper {}

#[repr(C)]
pub struct UserPageSet {
    /// The root page table that owns pages in this UserPageSet.
    owning_rpt: KernelObjectRef<PageTableObject>,

    /// Number of filled elements in `backing_user`.
    n_backings: u64,

    /// Virtual addresses of the backing pages in owning_rpt.
    ///
    /// u64 is used here instead of VirtAddr because these addresses are not necessarily valid before
    /// retyping.
    backing_user: [u64; 256],
}

impl Retype for UserPageSet {}
impl Notify for UserPageSet {
    fn will_drop(&mut self, owner: &dyn LikeKernelObject) {
        assert_eq!(
            owner as *const _ as *const PageTableObject,
            &*self.owning_rpt as *const PageTableObject
        );

        for i in 0..self.n_backings {
            unsafe {
                // Already checked in retype().
                owner.return_user_page(VirtAddr::new_unchecked(self.backing_user[i as usize]));
            }
        }
    }
}

impl UserPageSet {
    pub unsafe fn retype(
        &mut self,
        owning_rpt: KernelObjectRef<PageTableObject>,
    ) -> KernelResult<()> {
        if self.n_backings > self.backing_user.len() as u64 {
            return Err(KernelError::InvalidArgument);
        }

        owning_rpt.with(|pt| -> KernelResult<()> {
            for i in 0..self.n_backings {
                crate::paging::take_from_user(
                    pt,
                    VirtAddr::try_new(self.backing_user[i as usize])
                        .map_err(|_| KernelError::InvalidAddress)?,
                )?;
            }
            Ok(())
        })?;

        core::ptr::write(&mut self.owning_rpt, owning_rpt);
        Ok(())
    }
}

unsafe impl Send for UserPageSet {}
unsafe impl Sync for UserPageSet {}

#[repr(C)]
pub struct Task {
    /// Thread-unsafe local state.
    pub local_state: LocalStateWrapper,

    /// Page table of this task.
    pub page_table_root: KernelObjectRef<PageTableObject>,

    /// Root capability set.
    pub capabilities: KernelObjectRef<CapabilitySet>,

    /// IPC capabilities.
    pub ipc_caps: Mutex<[CapabilityEndpoint; 4]>,
}

#[repr(C)]
#[derive(Clone, Debug)]
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

pub fn empty_ipc_caps() -> [CapabilityEndpoint; 4] {
    [
        CapabilityEndpoint::default(),
        CapabilityEndpoint::default(),
        CapabilityEndpoint::default(),
        CapabilityEndpoint::default(),
    ]
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
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rsp: 0,
            rbp: 0,
            rip: 0,
            rflags: RFlags::INTERRUPT_FLAG.bits(),
        }
    }

    pub fn field_mut(&mut self, idx: usize) -> KernelResult<&mut u64> {
        Ok(match idx {
            0 => &mut self.rax,
            1 => &mut self.rdx,
            2 => &mut self.rcx,
            3 => &mut self.rbx,
            4 => &mut self.rsi,
            5 => &mut self.rdi,
            6 => &mut self.rbp,
            7 => &mut self.rsp,
            8 => &mut self.r8,
            9 => &mut self.r9,
            10 => &mut self.r10,
            11 => &mut self.r11,
            12 => &mut self.r12,
            13 => &mut self.r13,
            14 => &mut self.r14,
            15 => &mut self.r15,
            16 => &mut self.rip,
            _ => return Err(KernelError::InvalidArgument),
        })
    }
}

/// This function is unsafe because arbitrary physical memory can be mapped.
unsafe fn make_user_continuous_map<I: Iterator<Item = PhysFrame>>(
    region: I,
    mut vaddr: VirtAddr,
    root: &mut RootPageTable,
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

impl Notify for Task {
    unsafe fn return_user_page(&self, addr: VirtAddr) {
        self.page_table_root.return_user_page(addr);
    }
}

impl Task {
    /// Creates a new initial task for the current CPU.
    /// This does not depend on having a current task.
    pub fn new_initial(
        kernel_stack: VirtAddr,
        page_table_root: KernelObjectRef<PageTableObject>,
        cap_root: KernelObjectRef<CapabilitySet>,
    ) -> Task {
        Task {
            local_state: LocalStateWrapper(UnsafeCell::new(LocalState {
                kernel_stack: Cell::new(kernel_stack),
                user_stack: Cell::new(VirtAddr::new(0)),
                pending_fault: Cell::new(TaskFaultState::NoFault),
                registers: UnsafeCell::new(TaskRegisters::new()),
            })),
            page_table_root: page_table_root,
            capabilities: cap_root,
            ipc_caps: Mutex::new(empty_ipc_caps()),
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

pub unsafe fn retype_user_with<
    T: Retype + Notify + Send + Sync + 'static,
    K: Into<LikeKernelObjectRef>,
    F: FnOnce(&mut T) -> KernelResult<()>,
>(
    current: &KernelObjectRef<PageTableObject>,
    owner: K,
    vaddr: VirtAddr,
    retyper: Option<F>,
) -> KernelResult<KernelObjectRef<T>> {
    if !vaddr.is_aligned(PAGE_SIZE) {
        return Err(KernelError::InvalidDelegation);
    }

    let kvaddr = current.with(|current| crate::paging::take_from_user(current, vaddr))?;
    let maybe_value = kvaddr.as_mut_ptr::<KernelObject<T>>();
    let owner = owner.into();

    let result = if let Some(retyper) = retyper {
        (*maybe_value).init_with(owner.get(), vaddr, retyper)
    } else {
        (*maybe_value).init(owner.get(), vaddr, true)
    };
    match result {
        Ok(_) => Ok((*maybe_value).get_ref()),
        Err(e) => {
            match current.with(|current| crate::paging::put_to_user(current, kvaddr)) {
                _ => {}
            }
            Err(e)
        }
    }
}

pub fn retype_user<T: Retype + Notify + Send + Sync + 'static, K: Into<LikeKernelObjectRef>>(
    current: &KernelObjectRef<PageTableObject>,
    owner: K,
    vaddr: VirtAddr,
) -> KernelResult<KernelObjectRef<T>> {
    unsafe { retype_user_with::<_, _, fn(&mut T) -> KernelResult<()>>(current, owner, vaddr, None) }
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
        _user_code_selector: u32,
        _user_data_selector: u32,
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

    let task = get_current_task().expect("enter_user_mode: no current task");
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
