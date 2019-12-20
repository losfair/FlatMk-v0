use crate::addr::*;
use crate::arch::{arch_set_current_page_table, tlb, PAGE_SIZE, PAGE_TABLE_LEVELS};
use crate::capability::{CapabilityEndpoint, CapabilitySet};
use crate::error::*;
use crate::kobj::*;
use crate::paging::{PageTableLevel, PageTableObject};
use crate::serial::with_serial_port;
use bootloader::bootinfo::MemoryRegionType;
use core::cell::{Cell, UnsafeCell};
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::registers::{model_specific::GsBase, rflags::RFlags};

pub const ROOT_TASK_FULL_MAP_BASE: u64 = 0x20000000u64;

static ROOT_IMAGE: &'static [u8] =
    include_bytes!("../../user/init/target/x86_64-flatmk/release/init");

#[naked]
#[inline(never)]
unsafe extern "C" fn enable_sse() {
    asm!(r#"
        mov %cr4, %rax
        or $$0x600, %rax // CR4.OSFXSR + CR4.OSXMMEXCPT
        mov %rax, %cr4
        retq
    "# :::: "volatile");
}

#[derive(Clone, Debug)]
pub enum TaskFaultState {
    NoFault,
    PageFault,
    IpcBlocked,
    GeneralProtection,
    IllegalInstruction,
    IntegerDivision,
}

/// LocalState is NOT thread safe and should only be accessed on the task's
/// own thread.
#[repr(C)]
pub struct LocalState {
    /// Address of the kernel syscall stack.
    pub kernel_stack: Cell<VirtAddr>,

    /// Saved address of the user stack.
    pub user_stack: Cell<UserAddr>,
}

impl LocalState {
    pub fn new() -> LocalState {
        let current = Task::current();
        LocalState {
            kernel_stack: Cell::new(
                unsafe { current.local_state.unsafe_deref() }
                    .kernel_stack
                    .get(),
            ),
            user_stack: Cell::new(UserAddr(0)),
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
pub struct Task {
    /// Thread-unsafe local state. Used in assembly and must be the first field.
    pub local_state: LocalStateWrapper,

    /// Page table of this task.
    pub page_table_root: AtomicKernelObjectRef<PageTableObject>,

    /// Root capability set.
    pub capabilities: AtomicKernelObjectRef<CapabilitySet>,

    /// IPC capabilities.
    pub ipc_caps: Mutex<[CapabilityEndpoint; 4]>,

    /// Pending fault.
    pub pending_fault: Mutex<TaskFaultState>,

    /// Saved registers when scheduled out.
    pub registers: Mutex<TaskRegisters>,

    /// Fault handler table.
    pub fault_handlers: Mutex<FaultHandlerTable>,

    /// Indicates whether or not IPC is being blocked.
    pub ipc_blocked: AtomicBool,

    /// Indicates whether this task is currently running (being the current task for any CPU).
    pub running: AtomicBool,
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
    pub gs_base: u64,
    pub fs_base: u64,
}

#[derive(Default, Clone)]
pub struct FaultHandlerTable {
    pub ipc_blocked: Option<FaultHandler>,
    pub page_fault: Option<FaultHandler>,
}

#[derive(Clone)]
pub struct FaultHandler {
    pub task: KernelObjectRef<Task>,
    pub entry: IpcEntry,
}

pub struct IpcEntry {
    /// Instruction pointer.
    pub pc: u64,

    /// Stack pointer.
    pub sp: u64,

    /// Context provided by the user.
    /// Can only be modified when equals to zero.
    pub user_context: AtomicU64,
}

impl IpcEntry {
    pub fn set_user_context(&self, ctx: u64) -> KernelResult<()> {
        self.user_context
            .compare_exchange(0, ctx, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| KernelError::InvalidState)
    }
}

impl Clone for IpcEntry {
    fn clone(&self) -> IpcEntry {
        IpcEntry {
            pc: self.pc,
            sp: self.sp,
            user_context: AtomicU64::new(self.user_context.load(Ordering::SeqCst)),
        }
    }
}

pub fn empty_ipc_caps() -> [CapabilityEndpoint; 4] {
    [
        CapabilityEndpoint::default(),
        CapabilityEndpoint::default(),
        CapabilityEndpoint::default(),
        CapabilityEndpoint::default(),
    ]
}

#[inline]
fn get_current_task() -> KernelObjectRef<Task> {
    // Clone the current reference, if any.
    let ptr = GsBase::read().as_ptr::<KernelObject<Task>>();
    let obj = unsafe { KernelObjectRef::from_raw(ptr) };
    let ret = obj.clone();
    // We should not drop the old reference here.
    KernelObjectRef::into_raw(obj);
    ret
}

fn set_current_task(t: KernelObjectRef<Task>) {
    // Drop the old reference.
    let old = GsBase::read().as_ptr::<KernelObject<Task>>();
    if !old.is_null() {
        let old_obj = unsafe { KernelObjectRef::from_raw(old) };
        old_obj
            .running
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .expect(
                "set_current_task: Expecting the previous current task to be in 'running' state.",
            );
    }

    // Write the new reference.
    let raw = KernelObjectRef::into_raw(t);
    GsBase::write(::x86_64::VirtAddr::new(raw as u64));
}

pub unsafe fn init() {
    GsBase::write(::x86_64::VirtAddr::new(0));
    enable_sse();
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
            gs_base: 0,
            fs_base: 0,
        }
    }

    #[inline]
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

    #[inline]
    pub fn return_value_mut(&mut self) -> &mut u64 {
        &mut self.rax
    }

    #[inline]
    pub fn syscall_arg(&self, n: usize) -> KernelResult<u64> {
        Ok(match n {
            0 => self.rdi,
            1 => self.rsi,
            2 => self.rdx,
            3 => self.r10,
            4 => self.r8,
            5 => self.r9,
            _ => return Err(KernelError::InvalidArgument),
        })
    }

    #[inline]
    pub fn pc_mut(&mut self) -> &mut u64 {
        &mut self.rip
    }

    #[inline]
    pub fn sp_mut(&mut self) -> &mut u64 {
        &mut self.rsp
    }
}

/// This function is unsafe because arbitrary physical memory can be mapped.
unsafe fn make_user_continuous_map<I: Iterator<Item = PhysAddr>>(
    region: I,
    mut uaddr: UserAddr,
    root: &PageTableObject,
) -> u64 {
    let mut count: u64 = 0;
    for page_phys in region {
        if uaddr.validate().is_err() {
            return count;
        }

        let page_virt = VirtAddr::from_phys(page_phys);
        for b in (*page_virt.as_mut_ptr::<[u8; PAGE_SIZE]>()).iter_mut() {
            *b = 0;
        }

        root.0.lookup_entry(uaddr.0, |depth, entry| {
            entry.set_addr_rw(page_phys);
            entry.set_user_accessible(true);

            if depth == PAGE_TABLE_LEVELS - 1 {
                uaddr.0 += PAGE_SIZE as u64;
                count += 1;
            }
        });
    }
    count
}

impl Retype for Task {}

impl Notify for Task {}

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
                user_stack: Cell::new(UserAddr(0)),
            })),
            page_table_root: AtomicKernelObjectRef::new(page_table_root),
            capabilities: AtomicKernelObjectRef::new(cap_root),
            ipc_caps: Mutex::new(empty_ipc_caps()),
            pending_fault: Mutex::new(TaskFaultState::NoFault),
            registers: Mutex::new(TaskRegisters::new()),
            fault_handlers: Mutex::new(FaultHandlerTable::default()),
            ipc_blocked: AtomicBool::new(true),
            running: AtomicBool::new(false),
        }
    }

    pub fn load_root_image(&self) -> u64 {
        // Map all available physical memory into root task's address space.
        let num_pages_mapped = {
            let phys_mappings = &crate::boot::boot_info().memory_map;

            let phys_iterator = phys_mappings
                .iter()
                .filter_map(|x| match x.region_type {
                    MemoryRegionType::Usable | MemoryRegionType::Bootloader => Some(
                        (x.range.start_addr()..x.range.end_addr())
                            .step_by(PAGE_SIZE as _)
                            .map(|x| PhysAddr(x)),
                    ),
                    _ => None,
                })
                .flatten();
            unsafe {
                make_user_continuous_map(
                    phys_iterator,
                    UserAddr(ROOT_TASK_FULL_MAP_BASE),
                    &self.page_table_root.get(),
                )
            }
        };
        tlb::flush_all();
        with_serial_port(|p| writeln!(p, "Mapped {} pages.", num_pages_mapped).unwrap());

        let user_view = unsafe {
            core::slice::from_raw_parts_mut(
                ROOT_TASK_FULL_MAP_BASE as *mut u8,
                (num_pages_mapped * (PAGE_SIZE as u64)) as usize,
            )
        };
        match crate::elf::load(ROOT_IMAGE, user_view, ROOT_TASK_FULL_MAP_BASE) {
            Some(x) => x,
            None => {
                panic!("Unable to load root image");
            }
        }
    }

    #[inline]
    pub fn current() -> KernelObjectRef<Task> {
        get_current_task()
    }

    pub fn deep_clone(&self) -> Task {
        Task {
            local_state: LocalStateWrapper::new(LocalState::new()),
            page_table_root: AtomicKernelObjectRef::new(self.page_table_root.get()),
            capabilities: AtomicKernelObjectRef::new(self.capabilities.get()),
            ipc_caps: Mutex::new(empty_ipc_caps()),
            pending_fault: Mutex::new(TaskFaultState::NoFault),
            registers: Mutex::new(TaskRegisters::new()),
            fault_handlers: Mutex::new(self.fault_handlers.lock().clone()),
            ipc_blocked: AtomicBool::new(true),
            running: AtomicBool::new(false),
        }
    }

    pub fn raise_fault(&self, fault: TaskFaultState) -> ! {
        panic!("fault not handled: {:?}", fault);
        *self.pending_fault.lock() = fault;
    }

    pub fn unblock_ipc(&self) -> KernelResult<()> {
        let mut caps = self.ipc_caps.lock();
        for cap in caps.iter_mut() {
            *cap = CapabilityEndpoint::default();
        }
        if self
            .ipc_blocked
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            Err(KernelError::InvalidState)
        } else {
            Ok(())
        }
    }

    pub fn block_ipc(&self) -> KernelResult<()> {
        if self
            .ipc_blocked
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            Err(KernelError::InvalidState)
        } else {
            Ok(())
        }
    }

    /// Invokes IPC on this task. The caller should ensure ipc_blocked is true.
    ///
    /// This function never returns if succeeded.
    pub fn invoke_ipc(
        task: KernelObjectRef<Task>,
        entry: IpcEntry,
    ) -> (KernelError, KernelObjectRef<Task>) {
        {
            // TODO: Save old PC/SP and pass user context.
            let mut target_regs = task.registers.lock();
            *target_regs.pc_mut() = entry.pc;
            *target_regs.sp_mut() = entry.sp;
        }

        match crate::task::switch_to(task.clone()) {
            Ok(()) => {
                drop(task);
            }
            Err(e) => {
                return (e, task);
            }
        }
        crate::task::enter_user_mode();
    }
}

pub unsafe fn retype_user_with<
    T: Retype + Notify + Send + Sync + 'static,
    K: Into<LikeKernelObjectRef>,
    F: FnOnce(&mut T) -> KernelResult<()>,
>(
    current: &KernelObjectRef<PageTableObject>,
    owner: K,
    uaddr: UserAddr,
    retyper: Option<F>,
) -> KernelResult<KernelObjectRef<T>> {
    let kvaddr = current.take_from_user(uaddr)?;
    let maybe_value = kvaddr.as_mut_ptr::<KernelObject<T>>();
    let owner = owner.into();

    let result = if let Some(retyper) = retyper {
        (*maybe_value).init_with(owner.get(), uaddr, retyper)
    } else {
        (*maybe_value).init(owner.get(), uaddr, true)
    };
    match result {
        Ok(_) => Ok((*maybe_value).get_ref()),
        Err(e) => {
            drop(current.put_to_user(uaddr));
            Err(e)
        }
    }
}

pub fn switch_to(task: KernelObjectRef<Task>) -> KernelResult<()> {
    let root = task.page_table_root.get();
    let root_level: VirtAddr = root
        .0
        .with_root(|x: &mut PageTableLevel| VirtAddr::from_ref(x));

    task.running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .map_err(|_| KernelError::InvalidState)?;
    set_current_task(task);
    unsafe {
        arch_set_current_page_table(PhysAddr::from_virt(&*root, root_level).unwrap());
    };

    Ok(())
}

/// Switches out of kernel mode and enters user mode.
pub fn enter_user_mode() -> ! {
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
    assert_eq!(core::mem::size_of::<TaskRegisters>(), 160);
    let selectors = crate::exception::get_selectors();

    let task = Task::current();

    unsafe {
        let registers: *const TaskRegisters = {
            let registers = task.registers.lock();
            &*registers as *const _
        };
        // Here we won't get a dangling `registers` pointer after drop because we know that
        // `GsBase` won't be dropped now.
        drop(task);

        __enter_user_mode(
            0,
            registers,
            selectors.user_code_selector.0 as u32,
            selectors.user_data_selector.0 as u32,
        );
    }

    loop {}
}
