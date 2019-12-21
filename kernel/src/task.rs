use crate::addr::*;
use crate::arch::{
    arch_get_current_page_table, arch_set_current_page_table,
    task::{
        arch_enter_user_mode, arch_enter_user_mode_syscall, arch_get_kernel_tls,
        arch_init_kernel_tls_for_cpu, arch_set_kernel_tls, TaskRegisters, TlsIndirect,
    },
    tlb, PAGE_SIZE, PAGE_TABLE_LEVELS,
};
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

pub const ROOT_TASK_FULL_MAP_BASE: u64 = 0x20000000u64;

static ROOT_IMAGE: &'static [u8] =
    include_bytes!("../../user/init/target/x86_64-flatmk/release/init");

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

fn set_current_task(t: KernelObjectRef<Task>) {
    // Drop the old reference.
    let old = arch_get_kernel_tls() as *mut KernelObject<Task>;
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
    unsafe {
        arch_set_kernel_tls(raw as u64);
    }
}

pub unsafe fn init() {
    static mut INIT_TLS: TlsIndirect = TlsIndirect::new(crate::arch::config::KERNEL_STACK_END);
    arch_init_kernel_tls_for_cpu(&mut INIT_TLS);
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
        // Clone the current reference, if any.
        let ptr = arch_get_kernel_tls() as *mut KernelObject<Task>;
        let obj = unsafe { KernelObjectRef::from_raw(ptr) };
        let ret = obj.clone();
        // We should not drop the old reference here.
        KernelObjectRef::into_raw(obj);
        ret
    }

    #[inline]
    pub fn is_current(&self) -> bool {
        let ptr = arch_get_kernel_tls() as *mut KernelObject<Task>;
        let inner = unsafe { (*ptr).value() as *const Task };
        self as *const Task == inner
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
        old_registers: &TaskRegisters,
        mode: StateRestoreMode,
    ) -> (KernelError, KernelObjectRef<Task>) {
        {
            // TODO: Save old PC/SP and pass user context.
            let mut target_regs = task.registers.lock();
            *target_regs.pc_mut() = entry.pc;
            *target_regs.sp_mut() = entry.sp;
        }

        match switch_to(task.clone(), Some(old_registers)) {
            Ok(()) => {
                drop(task);
            }
            Err(e) => {
                return (e, task);
            }
        }
        enter_user_mode(mode);
    }
}

pub fn retype_user<T: Notify + Send + Sync + 'static>(
    owner: &KernelObjectRef<PageTableObject>,
    uaddr: UserAddr,
    value: T,
) -> KernelResult<KernelObjectRef<T>> {
    let kvaddr = owner.take_from_user(uaddr)?;

    let maybe_obj = kvaddr.as_mut_ptr::<KernelObject<T>>();

    let result =
        unsafe { (*maybe_obj).init(LikeKernelObjectRef::from(owner.clone()).get(), uaddr, value) };
    match result {
        Ok(_) => Ok(unsafe { (*maybe_obj).get_ref() }),
        Err(e) => {
            drop(owner.put_to_user(uaddr));
            Err(e)
        }
    }
}

pub fn switch_to(
    task: KernelObjectRef<Task>,
    old_registers: Option<&TaskRegisters>,
) -> KernelResult<()> {
    if let Some(old_regs) = old_registers {
        let current = Task::current();
        let mut regs = current.registers.lock();
        *regs = old_regs.clone();
        regs.lazy_read();
    }

    // Do nothing if we are switching to the same task.
    if task.is_current() {
        return Ok(());
    }

    let root = task.page_table_root.get();
    let root_level: VirtAddr = root
        .0
        .with_root(|x: &mut PageTableLevel| VirtAddr::from_ref(x));

    task.running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .map_err(|_| KernelError::InvalidState)?;

    task.registers.lock().lazy_write();
    set_current_task(task);

    // Don't reload if the new task shares a same page table with ourselves.
    unsafe {
        let addr = PhysAddr::from_virt(&*root, root_level).unwrap();
        if addr != arch_get_current_page_table() {
            arch_set_current_page_table(addr);
        }
    }

    Ok(())
}

/// The mode for restoring user context.
#[derive(Copy, Clone, Debug)]
pub enum StateRestoreMode {
    /// Performs full GPR restore.
    Full,

    /// Performs state restore according to the platform calling convention.
    ///
    /// Kernel data will not be leaked.
    Syscall,
}

/// Switches out of kernel mode and enters user mode.
pub fn enter_user_mode(mode: StateRestoreMode) -> ! {
    let task = Task::current();

    let registers: *const TaskRegisters = {
        let registers = task.registers.lock();
        &*registers as *const _
    };
    // Here we won't get a dangling `registers` pointer after drop because we know that
    // the TLS won't be dropped now.
    drop(task);

    unsafe {
        match mode {
            StateRestoreMode::Full => arch_enter_user_mode(registers),
            StateRestoreMode::Syscall => arch_enter_user_mode_syscall(registers),
        }
    }
}
