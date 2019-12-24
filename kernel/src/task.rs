use crate::addr::*;
use crate::arch::{
    arch_get_current_page_table, arch_set_current_page_table,
    task::{
        arch_enter_user_mode, arch_enter_user_mode_syscall, arch_get_kernel_tls,
        arch_init_kernel_tls_for_cpu, arch_set_kernel_tls, TaskRegisters, TlsIndirect,
    },
    Page, PAGE_SIZE,
};
use crate::capability::{CapabilitySet, INVALID_CAP};
use crate::error::*;
use crate::kobj::*;
use crate::paging::{PageTableLevel, PageTableObject};
use crate::serial::with_serial_port;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

pub const ROOT_TASK_FULL_MAP_BASE: u64 = 0x20000000u64;

#[repr(C)]
struct AlignTo<T, U: ?Sized> {
    _align: [T; 0],
    value: U,
}

include!("../generated/user_init.decl.rs");
static ROOT_IMAGE: &'static AlignTo<Page, RootImageBytes> = &AlignTo {
    _align: [],
    value: *include_bytes!("../generated/user_init.img"),
};

#[derive(Clone, Debug)]
pub enum TaskFaultState {
    NoFault,
    PageFault,
    IpcBlocked,
    GeneralProtection,
    IllegalInstruction,
    IntegerDivision,
}

#[repr(C)]
pub struct Task {
    /// Page table of this task.
    pub page_table_root: AtomicKernelObjectRef<PageTableObject>,

    /// Root capability set.
    pub capabilities: AtomicKernelObjectRef<CapabilitySet>,

    /// IPC base capability address.
    pub ipc_base: AtomicU64,

    /// Indicates whether or not IPC is being blocked.
    pub ipc_blocked: AtomicBool,

    /// Indicates whether this task is currently running (being the current task for any CPU).
    pub running: AtomicBool,

    /// Saved registers when scheduled out.
    pub registers: Mutex<TaskRegisters>,

    /// Pending fault.
    pub pending_fault: Mutex<TaskFaultState>,

    /// Fault handler table.
    pub fault_handlers: Mutex<FaultHandlerTable>,
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
            user_context: AtomicU64::new(self.user_context.load(Ordering::SeqCst)),
        }
    }
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

impl Task {
    /// Creates a new initial task for the current CPU.
    /// This does not depend on having a current task.
    pub fn new_initial(
        page_table_root: KernelObjectRef<PageTableObject>,
        cap_root: KernelObjectRef<CapabilitySet>,
    ) -> Task {
        Task {
            page_table_root: AtomicKernelObjectRef::new(page_table_root),
            capabilities: AtomicKernelObjectRef::new(cap_root),
            ipc_base: AtomicU64::new(INVALID_CAP),
            pending_fault: Mutex::new(TaskFaultState::NoFault),
            registers: Mutex::new(TaskRegisters::new()),
            fault_handlers: Mutex::new(FaultHandlerTable::default()),
            ipc_blocked: AtomicBool::new(true),
            running: AtomicBool::new(false),
        }
    }

    pub fn load_root_image(&self) -> u64 {
        // Aligned and properly sized. Should already be checked during compilation.
        assert!(
            ROOT_IMAGE.value.len() % PAGE_SIZE == 0
                && ((ROOT_IMAGE as *const _ as usize) & (PAGE_SIZE - 1)) == 0
        );

        let pt = self.page_table_root.get();

        for i in (0..ROOT_IMAGE.value.len()).step_by(PAGE_SIZE) {
            let phys = PhysAddr::from_virt(&*pt, VirtAddr::from_ref(&ROOT_IMAGE.value[i])).expect(
                "load_root_image: Failed to lookup physical address for kernel root image data.",
            );
            let uaddr = UserAddr::new(ROOT_TASK_FULL_MAP_BASE + i as u64).unwrap();

            pt.make_leaf_entry(uaddr).unwrap();
            pt.0.lookup_leaf_entry(uaddr.get(), |entry| {
                entry.set_addr_rwxu(phys);
            })
            .expect("load_root_image: Leaf entry not found");
        }
        with_serial_port(|p| writeln!(p, "Mapped memory image for initial task.").unwrap());
        ROOT_ENTRY
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

    pub fn deep_clone(&self) -> KernelResult<KernelObjectRef<Task>> {
        KernelObjectRef::new(Task {
            page_table_root: AtomicKernelObjectRef::new(self.page_table_root.get()),
            capabilities: AtomicKernelObjectRef::new(self.capabilities.get()),
            ipc_base: AtomicU64::new(INVALID_CAP),
            pending_fault: Mutex::new(TaskFaultState::NoFault),
            registers: Mutex::new(TaskRegisters::new()),
            fault_handlers: Mutex::new(self.fault_handlers.lock().clone()),
            ipc_blocked: AtomicBool::new(true),
            running: AtomicBool::new(false),
        })
    }

    pub fn raise_fault(&self, fault: TaskFaultState) -> ! {
        panic!("fault not handled: {:?}", fault);
        *self.pending_fault.lock() = fault;
    }

    pub fn unblock_ipc(&self) -> KernelResult<()> {
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
    ) -> KernelError {
        {
            // TODO: Save old PC/SP and pass user context.
            let mut target_regs = task.registers.lock();
            *target_regs.pc_mut() = entry.pc;
        }

        match switch_to(task, Some(old_registers)) {
            Ok(()) => {}
            Err(e) => return e,
        }
        let user_context = entry.user_context.load(Ordering::SeqCst);
        unsafe {
            asm!(
                "mov $0, %xmm0" : : "r"(user_context) : : "volatile"
            );
        }
        enter_user_mode(mode);
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
        let addr = PhysAddr::from_phys_mapped_virt(root_level).unwrap();
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
