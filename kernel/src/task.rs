use crate::addr::*;
use crate::arch::{
    arch_get_current_page_table, arch_set_current_page_table,
    task::{
        arch_enter_user_mode, arch_enter_user_mode_syscall, arch_get_kernel_tls,
        arch_init_kernel_tls_for_cpu, arch_set_kernel_tls, arch_unblock_interrupt, TaskRegisters,
        TlsIndirect, wait_for_interrupt,
    },
    Page, PAGE_SIZE,
};
use crate::capability::{
    CapabilityEndpoint, CapabilityEndpointObject, CapabilitySet,
};
use crate::error::*;
use crate::kobj::*;
use crate::paging::{PageTableLevel, PageTableObject};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;
use core::convert::TryFrom;
use crate::spec::{TaskEndpointFlags, TaskFaultReason};

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

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

fn alloc_task_id() -> u64 {
    let id = NEXT_TASK_ID.fetch_add(1, Ordering::SeqCst);
    if id == core::u64::MAX {
        panic!("alloc_task_id: NEXT_TASK_ID overflow"); // is this ever possible?
    }
    id
}

#[repr(C)]
pub struct Task {
    /// Kernel-internal task identifier.
    pub id: u64,

    /// Page table of this task.
    pub page_table_root: AtomicKernelObjectRef<PageTableObject>,

    /// Root capability set.
    pub capabilities: AtomicKernelObjectRef<CapabilitySet>,

    /// IPC capability buffer.
    pub ipc_caps: Mutex<[CapabilityEndpoint; 4]>,

    /// Indicates whether this task is currently running (being the current task for any CPU).
    pub running: AtomicBool,

    /// Indicates whether there exists exactly one reply endpoint to this task.
    /// 
    /// It is a logic error to have more than one reply endpoints to a same task.
    pub ipc_blocked: AtomicBool,

    /// Indicates that this is an idle task.
    pub idle: AtomicBool,

    /// Indicates whether this task is handling an interrupt.
    pub interrupt_blocked: AtomicU8,

    /// Saved registers when scheduled out.
    pub registers: Mutex<TaskRegisters>,

    /// Fault handler table.
    pub fault_handler: Mutex<Option<TaskEndpoint>>,

    /// Tags.
    pub tags: Mutex<[TaskTag; 8]>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TaskTag {
    pub owner: u64,
    pub tag: u64,
}

#[derive(Clone)]
pub struct FaultHandler {
    pub task: KernelObjectRef<Task>,
    pub entry: IpcEntry,
}

#[derive(Copy, Clone, Debug)]
pub struct IpcEntry {
    /// Instruction pointer.
    pub pc: u64,

    /// Context provided by the user.
    pub user_context: u64,
}

/// Entry point information for a task endpoint.
#[derive(Clone)]
pub enum EntryType {
    /// A call endpoint.
    Call(WeakKernelObjectRef<Task>, IpcEntry),

    /// A cooperative reply endpoint.
    CooperativeReply(KernelObjectRef<Task>),

    /// A preemptiv reply endpoint.
    PreemptiveReply(KernelObjectRef<Task>),
}

#[derive(Clone)]
pub struct TaskEndpoint {
    /// Entry point information.
    pub entry: EntryType,

    /// Flags.
    pub flags: TaskEndpointFlags,
}

impl TaskEndpoint {
    pub fn get_task(&self) -> KernelResult<KernelObjectRef<Task>> {
        Ok(match self.entry {
            EntryType::Call(ref t, _) => KernelObjectRef::try_from(t.clone())?,
            EntryType::PreemptiveReply(ref t) => t.clone(),
            EntryType::CooperativeReply(ref t) => t.clone(),
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IpcReason {
    Interrupt(u8),
    CapInvoke,
    Fault(TaskFaultReason),
}

impl EntryType {
    pub fn direction(&self) -> EntryDirection {
        match *self {
            EntryType::Call(_, _) => EntryDirection::Push,
            EntryType::CooperativeReply(_) | EntryType::PreemptiveReply(_) => EntryDirection::Pop,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EntryDirection {
    Push,
    Pop,
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
            id: alloc_task_id(),
            page_table_root: AtomicKernelObjectRef::new(page_table_root),
            capabilities: AtomicKernelObjectRef::new(cap_root),
            ipc_caps: Mutex::new(Default::default()),
            registers: Mutex::new(TaskRegisters::new()),
            fault_handler: Mutex::new(None),
            running: AtomicBool::new(false),
            interrupt_blocked: AtomicU8::new(0),
            ipc_blocked: AtomicBool::new(true),
            idle: AtomicBool::new(false),
            tags: Mutex::new(Default::default()),
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
            let phys = PhysAddr::from_virt_null_filter(
                &*pt,
                VirtAddr::from_ref(&ROOT_IMAGE.value[i]),
            )
            .expect(
                "load_root_image: Failed to lookup physical address for kernel root image data.",
            );
            let uaddr = UserAddr::new(ROOT_TASK_FULL_MAP_BASE + i as u64).unwrap();

            pt.make_leaf_entry(uaddr).unwrap();
            pt.0.lookup_leaf_entry(uaddr.get(), |entry| {
                entry.set_addr_rwxu(phys);
            })
            .expect("load_root_image: Leaf entry not found");
        }
        println!("Mapped memory image for initial task.");
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

    pub fn shallow_clone(&self) -> KernelResult<KernelObjectRef<Task>> {
        KernelObjectRef::new(Task {
            id: alloc_task_id(),
            page_table_root: AtomicKernelObjectRef::new(self.page_table_root.get()),
            capabilities: AtomicKernelObjectRef::new(self.capabilities.get()),
            ipc_caps: Mutex::new(Default::default()),
            registers: Mutex::new(TaskRegisters::new()),
            fault_handler: Mutex::new(self.fault_handler.lock().clone()),
            running: AtomicBool::new(false),
            interrupt_blocked: AtomicU8::new(0),
            ipc_blocked: AtomicBool::new(false),
            idle: AtomicBool::new(false),
            tags: Mutex::new(Default::default()),
        })
    }

    /// Raises a fault on a task.
    /// 
    /// Panicks if no fault handler is registered. Never returns.
    pub fn raise_fault(me: KernelObjectRef<Task>, fault: TaskFaultReason, old_registers: &TaskRegisters) -> ! {
        let endpoint = match *me.fault_handler.lock() {
            Some(ref x) => x.clone(),
            None => panic!("Task::raise_fault: Got fault `{:?}` but no handler was registered.", fault),
        };
        drop(me);
        Task::invoke_ipc(endpoint, IpcReason::Fault(fault), old_registers);
        panic!("Task::raise_fault: Cannot invoke fault handler for fault: {:?}.", fault);
    }

    /// Invokes IPC on this task.
    /// 
    /// This function never returns if succeeded.
    /// 
    /// Also, this function should never fail on both `PreemptiveReply` and `CooperativeReply` endpoints, since
    /// they are not used for interrupts and use strong references to point to the underlying task.
    pub fn invoke_ipc(
        target: TaskEndpoint,
        reason: IpcReason,
        old_registers: &TaskRegisters,
    ) -> KernelError {
        // Try to get a strong reference to the task.
        let task = match target.get_task() {
            Ok(x) => x,
            Err(e) => return e,
        };

        // Block interrupt on this task.
        if let IpcReason::Interrupt(index) = reason {
            match task.block_interrupt(index) {
                Ok(()) => {},
                Err(e) => {
                    return e;
                }
            }
        }

        let prev = Task::current();

        // Attempts to block IPC for the target task, before switching to it.
        if target.entry.direction() == EntryDirection::Push {
            // Check invariant (stack-like structure).
            assert_eq!(prev.ipc_blocked.load(Ordering::Relaxed), true);

            if task.block_ipc().is_err() {
                // We are trying to re-enter a task whose IPC is already blocked. This is not allowed.

                // First, unblock interrupt if needed.
                if let IpcReason::Interrupt(_) = reason {
                    task.unblock_interrupt().expect(
                        "invoke_ipc: block_ipc failed on an interrupt endpoint but cannot unblock interrupt."
                    );
                }

                // Then, we are ready to return.
                return KernelError::InvalidState;
            }
        }

        // Here switch_to should always succeed, since we have checked ipc_blocked before.
        switch_to(task.clone(), Some(old_registers)).expect("invoke_ipc: switch_to failed.");

        // If CAP_TRANSFER is set, transfer capabilities before pop to avoid race conditions.
        if target.flags.contains(TaskEndpointFlags::CAP_TRANSFER) {
            let caps = core::mem::replace(&mut *prev.ipc_caps.lock(), Default::default());
            *task.ipc_caps.lock() = caps;
        }

        // A task always has `ipc_blocked == true` if it is successfully switched to. Since we are on the CPU that
        // switches out the task, we have the unique "ownership" for unblocking its IPC.
        if target.entry.direction() == EntryDirection::Pop {
            prev.unblock_ipc().expect("invoke_ipc: Unable to unblock IPC for the previous task.");

            // Check invariant (stack-like structure).
            assert_eq!(task.ipc_blocked.load(Ordering::Relaxed), true);

            // Unblock interrupt on the previous task, if it was running an interrupt handler.
            // We can safely ignore the return value, since it's okay if the task wasn't running an interrupt handler.
            drop(prev.unblock_interrupt());
        }

        let state_restore_mode: StateRestoreMode;

        // For the `Call` entry type, initialize program counter and the reply endpoint.
        match target.entry {
            EntryType::Call(_, entrypoint) => {
                // Set up the entry and flags for the reply endpoint.
                // 
                // Determine the entry type from the provided IPC reason.
                // Just use the same flags as the target endpoint for now.
                let (entry_type, flags) = match reason {
                    IpcReason::Interrupt(_) | IpcReason::Fault(_) => (EntryType::PreemptiveReply(prev.clone()), target.flags),
                    IpcReason::CapInvoke => (EntryType::CooperativeReply(prev.clone()), target.flags),
                };

                let reply_endpoint = TaskEndpoint {
                    entry: entry_type,
                    flags,
                };

                task.ipc_caps.lock()[0] = CapabilityEndpoint {
                    object: CapabilityEndpointObject::TaskEndpoint(reply_endpoint),
                };

                // Set registers.
                let mut regs = task.registers.lock();
                *regs.pc_mut() = entrypoint.pc;
                *regs.usermode_arg_mut(0).unwrap() = entrypoint.user_context;
                *regs.usermode_arg_mut(1).unwrap() = prev.get_tag(task.id).unwrap_or(0);

                if let IpcReason::Fault(fault) = reason {
                    *regs.usermode_arg_mut(2).unwrap() = fault as i64 as u64;
                }

                // Use syscall mode, since the target task is aware of the switch.
                state_restore_mode = StateRestoreMode::Syscall;
            }
            EntryType::PreemptiveReply(_) => {
                // Check invariant.
                assert_eq!(reason, IpcReason::CapInvoke);

                // Preemptive switch requires full state restore.
                state_restore_mode = StateRestoreMode::Full;
            }
            EntryType::CooperativeReply(_) => {
                // Check invariant.
                assert_eq!(reason, IpcReason::CapInvoke);

                // Use syscall mode.
                state_restore_mode = StateRestoreMode::Syscall;
            }
        }

        // Drop reference-counted values.
        drop(target);
        drop(prev);
        drop(task);

        // Enter user mode.
        enter_user_mode(state_restore_mode);
    }

    pub fn unblock_interrupt(&self) -> KernelResult<u8> {
        loop {
            let x = self.interrupt_blocked.load(Ordering::SeqCst);
            if x == 0 {
                return Err(KernelError::InvalidState);
            }
            if self
                .interrupt_blocked
                .compare_exchange(x, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                continue;
            }
            unsafe {
                arch_unblock_interrupt(x);
            }
            return Ok(x);
        }
    }

    pub fn block_interrupt(&self, index: u8) -> KernelResult<()> {
        if self
            .interrupt_blocked
            .compare_exchange(0, index, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            Err(KernelError::InvalidState)
        } else {
            Ok(())
        }
    }

    /// Atomically cmpxchg `ipc_blocked` from true to false.
    /// 
    /// Should ONLY be called on the current task.
    pub fn unblock_ipc(&self) -> KernelResult<()> {
        self.ipc_blocked.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst).map_err(|_| KernelError::InvalidState).map(|_| ())
    }

    /// Atomically cmpxchg `ipc_blocked` from false to true.
    /// 
    /// Should ONLY be called on the current task.
    pub fn block_ipc(&self) -> KernelResult<()> {
        self.ipc_blocked.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).map_err(|_| KernelError::InvalidState).map(|_| ())
    }

    pub fn set_tag(&self, owner: u64, tag: u64) -> KernelResult<()> {
        assert_ne!(owner, 0);

        let mut tags = self.tags.lock();
        for entry in tags.iter_mut() {
            if entry.owner == owner {
                entry.tag = tag;
                return Ok(());
            }
        }
        for entry in tags.iter_mut() {
            if entry.owner == 0 {
                entry.owner = owner;
                entry.tag = tag;
                return Ok(());
            }
        }
        Err(KernelError::InvalidState)
    }

    pub fn get_tag(&self, owner: u64) -> Option<u64> {
        let tags = self.tags.lock();
        for entry in tags.iter() {
            if entry.owner == owner {
                return Some(entry.tag);
            }
        }
        None
    }

    pub fn is_idle(&self) -> bool {
        self.idle.load(Ordering::SeqCst)
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

    // We are already on the target task.
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
    if task.is_idle() {
        wait_for_interrupt();
    } else {
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
}

lazy_static! {
    static ref INTERRUPT_BINDINGS: Mutex<[Option<TaskEndpoint>; 256]> = Mutex::new(unsafe {
        let mut result: MaybeUninit<[Option<TaskEndpoint>; 256]> = MaybeUninit::uninit();
        for entry in (*result.as_mut_ptr()).iter_mut() {
            core::ptr::write(entry, None);
        }
        result.assume_init()
    });
}

pub fn bind_interrupt(index: u8, handler: KernelObjectRef<Task>, entry: IpcEntry) {
    INTERRUPT_BINDINGS.lock()[index as usize] = Some(TaskEndpoint {
        entry: EntryType::Call(handler.into(), entry),
        flags: TaskEndpointFlags::TAGGABLE,
    });
}

pub fn unbind_interrupt(index: u8) {
    INTERRUPT_BINDINGS.lock()[index as usize] = None;
}

pub fn invoke_interrupt(
    index: u8,
    old_registers: &TaskRegisters,
) -> KernelError {
    let endpoint = INTERRUPT_BINDINGS.lock()[index as usize].clone();
    if let Some(endpoint) = endpoint {
        let e = Task::invoke_ipc(endpoint, IpcReason::Interrupt(index), old_registers);
        println!("WARNING: invoke_interrupt: {:?}", e);
        e
    } else {
        unsafe {
            arch_unblock_interrupt(index);
        }
        KernelError::EmptyObject
    }
}
