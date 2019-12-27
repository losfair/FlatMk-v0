use crate::addr::*;
use crate::arch::{
    arch_get_current_page_table, arch_set_current_page_table,
    task::{
        arch_enter_user_mode, arch_enter_user_mode_syscall, arch_get_kernel_tls,
        arch_init_kernel_tls_for_cpu, arch_set_kernel_tls, arch_unblock_interrupt, TaskRegisters,
        TlsIndirect,
    },
    Page, PAGE_SIZE,
};
use crate::capability::{
    CapPtr, CapTaskEndpoint, CapabilityEndpointObject, CapabilitySet, TaskEndpointFlags,
    INVALID_CAP,
};
use crate::error::*;
use crate::kobj::*;
use crate::paging::{PageTableLevel, PageTableObject};
use crate::serial::with_serial_port;
use core::fmt::Write;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
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
    GeneralProtection,
    IllegalInstruction,
    IntegerDivision,
}

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

    /// IPC base capability address.
    pub ipc_base: AtomicU64,

    /// Indicates whether this task is currently running (being the current task for any CPU).
    pub running: AtomicBool,

    /// Indicates whether this task is handling an interrupt.
    pub interrupt_blocked: AtomicU8,

    /// Saved registers when scheduled out.
    pub registers: Mutex<TaskRegisters>,

    /// Pending fault.
    pub pending_fault: Mutex<TaskFaultState>,

    /// Fault handler table.
    pub fault_handlers: Mutex<FaultHandlerTable>,

    /// Tags.
    pub tags: Mutex<[TaskTag; 16]>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TaskTag {
    pub owner: u64,
    pub tag: u64,
}

#[derive(Default, Clone)]
pub struct FaultHandlerTable {
    pub page_fault: Option<FaultHandler>,
}

#[derive(Clone)]
pub struct FaultHandler {
    pub task: KernelObjectRef<Task>,
    pub entry: IpcEntry,
}

#[derive(Clone)]
pub struct IpcEntry {
    /// Instruction pointer.
    pub pc: u64,

    /// Context provided by the user.
    pub user_context: u64,
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
            ipc_base: AtomicU64::new(INVALID_CAP),
            pending_fault: Mutex::new(TaskFaultState::NoFault),
            registers: Mutex::new(TaskRegisters::new()),
            fault_handlers: Mutex::new(FaultHandlerTable::default()),
            running: AtomicBool::new(false),
            interrupt_blocked: AtomicU8::new(0),
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

    pub fn shallow_clone(&self) -> KernelResult<KernelObjectRef<Task>> {
        KernelObjectRef::new(Task {
            id: alloc_task_id(),
            page_table_root: AtomicKernelObjectRef::new(self.page_table_root.get()),
            capabilities: AtomicKernelObjectRef::new(self.capabilities.get()),
            ipc_base: AtomicU64::new(INVALID_CAP),
            pending_fault: Mutex::new(TaskFaultState::NoFault),
            registers: Mutex::new(TaskRegisters::new()),
            fault_handlers: Mutex::new(self.fault_handlers.lock().clone()),
            running: AtomicBool::new(false),
            interrupt_blocked: AtomicU8::new(0),
            tags: Mutex::new(Default::default()),
        })
    }

    pub fn raise_fault(&self, fault: TaskFaultState) -> ! {
        panic!("fault not handled: {:?}", fault);
        *self.pending_fault.lock() = fault;
    }

    /// Invokes IPC on this task.
    ///
    /// This function never returns if succeeded.
    pub fn invoke_ipc(
        task: KernelObjectRef<Task>,
        entry: IpcEntry,
        old_registers: &TaskRegisters,
        mode: StateRestoreMode,
        reply_endpoint: Option<(CapPtr, CapTaskEndpoint)>,
    ) -> (KernelObjectRef<Task>, KernelError) {
        match switch_to(task.clone(), Some(old_registers)) {
            Ok(()) => {}
            Err(e) => return (task, e),
        }

        drop(task);

        {
            let current = Task::current();
            let mut target_regs = current.registers.lock();
            *target_regs.pc_mut() = entry.pc;
            if entry.user_context != core::u64::MAX {
                *target_regs.usermode_arg_mut(0).unwrap() = entry.user_context;
            }
            if let Some((base, reply_endpoint)) = reply_endpoint {
                drop(current.capabilities.get().entry_endpoint(base, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::TaskEndpoint(reply_endpoint);
                }));
            }
        }

        enter_user_mode(mode);
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

    /// Invokes asynchronous preemption to this task.
    pub fn invoke_async_preemption(
        task: KernelObjectRef<Task>,
        entry: IpcEntry,
        old_registers: &TaskRegisters,
    ) -> (KernelObjectRef<Task>, KernelError) {
        let remote_base = task.ipc_base.load(Ordering::SeqCst);

        let reply_endpoint = if remote_base != INVALID_CAP {
            Some((
                CapPtr(remote_base),
                CapTaskEndpoint {
                    task: Task::current(),
                    entry: IpcEntry {
                        pc: old_registers.pc(),
                        user_context: core::u64::MAX,
                    },
                    flags: TaskEndpointFlags::REPLY | TaskEndpointFlags::STATE_TRANSPARENT | TaskEndpointFlags::TAGGABLE,
                },
            ))
        } else {
            None
        };

        Self::invoke_ipc(
            task,
            entry,
            old_registers,
            StateRestoreMode::Syscall,
            reply_endpoint,
        )
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
}

pub fn switch_to(
    task: KernelObjectRef<Task>,
    old_registers: Option<&TaskRegisters>,
) -> KernelResult<()> {
    // Switching to the same task is not allowed.
    if task.is_current() {
        return Err(KernelError::InvalidState);
    }

    if let Some(old_regs) = old_registers {
        let current = Task::current();
        let mut regs = current.registers.lock();
        *regs = old_regs.clone();
        regs.lazy_read();
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

lazy_static! {
    static ref INTERRUPT_BINDINGS: Mutex<[Option<InterruptEntry>; 256]> = Mutex::new(unsafe {
        let mut result: MaybeUninit<[Option<InterruptEntry>; 256]> = MaybeUninit::uninit();
        for entry in (*result.as_mut_ptr()).iter_mut() {
            core::ptr::write(entry, None);
        }
        result.assume_init()
    });
}

#[derive(Clone)]
struct InterruptEntry {
    task: KernelObjectRef<Task>,
    entry: IpcEntry,
}

pub fn bind_interrupt(index: u8, handler: KernelObjectRef<Task>, entry: IpcEntry) {
    INTERRUPT_BINDINGS.lock()[index as usize] = Some(InterruptEntry {
        task: handler,
        entry,
    });
}

pub fn unbind_interrupt(index: u8) {
    INTERRUPT_BINDINGS.lock()[index as usize] = None;
}

pub fn invoke_interrupt(
    index: u8,
    old_registers: &TaskRegisters,
) -> KernelError {
    let entry = INTERRUPT_BINDINGS.lock()[index as usize].clone();
    if let Some(entry) = entry {
        if let Err(e) = entry.task.block_interrupt(index) {
            return e;
        }
        let (task, e) = Task::invoke_async_preemption(entry.task, entry.entry, old_registers);
        task.unblock_interrupt().expect(
            "invoke_interrupt: invoke_async_preemption returned error but unblock_interrupt failed",
        );
        e
    } else {
        unsafe {
            arch_unblock_interrupt(index);
        }
        KernelError::EmptyObject
    }
}
