use crate::addr::*;
use crate::arch::task::{wait_for_interrupt, TaskRegisters};
use crate::error::*;
use crate::kobj::*;
use crate::multilevel::*;
use crate::pagealloc::*;
use crate::paging::{PageTableMto, PageTableObject};
use crate::task::{IpcEntry, StateRestoreMode, Task, TaskFaultState};
use core::convert::TryFrom;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use num_enum::TryFromPrimitive;

pub const N_ENDPOINT_SLOTS: usize = 32;
pub const INVALID_CAP: u64 = core::u64::MAX;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct CapPtr(pub u64);

#[repr(C)]
pub struct CapabilityInvocation {
    pub registers: TaskRegisters,
}

impl CapabilityInvocation {
    #[inline]
    pub fn cptr(&self) -> CapPtr {
        CapPtr(self.registers.syscall_arg(0).expect(
            "The platform system call convention should always have at least one argument.",
        ))
    }

    #[inline]
    pub fn arg(&self, n: usize) -> KernelResult<u64> {
        self.registers.syscall_arg(n + 1)
    }
}

#[repr(transparent)]
#[derive(Clone, Default)]
pub struct CapabilityTableNode {
    pub next: Option<NonNull<Level<CapabilityEndpointSet, CapabilityTableNode, 512>>>,
}

unsafe impl Send for CapabilityTableNode {}

pub struct CapabilitySet(pub CapabilityTable);
pub type CapabilityTable = MultilevelTableObject<
    CapabilityEndpointSet,
    CapabilityTableNode,
    GenericLeafCache,
    NullEntryFilter,
    9,
    3,
    34,
    512,
>;

impl AsLevel<CapabilityEndpointSet, 512> for CapabilityTableNode {
    fn as_level(
        &mut self,
    ) -> Option<NonNull<Level<CapabilityEndpointSet, CapabilityTableNode, 512>>> {
        self.next
    }

    fn attach_level(
        &mut self,
        level: NonNull<Level<CapabilityEndpointSet, CapabilityTableNode, 512>>,
    ) {
        self.next = Some(level);
    }

    fn clear_level(&mut self) {
        self.next = None;
    }
}

#[derive(Clone)]
pub struct CapabilityEndpointSet {
    pub endpoints: [CapabilityEndpoint; N_ENDPOINT_SLOTS],
}

impl CapabilityEndpointSet {
    pub fn new() -> CapabilityEndpointSet {
        let mut endpoints: MaybeUninit<[CapabilityEndpoint; N_ENDPOINT_SLOTS]> =
            MaybeUninit::uninit();
        unsafe {
            let inner = &mut *endpoints.as_mut_ptr();
            for elem in inner.iter_mut() {
                core::ptr::write(elem, CapabilityEndpoint::default());
            }
        }
        CapabilityEndpointSet {
            endpoints: unsafe { endpoints.assume_init() },
        }
    }
}

#[derive(Clone)]
pub struct CapabilityEndpoint {
    pub object: CapabilityEndpointObject,
}

impl Default for CapabilityEndpoint {
    fn default() -> CapabilityEndpoint {
        CapabilityEndpoint {
            object: CapabilityEndpointObject::Empty,
        }
    }
}

#[derive(Clone)]
pub enum CapabilityEndpointObject {
    Empty,
    BasicTask(KernelObjectRef<Task>),
    RootTask,
    X86IoPort(u16),
    Mmio(CapMmio),
    RootPageTable(KernelObjectRef<PageTableObject>),
    TaskEndpoint(CapTaskEndpoint),
    CapabilitySet(KernelObjectRef<CapabilitySet>),
    WaitForInterrupt,
    Interrupt(u8),
}

pub struct CapTaskEndpoint {
    /// Task object to send IPC messages to.
    pub task: Option<KernelObjectRef<Task>>,

    /// Entry point information.
    pub entry: IpcEntry,

    /// Whether this endpoint is a reply endpoint.
    ///
    /// A reply endpoint has the following properties:
    ///
    /// - Can only be used once.
    /// - Will not create another reply endpoint in the target task.
    pub reply: bool,

    /// Whether this endpoint is created by a non-cooperative preemption (e.g. interrupts, faults).
    ///
    /// Full state recovery will be performed if this is set to true.
    pub was_preempted: bool,
}

impl Clone for CapTaskEndpoint {
    fn clone(&self) -> CapTaskEndpoint {
        if self.reply {
            CapTaskEndpoint {
                task: None,
                entry: IpcEntry {
                    pc: 0,
                    user_context: core::u64::MAX,
                },
                reply: true,
                was_preempted: false,
            }
        } else {
            CapTaskEndpoint {
                task: self.task.clone(),
                entry: self.entry.clone(),
                reply: self.reply,
                was_preempted: self.was_preempted,
            }
        }
    }
}

#[derive(Clone)]
pub struct CapMmio {
    pub page_table: KernelObjectRef<PageTableObject>,
    pub page_addr: PhysAddr,
}

impl CapabilitySet {
    pub fn entry_endpoint<T, F: FnOnce(&mut CapabilityEndpoint) -> T>(
        &self,
        cptr: CapPtr,
        f: F,
    ) -> KernelResult<T> {
        Ok(self.0.lookup(cptr.0, |set| {
            let subindex = (cptr.0 & 0xff) as usize;
            if subindex >= set.endpoints.len() {
                Err(KernelError::InvalidArgument)
            } else {
                Ok(f(&mut set.endpoints[subindex]))
            }
        })??)
    }

    #[inline]
    pub fn lookup_cptr(&self, cptr: CapPtr) -> KernelResult<CapabilityEndpoint> {
        self.entry_endpoint(cptr, |x| x.clone())
    }

    #[inline]
    pub fn lookup_cptr_take(&self, cptr: CapPtr) -> KernelResult<CapabilityEndpoint> {
        self.entry_endpoint(cptr, |x| {
            core::mem::replace(x, CapabilityEndpoint::default())
        })
    }
}

impl CapabilityEndpointObject {
    /// invoke() takes self so that it can be dropped properly when this function does not return.
    pub fn invoke(self, invocation: &mut CapabilityInvocation) -> KernelResult<i64> {
        match self {
            CapabilityEndpointObject::Empty => Err(KernelError::EmptyCapability),
            CapabilityEndpointObject::BasicTask(task) => invoke_cap_basic_task(invocation, task),
            CapabilityEndpointObject::RootTask => invoke_cap_root_task(invocation),
            CapabilityEndpointObject::X86IoPort(index) => invoke_cap_x86_io_port(invocation, index),
            CapabilityEndpointObject::Mmio(mmio) => invoke_cap_mmio(invocation, mmio),
            CapabilityEndpointObject::RootPageTable(pt) => {
                invoke_cap_root_page_table(invocation, pt)
            }
            CapabilityEndpointObject::TaskEndpoint(endpoint) => {
                invoke_cap_task_endpoint(invocation, endpoint)
            }
            CapabilityEndpointObject::CapabilitySet(set) => {
                invoke_cap_capability_set(invocation, set)
            }
            CapabilityEndpointObject::WaitForInterrupt => wait_for_interrupt(),
            CapabilityEndpointObject::Interrupt(index) => invoke_cap_interrupt(invocation, index),
        }
    }
}

/// Type of a request to `BasicTask`.
///
/// Variants prefixed with `Fetch` uses resources in the associated task to create a new
/// capability in the current task's capability space.
///
/// Variants prefixed with `Put` uses resources in the current task to create a new capability
/// in the associated task's capability space.
///
/// Other variants only use and generate resources in the associated task.
#[repr(u32)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
enum BasicTaskRequest {
    FetchShallowClone = 1,
    FetchCapSet = 2,
    FetchRootPageTable = 3,
    GetRegister = 4,
    SetRegister = 5,
    FetchNewUserPageSet = 6,
    FetchTaskEndpoint = 7,
    UnblockIpc = 8,
    SetIpcBase = 9,
    PutCapSet = 10,
    IpcIsBlocked = 11,
    MakeCapSet = 12,
    MakeRootPageTable = 13,
    PutRootPageTable = 14,
}

fn invoke_cap_basic_task(
    invocation: &mut CapabilityInvocation,
    task: KernelObjectRef<Task>,
) -> KernelResult<i64> {
    let current = Task::current();

    let req = BasicTaskRequest::try_from(invocation.arg(0)? as u32)?;
    match req {
        BasicTaskRequest::FetchShallowClone => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let clone = task.shallow_clone()?;
            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::BasicTask(clone);
                })?;
            Ok(0)
        }
        BasicTaskRequest::FetchCapSet => {
            let dst = CapPtr(invocation.arg(1)? as u64);
            current.capabilities.get().entry_endpoint(dst, |endpoint| {
                endpoint.object = CapabilityEndpointObject::CapabilitySet(task.capabilities.get());
            })?;
            Ok(0)
        }
        BasicTaskRequest::FetchRootPageTable => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object =
                        CapabilityEndpointObject::RootPageTable(task.page_table_root.get());
                })?;
            Ok(0)
        }
        BasicTaskRequest::GetRegister => Err(KernelError::NotImplemented),
        BasicTaskRequest::SetRegister => {
            let field_index = invocation.arg(1)? as usize;
            let new_value = invocation.arg(2)? as u64;
            *task.registers.lock().field_mut(field_index)? = new_value;
            if task.is_current() {
                *invocation.registers.field_mut(field_index)? = new_value;
                invocation.registers.lazy_write();
            }
            Ok(0)
        }
        BasicTaskRequest::FetchNewUserPageSet => Err(KernelError::NotImplemented),
        BasicTaskRequest::FetchTaskEndpoint => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let entry_pc = invocation.arg(2)? as u64;
            let user_context = invocation.arg(3)? as u64;
            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::TaskEndpoint(CapTaskEndpoint {
                        task: Some(task.clone()),
                        entry: IpcEntry {
                            pc: entry_pc,
                            user_context,
                        },
                        reply: false,
                        was_preempted: false,
                    });
                })?;
            Ok(0)
        }
        BasicTaskRequest::UnblockIpc => {
            task.unblock_ipc()?;
            Ok(0)
        }
        BasicTaskRequest::SetIpcBase => {
            task.ipc_base
                .store(invocation.arg(1)? as u64, Ordering::SeqCst);
            Ok(0)
        }
        BasicTaskRequest::PutCapSet => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let capset =
                current
                    .capabilities
                    .get()
                    .entry_endpoint(cptr, |endpoint| match endpoint.object {
                        CapabilityEndpointObject::CapabilitySet(ref set) => Ok(set.clone()),
                        _ => Err(KernelError::InvalidArgument),
                    })??;
            task.capabilities.swap(capset);
            Ok(0)
        }
        BasicTaskRequest::IpcIsBlocked => {
            if task.ipc_blocked.load(Ordering::SeqCst) {
                Ok(1)
            } else {
                Ok(0)
            }
        }
        BasicTaskRequest::MakeCapSet => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let capset = KernelObjectRef::new(CapabilitySet(CapabilityTable::new()?))?;
            task.capabilities.get().entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::CapabilitySet(capset);
            })?;
            Ok(0)
        }
        BasicTaskRequest::MakeRootPageTable => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let pto = KernelObjectRef::new(PageTableObject(PageTableMto::new()?))?;
            pto.copy_kernel_range_from(&*current.page_table_root.get());
            task.capabilities.get().entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::RootPageTable(pto);
            })?;
            Ok(0)
        }
        BasicTaskRequest::PutRootPageTable => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let pto =
                current
                    .capabilities
                    .get()
                    .entry_endpoint(cptr, |endpoint| match endpoint.object {
                        CapabilityEndpointObject::RootPageTable(ref pto) => Ok(pto.clone()),
                        _ => Err(KernelError::InvalidArgument),
                    })??;
            task.page_table_root.swap(pto);
            Ok(0)
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
enum RootTaskCapRequest {
    X86IoPort = 0,
    Mmio = 1,
    WaitForInterrupt = 2,
    Interrupt = 3,
}

fn invoke_cap_root_task(invocation: &CapabilityInvocation) -> KernelResult<i64> {
    let current = Task::current();

    let requested_cap = RootTaskCapRequest::try_from(invocation.arg(0)? as u32)?;
    match requested_cap {
        RootTaskCapRequest::X86IoPort => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let port = invocation.arg(2)? as u16;
            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::X86IoPort(port);
                })?;
            Ok(0)
        }
        RootTaskCapRequest::Mmio => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let phys_addr = PhysAddr(invocation.arg(2)? as u64);

            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::Mmio(CapMmio {
                        page_table: current.page_table_root.get(),
                        page_addr: phys_addr,
                    });
                })?;
            Ok(0)
        }
        RootTaskCapRequest::WaitForInterrupt => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::WaitForInterrupt;
                })?;
            Ok(0)
        }
        RootTaskCapRequest::Interrupt => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let interrupt_index = invocation.arg(2)? as u8;
            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::Interrupt(interrupt_index);
                })?;
            Ok(0)
        }
    }
}

fn invoke_cap_x86_io_port(invocation: &CapabilityInvocation, port: u16) -> KernelResult<i64> {
    use x86::io;
    unsafe {
        if invocation.arg(0)? == 0 {
            // read
            Ok(match invocation.arg(1)? {
                1 => io::inb(port) as i64,
                2 => io::inw(port) as i64,
                4 => io::inl(port) as i64,
                _ => return Err(KernelError::InvalidArgument),
            })
        } else if invocation.arg(0)? == 1 {
            // write
            match invocation.arg(1)? {
                1 => io::outb(port, invocation.arg(2)? as u8),
                2 => io::outw(port, invocation.arg(2)? as u16),
                4 => io::outl(port, invocation.arg(2)? as u32),
                _ => return Err(KernelError::InvalidArgument),
            }
            Ok(0)
        } else {
            Err(KernelError::InvalidArgument)
        }
    }
}

#[repr(u32)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
enum RootPageTableRequest {
    MakeLeaf = 0,
    AllocLeaf = 1,
    FetchDeepClone = 2,
    PutPage = 3,
    FetchPage = 4,
    DropPage = 5,
}

fn invoke_cap_root_page_table(
    invocation: &CapabilityInvocation,
    pt: KernelObjectRef<PageTableObject>,
) -> KernelResult<i64> {
    let req = RootPageTableRequest::try_from(invocation.arg(0)? as u32)?;
    let current = Task::current();

    match req {
        RootPageTableRequest::MakeLeaf => {
            let target = UserAddr::new(invocation.arg(1)? as u64)?;
            pt.make_leaf_entry(target)?;
            Ok(0)
        }
        RootPageTableRequest::AllocLeaf => {
            let target = UserAddr::new(invocation.arg(1)? as u64)?;
            pt.map_anonymous(target)?;
            Ok(0)
        }
        RootPageTableRequest::FetchDeepClone => {
            let dst = CapPtr(invocation.arg(1)? as u64);
            let clone = KernelObjectRef::new(PageTableObject(pt.0.deep_clone_direct()?))?;
            clone.copy_kernel_range_from(&*pt);
            current.capabilities.get().entry_endpoint(dst, |endpoint| {
                endpoint.object = CapabilityEndpointObject::RootPageTable(clone);
            })?;
            Ok(0)
        }
        RootPageTableRequest::PutPage => {
            let src = UserAddr::new(invocation.arg(1)? as u64)?;
            let dst = UserAddr::new(invocation.arg(2)? as u64)?;
            let page = current.page_table_root.get().0.get_leaf(src.get())?;
            pt.0.attach_leaf(dst.get(), page)?;
            pt.flush_tlb_if_current(dst);
            Ok(0)
        }
        RootPageTableRequest::FetchPage => {
            let src = UserAddr::new(invocation.arg(1)? as u64)?;
            let dst = UserAddr::new(invocation.arg(2)? as u64)?;
            let page = pt.0.get_leaf(src.get())?;
            let current_pt = current.page_table_root.get();
            current_pt.0.attach_leaf(dst.get(), page)?;
            current_pt.flush_tlb_assume_current(dst);
            Ok(0)
        }
        RootPageTableRequest::DropPage => {
            let target = UserAddr::new(invocation.arg(1)? as u64)?;
            pt.0.drop_leaf(target.get())?;
            pt.flush_tlb_if_current(target);
            Ok(0)
        }
    }
}

fn invoke_cap_mmio(invocation: &CapabilityInvocation, mmio: CapMmio) -> KernelResult<i64> {
    let target = UserAddr::new(invocation.arg(0)? as u64)?;
    unsafe {
        mmio.page_table.map_physical_page(target, mmio.page_addr)?;
    }
    Ok(0)
}

#[repr(u32)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
enum IpcRequest {
    SwitchToBlocking = 0,
    SwitchToNonblocking = 1,
    SwitchToBlocking_UnblockLocalIpc = 2,
    SwitchToNonblocking_UnblockLocalIpc = 3,
}

fn invoke_cap_task_endpoint(
    invocation: &mut CapabilityInvocation,
    endpoint: CapTaskEndpoint,
) -> KernelResult<i64> {
    let current = Task::current();
    let endpoint = if endpoint.reply {
        // The `endpoint` we received as an argument is cloned.
        // The `Clone` implementation should not produce a valid clone of reply endpoints.
        assert!(endpoint.task.is_none());
        drop(endpoint);
        match current
            .capabilities
            .get()
            .lookup_cptr_take(invocation.cptr())?
            .object
        {
            CapabilityEndpointObject::TaskEndpoint(x) => x,
            _ => return Err(KernelError::InvalidState),
        }
    } else {
        endpoint
    };

    let req = IpcRequest::try_from(invocation.arg(0)? as u32)?;
    let task: KernelObjectRef<Task> = match endpoint.task {
        Some(ref t) => t.clone(),
        None => return Err(KernelError::InvalidArgument),
    };

    match req {
        IpcRequest::SwitchToBlocking
        | IpcRequest::SwitchToNonblocking
        | IpcRequest::SwitchToBlocking_UnblockLocalIpc
        | IpcRequest::SwitchToNonblocking_UnblockLocalIpc => {
            match req {
                IpcRequest::SwitchToBlocking_UnblockLocalIpc
                | IpcRequest::SwitchToNonblocking_UnblockLocalIpc => {
                    Task::current().unblock_ipc()?;
                }
                _ => {}
            }

            // Only modify the remote task's IPC blocking state if the remote task is "aware of" it.
            // This means the remote task wasn't preempted out.
            if !endpoint.was_preempted && task.block_ipc().is_err() {
                match req {
                    IpcRequest::SwitchToBlocking | IpcRequest::SwitchToBlocking_UnblockLocalIpc => {
                        task.raise_fault(TaskFaultState::IpcBlocked);
                    }
                    IpcRequest::SwitchToNonblocking
                    | IpcRequest::SwitchToNonblocking_UnblockLocalIpc => {
                        return Err(KernelError::WouldBlock);
                    }
                }
            } else {
                // Only transfer capabilities if the remote task wasn't preempted out.
                if !endpoint.was_preempted {
                    let remote_base = task.ipc_base.load(Ordering::SeqCst);

                    // Swap CapabilityEndpointSet of local and remote tasks.
                    {
                        let current_capabilities = current.capabilities.get();
                        let remote_capabilities = task.capabilities.get();
                        if &*current_capabilities as *const CapabilitySet
                            != &*remote_capabilities as *const CapabilitySet
                        {
                            let local_base = current.ipc_base.load(Ordering::SeqCst);
                            if local_base != INVALID_CAP && remote_base != INVALID_CAP {
                                current_capabilities.0.lookup_leaf_entry(
                                    local_base,
                                    |local_entry| {
                                        remote_capabilities.0.lookup_leaf_entry(
                                            remote_base,
                                            |remote_entry| {
                                                let remote_next = remote_entry.next;
                                                remote_entry.next = local_entry.next;
                                                local_entry.next = remote_next;
                                            },
                                        )
                                    },
                                )??;
                            }
                        }
                    }

                    if !endpoint.reply && remote_base != INVALID_CAP {
                        task.capabilities.get().0.lookup(remote_base, |entry| {
                            entry.endpoints[0] = CapabilityEndpoint {
                                object: CapabilityEndpointObject::TaskEndpoint(CapTaskEndpoint {
                                    task: Some(current.clone()),
                                    entry: IpcEntry {
                                        pc: *invocation.registers.pc_mut(),
                                        user_context: core::u64::MAX,
                                    },
                                    reply: true,
                                    was_preempted: false,
                                }),
                            };
                        })?;
                    }
                }

                *invocation.registers.return_value_mut() = 0;

                let entry = endpoint.entry.clone();
                let mode = if endpoint.was_preempted {
                    StateRestoreMode::Full
                } else {
                    StateRestoreMode::Syscall
                };

                drop(current);
                drop(endpoint);

                let e = Task::invoke_ipc(task, entry, &invocation.registers, mode);
                return Err(e);
            }
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
enum CapSetRequest {
    MakeLeafSet = 0,
    CloneCap = 1,
    DropCap = 2,
    FetchCap = 3,
    PutCap = 4,
    FetchDeepClone = 5,
}

fn invoke_cap_capability_set(
    invocation: &mut CapabilityInvocation,
    set: KernelObjectRef<CapabilitySet>,
) -> KernelResult<i64> {
    let req = CapSetRequest::try_from(invocation.arg(0)? as u32)?;
    let current = Task::current();

    match req {
        CapSetRequest::MakeLeafSet => {
            let ptr = invocation.arg(1)? as u64;
            set.0.make_leaf_entry(ptr)?;
            set.0
                .attach_leaf(ptr, KernelPageRef::new(CapabilityEndpointSet::new())?)?;
            Ok(0)
        }
        CapSetRequest::CloneCap => {
            let src = CapPtr(invocation.arg(1)? as u64);
            let dst = CapPtr(invocation.arg(2)? as u64);
            let cap = set.entry_endpoint(src, |endpoint| endpoint.object.clone())?;
            set.entry_endpoint(dst, |endpoint| {
                endpoint.object = cap;
            })?;
            Ok(0)
        }
        CapSetRequest::DropCap => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            set.entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::Empty;
            })?;
            Ok(0)
        }
        CapSetRequest::FetchCap => {
            let src = CapPtr(invocation.arg(1)? as u64);
            let dst = CapPtr(invocation.arg(2)? as u64);
            let cap = set.entry_endpoint(src, |endpoint| endpoint.object.clone())?;
            current.capabilities.get().entry_endpoint(dst, |endpoint| {
                endpoint.object = cap;
            })?;
            Ok(0)
        }
        CapSetRequest::PutCap => {
            let src = CapPtr(invocation.arg(1)? as u64);
            let dst = CapPtr(invocation.arg(2)? as u64);
            let cap = current
                .capabilities
                .get()
                .entry_endpoint(src, |endpoint| endpoint.object.clone())?;
            set.entry_endpoint(dst, |endpoint| {
                endpoint.object = cap;
            })?;
            Ok(0)
        }
        CapSetRequest::FetchDeepClone => {
            let dst = CapPtr(invocation.arg(1)? as u64);
            let clone = KernelObjectRef::new(CapabilitySet(set.0.deep_clone()?))?;
            current.capabilities.get().entry_endpoint(dst, |endpoint| {
                endpoint.object = CapabilityEndpointObject::CapabilitySet(clone);
            })?;
            Ok(0)
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
enum InterruptRequest {
    Bind = 0,
    Unbind = 1,
}

fn invoke_cap_interrupt(invocation: &mut CapabilityInvocation, index: u8) -> KernelResult<i64> {
    let req = InterruptRequest::try_from(invocation.arg(0)? as u32)?;

    match req {
        InterruptRequest::Bind => {
            let task = Task::current().capabilities.get().entry_endpoint(
                CapPtr(invocation.arg(1)? as u64),
                |endpoint| match endpoint.object {
                    CapabilityEndpointObject::BasicTask(ref t) => Ok(t.clone()),
                    _ => Err(KernelError::InvalidArgument),
                },
            )??;
            let entry_pc = invocation.arg(2)? as u64;
            let user_context = invocation.arg(3)? as u64;

            crate::task::bind_interrupt(
                index,
                task,
                IpcEntry {
                    pc: entry_pc,
                    user_context,
                },
            );
            Ok(0)
        }
        InterruptRequest::Unbind => {
            crate::task::unbind_interrupt(index);
            Ok(0)
        }
    }
}
