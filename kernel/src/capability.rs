use crate::addr::*;
use crate::error::*;
use crate::kobj::*;
use crate::multilevel::*;
use crate::paging::PageTableObject;

use crate::arch::{task::TaskRegisters, tlb};
use crate::task::{retype_user, IpcEntry, StateRestoreMode, Task, TaskFaultState};
use core::convert::TryFrom;
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use num_enum::TryFromPrimitive;
use spin::Mutex;

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

#[repr(C)]
#[derive(Clone, Default)]
pub struct CapabilityTableNode {
    pub next: Option<NonNull<Level<LockedCapabilityEndpointSet, CapabilityTableNode, 128>>>,
    pub owner: Option<KernelObjectRef<PageTableObject>>,
    pub uaddr: UserAddr,
}

unsafe impl Send for CapabilityTableNode {}

pub struct CapabilitySet(pub CapabilityTable);
pub type CapabilityTable =
    MultilevelTableObject<LockedCapabilityEndpointSet, CapabilityTableNode, 7, 4, 35, 128>;

impl CapabilityTableNode {
    pub fn new_table() -> [CapabilityTableNode; 128] {
        unsafe {
            let mut nodes: MaybeUninit<[CapabilityTableNode; 128]> = MaybeUninit::uninit();
            for entry in (*nodes.as_mut_ptr()).iter_mut() {
                core::ptr::write(entry, CapabilityTableNode::default());
            }
            nodes.assume_init()
        }
    }
}
impl AsLevel<LockedCapabilityEndpointSet, 128> for CapabilityTableNode {
    fn as_level(
        &mut self,
    ) -> Option<NonNull<Level<LockedCapabilityEndpointSet, CapabilityTableNode, 128>>> {
        self.next
    }
}
impl DefaultUser<LockedCapabilityEndpointSet, CapabilityTableNode, 128> for CapabilityTableNode {
    unsafe fn default_user(
        mut kref: NonNull<Level<LockedCapabilityEndpointSet, CapabilityTableNode, 128>>,
        leaf: bool,
        owner: KernelObjectRef<PageTableObject>,
        uaddr: UserAddr,
    ) -> KernelResult<Self> {
        if leaf {
            kref.as_mut().value = ManuallyDrop::new(LockedCapabilityEndpointSet::new());
        } else {
            kref.as_mut().table = ManuallyDrop::new(Self::new_table());
        }
        Ok(CapabilityTableNode {
            next: Some(kref),
            owner: Some(owner),
            uaddr: uaddr,
        })
    }
}

impl Drop for CapabilityTableNode {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            if self.uaddr.0 != 0 {
                unsafe {
                    LikeKernelObjectRef::from(owner)
                        .get()
                        .return_user_page(self.uaddr);
                }
            }
        }
    }
}

pub struct LockedCapabilityEndpointSet {
    pub endpoints: Mutex<[CapabilityEndpoint; N_ENDPOINT_SLOTS]>,
}

impl LockedCapabilityEndpointSet {
    pub fn new() -> LockedCapabilityEndpointSet {
        let mut endpoints: MaybeUninit<[CapabilityEndpoint; N_ENDPOINT_SLOTS]> =
            MaybeUninit::uninit();
        unsafe {
            let inner = &mut *endpoints.as_mut_ptr();
            for elem in inner.iter_mut() {
                core::ptr::write(elem, CapabilityEndpoint::default());
            }
        }
        LockedCapabilityEndpointSet {
            endpoints: Mutex::new(unsafe { endpoints.assume_init() }),
        }
    }
}

impl Notify for LockedCapabilityEndpointSet {}

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
    IpcEndpoint(CapIpcEndpoint),
    CapabilitySet(KernelObjectRef<CapabilitySet>),
}

pub struct CapIpcEndpoint {
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

impl Clone for CapIpcEndpoint {
    fn clone(&self) -> CapIpcEndpoint {
        if self.reply {
            CapIpcEndpoint {
                task: None,
                entry: IpcEntry {
                    pc: 0,
                    sp: 0,
                    user_context: AtomicU64::new(core::u64::MAX),
                },
                reply: true,
                was_preempted: false,
            }
        } else {
            CapIpcEndpoint {
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

impl Notify for CapabilitySet {
    unsafe fn will_drop(&mut self, owner: &dyn LikeKernelObject) {
        self.0.will_drop(owner);
    }
}

impl CapabilitySet {
    pub fn entry_endpoint<T, F: FnOnce(&mut CapabilityEndpoint) -> T>(
        &self,
        cptr: CapPtr,
        f: F,
    ) -> KernelResult<T> {
        Ok(self.0.lookup(cptr.0, |set| {
            let mut set = set.endpoints.lock();
            let subindex = (cptr.0 & 0xff) as usize;
            if subindex >= set.len() {
                Err(KernelError::InvalidArgument)
            } else {
                Ok(f(&mut set[subindex]))
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
            CapabilityEndpointObject::IpcEndpoint(endpoint) => {
                invoke_cap_ipc_endpoint(invocation, endpoint)
            }
            CapabilityEndpointObject::CapabilitySet(set) => {
                invoke_cap_capability_set(invocation, set)
            }
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
    FetchDeepClone = 1,
    FetchCapSet = 2,
    FetchRootPageTable = 3,
    GetRegister = 4,
    SetRegister = 5,
    FetchNewUserPageSet = 6,
    FetchIpcEndpoint = 7,
    UnblockIpc = 8,
    FetchIpcCap = 9,
    PutCapSet = 10,
    IpcIsBlocked = 11,
    IsUnique = 12,
    MakeCapSet = 13,
}

fn invoke_cap_basic_task(
    invocation: &mut CapabilityInvocation,
    task: KernelObjectRef<Task>,
) -> KernelResult<i64> {
    let current = Task::current();

    let req = BasicTaskRequest::try_from(invocation.arg(0)? as u32)?;
    match req {
        BasicTaskRequest::FetchDeepClone => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let current_root = current.page_table_root.get();
            let delegation: KernelObjectRef<Task> = retype_user(
                &current_root,
                UserAddr(invocation.arg(2)? as u64),
                task.deep_clone(),
            )?;
            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::BasicTask(delegation);
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
        BasicTaskRequest::FetchIpcEndpoint => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let entry_pc = invocation.arg(2)? as u64;
            let entry_sp = invocation.arg(3)? as u64;
            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::IpcEndpoint(CapIpcEndpoint {
                        task: Some(task.clone()),
                        entry: IpcEntry {
                            pc: entry_pc,
                            sp: entry_sp,
                            user_context: AtomicU64::new(0),
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
        BasicTaskRequest::FetchIpcCap => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let index = invocation.arg(2)? as usize;

            let mut caps = task.ipc_caps.lock();
            if index >= caps.len() {
                return Err(KernelError::InvalidArgument);
            }

            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = core::mem::replace(
                        &mut caps[index],
                        CapabilityEndpoint {
                            object: CapabilityEndpointObject::Empty,
                        },
                    )
                    .object;
                })?;

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
        BasicTaskRequest::IsUnique => {
            let task = LikeKernelObjectRef::from(task);

            // Capabilities are cloned for invocation.
            if task.get().count_ref() == 2 {
                Ok(1)
            } else {
                Ok(0)
            }
        }
        BasicTaskRequest::MakeCapSet => {
            let current_root = current.page_table_root.get();
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let obj_delegation = UserAddr(invocation.arg(2)? as u64);
            let root_delegation = UserAddr(invocation.arg(3)? as u64);
            let delegation: KernelObjectRef<CapabilitySet> = retype_user(
                &current_root,
                obj_delegation,
                CapabilitySet(CapabilityTable::new_from_user(
                    &current_root,
                    root_delegation,
                )?),
            )?;
            task.capabilities.get().entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::CapabilitySet(delegation);
            })?;
            Ok(0)
        }
    }
}

fn invoke_cap_root_task(invocation: &CapabilityInvocation) -> KernelResult<i64> {
    #[repr(u32)]
    #[derive(Debug, Copy, Clone, TryFromPrimitive)]
    enum RootTaskCapRequest {
        X86IoPort = 0,
        Mmio = 1,
    }

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

fn invoke_cap_root_page_table(
    invocation: &CapabilityInvocation,
    pt: KernelObjectRef<PageTableObject>,
) -> KernelResult<i64> {
    let current = Task::current();
    let target = UserAddr(invocation.arg(0)? as u64);
    let user_page = UserAddr(invocation.arg(1)? as u64);

    let leaf = pt.build_from_user(target, current.page_table_root.get(), user_page)?;
    Ok(if leaf { 1 } else { 0 })
}

fn invoke_cap_mmio(invocation: &CapabilityInvocation, mmio: CapMmio) -> KernelResult<i64> {
    let target = UserAddr(invocation.arg(0)? as u64);
    unsafe {
        mmio.page_table
            .map_physical_page_for_user(target, mmio.page_addr)?;
    }
    tlb::flush(target);
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
    SetUserContext = 4,
}

fn invoke_cap_ipc_endpoint(
    invocation: &mut CapabilityInvocation,
    endpoint: CapIpcEndpoint,
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
            CapabilityEndpointObject::IpcEndpoint(x) => x,
            _ => return Err(KernelError::InvalidState),
        }
    } else {
        endpoint
    };

    let req = IpcRequest::try_from(invocation.arg(0)? as u32)?;
    let task: &KernelObjectRef<Task> = match endpoint.task {
        Some(ref t) => t,
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
            if task.block_ipc().is_err() {
                match req {
                    IpcRequest::SwitchToBlocking | IpcRequest::SwitchToBlocking_UnblockLocalIpc => {
                        task.raise_fault(TaskFaultState::IpcBlocked);
                    }
                    IpcRequest::SwitchToNonblocking
                    | IpcRequest::SwitchToNonblocking_UnblockLocalIpc => {
                        return Err(KernelError::WouldBlock);
                    }
                    _ => unreachable!(),
                }
            } else {
                // From here on we should not return or fault.
                {
                    let mut ipc_caps = task.ipc_caps.lock();

                    if !endpoint.reply {
                        ipc_caps[0] = CapabilityEndpoint {
                            object: CapabilityEndpointObject::IpcEndpoint(CapIpcEndpoint {
                                task: Some(current.clone()),
                                entry: IpcEntry {
                                    pc: *invocation.registers.pc_mut(),
                                    sp: *invocation.registers.sp_mut(),
                                    user_context: AtomicU64::new(core::u64::MAX),
                                },
                                reply: true,
                                was_preempted: false,
                            }),
                        };
                    }

                    for i in 1.. {
                        if i >= ipc_caps.len() {
                            break;
                        }
                        let arg = match invocation.arg(i) {
                            Ok(x) => x,
                            Err(_) => break,
                        };
                        if arg != INVALID_CAP {
                            match current
                                .capabilities
                                .get()
                                .entry_endpoint(CapPtr(arg), |x| x.clone())
                            {
                                Ok(x) => {
                                    ipc_caps[i] = x;
                                }
                                Err(_) => {
                                    ipc_caps[i] = CapabilityEndpoint::default();
                                }
                            }
                        }
                    }

                    *invocation.registers.return_value_mut() = 0;
                }

                let task = task.clone();
                let entry = endpoint.entry.clone();
                let mode = if endpoint.was_preempted {
                    StateRestoreMode::Full
                } else {
                    StateRestoreMode::Syscall
                };

                drop(current);
                drop(endpoint);

                let (e, task) = Task::invoke_ipc(task, entry, &invocation.registers, mode);
                drop(task.unblock_ipc());
                return Err(e);
            }
        }
        IpcRequest::SetUserContext => {
            let new_context_value = invocation.arg(1)? as u64;
            endpoint.entry.set_user_context(new_context_value)?;
            Ok(0)
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
enum CapSetRequest {
    Map = 0,
    IsUnique = 1,
    CloneCap = 2,
    DropCap = 3,
    FetchCap = 4,
    PutCap = 5,
}

fn invoke_cap_capability_set(
    invocation: &mut CapabilityInvocation,
    set: KernelObjectRef<CapabilitySet>,
) -> KernelResult<i64> {
    let req = CapSetRequest::try_from(invocation.arg(0)? as u32)?;
    let current = Task::current();

    match req {
        CapSetRequest::Map => {
            let ptr = invocation.arg(1)? as u64;
            let uaddr = UserAddr(invocation.arg(2)? as u64);
            let leaf = set
                .0
                .build_from_user(ptr, current.page_table_root.get(), uaddr)?;
            Ok(if leaf { 1 } else { 0 })
        }
        CapSetRequest::IsUnique => {
            let set = LikeKernelObjectRef::from(set);

            // Capabilities are cloned for invocation.
            if set.get().count_ref() == 2 {
                Ok(1)
            } else {
                Ok(0)
            }
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
    }
}
