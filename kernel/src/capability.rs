use crate::addr::*;
use crate::arch::task::TaskRegisters;
use crate::error::*;
use crate::kobj::*;
use crate::multilevel::*;
use crate::pagealloc::*;
use crate::paging::{PageTableMto, PageTableObject, UserPteFlags};
use crate::task::{IpcEntry, EntryType, StateRestoreMode, Task, TaskEndpoint, TaskEndpointFlags, EntryDirection, IpcReason, TaskFaultState, enter_user_mode};
use core::convert::TryFrom;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use num_enum::TryFromPrimitive;
use bit_field::BitField;

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
        _leaf: bool,
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

impl TryClone for CapabilityEndpointSet {
    fn try_clone(&self) -> KernelResult<Self> {
        for e in self.endpoints.iter() {
            if !e.object.allow_clone() {
                return Err(KernelError::InvalidState);
            }
        }
        Ok(self.clone())
    }
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
    TaskEndpoint(TaskEndpoint),
    CapabilitySet(KernelObjectRef<CapabilitySet>),
    Interrupt(u8),
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

impl TryClone for CapabilityEndpointObject {
    fn try_clone(&self) -> KernelResult<Self> {
        if self.allow_clone() {
            Ok(self.clone())
        } else {
            Err(KernelError::InvalidState)
        }
    }
}

impl CapabilityEndpointObject {
    pub fn allow_clone(&self) -> bool {
        match *self {
            CapabilityEndpointObject::TaskEndpoint(ref endpoint) => {
                match endpoint.entry.direction() {
                    EntryDirection::Push => true,
                    EntryDirection::Pop => false,
                }
            },
            _ => true
        }
    }

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
    FetchTaskEndpoint = 7,
    FetchIpcCap = 8,
    PutIpcCap = 9,
    PutCapSet = 10,
    MakeCapSet = 12,
    MakeRootPageTable = 13,
    PutRootPageTable = 14,
    IpcReturn = 15,
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
        BasicTaskRequest::FetchTaskEndpoint => {
            let mixed_arg1 = invocation.arg(1)? as u64;
            let cptr = CapPtr(mixed_arg1.get_bits(0..=47));
            let flags = TaskEndpointFlags::from_bits(mixed_arg1.get_bits(48..=62) as u16)?;
            let reply = mixed_arg1.get_bit(63);

            let entry_pc = invocation.arg(2)? as u64;
            let user_context = invocation.arg(3)? as u64;

            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| -> KernelResult<()> {
                    let entry = if reply {
                        // In the call tree, attempt to assign the current task as the parent node of `task`.
                        task.block_ipc()?;
                        EntryType::CooperativeReply
                    } else {
                        EntryType::Call(IpcEntry {
                            pc: entry_pc,
                            user_context
                        })
                    };
                    endpoint.object = CapabilityEndpointObject::TaskEndpoint(TaskEndpoint {
                        task: task.clone(),
                        entry,
                        flags,
                    });
                    Ok(())
                })??;
            Ok(0)
        }
        BasicTaskRequest::FetchIpcCap => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let index = invocation.arg(2)? as usize;
            let cap = {
                let mut caps = task.ipc_caps.lock();
                if index >= caps.len() {
                    return Err(KernelError::InvalidArgument);
                }
                core::mem::replace(&mut caps[index], CapabilityEndpoint::default())
            };
            current.capabilities.get().entry_endpoint(cptr, |endpoint| {
                *endpoint = cap;
            })?;
            Ok(0)
        }
        BasicTaskRequest::PutIpcCap => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let index = invocation.arg(2)? as usize;
            let cap = current.capabilities.get().entry_endpoint(cptr, |endpoint| {
                core::mem::replace(endpoint, CapabilityEndpoint::default())
            })?;
            {
                let mut caps = task.ipc_caps.lock();
                if index >= caps.len() {
                    return Err(KernelError::InvalidArgument);
                }
                caps[index] = cap;
            }
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
        BasicTaskRequest::IpcReturn => {
            let cap = core::mem::replace(&mut current.ipc_caps.lock()[0], Default::default());
            if let CapabilityEndpointObject::TaskEndpoint(endpoint) = cap.object {
                drop(current);
                let (_, e) = Task::invoke_ipc(
                    endpoint,
                    IpcReason::CapInvoke,
                    &invocation.registers,
                );
                Err(e)
            } else {
                Err(KernelError::InvalidArgument)
            }
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
enum RootTaskCapRequest {
    X86IoPort = 0,
    Mmio = 1,
    MakeIdle = 2,
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
            let pto = CapPtr(invocation.arg(2)? as u64);
            let phys_addr = PhysAddr(invocation.arg(3)? as u64);

            let pto =
                current
                    .capabilities
                    .get()
                    .entry_endpoint(pto, |endpoint| match endpoint.object {
                        CapabilityEndpointObject::RootPageTable(ref pto) => Ok(pto.clone()),
                        _ => Err(KernelError::InvalidArgument),
                    })??;

            current
                .capabilities
                .get()
                .entry_endpoint(cptr, |endpoint| {
                    endpoint.object = CapabilityEndpointObject::Mmio(CapMmio {
                        page_table: pto,
                        page_addr: phys_addr,
                    });
                })?;
            Ok(0)
        }
        RootTaskCapRequest::MakeIdle => {
            current.idle.store(true, Ordering::SeqCst);
            drop(current);

            // Use enter_user_mode instead of the fast syscall return routine to enter idle mode.
            enter_user_mode(StateRestoreMode::Syscall);
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
    SetProtection = 6,
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
            let protection = UserPteFlags::from_bits(invocation.arg(2)? as u64)?;
            pt.map_anonymous(target, protection)?;
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
            let protection = UserPteFlags::from_bits(invocation.arg(3)? as u64)?;
            let page = current.page_table_root.get().0.get_leaf(src.get())?;
            pt.0.attach_leaf(dst.get(), page)?;
            pt.0.lookup_leaf_entry(dst.get(), |entry| {
                entry.set_protection(protection);
            });
            pt.flush_tlb_if_current(dst);
            Ok(0)
        }
        RootPageTableRequest::FetchPage => {
            let src = UserAddr::new(invocation.arg(1)? as u64)?;
            let dst = UserAddr::new(invocation.arg(2)? as u64)?;
            let protection = UserPteFlags::from_bits(invocation.arg(3)? as u64)?;
            let page = pt.0.get_leaf(src.get())?;
            let current_pt = current.page_table_root.get();
            current_pt.0.attach_leaf(dst.get(), page)?;
            current_pt.0.lookup_leaf_entry(dst.get(), |entry| {
                entry.set_protection(protection);
            })?;
            current_pt.flush_tlb_assume_current(dst);
            Ok(0)
        }
        RootPageTableRequest::DropPage => {
            let target = UserAddr::new(invocation.arg(1)? as u64)?;
            pt.0.drop_leaf(target.get())?;
            pt.flush_tlb_if_current(target);
            Ok(0)
        }
        RootPageTableRequest::SetProtection => {
            let target = UserAddr::new(invocation.arg(1)? as u64)?;
            let protection = UserPteFlags::from_bits(invocation.arg(2)? as u64)?;
            pt.0.lookup_leaf_entry(target.get(), |entry| {
                if entry.is_unused() {
                    Err(KernelError::InvalidState)
                } else {
                    entry.set_protection(protection);
                    Ok(())
                }
            })??;
            pt.flush_tlb_if_current(target);
            Ok(0)
        }
    }
}

fn invoke_cap_mmio(invocation: &CapabilityInvocation, mmio: CapMmio) -> KernelResult<i64> {
    let target = UserAddr::new(invocation.arg(0)? as u64)?;
    let protection = UserPteFlags::from_bits(invocation.arg(1)? as u64)?;
    unsafe {
        mmio.page_table.map_physical_page(target, mmio.page_addr, protection)?;
    }
    Ok(0)
}

#[repr(u32)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
enum IpcRequest {
    SwitchTo = 0,
    IsCapTransfer = 1,
    IsTaggable = 2,
    IsReply = 3,
    SetTag = 4,
    GetTag = 5,
}

fn invoke_cap_task_endpoint(
    invocation: &mut CapabilityInvocation,
    endpoint: TaskEndpoint,
) -> KernelResult<i64> {
    let req = IpcRequest::try_from(invocation.arg(0)? as u32)?;

    match req {
        IpcRequest::SwitchTo => {
            let (_, e) = Task::invoke_ipc(
                endpoint,
                IpcReason::CapInvoke,
                &invocation.registers,
            );
            Err(e)
        }
        IpcRequest::IsCapTransfer => Ok(
            if endpoint
                .flags
                .contains(TaskEndpointFlags::CAP_TRANSFER)
            {
                1
            } else {
                0
            },
        ),
        IpcRequest::IsTaggable => Ok(
            if endpoint
                .flags
                .contains(TaskEndpointFlags::TAGGABLE)
            {
                1
            } else {
                0
            },
        ),
        IpcRequest::IsReply => Ok(
            if endpoint.entry.direction() == EntryDirection::Pop {
                1
            } else {
                0
            }
        ),
        IpcRequest::SetTag => {
            if !endpoint
                .flags
                .contains(TaskEndpointFlags::TAGGABLE) {
                    return Err(KernelError::InvalidState);
                }
            let current = Task::current();
            let tag = invocation.arg(1)? as u64;
            endpoint.task.set_tag(current.id, tag)?;
            Ok(0)
        }
        IpcRequest::GetTag => {
            let current = Task::current();
            let tag = endpoint.task.get_tag(current.id)?;
            Ok(tag as _)
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
    MoveCap = 6,
    GetCapType = 7,
    FetchCapMove = 8,
    PutCapMove = 9,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum CapType {
    Other = 0,
    TaskEndpoint = 1,
    RootPageTable = 2,
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
            let cap = set.entry_endpoint(src, |endpoint| endpoint.object.try_clone())??;
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
            let cap = set.entry_endpoint(src, |endpoint| endpoint.object.try_clone())??;
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
                .entry_endpoint(src, |endpoint| endpoint.object.try_clone())??;
            set.entry_endpoint(dst, |endpoint| {
                endpoint.object = cap;
            })?;
            Ok(0)
        }
        CapSetRequest::FetchDeepClone => {
            let dst = CapPtr(invocation.arg(1)? as u64);
            let clone = KernelObjectRef::new(CapabilitySet(set.0.try_deep_clone()?))?;
            current.capabilities.get().entry_endpoint(dst, |endpoint| {
                endpoint.object = CapabilityEndpointObject::CapabilitySet(clone);
            })?;
            Ok(0)
        }
        CapSetRequest::MoveCap => {
            let src = CapPtr(invocation.arg(1)? as u64);
            let dst = CapPtr(invocation.arg(2)? as u64);
            let src_endpoint = set.lookup_cptr_take(src)?;
            set.entry_endpoint(dst, |endpoint| {
                *endpoint = src_endpoint;
            })?;
            Ok(0)
        }
        CapSetRequest::GetCapType => {
            let cptr = CapPtr(invocation.arg(1)? as u64);
            let ty = set.entry_endpoint(cptr, |endpoint| match endpoint.object {
                CapabilityEndpointObject::TaskEndpoint(_) => CapType::TaskEndpoint,
                CapabilityEndpointObject::RootPageTable(_) => CapType::RootPageTable,
                _ => CapType::Other,
            })?;
            Ok(ty as u32 as _)
        }
        CapSetRequest::FetchCapMove => {
            let src = CapPtr(invocation.arg(1)? as u64);
            let dst = CapPtr(invocation.arg(2)? as u64);
            let cap = set.entry_endpoint(src, |endpoint| core::mem::replace(endpoint, Default::default()))?;
            current.capabilities.get().entry_endpoint(dst, |endpoint| {
                *endpoint = cap;
            })?;
            Ok(0)
        }
        CapSetRequest::PutCapMove => {
            let src = CapPtr(invocation.arg(1)? as u64);
            let dst = CapPtr(invocation.arg(2)? as u64);
            let cap = current
                .capabilities
                .get()
                .entry_endpoint(src, |endpoint| core::mem::replace(endpoint, Default::default()))?;
            set.entry_endpoint(dst, |endpoint| {
                *endpoint = cap;
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
