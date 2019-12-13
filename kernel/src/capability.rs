use crate::error::*;
use crate::kobj::*;
use crate::paging::{phys_to_virt, virt_to_phys, PageTableObject};
use crate::task::{
    empty_ipc_caps, retype_user, retype_user_with, LocalState, LocalStateWrapper, Task,
    TaskRegisters, UserPageSet, PAGE_SIZE,
};
use core::convert::TryFrom;
use core::mem::MaybeUninit;
use core::ops::Deref;
use num_enum::TryFromPrimitive;
use spin::Mutex;
use x86_64::{instructions::tlb, structures::paging::PageTableFlags, PhysAddr, VirtAddr};

pub const N_CAPSET_SLOTS: usize = 256;
pub const N_ENDPOINT_SLOTS: usize = 32;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct CapPtr(pub u64);

pub struct CapabilityInvocation<'a> {
    pub args: [i64; 4],
    pub registers: Option<&'a TaskRegisters>,
}

#[derive(Clone)]
pub struct Capability {
    /// The object behind this capability.
    ///
    /// Option can be used here because KernelObjectRef is a transparent,
    /// non-null reference.
    pub object: Option<KernelObjectRef<LockedCapabilityObject>>,
}

pub struct LockedCapabilityObject(Mutex<CapabilityObject>);

impl LockedCapabilityObject {
    pub fn new(inner: CapabilityObject) -> LockedCapabilityObject {
        LockedCapabilityObject(Mutex::new(inner))
    }
}

impl Deref for LockedCapabilityObject {
    type Target = Mutex<CapabilityObject>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Retype for LockedCapabilityObject {
    unsafe fn retype_in_place(&mut self) -> KernelResult<()> {
        core::ptr::write(self, LockedCapabilityObject::new(CapabilityObject::Empty));
        Ok(())
    }
}
impl Notify for LockedCapabilityObject {}

pub enum CapabilityObject {
    Empty,
    Nested(CapabilitySet),
    Endpoint([CapabilityEndpoint; N_ENDPOINT_SLOTS]),
}

impl CapabilityObject {
    pub fn new_empty_endpoints() -> CapabilityObject {
        let mut endpoints: MaybeUninit<[CapabilityEndpoint; N_ENDPOINT_SLOTS]> =
            MaybeUninit::uninit();
        unsafe {
            let inner = &mut *endpoints.as_mut_ptr();
            for elem in inner.iter_mut() {
                core::ptr::write(elem, CapabilityEndpoint::default());
            }
        }
        CapabilityObject::Endpoint(unsafe { endpoints.assume_init() })
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
    UserPageSet(KernelObjectRef<UserPageSet>),
}

#[derive(Clone)]
pub struct CapMmio {
    pub page_table: KernelObjectRef<PageTableObject>,
    pub page_addr: PhysAddr,
}

pub struct CapabilitySet {
    pub capabilities: Mutex<[Capability; N_CAPSET_SLOTS]>,
}

impl Retype for CapabilitySet {
    unsafe fn retype_in_place(&mut self) -> KernelResult<()> {
        core::ptr::write(self, CapabilitySet::default());
        Ok(())
    }
}
impl Notify for CapabilitySet {}

impl Default for CapabilitySet {
    fn default() -> CapabilitySet {
        assert_eq!(
            core::mem::size_of::<Capability>(),
            core::mem::size_of::<usize>()
        );

        CapabilitySet {
            capabilities: Mutex::new(unsafe { core::mem::zeroed() }),
        }
    }
}

impl CapabilitySet {
    pub fn entry_endpoint<T, F: FnOnce(&mut CapabilityEndpoint) -> T>(
        &self,
        mut cptr: CapPtr,
        f: F,
    ) -> KernelResult<T> {
        let index = (cptr.0 >> 56) as usize;
        cptr.0 <<= 8;

        let caps = self.capabilities.lock();
        if index >= caps.len() {
            Err(KernelError::EmptyCapability)
        } else {
            if let Some(ref obj) = caps[index].object {
                let mut obj = obj.lock();
                match *obj {
                    CapabilityObject::Empty => Err(KernelError::EmptyCapability),
                    CapabilityObject::Nested(ref inner) => inner.entry_endpoint(cptr, f),
                    CapabilityObject::Endpoint(ref mut inner) => {
                        let index = (cptr.0 >> 56) as usize;
                        cptr.0 <<= 8;
                        if index >= inner.len() {
                            Err(KernelError::EmptyCapability)
                        } else {
                            Ok(f(&mut inner[index]))
                        }
                    }
                }
            } else {
                Err(KernelError::EmptyCapability)
            }
        }
    }
    pub fn lookup(&self, cptr: CapPtr) -> KernelResult<CapabilityEndpoint> {
        self.entry_endpoint(cptr, |x| x.clone())
    }
}

impl CapabilityEndpointObject {
    pub fn invoke(&self, invocation: &CapabilityInvocation) -> KernelResult<i64> {
        match *self {
            CapabilityEndpointObject::Empty => Err(KernelError::EmptyCapability),
            CapabilityEndpointObject::BasicTask(ref task) => {
                invoke_cap_basic_task(invocation, task)
            }
            CapabilityEndpointObject::RootTask => invoke_cap_root_task(invocation),
            CapabilityEndpointObject::X86IoPort(index) => invoke_cap_x86_io_port(invocation, index),
            CapabilityEndpointObject::Mmio(ref mmio) => invoke_cap_mmio(invocation, mmio),
            CapabilityEndpointObject::RootPageTable(ref pt) => {
                invoke_cap_root_page_table(invocation, pt)
            }
            CapabilityEndpointObject::UserPageSet(ref buffer) => {
                invoke_cap_user_page_set(invocation, buffer)
            }
        }
    }
}

fn invoke_cap_basic_task(
    invocation: &CapabilityInvocation,
    task: &KernelObjectRef<Task>,
) -> KernelResult<i64> {
    #[repr(u32)]
    #[derive(Debug, Copy, Clone, TryFromPrimitive)]
    enum BasicTaskRequest {
        MakeFirstLevelEndpoint = 0,
        CapRootPageTable = 1,
        SwitchTo = 2,
        DeepClone = 3,
        GetRegister = 4,
        SetRegister = 5,
        CloneCap = 6,
        DropCap = 7,
        CapUserPageSet = 8,
    }

    let current = Task::current().unwrap();

    let req = BasicTaskRequest::try_from(invocation.args[0] as u32)?;
    match req {
        BasicTaskRequest::MakeFirstLevelEndpoint => {
            let mut caps = task.capabilities.capabilities.lock();
            let target_first_level_index = invocation.args[1] as usize;
            if target_first_level_index >= caps.len() {
                return Err(KernelError::InvalidArgument);
            }

            let delegation: KernelObjectRef<LockedCapabilityObject> = retype_user(
                &current.page_table_root,
                current.clone(),
                VirtAddr::try_new(invocation.args[2] as u64)
                    .map_err(|_| KernelError::InvalidAddress)?,
            )?;
            *delegation.lock() = CapabilityObject::new_empty_endpoints();
            caps[target_first_level_index].object = Some(delegation);
            Ok(0)
        }
        BasicTaskRequest::CapRootPageTable => {
            let cptr = CapPtr(invocation.args[1] as u64);
            task.capabilities.entry_endpoint(cptr, |endpoint| {
                endpoint.object =
                    CapabilityEndpointObject::RootPageTable(task.page_table_root.clone());
            })?;
            Ok(0)
        }
        BasicTaskRequest::SwitchTo => {
            if let Some(registers) = invocation.registers {
                unsafe {
                    *current.local_state.unsafe_deref().registers.get() = registers.clone();
                }
            }
            drop(current);
            crate::task::switch_to(task.clone());
            unsafe {
                crate::task::enter_user_mode();
            }
        }
        BasicTaskRequest::DeepClone => {
            let cptr = CapPtr(invocation.args[1] as u64);
            let delegation: KernelObjectRef<Task> = unsafe {
                retype_user_with(
                    &current.page_table_root,
                    current.clone(),
                    VirtAddr::try_new(invocation.args[2] as u64)
                        .map_err(|_| KernelError::InvalidAddress)?,
                    Some(|task: &mut Task| {
                        core::ptr::write(
                            task,
                            Task {
                                local_state: LocalStateWrapper::new(LocalState::new()),
                                page_table_root: current.page_table_root.clone(),
                                capabilities: current.capabilities.clone(),
                                ipc_caps: Mutex::new(empty_ipc_caps()),
                            },
                        );
                        Ok(())
                    }),
                )?
            };
            task.capabilities.entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::BasicTask(delegation);
            })?;
            Ok(0)
        }
        BasicTaskRequest::GetRegister => {
            let field_index = invocation.args[1] as usize;
            let return_uvaddr = VirtAddr::try_new(invocation.args[2] as u64)
                .map_err(|_| KernelError::InvalidAddress)?;

            // Here we may read a "partial" value, but anyway it's memory safe,
            let value = unsafe {
                *(*task.local_state.unsafe_deref().registers.get()).field_mut(field_index)?
            };

            current.page_table_root.with(|pt| {
                let return_kvaddr = phys_to_virt(virt_to_phys(pt, return_uvaddr)?).as_u64();
                // Must be aligned.
                if return_kvaddr % 8 != 0 {
                    return Err(KernelError::InvalidAddress);
                }
                let return_kptr = return_kvaddr as *mut u64;
                unsafe {
                    *return_kptr = value;
                }
                Ok(())
            })?;
            Ok(0)
        }
        BasicTaskRequest::SetRegister => {
            let field_index = invocation.args[1] as usize;
            let new_value = invocation.args[2] as u64;
            unsafe {
                *(*task.local_state.unsafe_deref().registers.get()).field_mut(field_index)? =
                    new_value;
            }
            Ok(0)
        }
        BasicTaskRequest::CloneCap => {
            let src = CapPtr(invocation.args[1] as u64);
            let dst = CapPtr(invocation.args[2] as u64);
            let cap = task
                .capabilities
                .entry_endpoint(src, |endpoint| endpoint.object.clone())?;
            task.capabilities.entry_endpoint(dst, |endpoint| {
                endpoint.object = cap;
            })?;
            Ok(0)
        }
        BasicTaskRequest::DropCap => {
            let cptr = CapPtr(invocation.args[1] as u64);
            task.capabilities.entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::Empty;
            })?;
            Ok(0)
        }
        BasicTaskRequest::CapUserPageSet => {
            let cptr = CapPtr(invocation.args[1] as u64);
            let buf_object = VirtAddr::try_new(invocation.args[2] as u64)
                .map_err(|_| KernelError::InvalidAddress)?;
            let delegation: KernelObjectRef<UserPageSet> = unsafe {
                retype_user_with(
                    &current.page_table_root,
                    current.page_table_root.clone(),
                    buf_object,
                    Some(|buf_object: &mut UserPageSet| {
                        buf_object.retype(current.page_table_root.clone())
                    }),
                )?
            };
            task.capabilities.entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::UserPageSet(delegation);
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

    let current = Task::current().unwrap();

    let requested_cap = RootTaskCapRequest::try_from(invocation.args[0] as u32)?;
    match requested_cap {
        RootTaskCapRequest::X86IoPort => {
            let cptr = CapPtr(invocation.args[1] as u64);
            let port = invocation.args[2] as u16;
            current.capabilities.entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::X86IoPort(port);
            })?;
            Ok(0)
        }
        RootTaskCapRequest::Mmio => {
            let cptr = CapPtr(invocation.args[1] as u64);
            let phys_addr = PhysAddr::new(invocation.args[2] as u64);

            if !phys_addr.is_aligned(PAGE_SIZE) {
                return Err(KernelError::NotAligned);
            }

            current.capabilities.entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::Mmio(CapMmio {
                    page_table: current.page_table_root.clone(),
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
        if invocation.args[0] == 0 {
            // read
            Ok(match invocation.args[1] {
                1 => io::inb(port) as i64,
                2 => io::inw(port) as i64,
                4 => io::inl(port) as i64,
                _ => return Err(KernelError::InvalidArgument),
            })
        } else if invocation.args[0] == 1 {
            // write
            match invocation.args[1] {
                1 => io::outb(port, invocation.args[2] as u8),
                2 => io::outw(port, invocation.args[2] as u16),
                4 => io::outl(port, invocation.args[2] as u32),
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
    pt: &KernelObjectRef<PageTableObject>,
) -> KernelResult<i64> {
    let target_vaddr =
        VirtAddr::try_new(invocation.args[0] as u64).map_err(|_| KernelError::InvalidAddress)?;
    let user_page =
        VirtAddr::try_new(invocation.args[1] as u64).map_err(|_| KernelError::InvalidAddress)?;

    pt.with(|pt| crate::task::retype_page_table_from_user(pt, target_vaddr, user_page))
        .map(|x| x as i64)
}

fn invoke_cap_mmio(invocation: &CapabilityInvocation, mmio: &CapMmio) -> KernelResult<i64> {
    let target_vaddr =
        VirtAddr::try_new(invocation.args[0] as u64).map_err(|_| KernelError::InvalidAddress)?;

    mmio.page_table.with(|pt| unsafe {
        crate::task::map_physical_page_into_user(
            pt,
            target_vaddr,
            mmio.page_addr,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::NO_CACHE,
        )
    })?;
    tlb::flush(target_vaddr);
    Ok(0)
}

fn invoke_cap_user_page_set(
    invocation: &CapabilityInvocation,
    _buffer: &KernelObjectRef<UserPageSet>,
) -> KernelResult<i64> {
    #[repr(u32)]
    #[derive(Debug, Copy, Clone, TryFromPrimitive)]
    enum UserPageSetCapRequest {
        Map = 0,
    }

    //let current = Task::current().unwrap();
    let req = UserPageSetCapRequest::try_from(invocation.args[0] as u32)?;

    match req {
        UserPageSetCapRequest::Map => Err(KernelError::NotImplemented),
    }
}
