use crate::error::*;
use crate::kobj::*;
use crate::paging::PageTableObject;
use crate::serial::with_serial_port;
use crate::task::{retype_user, Task, PAGE_SIZE};
use core::cell::{Cell, UnsafeCell};
use core::convert::TryFrom;
use core::fmt::Write;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::sync::atomic::{AtomicU64, Ordering};
use num_enum::TryFromPrimitive;
use spin::Mutex;
use x86_64::{instructions::tlb, structures::paging::PageTableFlags, PhysAddr, VirtAddr};

bitflags! {
    pub struct Rights: u64 {
        const NONE = 0x0;
        const READ = 0x1;
        const WRITE = 0x2;
        const CLONE = 0x4;
        const SIGNAL = 0x8;
        const DEFAULT = Self::READ.bits | Self::WRITE.bits | Self::CLONE.bits;
    }
}

pub const N_CAPSET_SLOTS: usize = 256;
pub const N_ENDPOINT_SLOTS: usize = 32;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct CapPtr(pub u64);

pub struct CapabilityInvocation {
    pub args: [i64; 4],
}

#[derive(Clone)]
pub struct Capability {
    /// The object behind this capability.
    ///
    /// Option can be used here because KernelObjectRef is a transparent,
    /// non-null reference.
    pub object: Option<KernelObjectRef<LockedCapabilityObject>>,
}

impl Default for Capability {
    fn default() -> Capability {
        assert_eq!(
            core::mem::size_of::<Capability>(),
            core::mem::size_of::<usize>()
        );
        Capability { object: None }
    }
}

pub struct LockedCapabilityObject(Mutex<CapabilityObject>);
impl Deref for LockedCapabilityObject {
    type Target = Mutex<CapabilityObject>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Retype for LockedCapabilityObject {
    unsafe fn retype_in_place(&mut self) -> KernelResult<()> {
        core::ptr::write(
            self,
            LockedCapabilityObject(Mutex::new(CapabilityObject::Empty)),
        );
        Ok(())
    }
}
impl Notify for LockedCapabilityObject {}

pub enum CapabilityObject {
    Empty,
    Nested(CapabilitySet),
    Endpoint([CapabilityEndpoint; N_ENDPOINT_SLOTS]),
}

#[derive(Clone)]
pub struct CapabilityEndpoint {
    pub object: CapabilityEndpointObject,
    pub rights: Rights,
}

impl Default for CapabilityEndpoint {
    fn default() -> CapabilityEndpoint {
        CapabilityEndpoint {
            object: CapabilityEndpointObject::Empty,
            rights: Rights::NONE,
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
    Vmap(CapVmap),
}

#[derive(Clone)]
pub struct CapMmio {
    pub page_table: KernelObjectRef<PageTableObject>,
    pub page_addr: PhysAddr,
}

#[derive(Clone)]
pub struct CapVmap {
    pub page_table: KernelObjectRef<PageTableObject>,
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

        let mut caps = self.capabilities.lock();
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
    pub fn invoke(&self, invocation: CapabilityInvocation) -> KernelResult<i64> {
        match *self {
            CapabilityEndpointObject::Empty => Err(KernelError::EmptyCapability),
            CapabilityEndpointObject::BasicTask(ref task) => {
                invoke_cap_basic_task(invocation, task)
            }
            CapabilityEndpointObject::RootTask => invoke_cap_root_task(invocation),
            CapabilityEndpointObject::X86IoPort(index) => invoke_cap_x86_io_port(invocation, index),
            CapabilityEndpointObject::Mmio(ref mmio) => invoke_cap_mmio(invocation, mmio),
            CapabilityEndpointObject::Vmap(ref vmap) => invoke_cap_vmap(invocation, vmap),
        }
    }
}

fn invoke_cap_basic_task(
    invocation: CapabilityInvocation,
    task: &KernelObjectRef<Task>,
) -> KernelResult<i64> {
    #[repr(u32)]
    #[derive(Debug, Copy, Clone, TryFromPrimitive)]
    enum BasicTaskRequest {
        MakeFirstLevelEndpoint = 0,
        CapVmap = 1,
    }

    let current = Task::current().unwrap();

    let req = match BasicTaskRequest::try_from(invocation.args[0] as u32) {
        Ok(x) => x,
        Err(_) => return Err(KernelError::InvalidArgument),
    };
    match req {
        BasicTaskRequest::MakeFirstLevelEndpoint => {
            let mut caps = task.capabilities.capabilities.lock();
            let target_first_level_index = invocation.args[1] as usize;
            if target_first_level_index >= caps.len() {
                return Err(KernelError::InvalidArgument);
            }

            let delegation: KernelObjectRef<LockedCapabilityObject> =
                current.page_table_root.with(|pt| {
                    retype_user(
                        pt,
                        current.clone(),
                        VirtAddr::new(invocation.args[2] as u64),
                    )
                })?;
            let mut endpoints: MaybeUninit<[CapabilityEndpoint; N_ENDPOINT_SLOTS]> =
                MaybeUninit::uninit();
            unsafe {
                let inner = &mut *endpoints.as_mut_ptr();
                for elem in inner.iter_mut() {
                    core::ptr::write(elem, CapabilityEndpoint::default());
                }
            }
            *delegation.lock() = CapabilityObject::Endpoint(unsafe { endpoints.assume_init() });
            caps[target_first_level_index].object = Some(delegation);
            Ok(0)
        }
        BasicTaskRequest::CapVmap => {
            let cptr = CapPtr(invocation.args[1] as u64);
            task.capabilities.entry_endpoint(cptr, |endpoint| {
                endpoint.object = CapabilityEndpointObject::Vmap(CapVmap {
                    page_table: task.page_table_root.clone(),
                });
            })?;
            Ok(0)
        }
    }
}

fn invoke_cap_root_task(invocation: CapabilityInvocation) -> KernelResult<i64> {
    #[repr(u32)]
    #[derive(Debug, Copy, Clone, TryFromPrimitive)]
    enum RootTaskCapRequest {
        X86IoPort = 0,
        Mmio = 1,
    }

    let current = Task::current().unwrap();

    let cptr = CapPtr(invocation.args[0] as u64);

    let requested_cap = match RootTaskCapRequest::try_from(invocation.args[1] as u32) {
        Ok(x) => x,
        Err(_) => return Err(KernelError::InvalidArgument),
    };
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

fn invoke_cap_x86_io_port(invocation: CapabilityInvocation, port: u16) -> KernelResult<i64> {
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

fn invoke_cap_vmap(invocation: CapabilityInvocation, vmap: &CapVmap) -> KernelResult<i64> {
    let target_vaddr = VirtAddr::new(invocation.args[0] as u64);
    let user_page = VirtAddr::new(invocation.args[1] as u64);

    vmap.page_table
        .with(|pt| crate::task::retype_page_table_from_user(pt, target_vaddr, user_page))
        .map(|x| x as i64)
}

fn invoke_cap_mmio(invocation: CapabilityInvocation, mmio: &CapMmio) -> KernelResult<i64> {
    let target_vaddr = VirtAddr::new(invocation.args[0] as u64);

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
