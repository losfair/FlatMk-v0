use crate::serial::with_serial_port;
use crate::task::Retype;
use core::cell::{Cell, UnsafeCell};
use core::convert::TryFrom;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};
use num_enum::TryFromPrimitive;
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

pub const N_CAPSET_SLOTS: usize = 128;

#[repr(C)]
pub struct Capability {
    pub object: *const Opaque,
    pub vtable: *const VTable<Opaque>,
    pub rights: Rights,
}

#[repr(C)]
pub struct Opaque {
    _unsafe_do_not_use: u64,
}

impl Opaque {
    pub unsafe fn typed<T>(&self) -> &T {
        core::mem::transmute(self)
    }

    pub unsafe fn typed_mut<T>(&mut self) -> &mut T {
        core::mem::transmute(self)
    }
}

/// VTable for an object.
/// T must not be a DST or ZST.
pub struct VTable<T> {
    pub drop: Option<unsafe fn(*mut T)>,
    pub lookup_capability: Option<unsafe fn(&T, cptr: u64) -> Option<&Capability>>,
    pub entry_capability: Option<unsafe fn(&T, cptr: u64) -> Option<*mut Capability>>,
    pub call: Option<unsafe fn(&T, i64, i64, i64, i64) -> i64>,
    pub call_async: Option<unsafe fn(&T, i64, i64, i64, i64) -> Result<(), i64>>,
}

impl<T> VTable<T> {
    pub const fn const_default() -> VTable<T> {
        VTable {
            drop: None,
            lookup_capability: None,
            entry_capability: None,
            call: None,
            call_async: None,
        }
    }
}

impl Default for Capability {
    fn default() -> Capability {
        unsafe { core::mem::zeroed() }
    }
}

impl Drop for Capability {
    fn drop(&mut self) {
        if self.object.is_null() {
            return;
        }
        unsafe {
            if !self.vtable.is_null() {
                if let Some(f) = (*self.vtable).drop {
                    f(self.object as *mut _);
                }
            }
        }
    }
}

// Object types.

/// Nested capability set.
#[repr(C, align(4096))]
pub struct CapabilitySet {
    pub capabilities: UnsafeCell<[Capability; N_CAPSET_SLOTS]>,
}

impl Default for CapabilitySet {
    fn default() -> CapabilitySet {
        assert!(core::mem::size_of::<CapabilitySet>() <= 4096);
        unsafe { core::mem::zeroed() }
    }
}

impl CapabilitySet {
    pub fn vtable() -> &'static VTable<CapabilitySet> {
        static VT: VTable<CapabilitySet> = VTable {
            drop: Some(capability_set_drop),
            lookup_capability: Some(capability_set_lookup_capability),
            entry_capability: Some(capability_set_entry_capability),
            ..VTable::const_default()
        };
        &VT
    }

    pub fn init_for_root_task(&self) {
        unsafe {
            let caps = &mut *self.capabilities.get();
            caps[0].vtable = CapRootTask::vtable() as *const _ as *const VTable<Opaque>;
            caps[0].rights = Rights::DEFAULT;
        }
    }

    pub fn lookup_capability(&self, mut cptr: u64) -> Option<&Capability> {
        unsafe {
            let index = cptr & 255;
            cptr >>= 8;
            if index >= N_CAPSET_SLOTS as u64 {
                return None;
            }
            let child = &(*self.capabilities.get())[index as usize];
            if !child.vtable.is_null() {
                if let Some(f) = (*child.vtable).lookup_capability {
                    f(&*child.object, cptr)
                } else {
                    Some(child)
                }
            } else {
                None
            }
        }
    }

    pub unsafe fn entry_capability(&self, mut cptr: u64) -> Option<*mut Capability> {
        let index = cptr & 255;
        cptr >>= 8;
        if index >= N_CAPSET_SLOTS as u64 {
            return None;
        }
        let child = &mut (*self.capabilities.get())[index as usize];
        if !child.vtable.is_null() {
            if let Some(f) = (*child.vtable).entry_capability {
                f(&*child.object, cptr)
            } else {
                Some(child as *mut _)
            }
        } else {
            Some(child as *mut _)
        }
    }
}

unsafe fn capability_set_drop(obj: *mut CapabilitySet) {
    core::ptr::drop_in_place(&mut *obj);
}

unsafe fn capability_set_lookup_capability(obj: &CapabilitySet, cptr: u64) -> Option<&Capability> {
    obj.lookup_capability(cptr)
}

unsafe fn capability_set_entry_capability(
    obj: &CapabilitySet,
    cptr: u64,
) -> Option<*mut Capability> {
    obj.entry_capability(cptr)
}

/// Root task capability generator.
pub struct CapRootTask {
    _unused: u64,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, TryFromPrimitive)]
pub enum RootTaskCapRequest {
    AnyX86IoPort = 0,
    LocalMap = 1,
    LocalMmio = 2,
}

impl CapRootTask {
    pub fn vtable() -> &'static VTable<CapRootTask> {
        static VT: VTable<CapRootTask> = VTable {
            call: Some(CapRootTask::call),
            ..VTable::const_default()
        };
        &VT
    }

    unsafe fn call(obj: &CapRootTask, p0: i64, p1: i64, p2: i64, _p3: i64) -> i64 {
        let task = crate::task::get_current_task().unwrap();
        let caps = &(*task.as_ref().capabilities);

        let cap_slot = match caps.entry_capability(p0 as u64) {
            Some(x) => x,
            None => return -1,
        };
        let requested_cap = match RootTaskCapRequest::try_from(p1 as u32) {
            Ok(x) => x,
            Err(_) => return -1,
        };
        match requested_cap {
            RootTaskCapRequest::AnyX86IoPort => {
                let target_cap: *mut CapAnyX86IoPort = match crate::task::retype_user(
                    crate::paging::active_level_4_table(),
                    VirtAddr::new(p2 as u64),
                ) {
                    Some(x) => x,
                    None => return -1,
                };
                *cap_slot = Capability {
                    object: target_cap as *const Opaque,
                    vtable: CapAnyX86IoPort::vtable() as *const _ as *const VTable<Opaque>,
                    rights: Rights::DEFAULT,
                };
                0
            }
            RootTaskCapRequest::LocalMap => {
                *cap_slot = Capability {
                    object: core::ptr::null(),
                    vtable: CapLocalMap::vtable() as *const _ as *const VTable<Opaque>,
                    rights: Rights::DEFAULT,
                };
                0
            }
            RootTaskCapRequest::LocalMmio => {
                let target_cap: *mut CapLocalMmio = match crate::task::retype_user(
                    crate::paging::active_level_4_table(),
                    VirtAddr::new(p2 as u64),
                ) {
                    Some(x) => x,
                    None => return -1,
                };
                (*target_cap).make_root();
                *cap_slot = Capability {
                    object: target_cap as *const Opaque,
                    vtable: CapLocalMmio::vtable() as *const _ as *const VTable<Opaque>,
                    rights: Rights::DEFAULT,
                };
                0
            }
        }
    }
}

pub struct CapLocalMap {
    _unused: u64,
}

impl CapLocalMap {
    pub fn vtable() -> &'static VTable<CapLocalMap> {
        static VT: VTable<CapLocalMap> = VTable {
            call: Some(CapLocalMap::call),
            ..VTable::const_default()
        };
        &VT
    }

    unsafe fn call(obj: &CapLocalMap, p0: i64, p1: i64, _p2: i64, _p3: i64) -> i64 {
        let target_vaddr = VirtAddr::new(p0 as u64);
        let user_page = VirtAddr::new(p1 as u64);
        match crate::task::retype_page_table_from_user(
            crate::paging::active_level_4_table(),
            target_vaddr,
            user_page,
        ) {
            Some(x) => x as i64,
            None => -1,
        }
    }
}

pub struct CapLocalMmio {
    n_pages: usize,
    pages: [PhysAddr; 500],
}

impl Retype for CapLocalMmio {
    unsafe fn retype_in_place(&mut self) -> bool {
        core::ptr::write(self, core::mem::zeroed());
        true
    }
}

impl CapLocalMmio {
    pub fn vtable() -> &'static VTable<CapLocalMmio> {
        assert!(core::mem::size_of::<Self>() <= 4096);

        static VT: VTable<CapLocalMmio> = VTable {
            call: Some(CapLocalMmio::call),
            ..VTable::const_default()
        };
        &VT
    }

    fn make_root(&mut self) {
        static PAGES: &'static [u64] = &[
            0xb8000, // VGA
        ];
        self.n_pages = PAGES.len();
        for i in 0..PAGES.len() {
            self.pages[i] = PhysAddr::new(PAGES[i]);
        }
    }

    unsafe fn call(obj: &CapLocalMmio, p0: i64, p1: i64, _p2: i64, _p3: i64) -> i64 {
        let target_vaddr = VirtAddr::new(p0 as u64);
        let phys_addr = PhysAddr::new(p1 as u64);

        let mut ok = false;
        for i in 0..obj.n_pages {
            if obj.pages[i] == phys_addr {
                ok = true;
                break;
            }
        }
        if !ok {
            return -1;
        }

        match crate::task::map_physical_page_into_user(
            crate::paging::active_level_4_table(),
            target_vaddr,
            phys_addr,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::NO_CACHE,
        ) {
            true => {
                tlb::flush(target_vaddr);
                0
            }
            false => -1,
        }
    }
}

/// Capability to request any I/O ports.
pub struct CapAnyX86IoPort {
    ports: [UnsafeCell<CapX86IoPort>; 1024],
    next: Cell<usize>,
}

impl Retype for CapAnyX86IoPort {
    unsafe fn retype_in_place(&mut self) -> bool {
        core::ptr::write(self, core::mem::zeroed());
        true
    }
}

impl CapAnyX86IoPort {
    pub fn vtable() -> &'static VTable<CapAnyX86IoPort> {
        static VT: VTable<CapAnyX86IoPort> = VTable {
            call: Some(CapAnyX86IoPort::call),
            ..VTable::const_default()
        };
        &VT
    }

    unsafe fn call(obj: &CapAnyX86IoPort, p0: i64, p1: i64, _p2: i64, _p3: i64) -> i64 {
        if obj.next.get() == obj.ports.len() {
            return -1;
        }

        let task = crate::task::get_current_task().unwrap();
        let caps = &(*task.as_ref().capabilities);

        let cap_slot = match caps.entry_capability(p0 as u64) {
            Some(x) => x,
            None => return -1,
        };
        let port = p1 as u16;

        let index = obj.next.get();
        obj.next.set(index + 1);
        (*obj.ports[index].get()).which = port;
        *cap_slot = Capability {
            object: obj.ports[index].get() as *const Opaque,
            vtable: CapX86IoPort::vtable() as *const _ as *const VTable<Opaque>,
            rights: Rights::DEFAULT,
        };
        0
    }
}

/// Capability to an I/O port.\
#[repr(transparent)]
pub struct CapX86IoPort {
    pub which: u16,
}

impl CapX86IoPort {
    pub fn vtable() -> &'static VTable<CapX86IoPort> {
        static VT: VTable<CapX86IoPort> = VTable {
            call: Some(CapX86IoPort::call),
            ..VTable::const_default()
        };
        &VT
    }

    unsafe fn call(me: &CapX86IoPort, p0: i64, p1: i64, p2: i64, p3: i64) -> i64 {
        use x86::io;
        if p0 == 0 {
            // read
            match p1 {
                1 => io::inb(me.which) as i64,
                2 => io::inw(me.which) as i64,
                4 => io::inl(me.which) as i64,
                _ => -1,
            }
        } else if p0 == 1 {
            match p1 {
                1 => io::outb(me.which, p2 as u8),
                2 => io::outw(me.which, p2 as u16),
                4 => io::outl(me.which, p2 as u32),
                _ => return -1,
            }
            0
        } else {
            -1
        }
    }
}
