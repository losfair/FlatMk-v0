use crate::error::*;
use crate::kobj::*;
use bootloader::BootInfo;
use core::ops::{Deref, DerefMut};
use spin::Mutex;
use x86_64::{
    instructions::tlb,
    registers::control::Cr3,
    structures::paging::{
        mapper::{Mapper, MapperAllSizes},
        page::Size4KiB,
        OffsetPageTable, Page, PageTable, PageTableFlags,
    },
    PhysAddr, VirtAddr,
};

static mut PHYSICAL_OFFSET: VirtAddr = VirtAddr::zero();

#[repr(transparent)]
pub struct RootPageTable(PageTable);

impl Deref for RootPageTable {
    type Target = PageTable;
    fn deref(&self) -> &PageTable {
        &self.0
    }
}

impl DerefMut for RootPageTable {
    fn deref_mut(&mut self) -> &mut PageTable {
        &mut self.0
    }
}

impl RootPageTable {
    /// Unsafe because `inner` must be a root page table.
    pub unsafe fn new(inner: PageTable) -> RootPageTable {
        RootPageTable(inner)
    }
}

/// A root page table object.
pub struct PageTableObject {
    inner: Mutex<&'static mut RootPageTable>,
}

impl Retype for PageTableObject {}
impl Notify for PageTableObject {
    unsafe fn return_user_page(&self, addr: VirtAddr) {
        self.with(|pt| {
            drop(put_to_user(pt, addr));
        })
    }
}

impl PageTableObject {
    /// Creates a PageTableObject from a page-sized PageTable.
    /// This function is unsafe because the caller needs to ensure that `inner` is a root page table.
    pub unsafe fn new(inner: &'static mut RootPageTable) -> PageTableObject {
        PageTableObject {
            inner: Mutex::new(inner),
        }
    }

    pub fn with<T, F: FnOnce(&mut RootPageTable) -> T>(&self, cb: F) -> T {
        let lg = self.inner.lock();
        let inner: &mut RootPageTable = unsafe { core::ptr::read(&*lg) };
        cb(inner)
    }
}

pub unsafe fn init() {
    PHYSICAL_OFFSET = VirtAddr::new(crate::boot::boot_info().physical_memory_offset);
    let l4_table = active_level_4_table();

    // Invalidate non-kernel memory mappings.
    {
        // Save the physical address of BootInfo structure.
        let boot_info_phys_addr = OffsetPageTable::new(l4_table, PHYSICAL_OFFSET)
            .translate_addr(VirtAddr::new(crate::boot::boot_info() as *const _ as u64))
            .expect("cannot translate virtual address for BootInfo")
            .as_u64();

        // Invalidate and flush.
        for entry in l4_table.iter_mut().take(256) {
            if !entry.is_unused() {
                entry.set_unused();
            }
        }
        tlb::flush_all();

        // Update boot info virtual address.
        crate::boot::set_boot_info(
            &*((PHYSICAL_OFFSET.as_u64() + boot_info_phys_addr) as *const BootInfo),
        );
    }
}

/// Takes a page at `addr` from userspace.
pub fn take_from_user(current: &mut RootPageTable, addr: VirtAddr) -> KernelResult<VirtAddr> {
    if u16::from(addr.p4_index()) >= 256 {
        return Err(KernelError::InvalidDelegation);
    }

    let mut table = unsafe { OffsetPageTable::new(&mut **current, PHYSICAL_OFFSET) };
    let page = match Page::<Size4KiB>::from_start_address(addr) {
        Ok(x) => x,
        _ => return Err(KernelError::InvalidDelegation),
    };
    match table.update_flags(
        page,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
    ) {
        Ok(flusher) => {
            flusher.flush();
            match table.translate_addr(page.start_address()) {
                Some(x) => Ok(phys_to_virt(x)),
                None => Err(KernelError::InvalidState),
            }
        }
        Err(_) => Err(KernelError::InvalidState),
    }
}

/// Returns `addr` to userspace.
/// This function is unsafe because userspace will be able to see contents pointed to by `addr`.
pub unsafe fn put_to_user(current: &mut RootPageTable, addr: VirtAddr) -> KernelResult<()> {
    if u16::from(addr.p4_index()) >= 256 {
        return Err(KernelError::InvalidAddress);
    }

    let mut table = OffsetPageTable::new(&mut **current, PHYSICAL_OFFSET);
    let page = match Page::<Size4KiB>::from_start_address(addr) {
        Ok(x) => x,
        _ => return Err(KernelError::InvalidAddress),
    };
    match table.update_flags(
        page,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
    ) {
        Ok(flusher) => {
            flusher.flush();
            Ok(())
        }
        Err(_) => Err(KernelError::InvalidState),
    }
}

pub fn virt_to_phys(current: &mut RootPageTable, addr: VirtAddr) -> KernelResult<PhysAddr> {
    match unsafe { OffsetPageTable::new(&mut **current, PHYSICAL_OFFSET).translate_addr(addr) } {
        Some(x) => Ok(x),
        None => Err(KernelError::InvalidAddress),
    }
}

pub fn phys_to_virt(addr: PhysAddr) -> VirtAddr {
    unsafe { PHYSICAL_OFFSET + addr.as_u64() }
}

/// This function is only intended to be used during early initialization.
pub unsafe fn active_level_4_table() -> &'static mut RootPageTable {
    let (level_4_table_frame, _) = Cr3::read();

    let phys = level_4_table_frame.start_address();
    let virt = PHYSICAL_OFFSET + phys.as_u64();
    let page_table_ptr: *mut RootPageTable = virt.as_mut_ptr();

    &mut *page_table_ptr
}

pub fn make_root_page_table(current: &mut RootPageTable, pt: &mut RootPageTable) {
    for (i, entry) in current.iter().enumerate().skip(256) {
        pt[i] = entry.clone();
    }
}
