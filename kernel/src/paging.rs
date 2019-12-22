//! Paging-related types and methods.

use crate::error::*;
use crate::kobj::*;

use crate::addr::*;
use crate::arch::tlb;
use crate::arch::{
    arch_get_current_page_table, Page, PageTableEntry, PAGE_TABLE_INDEX_START, PAGE_TABLE_LEVELS,
    PAGE_TABLE_LEVEL_BITS, PAGE_TABLE_SIZE,
};
use crate::multilevel::*;

pub(crate) static mut PHYSICAL_OFFSET: u64 = 0;

// Alignment comes from Page.
pub type PageTableMto = MultilevelTableObject<
    Page,
    PageTableEntry,
    GenericLeafCache,
    PAGE_TABLE_LEVEL_BITS,
    PAGE_TABLE_LEVELS,
    PAGE_TABLE_INDEX_START,
    PAGE_TABLE_SIZE,
>;
pub type PageTableLevel = Level<Page, PageTableEntry, PAGE_TABLE_SIZE>;

pub struct PageTableObject(pub PageTableMto);

impl Notify for PageTableObject {
    unsafe fn will_drop(&mut self, owner: &dyn LikeKernelObject) {
        self.0.will_drop(owner);
    }

    unsafe fn return_user_page(&self, addr: UserAddr) {
        drop(self.put_to_user(addr));
    }
}

pub unsafe fn init() {
    PHYSICAL_OFFSET = crate::boot::boot_info().physical_memory_offset as _;
    let l4_table = &mut *_active_level_4_table();

    // Invalidate non-kernel memory mappings.
    {
        // Save the physical address of BootInfo structure.
        let boot_info_kvaddr = l4_table
            .lookup(
                crate::boot::boot_info() as *const _ as u64,
                PAGE_TABLE_LEVELS,
                PAGE_TABLE_INDEX_START,
                PAGE_TABLE_LEVEL_BITS,
                |entry| VirtAddr::from_ref(entry),
            )
            .expect("cannot get boot info entry");

        // Invalidate and flush.
        for entry in l4_table.table[0..256].iter_mut() {
            if !entry.is_unused() {
                entry.set_unused();
            }
        }
        tlb::flush_all();

        // Update boot info virtual address.
        crate::boot::set_boot_info(&*boot_info_kvaddr.as_mut_ptr());
    }
}

impl PageTableObject {
    pub fn take_from_user(&self, addr: UserAddr) -> KernelResult<VirtAddr> {
        addr.validate()?;
        addr.check_page_alignment()?;

        Ok(self.0.lookup_leaf_entry(addr.0, |entry| {
            match entry.as_level() {
                Some(x) => {
                    if !entry.is_user_accessible() {
                        return Err(KernelError::InvalidState);
                    }
                    entry.set_user_accessible(false);
                    tlb::flush(addr); // TODO: Fix when we add multicore support.
                    Ok(VirtAddr::from_nonnull(x))
                }
                None => Err(KernelError::InvalidAddress),
            }
        })??)
    }

    pub fn put_to_user(&self, addr: UserAddr) -> KernelResult<()> {
        addr.validate()?;
        addr.check_page_alignment()?;

        Ok(self.0.lookup_leaf_entry(addr.0, |entry| {
            if entry.is_unused() {
                Err(KernelError::EmptyObject)
            } else {
                entry.set_user_accessible(true);
                tlb::flush(addr); // TODO: Fix when we add multicore support.
                Ok(())
            }
        })??)
    }

    pub unsafe fn copy_kernel_range_from_level(&self, src: &PageTableLevel) {
        self.0.with_root(|this| {
            for (i, entry) in src
                .table
                .iter()
                .enumerate()
                .skip((PAGE_TABLE_SIZE / 2) as usize)
            {
                this.table[i] = entry.clone();
            }
        })
    }

    pub fn build_from_user(
        &self,
        target: UserAddr,
        backing_owner: KernelObjectRef<PageTableObject>,
        backing: UserAddr,
    ) -> KernelResult<bool> {
        target.validate()?;
        target.check_page_alignment()?;

        self.0.build_from_user(target.0, backing_owner, backing)
    }

    pub unsafe fn map_physical_page_for_user(
        &self,
        target: UserAddr,
        backing: PhysAddr,
    ) -> KernelResult<()> {
        target.validate()?;
        target.check_page_alignment()?;

        self.0.lookup_leaf_entry(target.0, |entry| {
            entry.set_addr_rw(backing);
            entry.set_user_accessible(true);
            entry.set_no_cache(true);
        })?;
        Ok(())
    }
}

/// Using the return value from this function is very unsafe because
/// it is almost always mutably aliased.
pub(crate) fn _active_level_4_table() -> *mut PageTableLevel {
    unsafe { VirtAddr(PHYSICAL_OFFSET + arch_get_current_page_table().0 as u64).as_mut_ptr() }
}
