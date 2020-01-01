//! Paging-related types and methods.

use crate::error::*;

use crate::addr::*;
use crate::arch::tlb;
use crate::arch::{
    arch_get_current_page_table, Page, PageTableEntry, PAGE_SIZE, PAGE_TABLE_INDEX_START,
    PAGE_TABLE_LEVELS, PAGE_TABLE_LEVEL_BITS, PAGE_TABLE_SIZE,
};
use crate::multilevel::*;
use crate::pagealloc::*;
use bootloader::bootinfo::MemoryRegionType;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use crate::spec::UserPteFlags;

pub(crate) static mut PHYSICAL_OFFSET: u64 = 0;

pub struct PageTableEntryFilter;
impl EntryFilter for PageTableEntryFilter {
    #[inline]
    fn is_valid(depth: u8, index: usize) -> bool {
        if depth == 0 && index >= 256 {
            false
        } else {
            true
        }
    }
}

// Alignment comes from Page.
pub type PageTableMto = MultilevelTableObject<
    Page,
    PageTableEntry,
    GenericLeafCache,
    PageTableEntryFilter,
    PAGE_TABLE_LEVEL_BITS,
    PAGE_TABLE_LEVELS,
    PAGE_TABLE_INDEX_START,
    PAGE_TABLE_SIZE,
>;
pub type PageTableLevel = Level<Page, PageTableEntry, PAGE_TABLE_SIZE>;

pub struct PageTableObject(pub PageTableMto);

fn iter_physical_pages() -> impl Iterator<Item = PhysAddr> {
    crate::boot::boot_info()
        .memory_map
        .iter()
        .filter_map(|x| match x.region_type {
            MemoryRegionType::Usable | MemoryRegionType::Bootloader => Some(
                (x.range.start_addr()..x.range.end_addr())
                    .step_by(PAGE_SIZE as _)
                    .map(|x| PhysAddr(x)),
            ),
            _ => None,
        })
        .flatten()
}

/// Populates metadata (only refcounts for now).
unsafe fn populate_physical_mem_metadata(remaining: &mut impl Iterator<Item = PhysAddr>) {
    let l4_table = &mut *_active_level_4_table();
    let all_phys = iter_physical_pages();
    for page in all_phys {
        let md_vaddr = page.page_metadata();

        while l4_table
            .lookup_entry::<NullEntryFilter, _, _>(
                md_vaddr.0,
                PAGE_TABLE_LEVELS,
                PAGE_TABLE_INDEX_START,
                PAGE_TABLE_LEVEL_BITS,
                |depth, entry| {
                    if depth == PAGE_TABLE_LEVELS - 1 && !entry.is_unused() {
                        false
                    } else {
                        let frame = remaining
                            .next()
                            .expect("populate_physical_mem_metadata: No physical memory left.");
                        let page: *mut Page = VirtAddr::from_phys(frame).as_mut_ptr();
                        core::ptr::write(page, core::mem::zeroed());
                        entry.set_addr_rwxk(frame);
                        true
                    }
                },
            )
            .expect("populate_physical_mem_metadata: lookup_entry failed. Incorrect filter?")
        {
        }
    }
    tlb::flush_all();
}

unsafe fn populate_available_pages() {
    let mut phys_iterator = iter_physical_pages();
    populate_physical_mem_metadata(&mut phys_iterator);

    let mut next: usize = 0;
    for addr in phys_iterator {
        if next == 0 {
            init_clear_and_push_alloc_frame(VirtAddr::from_phys(addr).as_nonnull().unwrap());
        } else {
            init_push_physical_page(addr);
        }
        // Each group consists of one `AllocFrame` + `PAGES_PER_ALLOC_FRAME` normal pages.
        if next + 1 == 1 + PAGES_PER_ALLOC_FRAME {
            next = 0;
        } else {
            next += 1;
        }
    }
}

pub unsafe fn init() {
    PHYSICAL_OFFSET = crate::boot::boot_info().physical_memory_offset as _;
    let l4_table = &mut *_active_level_4_table();

    // Invalidate non-kernel memory mappings.
    {
        // Save the physical address of BootInfo structure.
        let boot_info_kvaddr = l4_table
            .lookup::<NullEntryFilter, _, _>(
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

    populate_available_pages();
}

impl PageTableObject {
    // FIXME: Fix this when we add multicore support.
    pub fn is_current(&self) -> bool {
        self.0.with_root(|root| {
            // Multiple mutable aliases?
            let cell = UnsafeCell::new(root as *mut PageTableLevel);
            unsafe { *cell.get() == _active_level_4_table() }
        })
    }

    pub fn flush_tlb_if_current(&self, target: UserAddr) {
        if self.is_current() {
            tlb::flush(target);
        }
    }

    pub fn flush_tlb_assume_current(&self, target: UserAddr) {
        tlb::flush(target);
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

    pub fn copy_kernel_range_from(&self, src: &PageTableObject) {
        src.0
            .with_root(|root| unsafe { self.copy_kernel_range_from_level(root) })
    }

    pub fn make_leaf_entry(&self, target: UserAddr) -> KernelResult<()> {
        target.check_page_alignment()?;
        self.0.make_leaf_entry(target.get())
    }

    pub fn map_anonymous(&self, target: UserAddr, prot: UserPteFlags) -> KernelResult<()> {
        target.check_page_alignment()?;
        let mut page: MaybeUninit<KernelPageRef<Page>> = KernelPageRef::new_uninit()?;
        for b in unsafe { (*page.as_mut_ptr()).0.iter_mut() } {
            *b = 0;
        }
        self.0
            .attach_leaf(target.get(), unsafe { page.assume_init() })?;
        self.0.lookup_leaf_entry(target.get(), |entry| {
            entry.set_protection(prot);
        })?;
        self.flush_tlb_if_current(target);
        Ok(())
    }

    pub unsafe fn map_physical_page(
        &self,
        target: UserAddr,
        backing: PhysAddr,
        prot: UserPteFlags,
    ) -> KernelResult<()> {
        target.check_page_alignment()?;
        self.0.lookup_leaf_entry(target.get(), |entry| {
            if let Some(mut old) = entry.as_level() {
                old.as_mut().drop_and_release_assuming_leaf();
            }
            entry.set_addr_ronxu(backing);
            entry.set_no_cache(true);
            entry.set_unowned(true); // Direct physical page mappings are always unowned.
            entry.set_protection(prot);
        })?;
        self.flush_tlb_if_current(target);
        Ok(())
    }
}

/// Using the return value from this function is very unsafe because
/// it is almost always mutably aliased.
pub(crate) fn _active_level_4_table() -> *mut PageTableLevel {
    unsafe { VirtAddr(PHYSICAL_OFFSET + arch_get_current_page_table().0 as u64).as_mut_ptr() }
}
