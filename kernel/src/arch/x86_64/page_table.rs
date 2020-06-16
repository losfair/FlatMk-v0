use crate::addr::*;
use crate::error::*;
use crate::multilevel::*;
use super::task::Pcid2pto;
use core::fmt;
use core::ptr::NonNull;
use crate::spec::UserPteFlags;

#[repr(align(4096))]
#[derive(Clone)]
pub struct Page(pub [u8; PAGE_SIZE]);

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_BITS: usize = 12;
pub const PAGE_TABLE_LEVEL_BITS: u8 = 9;
pub const PAGE_TABLE_LEVELS: u8 = 4;
pub const PAGE_TABLE_INDEX_START: u8 = 47;
pub const PAGE_TABLE_SIZE: usize = 512;
pub const MIN_PCID: u64 = 1;
pub const MAX_PCID: u64 = 4095;

bitflags! {
    /// Taken from https://docs.rs/x86_64/0.8.2/src/x86_64/structures/paging/page_table.rs.html .
    ///
    /// Possible flags for a page table entry.
    pub struct PageTableFlags: u64 {
        /// Specifies whether the mapped frame or page table is loaded in memory.
        const PRESENT =         1 << 0;
        /// Controls whether writes to the mapped frames are allowed.
        ///
        /// If this bit is unset in a level 1 page table entry, the mapped frame is read-only.
        /// If this bit is unset in a higher level page table entry the complete range of mapped
        /// pages is read-only.
        const WRITABLE =        1 << 1;
        /// Controls whether accesses from userspace (i.e. ring 3) are permitted.
        const USER_ACCESSIBLE = 1 << 2;
        /// If this bit is set, a “write-through” policy is used for the cache, else a “write-back”
        /// policy is used.
        const WRITE_THROUGH =   1 << 3;
        /// Disables caching for the pointed entry is cacheable.
        const NO_CACHE =        1 << 4;
        /// Set by the CPU when the mapped frame or page table is accessed.
        const ACCESSED =        1 << 5;
        /// Set by the CPU on a write to the mapped frame.
        const DIRTY =           1 << 6;
        /// Specifies that the entry maps a huge frame instead of a page table. Only allowed in
        /// P2 or P3 tables.
        const HUGE_PAGE =       1 << 7;
        /// Indicates that the mapping is present in all address spaces, so it isn't flushed from
        /// the TLB on an address space switch.
        const GLOBAL =          1 << 8;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_9 =           1 << 9;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_10 =          1 << 10;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_11 =          1 << 11;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_52 =          1 << 52;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_53 =          1 << 53;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_54 =          1 << 54;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_55 =          1 << 55;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_56 =          1 << 56;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_57 =          1 << 57;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_58 =          1 << 58;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_59 =          1 << 59;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_60 =          1 << 60;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_61 =          1 << 61;
        /// Available to the OS, can be used to store additional data, e.g. custom flags.
        const BIT_62 =          1 << 62;
        /// Forbid code execution from the mapped frames.
        ///
        /// Can be only used when the no-execute page protection feature is enabled in the EFER
        /// register.
        const NO_EXECUTE =      1 << 63;
    }
}

const PTE_UNOWNED: PageTableFlags = PageTableFlags::BIT_9;

/// Partially taken from https://docs.rs/x86_64/0.8.2/src/x86_64/structures/paging/page_table.rs.html .
///
/// A 64-bit page table entry.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct PageTableEntry {
    entry: u64,
}

impl PageTableEntry {
    /// Creates an unused page table entry.
    pub const fn new() -> Self {
        PageTableEntry { entry: 0 }
    }

    /// Returns whether this entry is zero.
    pub fn is_unused(&self) -> bool {
        self.entry == 0
    }

    /// Sets this entry to zero.
    pub fn set_unused(&mut self) {
        self.entry = 0;
    }

    /// Returns the flags of this entry.
    pub fn flags(&self) -> PageTableFlags {
        PageTableFlags::from_bits_truncate(self.entry)
    }

    /// Returns the physical address mapped by this entry, might be zero.
    pub fn addr(&self) -> PhysAddr {
        PhysAddr(self.entry & 0x000fffff_fffff000)
    }

    /// Map the entry to the specified physical address with the specified flags.
    pub fn set_addr(&mut self, addr: PhysAddr, flags: PageTableFlags) {
        self.entry = (addr.0) | flags.bits();
    }

    /// Sets the flags of this entry.
    pub fn set_flags(&mut self, flags: PageTableFlags) {
        self.entry = self.addr().0 | flags.bits();
    }

    pub fn set_addr_rwxu(&mut self, addr: PhysAddr) {
        self.set_addr(
            addr,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );
    }

    pub fn set_addr_ronxu(&mut self, addr: PhysAddr) {
        self.set_addr(
            addr,
            PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE | PageTableFlags::USER_ACCESSIBLE,
        );
    }

    pub fn set_addr_rwxk(&mut self, addr: PhysAddr) {
        self.set_addr(addr, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
    }

    pub fn set_protection(&mut self, user_flags: UserPteFlags) {
        let mut flags = self.flags();
        flags.set(PageTableFlags::WRITABLE, user_flags.contains(UserPteFlags::WRITABLE));
        flags.set(PageTableFlags::NO_EXECUTE, !user_flags.contains(UserPteFlags::EXECUTABLE));
        self.set_flags(flags);
    }

    fn test_flag(&self, flag: PageTableFlags) -> bool {
        if (self.flags() & flag).is_empty() {
            false
        } else {
            true
        }
    }

    fn toggle_flag(&mut self, flag: PageTableFlags, new_state: bool) {
        let mut current_flags = self.flags();
        if new_state {
            current_flags |= flag;
        } else {
            current_flags &= !flag;
        }
        self.set_flags(current_flags);
    }

    pub fn is_huge_page(&self) -> bool {
        self.test_flag(PageTableFlags::HUGE_PAGE)
    }

    pub fn set_no_cache(&mut self, no_cache: bool) {
        self.toggle_flag(PageTableFlags::NO_CACHE, no_cache);
    }

    pub fn set_unowned(&mut self, unowned: bool) {
        self.toggle_flag(PTE_UNOWNED, unowned);
    }

    pub fn set_global(&mut self, global: bool) {
        self.toggle_flag(PageTableFlags::GLOBAL, global);
    }

    pub fn is_unowned(&mut self) -> bool {
        self.test_flag(PTE_UNOWNED)
    }
}

impl fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut f = f.debug_struct("PageTableEntry");
        f.field("addr", &self.addr());
        f.field("flags", &self.flags());
        f.finish()
    }
}

impl Default for PageTableEntry {
    fn default() -> Self {
        PageTableEntry::new()
    }
}

impl AsLevel<Page, 512> for PageTableEntry {
    fn as_level(&mut self) -> Option<NonNull<Level<Page, PageTableEntry, 512>>> {
        // We don't yet support dereferencing huge pages.
        if self.is_huge_page() {
            return None;
        }

        // Prevent dereferencing or dropping the underlying physical page if this pte is unowned.
        // (e.g. MMIO)
        if self.is_unowned() {
            return None;
        }

        if self.is_unused() {
            None
        } else {
            VirtAddr::from_phys(self.addr()).as_nonnull::<Level<Page, PageTableEntry, 512>>()
        }
    }

    fn attach_level(&mut self, level: NonNull<Level<Page, PageTableEntry, 512>>, leaf: bool) {
        let addr = PhysAddr::from_phys_mapped_virt(VirtAddr::from_nonnull(level))
            .expect("PageTableEntry::attach_level: Invalid level pointer");
        if leaf {
            self.set_addr_ronxu(addr);
        } else {
            self.set_addr_rwxu(addr);
        }
    }

    fn clear_level(&mut self) {
        self.set_unused();
    }
}

pub unsafe fn arch_set_current_page_table_with_pcid(addr: PhysAddr, _pcid: u64) {
    let addr = addr.0 & !0xfffu64;
    #[cfg(feature = "x86_pcid")]
    {
        let pcid = _pcid & 0xfffu64;
        let value = addr | pcid | (1u64 << 63);
        llvm_asm!("mov $0, %cr3" :: "r" (value) : "memory");
    }
    #[cfg(not(feature = "x86_pcid"))]
    {
        llvm_asm!("mov $0, %cr3" :: "r" (addr) : "memory");
    }
}

pub fn arch_get_current_page_table_with_pcid() -> (PhysAddr, u64) {
    let value: u64;
    unsafe {
        llvm_asm!("mov %cr3, $0" : "=r" (value));
    }
    (
        PhysAddr(value & !0xfffu64 & !(1u64 << 63)),
        value & 0xfffu64
    )
}

#[cfg(feature = "x86_pcid")]
pub unsafe fn arch_with_pcid_array<F: FnOnce(Option<&mut Pcid2pto>) -> R, R>(f: F) -> R {
    f(Some(&mut (*super::task::get_indirect_tls()).pcid2pto))
}

#[cfg(not(feature = "x86_pcid"))]
pub unsafe fn arch_with_pcid_array<F: FnOnce(Option<&mut Pcid2pto>) -> R, R>(f: F) -> R {
    f(None)
}

#[cfg(feature = "x86_pcid")]
pub unsafe fn arch_flush_pcid(pcid: u64) {
    let ty: u64 = 1; // single-context invalidation
    let memarg: [u64; 2] = [pcid, 0];
    llvm_asm!(
        "invpcid ($1), $0" :: "r"(ty), "r"(&memarg) : "memory"
    );
}

#[cfg(not(feature = "x86_pcid"))]
pub unsafe fn arch_flush_pcid(_pcid: u64) {
}

#[inline]
pub fn arch_translate_phys_mapped_virt(virt: VirtAddr) -> KernelResult<PhysAddr> {
    const MAP_BEGIN: u64 = 0xFFFF800000000000;
    const MAP_END: u64 = 0xFFFFFF0000000000;
    if virt.0 >= MAP_BEGIN && virt.0 <= MAP_END {
        Ok(PhysAddr(virt.0 - MAP_BEGIN))
    } else {
        Err(KernelError::InvalidAddress)
    }
}
