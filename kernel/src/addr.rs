use crate::arch::{
    arch_translate_phys_mapped_virt, arch_validate_virtual_address, PAGE_SIZE, PAGE_SIZE_BITS,
    PAGE_TABLE_SIZE,
};
use crate::error::*;
use crate::multilevel::NullEntryFilter;
use crate::pagealloc::PHYSICAL_PAGE_METADATA_BASE;
use crate::paging::{PageTableMto, PageTableObject};
use core::ptr::NonNull;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct PhysAddr(pub u64);

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct VirtAddr(pub u64);

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct UserAddr(u64);

impl VirtAddr {
    #[inline]
    pub fn from_nonnull<T>(x: NonNull<T>) -> VirtAddr {
        VirtAddr(x.as_ptr() as u64)
    }

    #[inline]
    pub fn from_ptr<T>(x: *const T) -> VirtAddr {
        VirtAddr(x as u64)
    }

    #[inline]
    pub fn from_phys(phys: PhysAddr) -> VirtAddr {
        VirtAddr(unsafe { crate::paging::PHYSICAL_OFFSET } + phys.0)
    }

    #[inline]
    pub fn from_ref<T>(x: &T) -> VirtAddr {
        VirtAddr(x as *const T as u64)
    }

    #[inline]
    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    #[inline]
    pub fn as_nonnull<T>(&self) -> Option<NonNull<T>> {
        NonNull::new(self.0 as *mut T)
    }
}

impl PhysAddr {
    #[inline]
    pub fn from_phys_mapped_virt(virt: VirtAddr) -> KernelResult<PhysAddr> {
        arch_translate_phys_mapped_virt(virt)
    }

    pub fn from_virt_null_filter(pt: &PageTableObject, virt: VirtAddr) -> KernelResult<PhysAddr> {
        Ok(pt
            .0
            .lookup_leaf_entry_with_filter::<NullEntryFilter, _, _>(virt.0, |entry| {
                if entry.is_unused() {
                    None
                } else {
                    Some(entry.addr())
                }
            })??)
    }

    pub fn page_id(&self) -> u64 {
        self.0 >> PAGE_SIZE_BITS
    }

    pub fn page_metadata(&self) -> VirtAddr {
        // 8 bytes
        VirtAddr(
            PHYSICAL_PAGE_METADATA_BASE
                .checked_add(self.page_id() << 3)
                .expect("PhysAddr::metadata_vaddr: Add overflow. Invalid physical address?"),
        )
    }
}

impl UserAddr {
    pub fn new(value: u64) -> KernelResult<Self> {
        let result = unsafe { Self::new_unchecked(value) };
        result.validate()?;
        Ok(result)
    }

    pub unsafe fn new_unchecked(value: u64) -> Self {
        UserAddr(value)
    }

    pub fn get(&self) -> u64 {
        self.0
    }

    pub fn validate(&self) -> KernelResult<()> {
        arch_validate_virtual_address(self.0)?;

        if PageTableMto::ptr_to_index(self.0, 0) >= PAGE_TABLE_SIZE / 2 {
            Err(KernelError::InvalidAddress)
        } else {
            Ok(())
        }
    }

    pub fn check_page_alignment(&self) -> KernelResult<()> {
        if align_down(self.0, PAGE_SIZE as u64) != self.0 {
            Err(KernelError::InvalidAddress)
        } else {
            Ok(())
        }
    }
}

fn align_down(addr: u64, align: u64) -> u64 {
    assert!(align.is_power_of_two(), "`align` must be a power of two");
    addr & !(align - 1)
}
