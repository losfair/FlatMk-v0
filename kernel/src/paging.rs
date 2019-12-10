use crate::serial::with_serial_port;
use bootloader::BootInfo;
use core::fmt::Write;
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

pub unsafe fn init() {
    let (l4pt, _) = Cr3::read();

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
        for (i, entry) in l4_table.iter_mut().enumerate().take(256) {
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

pub fn take_from_user(current: &mut PageTable, addr: VirtAddr) -> Option<VirtAddr> {
    if u16::from(addr.p4_index()) >= 256 {
        return None; // kernel memory
    }

    let mut table = unsafe { OffsetPageTable::new(current, PHYSICAL_OFFSET) };
    let page = match Page::<Size4KiB>::from_start_address(addr) {
        Ok(x) => x,
        _ => return None,
    };
    match table.update_flags(
        page,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
    ) {
        Ok(flusher) => {
            flusher.flush();
            table
                .translate_addr(page.start_address())
                .map(|x| unsafe { PHYSICAL_OFFSET } + x.as_u64())
        }
        Err(_) => None,
    }
}

pub fn put_to_user(current: &mut PageTable, addr: VirtAddr) -> bool {
    if u16::from(addr.p4_index()) >= 256 {
        return false; // kernel memory
    }

    let mut table = unsafe { OffsetPageTable::new(current, PHYSICAL_OFFSET) };
    let page = match Page::<Size4KiB>::from_start_address(addr) {
        Ok(x) => x,
        _ => return false,
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
            true
        }
        Err(_) => false,
    }
}

pub fn virt_to_phys(current: &mut PageTable, addr: VirtAddr) -> Option<PhysAddr> {
    unsafe { OffsetPageTable::new(current, PHYSICAL_OFFSET).translate_addr(addr) }
}

pub fn phys_to_virt(addr: PhysAddr) -> VirtAddr {
    unsafe { PHYSICAL_OFFSET + addr.as_u64() }
}

pub unsafe fn active_level_4_table() -> &'static mut PageTable {
    let (level_4_table_frame, _) = Cr3::read();

    let phys = level_4_table_frame.start_address();
    let virt = PHYSICAL_OFFSET + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table_ptr
}

pub fn make_page_table(current: &mut PageTable, pt: &mut PageTable) {
    for (i, entry) in current.iter().enumerate().skip(256) {
        pt[i] = entry.clone();
    }
}
