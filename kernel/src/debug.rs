use crate::serial::with_serial_port;
use core::fmt::Write;
use x86_64::structures::paging::page_table::{PageTable, PageTableEntry};

/// The caller needs to ensure that the PageTable is a valid Level 4 page table.
pub unsafe fn print_l4_page_table(pt: &PageTable) {
    for (i, entry) in pt.iter().enumerate().take(256) {
        if !entry.is_unused() {
            with_serial_port(|p| writeln!(p, "L4 user entry used: {} {:#?}", i, entry).unwrap());
            for (i, entry) in (*crate::paging::phys_to_virt(entry.addr()).as_ptr::<PageTable>())
                .iter()
                .enumerate()
            {
                if !entry.is_unused() {
                    with_serial_port(|p| {
                        writeln!(p, "  L3 user entry used: {} {:#?}", i, entry).unwrap()
                    });
                    /*for (i, entry) in (*crate::paging::phys_to_virt(entry.addr()).as_ptr::<PageTable>()).iter().enumerate() {
                        if !entry.is_unused() {
                            with_serial_port(|p| writeln!(p, "    L2 user entry used: {} {:#?}", i, entry).unwrap());
                        }
                    }*/
                }
            }
        }
    }
}
