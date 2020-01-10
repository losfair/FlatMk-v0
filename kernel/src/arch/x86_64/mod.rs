mod addr;
pub mod config;
mod exception;
mod init;
mod page_table;
pub mod task;
pub mod tlb;
mod asm_import;
mod apic;
pub mod softuser;

pub use addr::*;
pub use init::*;
pub use page_table::*;
pub use exception::arch_handle_interrupt;

global_asm!(include_str!("asm.s"));

pub fn arch_cpu_relax_long() {
    unsafe {
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
        asm!("pause" :::: "volatile");
    }
}