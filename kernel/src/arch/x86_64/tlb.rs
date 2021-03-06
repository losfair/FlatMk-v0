use crate::addr::*;
use x86_64::instructions::tlb;

pub fn flush(addr: UserAddr) {
    tlb::flush(::x86_64::VirtAddr::new_unchecked(addr.get()));
}

pub fn flush_all() {
    tlb::flush_all();
}
