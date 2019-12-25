use crate::task::ROOT_PAGE_TABLE;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use wee_alloc::MMAP_IMPL;
use crate::layout;

static CURRENT_TOP: AtomicUsize = AtomicUsize::new(layout::HEAP_BASE as usize);
pub const PAGE_SIZE: usize = 4096;

fn do_mmap(bytes: usize) -> Option<NonNull<u8>> {
    assert!(bytes % PAGE_SIZE == 0);
    let begin = CURRENT_TOP.fetch_add(bytes, Ordering::SeqCst);
    for i in (begin..begin + bytes).step_by(PAGE_SIZE) {
        ROOT_PAGE_TABLE
            .make_leaf(i as u64)
            .expect("do_mmap: make_leaf failed");
        ROOT_PAGE_TABLE
            .alloc_leaf(i as u64)
            .expect("do_mmap: alloc_leaf failed");
    }
    Some(NonNull::new(begin as *mut u8).unwrap())
}

pub(crate) unsafe fn init() {
    MMAP_IMPL = Some(do_mmap);
}
