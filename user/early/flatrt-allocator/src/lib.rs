//! An allocator for a FlatRt process, backed by `wee_alloc`.
//! 
//! Requires a capability to the task's own root page table.

#![no_std]
#![feature(asm, alloc_error_handler)]

use flatmk_sys::spec::{PAGE_SIZE, RootPageTable, UserPteFlags};
use spin::Once;
use core::{
    sync::atomic::{AtomicUsize, Ordering},
    ptr::NonNull,
};
use wee_alloc::MMAP_IMPL;

struct AllocConf {
    pt: RootPageTable,
    virt_base: AtomicUsize,
}

static ALLOC_CONF: Once<AllocConf> = Once::new();

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Initializes the global allocator.
/// 
/// - `virt_base`: The base virtual address for the heap to start from.
/// - `pt`: The root page table of the current task to allocate in.
pub unsafe fn init(virt_base: usize, pt: RootPageTable) {
    ALLOC_CONF.call_once(|| {
        AllocConf {
            pt,
            virt_base: AtomicUsize::new(virt_base),
        }
    });
    MMAP_IMPL = Some(do_mmap);
}

fn do_mmap(bytes: usize) -> Option<NonNull<u8>> {
    let conf = ALLOC_CONF.r#try().expect("do_mmap: Allocator called without initialization.");
    assert!(bytes % PAGE_SIZE == 0);

    let begin = conf.virt_base.fetch_add(bytes, Ordering::SeqCst);
    for i in (begin..begin + bytes).step_by(PAGE_SIZE) {
        unsafe {
            if conf.pt
                .make_leaf(i as u64) < 0 {
                    return None;
                }
            if conf.pt
                .alloc_leaf(i as u64, UserPteFlags::WRITABLE) < 0 {
                    return None;
                }
        }
    }
    Some(NonNull::new(begin as *mut u8).unwrap())
}

#[alloc_error_handler]
fn on_alloc_error(_: core::alloc::Layout) -> ! {
    unsafe {
        asm!("mov $$0xffff8000000a110c, %rax\nmov (%rax), %rax" :::: "volatile");
    }
    loop {}
}
