//! Dynamic capability allocator.

#![no_std]

#[macro_use]
extern crate lazy_static;

extern crate alloc;

use flatmk_sys::spec;
use slab::Slab;
use alloc::collections::btree_set::BTreeSet;
use spin::Mutex;

static mut CAPSET: Option<spec::CapabilitySet> = None;
static mut DYNAMIC_BASE: u64 = 0;

lazy_static! {
    static ref ALLOC_STATE: Mutex<AllocState> = Mutex::new(AllocState {
        slab: Slab::new(),
        allocated_leafs: BTreeSet::new(),
    });
}

/// Allocation state.
struct AllocState {
    /// A slab that manages CPtr allocation.
    slab: Slab<()>,

    /// Allocated capability set leaf indexes.
    allocated_leafs: BTreeSet<u64>,
}

pub unsafe fn init(capset: spec::CapabilitySet, dynamic_base: u64) {
    CAPSET = Some(capset);
    DYNAMIC_BASE = dynamic_base;
}

fn get_capset() -> spec::CapabilitySet {
    unsafe {
        CAPSET.expect("capalloc: Global capability set is not set.")
    }
}

fn get_dynamic_base() -> u64 {
    unsafe {
        DYNAMIC_BASE
    }
}

/// Converts a capability pointer to a leaf index.
fn cptr_to_leaf(cptr: u64) -> u64 {
    cptr >> 8
}

/// Converts a leaf index to a base capability pointer.
fn leaf_to_cptr(cptr: u64) -> u64 {
    cptr << 8
}

/// Converts a sequential integer to a valid CPtr offset.
fn canonicalize_cptr_offset(cptr: u64) -> u64 {
    ((cptr >> 5) << 8) | (cptr & 0b11111)
}

/// Reverse operation of canonicalize_cptr_offset.
fn uncanonicalize_cptr_offset(cptr: u64) -> u64 {
    ((cptr >> 8) << 5) | (cptr & 0b11111)
}

/// Allocates a capability pointer.
pub fn allocate() -> spec::CPtr {
    let mut state = ALLOC_STATE.lock();
    let cptr = canonicalize_cptr_offset(state.slab.insert(()) as u64)
        .checked_add(get_dynamic_base())
        .expect("capalloc::allocate: Capability pointer overflow.");

    let leaf_index = cptr_to_leaf(cptr);
    if !state.allocated_leafs.contains(&leaf_index) {
        unsafe {
            spec::to_result(get_capset().make_leaf(&spec::CPtr::new(leaf_to_cptr(leaf_index)))).expect(
                "capalloc::allocate: Cannot allocate new leaf set."
            );
        }
        state.allocated_leafs.insert(leaf_index);
    }

    unsafe {
        spec::CPtr::new(cptr)
    }
}

/// Releases a capability pointer allocated by `allocate`.
pub fn release(cptr: spec::CPtr) {
    let mut state = ALLOC_STATE.lock();
    let index = uncanonicalize_cptr_offset(
        cptr.index().checked_sub(get_dynamic_base()).expect("capalloc::release: Index underflow.")
    );
    state.slab.remove(index as usize);
}
