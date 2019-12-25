//! Physical page allocator.

use crate::addr::*;
use crate::arch::PAGE_SIZE;
use crate::error::*;
use core::mem::{size_of, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// This number is chosen to ensure size_of::<AllocFrame>() == size_of::<Page>() .
pub const PAGES_PER_ALLOC_FRAME: usize = PAGE_SIZE / size_of::<usize>() - 3;

pub const PHYSICAL_PAGE_METADATA_BASE: u64 = 0xFFFFFFC000000000;

/// A NonNull pointer to `AllocFrame` that implements `Send`.
#[derive(Copy, Clone)]
#[repr(transparent)]
struct AllocFramePtr(pub NonNull<AllocFrame>);
unsafe impl Send for AllocFramePtr {}

/// A frame in the unused physical page stack.
#[repr(C)]
pub struct AllocFrame {
    /// A stack of unused physical addresses.
    elements: [PhysAddr; PAGES_PER_ALLOC_FRAME],

    /// Stack top, exclusively. `next_index == elements.len()` if the frame is full.
    next_index: usize,

    /// Link pointer to the previous AllocFrame, if any.
    prev_frame: Option<AllocFramePtr>,

    /// Link pointer to the next AllocFrame, if any.
    next_frame: Option<AllocFramePtr>,
}

static ALLOC_CURRENT: Mutex<Option<AllocFramePtr>> = Mutex::new(None);

/// Takes an uninitialized NonNull<AllocFrame>, initializes and pushes it.
///
/// Only used during initialization.
pub unsafe fn init_clear_and_push_alloc_frame(mut frame: NonNull<AllocFrame>) {
    core::ptr::write(frame.as_ptr(), core::mem::zeroed());

    let mut current = ALLOC_CURRENT.lock();
    if let Some(ref mut ptr) = *current {
        let ptr = ptr.0.as_mut();
        assert_eq!(ptr.next_index, ptr.elements.len());
        assert!(ptr.next_frame.is_none());
        ptr.next_frame = Some(AllocFramePtr(frame));
    }

    frame.as_mut().prev_frame = *current;
    *current = Some(AllocFramePtr(frame));
}

/// Pushes a physical page. Used during paging initialization.
pub unsafe fn init_push_physical_page(addr: PhysAddr) {
    push_physical_page(addr)
}

/// Pushes a physical page.
unsafe fn push_physical_page(addr: PhysAddr) {
    let mut current_locked = ALLOC_CURRENT.lock();
    let mut current = current_locked.unwrap();

    if current.0.as_ref().next_index == current.0.as_ref().elements.len() {
        let next = current.0.as_ref().next_frame;
        *current_locked = next;
        current = next.unwrap();
        assert_eq!(current.0.as_ref().next_index, 0);
    }

    let current = current.0.as_mut();
    current.elements[current.next_index] = addr;
    current.next_index += 1;
}

/// Pops a physical page.
unsafe fn pop_physical_page() -> KernelResult<PhysAddr> {
    let mut current_locked = ALLOC_CURRENT.lock();
    let mut current = current_locked.unwrap();

    if current.0.as_ref().next_index == 0 {
        let prev = current.0.as_ref().prev_frame;
        if prev.is_none() {
            return Err(KernelError::OutOfMemory);
        }
        *current_locked = prev;
        current = prev.unwrap();
        assert_eq!(
            current.0.as_ref().next_index,
            current.0.as_ref().elements.len()
        );
    }

    let current = current.0.as_mut();
    current.next_index -= 1;
    let addr = current.elements[current.next_index];

    Ok(addr)
}

/// An owned, typed reference to a page.
#[repr(transparent)]
pub struct KernelPageRef<T>(NonNull<T>);

unsafe impl<T: Send> Send for KernelPageRef<T> {}
unsafe impl<T: Sync> Sync for KernelPageRef<T> {}

impl<T> Clone for KernelPageRef<T> {
    fn clone(&self) -> Self {
        let phys = PhysAddr::from_phys_mapped_virt(VirtAddr::from_nonnull(self.0)).unwrap();
        unsafe {
            inc_refcount(phys);
        }
        KernelPageRef(self.0)
    }
}

impl<T> KernelPageRef<T> {
    pub fn new(inner: T) -> KernelResult<Self> {
        assert!(size_of::<T>() <= PAGE_SIZE);
        let phys = unsafe { pop_physical_page()? };
        unsafe {
            inc_refcount(phys);
        }
        let virt = VirtAddr::from_phys(phys);
        let ptr = virt.as_nonnull().unwrap();
        unsafe {
            core::ptr::write(ptr.as_ptr(), inner);
            Ok(KernelPageRef(ptr))
        }
    }

    pub fn new_uninit() -> KernelResult<MaybeUninit<Self>> {
        assert!(size_of::<T>() <= PAGE_SIZE);
        let phys = unsafe { pop_physical_page()? };
        unsafe {
            inc_refcount(phys);
        }
        let virt = VirtAddr::from_phys(phys);
        let ptr = virt.as_nonnull().unwrap();
        Ok(MaybeUninit::new(KernelPageRef(ptr)))
    }

    pub fn as_nonnull(&mut self) -> NonNull<T> {
        self.0
    }

    pub fn into_raw(me: KernelPageRef<T>) -> NonNull<T> {
        let result = me.0;
        core::mem::forget(me);
        result
    }

    pub unsafe fn from_raw(x: NonNull<T>) -> KernelPageRef<T> {
        KernelPageRef(x)
    }
}

// TODO: Better atomic ordering?
unsafe fn inc_refcount(phys: PhysAddr) -> u64 {
    let metadata = phys.page_metadata().as_nonnull().unwrap();
    let metadata: &AtomicU64 = metadata.as_ref();
    metadata.fetch_add(1, Ordering::SeqCst)
}

// TODO: Better atomic ordering?
unsafe fn dec_refcount(phys: PhysAddr) -> u64 {
    let metadata = phys.page_metadata().as_nonnull().unwrap();
    let metadata: &AtomicU64 = metadata.as_ref();
    metadata.fetch_sub(1, Ordering::SeqCst)
}

impl<T> Drop for KernelPageRef<T> {
    fn drop(&mut self) {
        let phys = PhysAddr::from_phys_mapped_virt(VirtAddr::from_nonnull(self.0)).unwrap();
        unsafe {
            let old_value = dec_refcount(phys);
            if old_value == 1 {
                core::ptr::drop_in_place(self.0.as_ptr());
                push_physical_page(phys);
            } else if old_value == 0 {
                panic!("pagealloc::dec_refcount: old refcount is zero");
            }
        }
    }
}

impl<T> Deref for KernelPageRef<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.0.as_ref() }
    }
}

impl<T> DerefMut for KernelPageRef<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.0.as_mut() }
    }
}
