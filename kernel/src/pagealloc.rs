//! Physical page allocator.

use crate::addr::*;
use crate::arch::PAGE_SIZE;
use crate::error::*;
use core::mem::size_of;
use core::ptr::NonNull;
use spin::Mutex;

/// A NonNull pointer to `AllocFrame` that implements `Send`.
#[derive(Copy, Clone)]
#[repr(transparent)]
struct AllocFramePtr(pub NonNull<AllocFrame>);
unsafe impl Send for AllocFramePtr {}

/// A frame in the unused physical page stack.
#[repr(C)]
pub struct AllocFrame {
    /// A stack of unused physical addresses.
    elements: [PhysAddr; PAGE_SIZE / size_of::<usize>() - 3],

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

/// Pushes a physical page.
pub unsafe fn push_physical_page(addr: PhysAddr) {
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
pub unsafe fn pop_physical_page() -> KernelResult<PhysAddr> {
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

impl<T> KernelPageRef<T> {
    pub fn new(inner: T) -> KernelResult<Self> {
        assert!(size_of::<T>() <= PAGE_SIZE);
        let phys = unsafe { pop_physical_page()? };
        let virt = VirtAddr::from_phys(phys);
        let ptr = virt.as_nonnull().unwrap();
        unsafe {
            core::ptr::write(ptr.as_ptr(), inner);
            Ok(KernelPageRef(ptr))
        }
    }
}

impl<T> Drop for KernelPageRef<T> {
    fn drop(&mut self) {
        unsafe {
            core::ptr::drop_in_place(self.0.as_ptr());
        }
        let phys = PhysAddr::from_phys_mapped_virt(VirtAddr::from_nonnull(self.0)).unwrap();
        unsafe {
            push_physical_page(phys);
        }
    }
}
