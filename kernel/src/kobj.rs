//! Reference-counted kernel objects.

use crate::error::*;
use crate::pagealloc::*;
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::ops::Deref;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

#[repr(transparent)]
pub struct AtomicKernelObjectRef<T: Send + Sync + 'static> {
    inner: UnsafeCell<KernelObjectRef<T>>,
}

unsafe impl<T: Send + Sync + 'static> Send for AtomicKernelObjectRef<T> {}
unsafe impl<T: Send + Sync + 'static> Sync for AtomicKernelObjectRef<T> {}

impl<T: Send + Sync + 'static> AtomicKernelObjectRef<T> {
    pub fn new(inner: KernelObjectRef<T>) -> AtomicKernelObjectRef<T> {
        AtomicKernelObjectRef {
            inner: UnsafeCell::new(inner),
        }
    }

    #[inline]
    pub fn get(&self) -> KernelObjectRef<T> {
        let obj = KernelObjectRef {
            inner: unsafe {
                &*(*(self.inner.get() as *mut AtomicPtr<KernelObject<T>>)).load(Ordering::SeqCst)
            },
        };
        obj.inner.inc_ref();
        obj
    }

    #[inline]
    pub fn swap(&self, other: KernelObjectRef<T>) -> KernelObjectRef<T> {
        let old = KernelObjectRef {
            inner: unsafe {
                &*(*(self.inner.get() as *mut AtomicPtr<KernelObject<T>>)).swap(
                    other.inner as *const KernelObject<T> as *mut KernelObject<T>,
                    Ordering::SeqCst,
                )
            },
        };
        // Prevent Drop from decrementing refcount.
        core::mem::forget(other);
        old
    }
}

#[repr(transparent)]
pub struct KernelObjectRef<T: Send + Sync + 'static> {
    inner: &'static KernelObject<T>,
}

impl<T: Send + Sync + 'static> KernelObjectRef<T> {
    pub fn new(inner: T) -> KernelResult<Self> {
        let kobj = KernelPageRef::new(KernelObject {
            refcount: AtomicU64::new(1),
            value: ManuallyDrop::new(UnsafeCell::new(inner)),
        })?;
        let ptr = KernelPageRef::into_raw(kobj);
        unsafe {
            Ok(KernelObjectRef {
                inner: core::mem::transmute::<&KernelObject<T>, &'static KernelObject<T>>(
                    ptr.as_ref(),
                ),
            })
        }
    }

    #[inline]
    pub fn into_raw(self) -> *const KernelObject<T> {
        let ret = self.inner as *const _;
        core::mem::forget(self);
        ret
    }

    #[inline]
    pub unsafe fn from_raw(raw: *const KernelObject<T>) -> KernelObjectRef<T> {
        KernelObjectRef { inner: &*raw }
    }
}

impl<T: Send + Sync + 'static> Clone for KernelObjectRef<T> {
    #[inline]
    fn clone(&self) -> Self {
        self.inner.inc_ref();
        KernelObjectRef { inner: self.inner }
    }
}

impl<T: Send + Sync + 'static> Drop for KernelObjectRef<T> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            self.inner.dec_ref();
        }
    }
}

impl<T: Send + Sync + 'static> Deref for KernelObjectRef<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        self.inner.value()
    }
}

/// A kernel object.
///
/// `value` must be the first element.
#[repr(C, align(4096))]
pub struct KernelObject<T: Send + Sync + 'static> {
    refcount: AtomicU64,
    value: ManuallyDrop<UnsafeCell<T>>,
}

/// For all immutable self references, `value` is only used immutably.
unsafe impl<T: Send + Sync + 'static> Send for KernelObject<T> {}

/// For all immutable self references, `value` is only used immutably.
unsafe impl<T: Send + Sync + 'static> Sync for KernelObject<T> {}

impl<T: Send + Sync + 'static> KernelObject<T> {
    /// Dereferences into the inner value.
    /// Only immutable dereferencing is allowed.
    #[inline]
    pub fn value(&self) -> &T {
        unsafe { &*(self.value.get()) }
    }

    /// Drop.
    unsafe fn do_drop(&self) {
        core::ptr::drop_in_place(&mut *self.value.get());
        KernelPageRef::from_raw(NonNull::from(self));
    }

    #[inline]
    fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::SeqCst);
    }

    #[inline]
    unsafe fn dec_ref(&self) {
        let old_count = self.refcount.fetch_sub(1, Ordering::SeqCst);
        if old_count == 1 {
            self.do_drop();
        } else if old_count == 0 {
            panic!("dec_ref(): refcount underflow");
        }
    }
}
