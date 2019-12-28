//! Reference-counted kernel objects.

use crate::error::*;
use crate::pagealloc::*;
use core::cell::UnsafeCell;
use core::mem::ManuallyDrop;
use core::ops::Deref;
use core::ptr::NonNull;
use core::convert::TryFrom;
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
        obj.inner.inc_ref_strong();
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

#[repr(transparent)]
pub struct WeakKernelObjectRef<T: Send + Sync + 'static> {
    inner: &'static KernelObject<T>,
}

impl<T: Send + Sync + 'static> KernelObjectRef<T> {
    pub fn new(inner: T) -> KernelResult<Self> {
        let kobj = KernelPageRef::new(KernelObject {
            total: AtomicU64::new(1),
            strong: AtomicU64::new(1),
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
        self.inner.inc_ref_strong();
        KernelObjectRef { inner: self.inner }
    }
}

impl<T: Send + Sync + 'static> Drop for KernelObjectRef<T> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            self.inner.dec_ref_strong();
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

impl<T: Send + Sync + 'static> Clone for WeakKernelObjectRef<T> {
    #[inline]
    fn clone(&self) -> Self {
        self.inner.inc_ref_weak();
        WeakKernelObjectRef { inner: self.inner }
    }
}

impl<T: Send + Sync + 'static> Drop for WeakKernelObjectRef<T> {
    fn drop(&mut self) {
        unsafe {
            self.inner.dec_ref_weak();
        }
    }
}

impl<T: Send + Sync + 'static> From<KernelObjectRef<T>> for WeakKernelObjectRef<T> {
    fn from(that: KernelObjectRef<T>) -> Self {
        let inner = that.inner;
        unsafe {
            inner.strong_to_weak();
        }
        core::mem::forget(that);

        WeakKernelObjectRef {
            inner,
        }
    }
}

impl<T: Send + Sync + 'static> TryFrom<WeakKernelObjectRef<T>> for KernelObjectRef<T> {
    type Error = KernelError;

    fn try_from(that: WeakKernelObjectRef<T>) -> KernelResult<Self> {
        let inner = that.inner;
        unsafe {
            inner.weak_to_strong()?;
        }
        core::mem::forget(that);

        Ok(KernelObjectRef {
            inner: inner,
        })
    }
}

/// A kernel object.
#[repr(C, align(4096))]
pub struct KernelObject<T: Send + Sync + 'static> {
    /// Total reference count.
    total: AtomicU64,

    /// Strong reference count.
    strong: AtomicU64,

    /// Inner value.
    value: ManuallyDrop<UnsafeCell<T>>,
}

/// For all immutable self references, `value` is only used immutably.
unsafe impl<T: Send + Sync + 'static> Send for KernelObject<T> {}

/// For all immutable self references, `value` is only used immutably.
unsafe impl<T: Send + Sync + 'static> Sync for KernelObject<T> {}

// TODO: Review atomic orderings.
impl<T: Send + Sync + 'static> KernelObject<T> {
    /// Dereferences into the inner value.
    /// Only immutable dereferencing is allowed.
    #[inline]
    pub fn value(&self) -> &T {
        unsafe { &*(self.value.get()) }
    }

    #[inline]
    fn inc_ref_strong(&self) {
        self.inc_ref_weak();

        // Refcount can never go up from 0.
        assert!(self.strong.fetch_add(1, Ordering::Acquire) > 0);
    }

    #[inline]
    fn inc_ref_weak(&self) {
        // Refcount can never go up from 0.
        assert!(self.total.fetch_add(1, Ordering::Acquire) > 0);
    }

    #[inline]
    unsafe fn dec_ref_strong(&self) {
        // Decrement `strong` refcount.
        self.strong_to_weak();

        // Decrement `total` refcount.
        self.dec_ref_weak();
    }

    #[inline]
    unsafe fn dec_ref_weak(&self) {
        let old_count = self.total.fetch_sub(1, Ordering::Release);
        if old_count == 1 {
            // Release the backing memory.
            KernelPageRef::from_raw(NonNull::from(self));
        } else if old_count == 0 {
            panic!("dec_ref_weak(): refcount underflow");
        }
    }

    #[inline]
    unsafe fn weak_to_strong(&self) -> KernelResult<()> {
        // Reference counts cannot go up again once reached zero.
        // So here we need a CAS loop.
        loop {
            let refcount = self.strong.load(Ordering::Relaxed);
            if refcount == 0 {
                return Err(KernelError::InvalidReference);
            }

            // FIXME: Is Acquire correct here?
            if self.strong.compare_exchange(refcount, refcount + 1, Ordering::Acquire, Ordering::Acquire).is_err() {
                continue;
            }
            return Ok(());
        }
    }

    #[inline]
    unsafe fn strong_to_weak(&self) {
        let old_count = self.strong.fetch_sub(1, Ordering::Release);
        if old_count == 1 {
            // Drop the inner value.
            core::ptr::drop_in_place(&mut *self.value.get());
        } else if old_count == 0 {
            panic!("strong_to_weak(): refcount underflow");
        }
    }
}
