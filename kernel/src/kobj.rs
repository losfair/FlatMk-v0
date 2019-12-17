use crate::error::*;
use core::cell::UnsafeCell;
use core::ops::Deref;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use x86_64::VirtAddr;

const PAGE_SIZE: u64 = 4096;

pub unsafe trait LikeKernelObject {
    /// Increments refcount by one.
    fn inc_ref(&self);

    /// Decrements refcount by one.
    unsafe fn dec_ref(&self);

    /// Releases a page taken from userspace, recursively.
    unsafe fn return_user_page(&self, addr: VirtAddr);

    /// Returns number of references to this kernel object.
    fn count_ref(&self) -> usize;
}

pub struct RootKernelObject;
unsafe impl LikeKernelObject for RootKernelObject {
    fn inc_ref(&self) {}
    unsafe fn dec_ref(&self) {}
    unsafe fn return_user_page(&self, _addr: VirtAddr) {}
    fn count_ref(&self) -> usize {
        1
    }
}

pub trait Retype: Sized {
    unsafe fn retype_in_place(&mut self) -> KernelResult<()> {
        Err(KernelError::NotImplemented)
    }
}

pub trait Notify {
    unsafe fn return_user_page(&self, _addr: VirtAddr) {}
    unsafe fn will_drop(&mut self, _owner: &dyn LikeKernelObject) {}
}

pub struct LikeKernelObjectRef {
    inner: &'static dyn LikeKernelObject,
}

impl Clone for LikeKernelObjectRef {
    fn clone(&self) -> Self {
        self.inner.inc_ref();
        LikeKernelObjectRef { inner: self.inner }
    }
}

impl Drop for LikeKernelObjectRef {
    fn drop(&mut self) {
        unsafe {
            self.inner.dec_ref();
        }
    }
}

impl LikeKernelObjectRef {
    #[inline]
    pub fn get(&self) -> &dyn LikeKernelObject {
        self.inner
    }
}

impl<T: Retype + Notify + Send + Sync + 'static> From<KernelObjectRef<T>> for LikeKernelObjectRef {
    #[inline]
    fn from(other: KernelObjectRef<T>) -> LikeKernelObjectRef {
        let result = LikeKernelObjectRef { inner: other.inner };
        core::mem::forget(other);
        result
    }
}

#[repr(transparent)]
pub struct AtomicKernelObjectRef<T: Retype + Notify + Send + Sync + 'static> {
    inner: UnsafeCell<KernelObjectRef<T>>,
}

unsafe impl<T: Retype + Notify + Send + Sync + 'static> Send for AtomicKernelObjectRef<T> {}
unsafe impl<T: Retype + Notify + Send + Sync + 'static> Sync for AtomicKernelObjectRef<T> {}

impl<T: Retype + Notify + Send + Sync + 'static> AtomicKernelObjectRef<T> {
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
pub struct KernelObjectRef<T: Retype + Notify + Send + Sync + 'static> {
    inner: &'static KernelObject<T>,
}

impl<T: Retype + Notify + Send + Sync + 'static> KernelObjectRef<T> {
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

impl<T: Retype + Notify + Send + Sync + 'static> Clone for KernelObjectRef<T> {
    #[inline]
    fn clone(&self) -> Self {
        self.inner.inc_ref();
        KernelObjectRef { inner: self.inner }
    }
}

impl<T: Retype + Notify + Send + Sync + 'static> Drop for KernelObjectRef<T> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            self.inner.dec_ref();
        }
    }
}

impl<T: Retype + Notify + Send + Sync + 'static> Deref for KernelObjectRef<T> {
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
pub struct KernelObject<T: Retype + Notify + Send + Sync + 'static> {
    value: UnsafeCell<T>,
    owner: &'static dyn LikeKernelObject,
    refcount: AtomicU64,
    uaddr: VirtAddr,
}

/// For all immutable self references, `value` is only used immutably.
unsafe impl<T: Retype + Notify + Send + Sync + 'static> Send for KernelObject<T> {}

/// For all immutable self references, `value` is only used immutably.
unsafe impl<T: Retype + Notify + Send + Sync + 'static> Sync for KernelObject<T> {}

impl<T: Retype + Notify + Send + Sync + 'static> KernelObject<T> {
    /// Writes a new value into this kernel object, without dropping the previous value.
    /// If the `retype` argument to `init` is false, `write` should be called before.
    pub fn write(&mut self, value: T) {
        unsafe {
            core::ptr::write(self.value.get(), value);
        }
    }

    /// Takes a newly retyped KernelObject as `self`, validates and initializes it with the provided retyper.
    pub unsafe fn init_with<F: FnOnce(&mut T) -> KernelResult<()>>(
        &mut self,
        owner: &dyn LikeKernelObject,
        uaddr: VirtAddr,
        retyper: F,
    ) -> KernelResult<()> {
        // Validate address properties.
        if core::mem::size_of::<Self>() > PAGE_SIZE as usize
            || !VirtAddr::new(self as *mut _ as u64).is_aligned(PAGE_SIZE)
        {
            return Err(KernelError::InvalidDelegation);
        }

        // Retype value.
        retyper(&mut *self.value.get())?;

        // Increment refcount of our owner.
        owner.inc_ref();

        // Initialize fields. Dynamic shared ownership to `owner` is guaranteed by reference counting.
        self.owner =
            core::mem::transmute::<&dyn LikeKernelObject, &'static dyn LikeKernelObject>(owner);
        self.refcount = AtomicU64::new(0);
        self.uaddr = uaddr;

        Ok(())
    }

    /// Takes a newly retyped KernelObject as `self`, validates and initializes it.
    pub fn init(
        &mut self,
        owner: &dyn LikeKernelObject,
        uaddr: VirtAddr,
        retype: bool,
    ) -> KernelResult<()> {
        unsafe {
            if retype {
                self.init_with(owner, uaddr, |x| x.retype_in_place())
            } else {
                self.init_with(owner, uaddr, |_| Ok(()))
            }
        }
    }

    /// Returns the owner of the kernel object.
    pub fn owner(&self) -> &dyn LikeKernelObject {
        self.owner
    }

    /// Dereferences into the inner value.
    /// Only immutable dereferencing is allowed.
    #[inline]
    pub fn value(&self) -> &T {
        unsafe { &*(self.value.get()) }
    }

    /// Returns a new dynamic reference to this kernel object.
    #[inline]
    pub fn get_ref(&self) -> KernelObjectRef<T> {
        self.inc_ref();
        unsafe {
            KernelObjectRef {
                inner: core::mem::transmute::<&Self, &'static Self>(self),
            }
        }
    }

    /// Drop.
    unsafe fn do_drop(&self) {
        let value = &mut *self.value.get();
        value.will_drop(self.owner);
        core::ptr::drop_in_place(value);

        // `self` becomes invalid after returning to user.
        let owner = self.owner;

        owner.return_user_page(self.uaddr);
        owner.dec_ref();
    }
}

/// This drop implementation usually won't be called. dec_ref() handles cleanup instead.
impl<T: Retype + Notify + Send + Sync + 'static> Drop for KernelObject<T> {
    fn drop(&mut self) {
        panic!("Attempting to call drop() on a KernelObject");
    }
}

unsafe impl<T: Retype + Notify + Send + Sync + 'static> LikeKernelObject for KernelObject<T> {
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

    unsafe fn return_user_page(&self, addr: VirtAddr) {
        self.value().return_user_page(addr);
    }

    fn count_ref(&self) -> usize {
        self.refcount.load(Ordering::SeqCst) as usize
    }
}
