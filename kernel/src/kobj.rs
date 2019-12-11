use crate::error::*;
use crate::task::Task;
use core::any::{Any, TypeId};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::VirtAddr;

const PAGE_SIZE: u64 = 4096;

pub unsafe trait LikeKernelObject {
    fn inc_ref(&self);
    unsafe fn dec_ref(&self);
    unsafe fn return_page(&self, addr: VirtAddr);
}

pub struct RootKernelObject;
unsafe impl LikeKernelObject for RootKernelObject {
    fn inc_ref(&self) {}
    unsafe fn dec_ref(&self) {}
    unsafe fn return_page(&self, _addr: VirtAddr) {}
}

pub trait Retype: Sized {
    unsafe fn retype_in_place(&mut self) -> KernelResult<()> {
        Err(KernelError::NotImplemented)
    }
}

pub trait Notify {
    unsafe fn return_page(&self, _addr: VirtAddr) {}
    fn will_drop(&mut self, _owner: &LikeKernelObject) {}
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
    unsafe fn return_page(&self, addr: VirtAddr) {
        self.inner.return_page(addr)
    }

    pub fn get(&self) -> &dyn LikeKernelObject {
        self.inner
    }
}

impl<T: Retype + Notify + Send + Sync + 'static> From<KernelObjectRef<T>> for LikeKernelObjectRef {
    fn from(other: KernelObjectRef<T>) -> LikeKernelObjectRef {
        let result = LikeKernelObjectRef { inner: other.inner };
        core::mem::forget(other);
        result
    }
}

#[repr(transparent)]
pub struct KernelObjectRef<T: Retype + Notify + Send + Sync + 'static> {
    inner: &'static KernelObject<T>,
}

impl<T: Retype + Notify + Send + Sync + 'static> KernelObjectRef<T> {
    pub fn into_raw(self) -> *const KernelObject<T> {
        let ret = self.inner as *const _;
        core::mem::forget(self);
        ret
    }

    pub unsafe fn from_raw(raw: *const KernelObject<T>) -> KernelObjectRef<T> {
        KernelObjectRef { inner: &*raw }
    }
}

impl<T: Retype + Notify + Send + Sync + 'static> Clone for KernelObjectRef<T> {
    fn clone(&self) -> Self {
        self.inner.inc_ref();
        KernelObjectRef { inner: self.inner }
    }
}

impl<T: Retype + Notify + Send + Sync + 'static> Drop for KernelObjectRef<T> {
    fn drop(&mut self) {
        unsafe {
            self.inner.dec_ref();
        }
    }
}

impl<T: Retype + Notify + Send + Sync + 'static> Deref for KernelObjectRef<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.inner.value()
    }
}

#[repr(C, align(4096))]
pub struct KernelObject<T: Retype + Notify + Send + Sync + 'static> {
    owner: &'static dyn LikeKernelObject,
    refcount: AtomicU64,
    value: UnsafeCell<T>,
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

    /// Takes a newly retyped KernelObject as `self`, validates and initializes it.
    pub fn init(&mut self, owner: &dyn LikeKernelObject, retype: bool) -> KernelResult<()> {
        // Validate address properties.
        if core::mem::size_of::<Self>() > PAGE_SIZE as usize
            || !VirtAddr::new(self as *mut _ as u64).is_aligned(PAGE_SIZE)
        {
            return Err(KernelError::InvalidDelegation);
        }

        if retype {
            // Retype value.
            unsafe {
                (*self.value.get()).retype_in_place()?;
            }
        }

        // Increment refcount of our owner.
        owner.inc_ref();

        // Initialize fields. Dynamic shared ownership to `owner` is guaranteed by reference counting.
        self.owner = unsafe {
            core::mem::transmute::<&dyn LikeKernelObject, &'static dyn LikeKernelObject>(owner)
        };
        self.refcount = AtomicU64::new(0);

        Ok(())
    }

    /// Returns the owner of the kernel object.
    pub fn owner(&self) -> &dyn LikeKernelObject {
        self.owner
    }

    /// Dereferences into the inner value.
    /// Only immutable dereferencing is allowed.
    pub fn value(&self) -> &T {
        unsafe { &*(self.value.get()) }
    }

    /// Returns a new dynamic reference to this kernel object.
    pub fn get_ref(&self) -> KernelObjectRef<T> {
        self.inc_ref();
        unsafe {
            KernelObjectRef {
                inner: core::mem::transmute::<&Self, &'static Self>(self),
            }
        }
    }

    /// Ensure object tree properties before drop.
    unsafe fn tree_drop(&self) {
        let value = &mut *self.value.get();
        value.will_drop(self.owner);
        self.owner
            .return_page(VirtAddr::new(self as *const _ as u64));
        self.owner.dec_ref();
    }
}

/// This drop implementation usually won't be called. dec_ref() handles cleanup instead.
impl<T: Retype + Notify + Send + Sync + 'static> Drop for KernelObject<T> {
    fn drop(&mut self) {
        if self.refcount.load(Ordering::SeqCst) != 0 {
            panic!("Attempting to call drop() on a KernelObject with alive references");
        }
        unsafe {
            self.tree_drop();
        }
        // self.value is automatically dropped.
    }
}

unsafe impl<T: Retype + Notify + Send + Sync + 'static> LikeKernelObject for KernelObject<T> {
    fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::SeqCst);
    }

    unsafe fn dec_ref(&self) {
        let old_count = self.refcount.fetch_sub(1, Ordering::SeqCst);
        if old_count == 1 {
            self.tree_drop();
            core::ptr::drop_in_place(self.value.get());
        } else if old_count == 0 {
            panic!("dec_ref(): refcount underflow");
        }
    }

    unsafe fn return_page(&self, addr: VirtAddr) {
        self.value().return_page(addr);
    }
}
