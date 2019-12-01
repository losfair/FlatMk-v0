use crate::task::Task;
use core::ops::{Deref, DerefMut};
use x86_64::VirtAddr;

const PAGE_SIZE: u64 = 4096;

#[repr(C)]
pub struct KernelObject<T> {
    owner: *const Task,
    value: *mut T,
}

impl<T> KernelObject<T> {
    pub unsafe fn new(owner: Option<&Task>, x: *mut T) -> KernelObject<T> {
        assert!(core::mem::size_of::<T>() <= PAGE_SIZE as usize);
        assert!(VirtAddr::new(x as u64).is_aligned(PAGE_SIZE));

        if let Some(owner) = owner {
            owner.inc_ref();
        }

        KernelObject {
            owner: owner.map(|x| x as *const Task).unwrap_or(core::ptr::null()),
            value: x,
        }
    }

    pub fn owner(obj: &KernelObject<T>) -> &Task {
        unsafe { &*obj.owner }
    }
}

impl<T> Deref for KernelObject<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.value }
    }
}
impl<T> DerefMut for KernelObject<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.value }
    }
}

impl<T> Drop for KernelObject<T> {
    fn drop(&mut self) {
        if self.owner.is_null() {
            panic!("Kernel objects without owner should not be dropped.");
        } else {
            unsafe {
                Task::dec_ref(self.owner);
            }
        }
    }
}
