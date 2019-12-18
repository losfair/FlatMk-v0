//! Multilevel table objects.

use crate::arch;
use crate::error::*;
use crate::kobj::*;
use crate::paging::phys_to_virt;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;
use spin::Mutex;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::VirtAddr;

/// A multilevel table object (MTO) is an abstraction for pagetable-like structures and is used
/// for page tables and capability tables.
pub struct MultilevelTableObject<
    T: Send,
    P: AsLevel<T, TABLE_SIZE> + Send,
    const BITS: u8,
    const LEVELS: u8,
    const START_BIT: u8,
    const TABLE_SIZE: usize,
> {
    root: Mutex<NonNull<Level<T, P, TABLE_SIZE>>>,
    root_uaddr: VirtAddr,
}

unsafe impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > Send for MultilevelTableObject<T, P, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
}

unsafe impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > Sync for MultilevelTableObject<T, P, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
}

/// A level in an multilevel table.
///
/// Leaf levels are always of the variant `value`, and other levels are always of the variant `table`.
pub union Level<T: Send, P: AsLevel<T, TABLE_SIZE> + Send, const TABLE_SIZE: usize> {
    pub table: ManuallyDrop<[P; TABLE_SIZE]>,
    pub value: ManuallyDrop<T>,
}

/// The entry type in a MTO must implement the AsLevel trait.
///
/// If the type has a Drop implementation, it should only cleanup the resources associated
/// with itself and the direct Level pointer it manages, without attempting to look into union
/// fields of Level. Recursive cleanup on all levels is managed by the caller.
pub trait AsLevel<T: Send, const TABLE_SIZE: usize>: Sized + Send {
    fn as_level(&mut self) -> Option<NonNull<Level<T, Self, TABLE_SIZE>>>;
}

pub type Page = [u8; 4096];
pub type PageTableObject = MultilevelTableObject<Page, PageTableEntry, 9, 4, 47, 512>;

impl AsLevel<Page, 512> for PageTableEntry {
    fn as_level(&mut self) -> Option<NonNull<Level<Page, Self, 512>>> {
        NonNull::new(phys_to_virt(self.addr()).as_mut_ptr())
    }
}

impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > MultilevelTableObject<T, P, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
    /// Checks that the constant type parameters are correct.
    const fn check() {
        _check_size(
            core::mem::size_of::<Level<T, P, TABLE_SIZE>>(),
            arch::PAGE_SIZE,
        );
        _check_bounds(BITS, LEVELS, START_BIT);
        _check_bit_to_size(BITS, TABLE_SIZE);
    }

    /// Informs that the caller is going to call the drop implementation on this object.
    pub unsafe fn will_drop(&mut self, owner: &dyn LikeKernelObject) {
        self.foreach_entry(|depth, entry| {
            // If this is a leaf node, it contains a value of type T and we should drop it.
            // Otherwise, it contains a table and should have been cleaned up in previous iterations,
            // by the following drop_in_place.
            if depth == LEVELS - 1 {
                if let Some(mut entry) = entry.as_level() {
                    let entry = entry.as_mut();
                    ManuallyDrop::drop(&mut entry.value);
                }
            }

            // Call drop on the entry itself.
            // This will clean up the resources associated with the entry.
            core::ptr::drop_in_place(entry);
            Ok(())
        })
        .unwrap();
        if self.root_uaddr.as_u64() != 0 {
            owner.return_user_page(self.root_uaddr);
        }
    }

    /// Creates a new MultilevelTableObject. This function is unsafe because the caller must guarantee
    /// that both `inner` and `uaddr` are valid.
    ///
    /// If uaddr == 0, no cleanup will be performed on `inner` itself.
    pub unsafe fn new(inner: NonNull<Level<T, P, TABLE_SIZE>>, uaddr: VirtAddr) -> Self {
        Self::check();
        MultilevelTableObject {
            root: Mutex::new(inner),
            root_uaddr: uaddr,
        }
    }

    /// Extracts index of a specific level from a pointer.
    #[inline]
    fn ptr_to_index(ptr: u64, current_level: u8) -> usize {
        let start = START_BIT + current_level * BITS - 1;
        ((ptr << (64 - start as usize)) >> (64 - BITS as usize)) as usize
    }

    /// Recursive foreach implementation.
    unsafe fn inner_foreach<F: FnMut(u8, &mut P) -> KernelResult<()>>(
        mut current: NonNull<Level<T, P, TABLE_SIZE>>,
        cb: &mut F,
        depth: u8,
    ) -> KernelResult<()> {
        assert!(depth < LEVELS);
        for entry in current.as_mut().table.iter_mut() {
            if depth != LEVELS - 1 {
                if let Some(inner) = entry.as_level() {
                    Self::inner_foreach(inner, cb, depth + 1)?;
                }
            }
            cb(depth, entry)?;
        }
        Ok(())
    }

    /// Iterates over all entries in the current MTO, in post-order.
    pub fn foreach_entry<F: FnMut(u8, &mut P) -> KernelResult<()>>(
        &self,
        mut cb: F,
    ) -> KernelResult<()> {
        let root = self.root.lock();
        unsafe { Self::inner_foreach(*root, &mut cb, 0) }
    }

    /// Looks up an entry by a pointer in this MTO.
    ///
    /// O(LEVELS).
    pub fn lookup_entry<F: FnOnce(u8, &mut P) -> R, R>(&self, ptr: u64, cb: F) -> R {
        let root = self.root.lock();
        let mut current = *root;

        for i in 0..LEVELS {
            unsafe {
                let entry = &mut current.as_mut().table[Self::ptr_to_index(ptr, i)];
                if i == LEVELS - 1 {
                    return cb(i, entry);
                }
                current = match entry.as_level() {
                    Some(x) => x,
                    None => return cb(i, entry),
                }
            }
        }

        unreachable!()
    }

    /// Convenience function for looking up a leaf entry in this MTO. Internally calls `lookup_entry`.
    pub fn lookup<F: FnOnce(&mut T) -> R, R>(&self, ptr: u64, cb: F) -> Option<R> {
        self.lookup_entry(ptr, |depth, entry| {
            if depth == LEVELS - 1 {
                match entry.as_level() {
                    Some(mut x) => Some(cb(unsafe { &mut *x.as_mut().value })),
                    None => None,
                }
            } else {
                None
            }
        })
    }
}

/// Default value for a MTO entry that has its managed memory taken from userspace.
pub trait DefaultUser<T: Send, P: AsLevel<T, TABLE_SIZE> + Send, const TABLE_SIZE: usize>:
    Sized
{
    unsafe fn default_user(
        kref: NonNull<Level<T, P, TABLE_SIZE>>,
        leaf: bool,
        owner: KernelObjectRef<crate::paging::PageTableObject>,
        uaddr: VirtAddr,
    ) -> KernelResult<Self>;
}

impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Default + Send,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > MultilevelTableObject<T, P, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
    /// Creates a MTO with root taken from userspace.
    pub fn new_from_user(
        owner: &KernelObjectRef<crate::paging::PageTableObject>,
        uaddr: VirtAddr,
    ) -> KernelResult<Self> {
        let page = owner.with(|pt| crate::paging::take_from_user(pt, uaddr))?;
        let raw = NonNull::new(page.as_mut_ptr::<Level<T, P, TABLE_SIZE>>()).unwrap();
        unsafe {
            for entry in (*raw.as_ptr()).table.iter_mut() {
                core::ptr::write(entry, P::default());
            }
            Ok(Self::new(raw, uaddr))
        }
    }
}

impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + DefaultUser<T, P, TABLE_SIZE> + Send,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > MultilevelTableObject<T, P, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
    /// Builds either a leaf or an intermediate level in an MTO, with memory taken from userspace.
    ///
    /// `owner` here can be different from owner of the current MTO.
    pub fn build_from_user(
        &self,
        ptr: u64,
        owner: KernelObjectRef<crate::paging::PageTableObject>,
        uaddr: VirtAddr,
    ) -> KernelResult<bool> {
        self.lookup_entry(ptr, |depth, entry| {
            let leaf = if depth == LEVELS - 1 { true } else { false };
            if uaddr.as_u64() == 0 {
                return Ok(leaf);
            }

            let page = owner.with(|pt| crate::paging::take_from_user(pt, uaddr))?;
            let raw = NonNull::new(page.as_mut_ptr::<Level<T, P, TABLE_SIZE>>()).unwrap();
            let new_entry = match unsafe { P::default_user(raw, leaf, owner.clone(), uaddr) } {
                Ok(x) => x,
                Err(e) => {
                    owner.with(|pt| {
                        drop(unsafe { crate::paging::put_to_user(pt, uaddr) });
                    });
                    return Err(e);
                }
            };
            *entry = new_entry;
            Ok(leaf)
        })
    }
}

const fn _check_size(size: usize, limit: usize) {
    if size > limit {
        panic!("invalid type size");
    }
}

const fn _check_bounds(bits: u8, levels: u8, start_bit: u8) {
    let bits = bits as u32;
    let levels = levels as u32;
    let start_bit = start_bit as u32;

    if levels == 0 {
        panic!("levels cannot be zero");
    }

    if start_bit > 63 {
        panic!("start_bit must not be greater than 63");
    }

    if start_bit + 1 < bits * levels {
        panic!("bit range out of bounds");
    }
}

const fn _check_bit_to_size(bit: u8, size: usize) {
    if (1usize << (bit as u32)) != size {
        panic!("bit and size mismatch")
    }
}
