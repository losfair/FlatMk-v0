//! Multilevel table objects.

use crate::addr::*;
use crate::arch;
use crate::error::*;
use crate::kobj::*;
use crate::paging::PageTableObject;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;
use spin::Mutex;

pub enum OpaqueCacheElement {}

pub struct GenericLeafCache {
    inner: [Option<(u64, NonNull<OpaqueCacheElement>)>; 8],
    next: usize,
}
unsafe impl Send for GenericLeafCache {}

impl LeafCache for GenericLeafCache {
    fn new() -> Self {
        Self {
            inner: [None; 8],
            next: 0,
        }
    }

    fn lookup(&mut self, ptr: u64) -> Option<NonNull<OpaqueCacheElement>> {
        for elem in self.inner.iter() {
            if let Some(ref elem) = *elem {
                if elem.0 == ptr {
                    return Some(elem.1);
                }
            }
        }
        None
    }

    fn insert(&mut self, ptr: u64, value: NonNull<OpaqueCacheElement>) {
        self.inner[self.next] = Some((ptr, value));
        if self.next + 1 == self.inner.len() {
            self.next = 0;
        } else {
            self.next += 1;
        }
    }

    fn invalidate(&mut self, _ptr: u64) {
        unimplemented!()
    }
}

pub trait LeafCache: Sized + Send {
    /// Creates Self.
    fn new() -> Self;

    /// Looks up an entry in this cache.
    ///
    /// The caller needs to ensure proper cache validation.
    fn lookup(&mut self, ptr: u64) -> Option<NonNull<OpaqueCacheElement>>;

    /// Inserts an entry.
    fn insert(&mut self, ptr: u64, value: NonNull<OpaqueCacheElement>);

    /// Invalidates an entry.
    fn invalidate(&mut self, ptr: u64);
}

/// A multilevel table object (MTO) is an abstraction for pagetable-like structures and is used
/// for page tables and capability tables.
pub struct MultilevelTableObject<
    T: Send,
    P: AsLevel<T, TABLE_SIZE> + Send,
    C: LeafCache,
    const BITS: u8,
    const LEVELS: u8,
    const START_BIT: u8,
    const TABLE_SIZE: usize,
> {
    root: Mutex<NonNull<Level<T, P, TABLE_SIZE>>>,
    root_uaddr: UserAddr,
    cache: Mutex<C>,
}

unsafe impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        C: LeafCache,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > Send for MultilevelTableObject<T, P, C, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
}

unsafe impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        C: LeafCache,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > Sync for MultilevelTableObject<T, P, C, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
}

/// A level in an multilevel table.
///
/// Leaf levels are always of the variant `value`, and other levels are always of the variant `table`.
pub union Level<T: Send, P: AsLevel<T, TABLE_SIZE> + Send, const TABLE_SIZE: usize> {
    pub table: ManuallyDrop<[P; TABLE_SIZE]>,
    pub value: ManuallyDrop<T>,
}

impl<T: Send, P: AsLevel<T, TABLE_SIZE> + Send, const TABLE_SIZE: usize> Level<T, P, TABLE_SIZE> {
    /// Looks up an entry by a pointer.
    ///
    /// O(levels).
    pub unsafe fn lookup_entry<F: FnOnce(u8, &mut P) -> R, R>(
        &mut self,
        ptr: u64,
        levels: u8,
        start_bit: u8,
        bits: u8,
        cb: F,
    ) -> R {
        assert!(levels > 0);
        let mut current = NonNull::from(self);

        for i in 0..levels {
            let index = ptr_to_index(ptr, i, start_bit, bits);
            let entry = &mut current.as_mut().table[index];
            if i == levels - 1 {
                return cb(i, entry);
            }
            current = match entry.as_level() {
                Some(x) => x,
                None => return cb(i, entry),
            }
        }

        unreachable!()
    }

    pub unsafe fn lookup_leaf_entry<F: FnOnce(&mut P) -> R, R>(
        &mut self,
        ptr: u64,
        levels: u8,
        start_bit: u8,
        bits: u8,
        cb: F,
    ) -> Option<R> {
        self.lookup_entry(ptr, levels, start_bit, bits, |depth, entry| {
            if depth == levels - 1 {
                Some(cb(entry))
            } else {
                None
            }
        })
    }

    /// Convenience function for looking up a leaf entry. Internally calls `lookup_entry`.
    pub unsafe fn lookup<F: FnOnce(&mut T) -> R, R>(
        &mut self,
        ptr: u64,
        levels: u8,
        start_bit: u8,
        bits: u8,
        cb: F,
    ) -> Option<R> {
        Some(self.lookup_leaf_entry(
            ptr,
            levels,
            start_bit,
            bits,
            |entry| match entry.as_level() {
                Some(mut x) => Some(cb(&mut *x.as_mut().value)),
                None => None,
            },
        )??)
    }
}

/// The entry type in a MTO must implement the AsLevel trait.
///
/// If the type has a Drop implementation, it should only cleanup the resources associated
/// with itself and the direct Level pointer it manages, without attempting to look into union
/// fields of Level. Recursive cleanup on all levels is managed by the caller.
pub trait AsLevel<T: Send, const TABLE_SIZE: usize>: Sized + Send {
    fn as_level(&mut self) -> Option<NonNull<Level<T, Self, TABLE_SIZE>>>;
}

impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        C: LeafCache,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > MultilevelTableObject<T, P, C, BITS, LEVELS, START_BIT, TABLE_SIZE>
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
        if self.root_uaddr.0 != 0 {
            owner.return_user_page(self.root_uaddr);
        }
    }

    /// Creates a new MultilevelTableObject. This function is unsafe because the caller must guarantee
    /// that both `inner` and `uaddr` are valid.
    ///
    /// If uaddr == 0, no cleanup will be performed on `inner` itself.
    pub unsafe fn new(inner: NonNull<Level<T, P, TABLE_SIZE>>, uaddr: UserAddr) -> Self {
        Self::check();
        MultilevelTableObject {
            root: Mutex::new(inner),
            root_uaddr: uaddr,
            cache: Mutex::new(C::new()),
        }
    }

    /// Extracts index of a specific level from a pointer.
    #[inline]
    pub fn ptr_to_index(ptr: u64, current_level: u8) -> usize {
        ptr_to_index(ptr, current_level, START_BIT, BITS)
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
        let mut root = self.root.lock();
        unsafe { root.as_mut().lookup_entry(ptr, LEVELS, START_BIT, BITS, cb) }
    }

    pub fn lookup_leaf_entry<F: FnOnce(&mut P) -> R, R>(&self, ptr: u64, cb: F) -> Option<R> {
        let mut root = self.root.lock();
        let mut cache = self.cache.lock();
        if let Some(x) = cache.lookup(ptr) {
            Some(cb(unsafe { &mut *(x.as_ptr() as *mut P) }))
        } else {
            unsafe {
                root.as_mut()
                    .lookup_leaf_entry(ptr, LEVELS, START_BIT, BITS, |x| {
                        cache.insert(
                            ptr,
                            NonNull::new_unchecked(x as *mut P as *mut OpaqueCacheElement),
                        );
                        cb(x)
                    })
            }
        }
    }

    /// Convenience function for looking up a leaf entry in this MTO. Internally calls `lookup_entry`.
    pub fn lookup<F: FnOnce(&mut T) -> R, R>(&self, ptr: u64, cb: F) -> Option<R> {
        self.lookup_leaf_entry(ptr, |entry| match entry.as_level() {
            Some(mut x) => Some(cb(unsafe { &mut *x.as_mut().value })),
            None => None,
        })?
    }

    pub fn with_root<F: FnOnce(&mut Level<T, P, TABLE_SIZE>) -> R, R>(&self, cb: F) -> R {
        let mut root = self.root.lock();
        cb(unsafe { root.as_mut() })
    }
}

/// Default value for a MTO entry that has its managed memory taken from userspace.
pub trait DefaultUser<T: Send, P: AsLevel<T, TABLE_SIZE> + Send, const TABLE_SIZE: usize>:
    Sized
{
    unsafe fn default_user(
        kref: NonNull<Level<T, P, TABLE_SIZE>>,
        leaf: bool,
        owner: KernelObjectRef<PageTableObject>,
        uaddr: UserAddr,
    ) -> KernelResult<Self>;
}

impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Default + Send,
        C: LeafCache,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > MultilevelTableObject<T, P, C, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
    /// Creates a MTO with root taken from userspace.
    pub fn new_from_user(
        owner: &KernelObjectRef<PageTableObject>,
        uaddr: UserAddr,
    ) -> KernelResult<Self> {
        let page = owner.take_from_user(uaddr)?;
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
        C: LeafCache,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > MultilevelTableObject<T, P, C, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
    /// Builds either a leaf or an intermediate level in an MTO, with memory taken from userspace.
    ///
    /// `owner` here can be different from owner of the current MTO.
    pub fn build_from_user(
        &self,
        ptr: u64,
        owner: KernelObjectRef<PageTableObject>,
        uaddr: UserAddr,
    ) -> KernelResult<bool> {
        let prev_depth = self.lookup_entry(ptr, |depth, _| depth);
        let leaf = if prev_depth == LEVELS - 1 {
            true
        } else {
            false
        };
        let page = owner.take_from_user(uaddr)?;
        let raw = NonNull::new(page.as_mut_ptr::<Level<T, P, TABLE_SIZE>>()).unwrap();
        let result = match unsafe { P::default_user(raw, leaf, owner.clone(), uaddr) } {
            Ok(new_entry) => self.lookup_entry(ptr, |depth, entry| {
                if depth != prev_depth {
                    return Err(KernelError::RaceRetry);
                }
                *entry = new_entry;
                Ok(())
            }),
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => Ok(leaf),
            Err(e) => {
                drop(owner.put_to_user(uaddr));
                Err(e)
            }
        }
    }
}

#[inline]
fn ptr_to_index(ptr: u64, current_level: u8, start_bit: u8, bits: u8) -> usize {
    let start = start_bit + 1 - current_level * bits;
    ((ptr << (64 - start as usize)) >> (64 - bits as usize)) as usize
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
