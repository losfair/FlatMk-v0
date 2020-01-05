//! Multilevel table objects.

use crate::arch;
use crate::error::*;
use crate::pagealloc::KernelPageRef;
use bit_field::BitField;
use core::marker::PhantomData;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr::NonNull;
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};

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

pub trait EntryFilter {
    fn is_valid(depth: u8, index: usize) -> bool;
}

pub struct NullEntryFilter;
impl EntryFilter for NullEntryFilter {
    #[inline]
    fn is_valid(_depth: u8, _index: usize) -> bool {
        true
    }
}

pub struct MtoId(AtomicU64);
impl MtoId {
    pub const fn new() -> MtoId {
        MtoId(AtomicU64::new(1)) // 0 is reserved
    }

    fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

/// A multilevel table object (MTO) is an abstraction for pagetable-like structures and is used
/// for page tables and capability tables.
pub struct MultilevelTableObject<
    T: Send,
    P: AsLevel<T, TABLE_SIZE> + Send,
    C: LeafCache,
    L: EntryFilter,
    const BITS: u8,
    const LEVELS: u8,
    const START_BIT: u8,
    const TABLE_SIZE: usize,
> {
    root: Mutex<KernelPageRef<Level<T, P, TABLE_SIZE>>>,
    cache: Mutex<C>,
    id: u64,
    _phantom: PhantomData<L>,
}

unsafe impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        C: LeafCache,
        L: EntryFilter,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > Send for MultilevelTableObject<T, P, C, L, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
}

unsafe impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        C: LeafCache,
        L: EntryFilter,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > Sync for MultilevelTableObject<T, P, C, L, BITS, LEVELS, START_BIT, TABLE_SIZE>
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
    /// Assuming this is a leaf level, call drop on the inner value and release its memory.
    pub unsafe fn drop_and_release_assuming_leaf(&mut self) {
        KernelPageRef::from_raw(NonNull::from(self).cast::<T>());
    }

    /// Looks up an entry by a pointer.
    ///
    /// O(levels).
    pub unsafe fn lookup_entry<L: EntryFilter, F: FnOnce(u8, &mut P) -> R, R>(
        &mut self,
        ptr: u64,
        levels: u8,
        start_bit: u8,
        bits: u8,
        cb: F,
    ) -> Option<R> {
        assert!(levels > 0);
        let mut current = NonNull::from(self);

        for i in 0..levels {
            let index = ptr_to_index(ptr, i, start_bit, bits);
            if !L::is_valid(i, index) {
                return None;
            }
            let entry = &mut current.as_mut().table[index];
            if i == levels - 1 {
                return Some(cb(i, entry));
            }
            current = match entry.as_level() {
                Some(x) => x,
                None => return Some(cb(i, entry)),
            }
        }

        unreachable!()
    }

    pub unsafe fn lookup_leaf_entry<L: EntryFilter, F: FnOnce(&mut P) -> R, R>(
        &mut self,
        ptr: u64,
        levels: u8,
        start_bit: u8,
        bits: u8,
        cb: F,
    ) -> Option<R> {
        self.lookup_entry::<L, _, _>(ptr, levels, start_bit, bits, |depth, entry| {
            if depth == levels - 1 {
                Some(cb(entry))
            } else {
                None
            }
        })?
    }

    /// Convenience function for looking up a leaf entry. Internally calls `lookup_entry`.
    pub unsafe fn lookup<L: EntryFilter, F: FnOnce(&mut T) -> R, R>(
        &mut self,
        ptr: u64,
        levels: u8,
        start_bit: u8,
        bits: u8,
        cb: F,
    ) -> Option<R> {
        Some(
            self.lookup_leaf_entry::<L, _, _>(ptr, levels, start_bit, bits, |entry| match entry
                .as_level()
            {
                Some(mut x) => Some(cb(&mut *x.as_mut().value)),
                None => None,
            })??,
        )
    }
}

/// The entry type in a MTO must implement the AsLevel trait.
///
/// If the type has a Drop implementation, it should only cleanup the resources associated
/// with itself and the direct Level pointer it manages, without attempting to look into union
/// fields of Level. Recursive cleanup on all levels is managed by the caller.
pub trait AsLevel<T: Send, const TABLE_SIZE: usize>: Sized + Send {
    fn as_level(&mut self) -> Option<NonNull<Level<T, Self, TABLE_SIZE>>>;
    fn attach_level(&mut self, level: NonNull<Level<T, Self, TABLE_SIZE>>, leaf: bool);
    fn clear_level(&mut self);
}

impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        C: LeafCache,
        L: EntryFilter,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > Drop for MultilevelTableObject<T, P, C, L, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
    fn drop(&mut self) {
        self.foreach_entry(|depth, _, entry| {
            if let Some(mut level) = entry.as_level() {
                // If this is a leaf node, it contains a value of type T and we should drop it.
                // Otherwise, it contains a table and should have been cleaned up in previous iterations,
                // by the following drop_in_place.
                unsafe {
                    if depth == LEVELS - 1 {
                        level.as_mut().drop_and_release_assuming_leaf();
                    } else {
                        KernelPageRef::from_raw(level);
                    }
                }
            }

            // Call drop on the entry itself.
            // This will clean up the resources associated with the entry.
            unsafe {
                core::ptr::drop_in_place(entry);
            }
            Ok(())
        })
        .unwrap();
    }
}

impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Send,
        C: LeafCache,
        L: EntryFilter,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > MultilevelTableObject<T, P, C, L, BITS, LEVELS, START_BIT, TABLE_SIZE>
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

    /// Extracts index of a specific level from a pointer.
    #[inline]
    pub fn ptr_to_index(ptr: u64, current_level: u8) -> usize {
        ptr_to_index(ptr, current_level, START_BIT, BITS)
    }

    #[inline]
    fn index_to_ptr(prev_ptr: u64, current_level: u8, current_index: usize) -> u64 {
        index_to_ptr(prev_ptr, current_level, current_index, START_BIT, BITS)
    }

    /// Recursive foreach implementation. (post-order)
    unsafe fn inner_foreach_postorder<L2: EntryFilter, F: FnMut(u8, u64, &mut P) -> KernelResult<()>>(
        mut current: NonNull<Level<T, P, TABLE_SIZE>>,
        cb: &mut F,
        depth: u8,
        partial_ptr: u64,
    ) -> KernelResult<()> {
        assert!(depth < LEVELS);
        for (i, entry) in current.as_mut().table.iter_mut().enumerate() {
            if !L2::is_valid(depth, i) {
                continue;
            }
            let new_ptr = Self::index_to_ptr(partial_ptr, depth, i);
            if depth != LEVELS - 1 {
                if let Some(inner) = entry.as_level() {
                    Self::inner_foreach_postorder::<L2, F>(inner, cb, depth + 1, new_ptr)?;
                }
            }
            cb(depth, new_ptr, entry)?;
        }
        Ok(())
    }

    /// Iterates over all entries in the current MTO except the root table itself. (in post-order)
    pub fn foreach_entry_with_filter<L2: EntryFilter, F: FnMut(u8, u64, &mut P) -> KernelResult<()>>(
        &self,
        mut cb: F,
    ) -> KernelResult<()> {
        let mut root = self.root.lock();
        unsafe { Self::inner_foreach_postorder::<L2, _>(root.as_nonnull(), &mut cb, 0, 0) }
    }

    /// Iterates over all entries in the current MTO except the root table itself. (in post-order)
    pub fn foreach_entry<F: FnMut(u8, u64, &mut P) -> KernelResult<()>>(
        &self,
        cb: F,
    ) -> KernelResult<()> {
        self.foreach_entry_with_filter::<L, F>(cb)
    }

    /// Looks up an entry by a pointer in this MTO.
    ///
    /// O(LEVELS).
    pub fn lookup_entry<F: FnOnce(u8, &mut P) -> R, R>(&self, ptr: u64, cb: F) -> Option<R> {
        let mut root = self.root.lock();
        unsafe { root.lookup_entry::<L, _, _>(ptr, LEVELS, START_BIT, BITS, cb) }
    }

    pub fn lookup_leaf_entry_with_filter<L2: EntryFilter, F: FnOnce(&mut P) -> R, R>(
        &self,
        ptr: u64,
        cb: F,
    ) -> Option<R> {
        let mut root = self.root.lock();
        let mut cache = self.cache.lock();
        if let Some(x) = cache.lookup(ptr) {
            Some(cb(unsafe { &mut *(x.as_ptr() as *mut P) }))
        } else {
            unsafe {
                root.lookup_leaf_entry::<L2, _, _>(ptr, LEVELS, START_BIT, BITS, |x| {
                    cache.insert(
                        ptr,
                        NonNull::new_unchecked(x as *mut P as *mut OpaqueCacheElement),
                    );
                    cb(x)
                })
            }
        }
    }

    pub fn lookup_leaf_entry<F: FnOnce(&mut P) -> R, R>(&self, ptr: u64, cb: F) -> Option<R> {
        self.lookup_leaf_entry_with_filter::<L, _, _>(ptr, cb)
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
        cb(&mut **root)
    }

    /// Attaches a leaf.
    pub fn attach_leaf(&self, ptr: u64, leaf: KernelPageRef<T>) -> KernelResult<()> {
        self.lookup_leaf_entry(ptr, |entry| {
            // Release the old leaf, if any.
            if let Some(mut old) = entry.as_level() {
                unsafe {
                    old.as_mut().drop_and_release_assuming_leaf();
                }
            }
            entry.attach_level(KernelPageRef::into_raw(leaf).cast::<_>(), true);
        })?;
        Ok(())
    }

    /// Clones and returns the reference to a given leaf.
    pub fn get_leaf(&self, ptr: u64) -> KernelResult<KernelPageRef<T>> {
        Ok(self.lookup_leaf_entry(ptr, |entry| {
            if let Some(level) = entry.as_level() {
                let level = unsafe { KernelPageRef::from_raw(level.cast::<T>()) };
                let ret = level.clone();
                KernelPageRef::into_raw(level); // don't drop
                Some(ret)
            } else {
                None
            }
        })??)
    }

    /// Drops a leaf entry.
    ///
    /// This does not currently drop non-leaf levels and should be fixed.
    pub fn drop_leaf(&self, ptr: u64) -> KernelResult<()> {
        Ok(self.lookup_leaf_entry(ptr, |entry| {
            if let Some(mut level) = entry.as_level() {
                unsafe {
                    level.as_mut().drop_and_release_assuming_leaf();
                }
                entry.clear_level();
            }
        })?)
    }
}

impl<
        T: Send,
        P: AsLevel<T, TABLE_SIZE> + Default + Send,
        C: LeafCache,
        L: EntryFilter,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > MultilevelTableObject<T, P, C, L, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
    fn default_level_table() -> KernelResult<KernelPageRef<Level<T, P, TABLE_SIZE>>> {
        unsafe {
            let mut table: MaybeUninit<KernelPageRef<Level<T, P, TABLE_SIZE>>> =
                KernelPageRef::new_uninit()?;
            for entry in (*table.as_mut_ptr()).table.iter_mut() {
                core::ptr::write(entry, P::default());
            }
            Ok(table.assume_init())
        }
    }

    /// Creates an MTO.
    pub fn new(mto_id: &MtoId) -> KernelResult<Self> {
        Self::check();
        let root = Self::default_level_table()?;
        Ok(MultilevelTableObject {
            root: Mutex::new(root),
            cache: Mutex::new(C::new()),
            id: mto_id.next(),
            _phantom: PhantomData,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// Builds the leaf entry, without the leaf itself.
    pub fn make_leaf_entry(&self, ptr: u64) -> KernelResult<()> {
        while self.lookup_entry(ptr, |depth, entry| -> KernelResult<bool> {
            if depth == LEVELS - 1 {
                return Ok(false);
            }

            let next_level = Self::default_level_table()?;
            entry.attach_level(KernelPageRef::into_raw(next_level), false);

            Ok(true)
        })?? {}
        Ok(())
    }
}

#[inline]
fn ptr_to_index(ptr: u64, current_level: u8, start_bit: u8, bits: u8) -> usize {
    let start = start_bit - current_level * bits;
    ptr.get_bits((start + 1 - bits) as usize..=start as usize) as usize
}

#[inline]
fn index_to_ptr(
    mut prev_ptr: u64,
    current_level: u8,
    current_index: usize,
    start_bit: u8,
    bits: u8,
) -> u64 {
    let start = start_bit - current_level * bits;
    prev_ptr.set_bits(
        (start + 1 - bits) as usize..=start as usize,
        current_index as u64,
    );
    prev_ptr
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
