use crate::arch;
use crate::error::*;
use crate::kobj::*;
use crate::paging::phys_to_virt;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;
use spin::Mutex;
use x86_64::structures::paging::page_table::PageTableEntry;

pub struct MultilevelTableObject<
    T,
    P: AsLevel<T, TABLE_SIZE>,
    const BITS: u8,
    const LEVELS: u8,
    const START_BIT: u8,
    const TABLE_SIZE: usize,
> {
    root: Mutex<NonNull<Level<T, P, TABLE_SIZE>>>,
}

pub union Level<T, P: AsLevel<T, TABLE_SIZE>, const TABLE_SIZE: usize> {
    table: ManuallyDrop<[P; TABLE_SIZE]>,
    value: ManuallyDrop<T>,
}

pub trait AsLevel<T, const TABLE_SIZE: usize>: Sized {
    fn as_level(&mut self) -> Option<NonNull<Level<T, Self, TABLE_SIZE>>>;
    fn user_address(&self) -> Option<u64> {
        None
    }
}

impl<
        T,
        P: AsLevel<T, TABLE_SIZE>,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > Retype for MultilevelTableObject<T, P, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
}
impl<
        T,
        P: AsLevel<T, TABLE_SIZE>,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > Notify for MultilevelTableObject<T, P, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
    unsafe fn will_drop(&mut self, owner: &dyn LikeKernelObject) {
        self.foreach_entry(|depth, entry| {
            if let Some(mut entry) = entry.as_level() {
                let entry = entry.as_mut();
                if depth == LEVELS - 1 {
                    ManuallyDrop::drop(&mut entry.value);
                } else {
                    ManuallyDrop::drop(&mut entry.table);
                }
            }
            if let Some(uaddr) = entry.user_address() {
                if let Ok(uaddr) = x86_64::VirtAddr::try_new(uaddr) {
                    owner.return_user_page(uaddr);
                }
            }
            Ok(())
        })
        .unwrap();
    }
}

pub type Page = [u8; 4096];
pub type PageTableObject = MultilevelTableObject<Page, PageTableEntry, 9, 4, 47, 512>;

impl AsLevel<Page, 512> for PageTableEntry {
    fn as_level(&mut self) -> Option<NonNull<Level<Page, Self, 512>>> {
        NonNull::new(phys_to_virt(self.addr()).as_mut_ptr())
    }
}

impl<
        T,
        P: AsLevel<T, TABLE_SIZE>,
        const BITS: u8,
        const LEVELS: u8,
        const START_BIT: u8,
        const TABLE_SIZE: usize,
    > MultilevelTableObject<T, P, BITS, LEVELS, START_BIT, TABLE_SIZE>
{
    const fn check() {
        _check_size(
            core::mem::size_of::<Level<T, P, TABLE_SIZE>>(),
            arch::PAGE_SIZE,
        );
        _check_bounds(BITS, LEVELS, START_BIT);
        _check_bit_to_size(BITS, TABLE_SIZE);
    }

    pub unsafe fn new(inner: NonNull<Level<T, P, TABLE_SIZE>>) -> Self {
        Self::check();
        MultilevelTableObject {
            root: Mutex::new(inner),
        }
    }

    #[inline]
    fn ptr_to_index(ptr: u64, current_level: u8) -> usize {
        let start = START_BIT + current_level * BITS - 1;
        ((ptr << (64 - start as usize)) >> (64 - BITS as usize)) as usize
    }

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

    pub fn foreach_entry<F: FnMut(u8, &mut P) -> KernelResult<()>>(
        &self,
        mut cb: F,
    ) -> KernelResult<()> {
        let mut root = self.root.lock();
        unsafe { Self::inner_foreach(*root, &mut cb, 0) }
    }

    pub fn lookup_entry<F: FnOnce(u8, &mut P) -> R, R>(&self, ptr: u64, cb: F) -> R {
        let mut root = self.root.lock();
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
