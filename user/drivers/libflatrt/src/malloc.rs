use flatmk_sys::spec;
use alloc::boxed::Box;
use byteorder::{ByteOrder, LittleEndian};

#[no_mangle]
pub unsafe extern "C" fn libmalloc_init(heap_start: u64, rpt: u64) {
    flatrt_allocator::init(heap_start as usize, spec::RootPageTable::new(spec::CPtr::new(rpt)));
}

#[no_mangle]
pub unsafe extern "C" fn malloc(n: usize) -> *mut u8 {
    // Alloc memory and write size prefix.
    let mut mem: Box<[u8]> = Box::new_uninit_slice(n + 8).assume_init();
    LittleEndian::write_u64(&mut *mem, n as u64);
    (Box::into_raw(mem) as *mut u8).offset(8)
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    // Offset to the size prefix.
    let ptr = ptr.offset(-8);

    // Read alloc size and construct slice.
    let mut alloc_size = LittleEndian::read_u64(core::slice::from_raw_parts(ptr, 8)) as usize;
    Box::from_raw(core::slice::from_raw_parts_mut(ptr, alloc_size + 8));
}

#[no_mangle]
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut u8 {
    let n = count * size;
    let mem = malloc(n);
    for i in 0..n {
        *mem.offset(i as isize) = 0;
    }
    mem
}

#[no_mangle]
pub unsafe extern "C" fn realloc(old: *mut u8, n: usize) -> *mut u8 {
    // Offset to the size prefix.
    let old = old.offset(-8);

    // Read alloc size and construct slice.
    let mut alloc_size = LittleEndian::read_u64(core::slice::from_raw_parts(old, 8)) as usize;

    // Do not resize if the new size is not larger than the previous size.
    if alloc_size >= n {
        return old;
    }

    // The old slice, including the size prefix.
    // Automatically dropped at return.
    let old_slice = Box::from_raw(core::slice::from_raw_parts_mut(old, alloc_size + 8));

    // Allocate new slice.
    let new = malloc(n);
    core::slice::from_raw_parts_mut(new, n)[..alloc_size].copy_from_slice(&old_slice[8..8 + alloc_size]);
    new
}

#[no_mangle]
pub unsafe extern "C" fn valloc(n: usize) -> *mut u8 {
    unimplemented!()
}

#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(n: usize) -> *mut u8 {
    unimplemented!()
}