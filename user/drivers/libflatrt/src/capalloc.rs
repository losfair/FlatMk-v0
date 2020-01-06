use flatmk_sys::spec;

#[no_mangle]
pub unsafe extern "C" fn libcapalloc_init(capset: spec::CPtr, dynamic_base: u64) {
    flatrt_capalloc::init(spec::CapabilitySet::new(capset), dynamic_base);
}

#[no_mangle]
pub unsafe extern "C" fn libcapalloc_allocate() -> spec::CPtr {
    flatrt_capalloc::allocate()
}

#[no_mangle]
pub unsafe extern "C" fn libcapalloc_release(cptr: spec::CPtr) {
    flatrt_capalloc::release(cptr)
}
