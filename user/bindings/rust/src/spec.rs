use num_enum::TryFromPrimitive;
use bitflags::bitflags;

pub struct CPtr(u64);

impl CPtr {
    pub const unsafe fn new(inner: u64) -> Self {
        CPtr(inner)
    }

    pub fn index(&self) -> u64 {
        self.0
    }

    pub unsafe fn call(&self, p0: i64, p1: i64, p2: i64, p3: i64) -> i64 {
        unimplemented!()
    }
}

include!("../generated/flatmk_spec.rs");
