#![no_std]
#![no_main]

extern crate flatrt_softuser;

use flatmk_sys::spec::{self, KernelError};

#[no_mangle]
extern "C" fn user_start() -> ! {
    unsafe {
        spec::CAP_TRIVIAL_SYSCALL.softuser_leave();
        unreachable!()
    }
}
