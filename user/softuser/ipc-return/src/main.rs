#![no_std]
#![no_main]

extern crate flatrt_softuser;

use flatmk_sys::spec::{self, KernelError};

static mut ME: Option<spec::BasicTask> = None;

#[no_mangle]
unsafe extern "C" fn user_start(cap_me: spec::CPtr) -> ! {
    if ME.is_none() {
        ME = Some(spec::BasicTask::new(cap_me));
    }
    ME.unwrap().ipc_return();
    unreachable!()
}
