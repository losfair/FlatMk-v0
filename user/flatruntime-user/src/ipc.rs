use crate::error::*;
use crate::syscall::{CPtr, INVALID_CAP};
use core::convert::TryFrom;
use crate::thread::this_ipc_base;

pub fn fastipc_read(out: &mut FastIpcPayload) {
    unsafe {
        asm!(
            r#"
            mov %xmm0, 0($0)
            mov %xmm1, 8($0)
            mov %xmm2, 16($0)
            mov %xmm3, 24($0)
            mov %xmm4, 32($0)
            mov %xmm5, 40($0)
            mov %xmm6, 48($0)
            mov %xmm7, 56($0)
        "# : : "r"(out) : : "volatile");
    }
}

pub fn fastipc_write(data: &FastIpcPayload) {
    unsafe {
        asm!(
            r#"
            mov 0($0), %xmm0
            mov 8($0), %xmm1
            mov 16($0), %xmm2
            mov 24($0), %xmm3
            mov 32($0), %xmm4
            mov 40($0), %xmm5
            mov 48($0), %xmm6
            mov 56($0), %xmm7
        "# : : "r"(data) : : "volatile");
    }
}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct FastIpcPayload {
    pub data: [u64; 8],
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum IpcRequest {
    SwitchTo = 0,
    IsTransparent = 1,
}

pub struct TaskEndpoint {
    cap: CPtr,
}

impl TaskEndpoint {
    pub unsafe fn new(cap: CPtr) -> TaskEndpoint {
        TaskEndpoint { cap }
    }

    pub fn cptr(&self) -> &CPtr {
        &self.cap
    }

    pub fn call(&self, payload: &mut FastIpcPayload) -> KernelResult<()> {
        fastipc_write(payload);

        match unsafe {
            self.cap.call(
                IpcRequest::SwitchTo as u32 as i64,
                INVALID_CAP as _,
                INVALID_CAP as _,
                INVALID_CAP as _,
            )
        } {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            _ => {
                fastipc_read(payload);
                Ok(())
            }
        }
    }
}

pub fn ipc_return() -> ! {
    unsafe {
        ipc_return_to(CPtr::new(this_ipc_base()))
    }
}

pub unsafe fn ipc_return_to(cptr: CPtr) -> ! {
    cptr.call_result(
        IpcRequest::SwitchTo as u32 as i64,
        0, 0, 0,
    ).expect("ipc_return_to: cannot send reply");
    unreachable!()
}

pub unsafe fn ipc_endpoint_is_transparent(cptr: &CPtr) -> bool {
    let result = cptr.call_result(
        IpcRequest::IsTransparent as u32 as i64,
        0, 0, 0,
    ).expect("ipc_endpoint_is_transparent: call_result returned error");
    result == 1
}
