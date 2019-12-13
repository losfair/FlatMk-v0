use crate::error::*;
use crate::syscall::{CPtr, INVALID_CAP};
use crate::task::THIS_TASK;
use core::convert::TryFrom;

mod fastipc_impl {
    #[naked]
    #[inline(never)]
    #[no_mangle]
    unsafe extern "C" fn _fastipc_write() {
        asm!(
            r#"
            mov 0(%rdi), %xmm0
            mov 8(%rdi), %xmm1
            mov 16(%rdi), %xmm2
            mov 24(%rdi), %xmm3
            mov 32(%rdi), %xmm4
            mov 40(%rdi), %xmm5
            mov 48(%rdi), %xmm6
            mov 56(%rdi), %xmm7
            retq
        "#
        );
    }

    #[naked]
    #[inline(never)]
    #[no_mangle]
    unsafe extern "C" fn _fastipc_read() {
        asm!(
            r#"
            mov %xmm0, 0(%rdi)
            mov %xmm1, 8(%rdi)
            mov %xmm2, 16(%rdi)
            mov %xmm3, 24(%rdi)
            mov %xmm4, 32(%rdi)
            mov %xmm5, 40(%rdi)
            mov %xmm6, 48(%rdi)
            mov %xmm7, 56(%rdi)
            retq
        "#
        );
    }
}

extern "C" {
    fn _fastipc_read(out: &mut FastIpcPayload);
    fn _fastipc_write(data: &FastIpcPayload);
}

#[derive(Default)]
#[repr(transparent)]
pub struct FastIpcPayload(pub [u64; 8]);

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum IpcRequest {
    SwitchToBlocking = 0,
    SwitchToNonblocking = 1,
}

pub struct IpcEndpoint {
    cap: CPtr,
}

impl IpcEndpoint {
    pub unsafe fn new(cap: CPtr) -> IpcEndpoint {
        IpcEndpoint { cap }
    }

    pub fn call(&self, payload: &mut FastIpcPayload) -> KernelResult<()> {
        unsafe {
            _fastipc_write(payload);
        }

        match unsafe {
            self.cap.call(
                IpcRequest::SwitchToBlocking as u32 as i64,
                INVALID_CAP as _,
                INVALID_CAP as _,
                INVALID_CAP as _,
            )
        } {
            x if x < 0 => Err(KernelError::try_from(x as i32).unwrap()),
            _ => {
                THIS_TASK.unblock_ipc().unwrap();
                unsafe {
                    _fastipc_read(payload);
                }
                Ok(())
            }
        }
    }
}

pub fn wait_ipc() {
    loop {
        let peer_endpoint = THIS_TASK.fetch_ipc_cap(0).unwrap();
        THIS_TASK.unblock_ipc().unwrap();
        unsafe {
            let mut payload = FastIpcPayload::default();
            _fastipc_read(&mut payload);
            payload.0[0] = payload.0[0] + payload.0[1];
            _fastipc_write(&mut payload);
        }
        match unsafe {
            peer_endpoint.call(
                IpcRequest::SwitchToBlocking as u32 as i64,
                INVALID_CAP as _,
                INVALID_CAP as _,
                INVALID_CAP as _,
            )
        } {
            x if x < 0 => panic!("unable to switch to peer endpoint: {}", x),
            _ => {}
        }
    }
}
