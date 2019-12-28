use crate::error::*;
use crate::syscall::{CPtr, INVALID_CAP};
use core::convert::TryFrom;
use core::mem::ManuallyDrop;
use crate::capset::CapType;
use crate::task::ROOT_CAPSET;
use crate::thread::this_task;

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
    IsCapTransfer = 1,
    IsTaggable = 2,
    IsReply = 3,
    SetTag = 4,
    GetTag = 5,
    Ping = 6,
}

pub struct TaskEndpoint {
    cap: CPtr,
}

impl TaskEndpoint {
    pub const unsafe fn new(cap: CPtr) -> TaskEndpoint {
        TaskEndpoint { cap }
    }

    pub fn checked_new(cap: CPtr) -> KernelResult<TaskEndpoint> {
        if ROOT_CAPSET.get_cap_type(&cap)? == CapType::TaskEndpoint as u32 {
            Ok(unsafe { TaskEndpoint::new(cap) })
        } else {
            Err(KernelError::InvalidArgument)
        }
    }

    pub fn cptr(&self) -> &CPtr {
        &self.cap
    }

    pub fn into_cptr(self) -> CPtr {
        self.cap
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

    pub fn set_tag(&self, tag: u64) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(IpcRequest::SetTag as u32 as i64, tag as _, 0, 0).map(|_| ())
        }
    }

    pub fn get_tag(&self) -> KernelResult<u64> {
        unsafe {
            self.cap.call_result(IpcRequest::GetTag as u32 as i64, 0, 0, 0).map(|x| x as u64)
        }
    }

    pub fn ping(&self) -> KernelResult<()> {
        unsafe {
            self.cap.call_result(IpcRequest::Ping as u32 as i64, 0, 0, 0).map(|x| ())
        }
    }
}

pub fn ipc_return() -> KernelError {
    this_task().ipc_return()
}

pub unsafe fn ipc_return_to_unowned(cptr: ManuallyDrop<CPtr>) -> KernelError {
    match cptr.call_result(
        IpcRequest::SwitchTo as u32 as i64,
        0, 0, 0,
    ) {
        Ok(_) => {
            KernelError::InvalidState
        },
        Err(e) => e,
    }
}

pub unsafe fn ipc_endpoint_is_cap_transfer(cptr: &CPtr) -> bool {
    let result = cptr.call_result(
        IpcRequest::IsCapTransfer as u32 as i64,
        0, 0, 0,
    ).expect("ipc_endpoint_is_cap_transfer: call_result returned error");
    result == 1
}

pub unsafe fn ipc_endpoint_is_taggable(cptr: &CPtr) -> bool {
    let result = cptr.call_result(
        IpcRequest::IsTaggable as u32 as i64,
        0, 0, 0,
    ).expect("ipc_endpoint_is_taggable: call_result returned error");
    result == 1
}

pub unsafe fn ipc_endpoint_is_reply(cptr: &CPtr) -> bool {
    let result = cptr.call_result(
        IpcRequest::IsReply as u32 as i64,
        0, 0, 0,
    ).expect("ipc_endpoint_is_reply: call_result returned error");
    result == 1
}

#[macro_export]
macro_rules! ipc_entry_with_context {
    ($name:ident, $internal_name:ident, $context:ident, $tag:ident, $body:block) => {
        #[no_mangle]
        extern "C" fn $internal_name($context: u64, $tag: u64) -> ! {
            $body
        }

        #[naked]
        unsafe extern "C" fn $name() {
            asm!(
                concat!(r#"
                    mov %gs:8, %rsp
                    jmp "#, stringify!($internal_name), r#"
                "#) :::: "volatile"
            );
            loop {}
        }
    };
}

#[macro_export]
macro_rules! ipc_entry {
    ($name:ident, $internal_name:ident, $body:block) => {
        ipc_entry_with_context!($name, $internal_name, _context, _tag, $body);
    };
}

#[macro_export]
macro_rules! ipc_entry_with_context_result_fastipc {
    ($name:ident, $internal_name:ident, $payload:ident, $context:ident, $tag:ident, $body:block) => {
        ipc_entry_with_context!($name, $internal_name, ipc_context, ipc_tag, {
            fn handler($payload: &mut $crate::ipc::FastIpcPayload, $context: u64, $tag: u64) -> $crate::error::KernelResult<i64> {
                $body
            }

            let mut payload = $crate::ipc::FastIpcPayload::default();
            $crate::ipc::fastipc_read(&mut payload);

            let result = handler(&mut payload, ipc_context, ipc_tag);
            
            match result {
                Ok(x) => {
                    payload.data[0] = x as _;
                }
                Err(e) => {
                    payload.data[0] = e as i32 as _;
                }
            }
            $crate::ipc::fastipc_write(&payload);
            $crate::ipc::ipc_return();
            unreachable!()
        });
    };
}