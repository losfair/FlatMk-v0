use crate::syscall::*;
use crate::error::*;
use crate::task::Task;
use crate::ipc::TaskEndpoint;

pub struct Interrupt {
    cap: CPtr,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum InterruptRequest {
    Bind = 0,
    Unbind = 1,
}

impl Interrupt {
    pub const unsafe fn new(cap: CPtr) -> Interrupt {
        Interrupt { cap }
    }

    pub fn cptr(&self) -> &CPtr {
        &self.cap
    }

    pub unsafe fn bind(&self, task: &Task, pc: u64, user_context: u64) -> KernelResult<()> {
        self.cap.call_result(
            InterruptRequest::Bind as u32 as _,
            task.cptr().index() as _,
            pc as _,
            user_context as _,
        ).map(|_| ())
    }

    pub unsafe fn unbind(&self) -> KernelResult<()> {
        self.cap.call_result(
            InterruptRequest::Unbind as u32 as _,
            0, 0, 0,
        ).map(|_| ())
    }
}

pub struct WaitForInterrupt {
    cap: CPtr,
}

impl WaitForInterrupt {
    pub const unsafe fn new(cap: CPtr) -> WaitForInterrupt {
        WaitForInterrupt { cap }
    }

    pub fn cptr(&self) -> &CPtr {
        &self.cap
    }

    pub fn wait(&self) -> ! {
        unsafe {
            self.cap.call_result(0, 0, 0, 0).expect("WaitForInterrupt::wait() should not return");
        }
        unreachable!()
    }
}
