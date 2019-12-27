#![no_std]

use flatruntime_user::ipc::*;
use flatruntime_user::task::{Task, ROOT_CAPSET};
use flatruntime_user::thread::{this_task};
use flatruntime_user::error::*;

pub struct SchedYield {
    endpoint: TaskEndpoint,
}

impl SchedYield {
    pub const unsafe fn new(endpoint: TaskEndpoint) -> SchedYield {
        SchedYield {
            endpoint,
        }
    }

    pub fn endpoint(&self) -> &TaskEndpoint {
        &self.endpoint
    }

    pub fn yield_busy(&self) {
        let mut payload = FastIpcPayload::default();
        payload.data[0] = 1;
        self.endpoint.call(&mut payload).expect("yield_busy: IPC call failed");
    }

    pub fn yield_lazy(&self) -> ! {
        let mut payload = FastIpcPayload::default();
        payload.data[0] = 0;
        self.endpoint.call(&mut payload).expect("yield_lazy: IPC call failed");
        panic!("yield_lazy should never return");
    }

    pub fn sleep(&self, ns: u64) {
        let mut payload = FastIpcPayload::default();
        payload.data[0] = 2;
        payload.data[1] = ns;
        self.endpoint.call(&mut payload).expect("sleep: IPC call failed");
    }
}

pub struct SchedAdd {
    endpoint: TaskEndpoint,
}

impl SchedAdd {
    pub const unsafe fn new(endpoint: TaskEndpoint) -> SchedAdd {
        SchedAdd {
            endpoint,
        }
    }

    pub fn endpoint(&self) -> &TaskEndpoint {
        &self.endpoint
    }

    pub fn add(&self, task: TaskEndpoint) -> KernelResult<()> {
        this_task().put_ipc_cap(1, task.into_cptr())?;
        let mut payload = FastIpcPayload::default();
        self.endpoint.call(&mut payload).expect("add: IPC call failed");
        if payload.data[0] == 0 {
            Ok(())
        } else {
            Err(KernelError::InvalidArgument)
        }
    }
}
