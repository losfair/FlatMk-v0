#![no_std]

use flatruntime_user::ipc::*;
use flatruntime_user::task::{Task, ROOT_CAPSET};
use flatruntime_user::thread::{this_task};
use flatruntime_user::error::*;
use flatruntime_user::mm::{UserPteFlags, RootPageTable};

pub struct ShmemCreate {
    endpoint: TaskEndpoint,
}

impl ShmemCreate {
    pub const unsafe fn new(endpoint: TaskEndpoint) -> ShmemCreate {
        ShmemCreate {
            endpoint,
        }
    }

    pub fn endpoint(&self) -> &TaskEndpoint {
        &self.endpoint
    }

    pub fn create(&self, size: usize) -> KernelResult<ShmemMap> {
        let mut payload = FastIpcPayload::default();
        payload.data[0] = size as _;
        self.endpoint.call(&mut payload)?;

        if payload.data[0] == 0 {
            Ok(unsafe {
                ShmemMap::new(
                    TaskEndpoint::new(this_task().fetch_ipc_cap(1)?)
                )
            })
        } else {
            Err(KernelError::EmptyObject)
        }
    }
}

pub struct ShmemMap {
    endpoint: TaskEndpoint
}

impl ShmemMap {
    pub const unsafe fn new(endpoint: TaskEndpoint) -> ShmemMap {
        ShmemMap {
            endpoint,
        }
    }

    pub fn endpoint(&self) -> &TaskEndpoint {
        &self.endpoint
    }

    pub fn map(&self, rpt: &RootPageTable, vaddr: u64, len: usize, flags: UserPteFlags) -> KernelResult<()> {
        this_task().put_ipc_cap(1, ROOT_CAPSET.clone_cap(rpt.cptr())?)?;

        let mut payload = FastIpcPayload::default();
        payload.data[0] = 0; // map
        payload.data[1] = vaddr;
        payload.data[2] = len as _;
        payload.data[3] = flags.bits();
        self.endpoint.call(&mut payload)?;

        if payload.data[0] == 0 {
            Ok(())
        } else {
            Err(KernelError::EmptyObject)
        }
    }
}
