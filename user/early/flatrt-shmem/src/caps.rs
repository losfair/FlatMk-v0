//! Definitions of static capabilities.

use flatmk_sys::spec;


// These capabilities are provided by the init task.

pub static ME: spec::BasicTask = unsafe { spec::BasicTask::new(spec::CPtr::new(0x00)) };

pub static PUTCHAR: spec::DebugPutchar = unsafe { spec::DebugPutchar::new(spec::CPtr::new(0x01)) };

// These capabilities are created by ourselves.

pub static RPT: spec::RootPageTable = unsafe { spec::RootPageTable::new(spec::CPtr::new(0x08)) };

pub static CAPSET: spec::CapabilitySet = unsafe { spec::CapabilitySet::new(spec::CPtr::new(0x09)) };

pub static IPC_HANDLER: spec::BasicTask = unsafe { spec::BasicTask::new(spec::CPtr::new(0x0a)) };

pub static ENDPOINT_SHMEM_CREATE: spec::TaskEndpoint = unsafe { spec::TaskEndpoint::new(spec::CPtr::new(0x0b)) };

/// Derive our own capabilities from the provided ones.
pub unsafe fn init() {
    if ME.fetch_root_page_table(RPT.cptr()) < 0 {
        panic!("flatrt-shmem: init: Cannot fetch root page table.");
    }

    if ME.fetch_capset(CAPSET.cptr()) < 0 {
        panic!("flatrt-shmem: init: Cannot fetch capability set.");
    }
}
