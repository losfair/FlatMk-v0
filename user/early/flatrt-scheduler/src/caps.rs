//! Definitions of static capabilities.

use flatmk_sys::spec;


// These capabilities are provided by the init task.

pub static ME: spec::BasicTask = unsafe { spec::BasicTask::new(spec::CPtr::new(0x00)) };

pub static IDLE_REPLY: spec::TaskEndpoint = unsafe { spec::TaskEndpoint::new(spec::CPtr::new(0x01)) };

pub static TIMER_INTERRUPT: spec::Interrupt = unsafe { spec::Interrupt::new(spec::CPtr::new(0x02)) };

pub static PIT_CHANNEL_0: spec::X86IoPort = unsafe { spec::X86IoPort::new(spec::CPtr::new(0x03)) };

pub static PIT_MODE_COMMAND: spec::X86IoPort = unsafe { spec::X86IoPort::new(spec::CPtr::new(0x04)) };

pub static PUTCHAR: spec::DebugPutchar = unsafe { spec::DebugPutchar::new(spec::CPtr::new(0x05)) };

// These capabilities are created by ourselves.

pub static BUFFER: spec::CPtr = unsafe { spec::CPtr::new(0x0b) };

pub static RPT: spec::RootPageTable = unsafe { spec::RootPageTable::new(spec::CPtr::new(0x0c)) };

pub static CAPSET: spec::CapabilitySet = unsafe { spec::CapabilitySet::new(spec::CPtr::new(0x0d)) };

pub static THREAD_TIMER: spec::BasicTask = unsafe { spec::BasicTask::new(spec::CPtr::new(0x0e)) };

pub static THREAD_TIMER_ENDPOINT: spec::TaskEndpoint = unsafe { spec::TaskEndpoint::new(spec::CPtr::new(0x0f)) };

pub static THREAD_SCHED_API: spec::BasicTask = unsafe { spec::BasicTask::new(spec::CPtr::new(0x10)) };

pub static THREAD_SCHED_CREATE_ENDPOINT: spec::TaskEndpoint = unsafe { spec::TaskEndpoint::new(spec::CPtr::new(0x11)) };

pub static THREAD_SCHED_YIELD_ENDPOINT: spec::TaskEndpoint = unsafe { spec::TaskEndpoint::new(spec::CPtr::new(0x13)) };

/// Derive our own capabilities from the provided ones.
pub unsafe fn init() {
    if ME.fetch_root_page_table(RPT.cptr()) < 0 {
        panic!("init: Cannot fetch root page table.");
    }

    if ME.fetch_capset(CAPSET.cptr()) < 0 {
        panic!("init: Cannot fetch capability set.");
    }
}
