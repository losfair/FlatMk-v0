//! Definitions of static capabilities used in the init task.

use flatmk_sys::spec;

macro_rules! define_task {
    ($name:ident, $base:expr) => {
        pub mod $name {
            use flatmk_sys::spec;

            pub static TASK: spec::BasicTask = unsafe { spec::BasicTask::new(spec::CPtr::new($base)) };

            pub static CAPSET: spec::CapabilitySet = unsafe { spec::CapabilitySet::new(spec::CPtr::new($base + 1)) };
    
            pub static RPT: spec::RootPageTable = unsafe { spec::RootPageTable::new(spec::CPtr::new($base + 2)) };

            pub static ENDPOINT: spec::TaskEndpoint = unsafe { spec::TaskEndpoint::new(spec::CPtr::new($base + 3)) };
        }
    };
}

/// The init task itself.
pub static ME: spec::BasicTask = unsafe { spec::BasicTask::new(spec::CPtr::new(0x00)) };

/// The `RootTask` capability.
pub static ROOT_TASK: spec::RootTask = unsafe { spec::RootTask::new(spec::CPtr::new(0x01)) };

/// The root page table of the init task.
pub static RPT: spec::RootPageTable = unsafe { spec::RootPageTable::new(spec::CPtr::new(0x02)) };

/// The capability set of the init task.
pub static CAPSET: spec::CapabilitySet = unsafe { spec::CapabilitySet::new(spec::CPtr::new(0x03)) };

/// Capability to print a character to the serial port.
pub static PUTCHAR: spec::DebugPutchar = unsafe { spec::DebugPutchar::new(spec::CPtr::new(0x04)) };

/// Temporary capability buffer.
pub static BUFFER: spec::CPtr = unsafe { spec::CPtr::new(0x05) };

/// The idle task.
pub static IDLE: spec::BasicTask = unsafe { spec::BasicTask::new(spec::CPtr::new(0x06)) };

/// Reply endpoint of the idle task.
pub static IDLE_REPLY: spec::TaskEndpoint = unsafe { spec::TaskEndpoint::new(spec::CPtr::new(0x07)) };

define_task!(scheduler, 0x200);

/// Initializes all the static capabilities defined above.
/// 
/// Must be called before using any of those caps.
pub unsafe fn initialize_static_caps() {
    if ROOT_TASK.new_debug_putchar(PUTCHAR.cptr()) < 0 {
        panic!("initialize_static_caps: Cannot create DebugPutchar capability.");
    }

    if ME.fetch_root_page_table(RPT.cptr()) < 0 {
        panic!("initialize_static_caps: Cannot fetch root page table.");
    }

    if ME.fetch_capset(CAPSET.cptr()) < 0 {
        panic!("initialize_static_caps: Cannot fetch capability set.");
    }

    if CAPSET.make_leaf(scheduler::TASK.cptr()) < 0 {
        panic!("initialize_static_caps: Cannot allocate leaf for scheduler.");
    }
}
