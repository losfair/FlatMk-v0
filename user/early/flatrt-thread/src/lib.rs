//! This crate builds a thread abstraction on top of FlatMk's Task capability.

#![no_std]
#![feature(naked_functions, asm, new_uninit)]

extern crate flatrt_allocator;
extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use flatmk_sys::spec;
use spin::RwLock;
use core::sync::atomic::{AtomicU64, Ordering};

/// DWARF index of SP(RSP) on x86-64.
const SP_INDEX: u64 = 7;

/// DWARF index of PC(RIP) on x86-64.
const PC_INDEX: u64 = 16;

/// DWARF index of RDI on x86-64.
const FIRST_ARG_REG_INDEX: u64 = 5;

/// DWARF index of GS_BASE on x86-64.
const TLS_REG_INDEX: u64 = 59;

/// Type of a thread entry function.
/// 
/// The argument is the source-specific tag associated with the caller task.
pub type ThreadEntry = Fn(spec::BasicTask, u64) + Send;

#[repr(C, align(16))]
struct ThreadStack([u8; 65536]);

/// A `Thread` is the backing FlatMk task + its own stack. Note that a thread does not automatically gets
/// scheduled; invoke its IPC endpoint (or pass it to a scheduler) to run the thread.
/// 
/// Threads are leaked if not explicitly released, e.g., by calling `kill()`.
pub struct Thread {
    cptr_set: ThreadCapSet,
    direct_tls: ManuallyDrop<Box<DirectTls>>,
    stack: ManuallyDrop<Box<ThreadStack>>,

    // The next index to be allocated to an IPC entry.
    next_ipc_entry_index: AtomicU64,

    /// IPC entries for endpoints shared with other tasks.
    /// 
    /// Since this can be modified after/during the thread being invoked, we need to use a RwLock
    /// for it. Mutex is not good because this is a spinlock and with multitasking there can be high latency
    /// due to contention.
    /// 
    /// Here we also cannot use more efficient, linear structures like Slab because there should never be
    /// duplicate keys.
    ipc_entries: ManuallyDrop<Box<RwLock<BTreeMap<u64, Arc<ThreadEntry>>>>>,
}

/// Capability pointers used by a thread.
pub struct ThreadCapSet {
    pub owner_task: spec::BasicTask,
    pub owner_capset: spec::CapabilitySet,
    pub new_task: spec::BasicTask,
}

/// The type stored in the platform-specific TLS register, e.g. `gs` on x86-64.
#[repr(C)]
pub struct DirectTls {
    stack_end: *mut ThreadStack,
    task: spec::CPtr,
    ipc_entries: *mut RwLock<BTreeMap<u64, Arc<ThreadEntry>>>,
}

impl Thread {
    /// Creates a `Thread`.
    pub fn new(cptr_set: ThreadCapSet) -> Thread {
        let mut stack: Box<ThreadStack> = unsafe {
            Box::new_uninit().assume_init()
        };
        let stack_end = unsafe {
            (&mut *stack as *mut ThreadStack).offset(1)
        };

        let mut ipc_entries: Box<RwLock<BTreeMap<u64, Arc<ThreadEntry>>>> = Box::new(RwLock::new(BTreeMap::new()));

        let mut direct_tls = Box::new(DirectTls {
            stack_end: stack_end,
            task: *cptr_set.new_task.cptr(),
            ipc_entries: &mut *ipc_entries,
        });
        spec::to_result(unsafe {
            cptr_set.owner_task.fetch_shallow_clone(cptr_set.new_task.cptr())
        }).expect("Thread::new: Cannot clone task.");

        spec::to_result(unsafe {
            cptr_set.new_task.set_register(TLS_REG_INDEX, &mut *direct_tls as *mut DirectTls as u64)
        }).expect(
            "Thread::new: Cannot set TLS register."
        );
        Thread {
            cptr_set,
            direct_tls: ManuallyDrop::new(direct_tls),
            stack: ManuallyDrop::new(stack),
            next_ipc_entry_index: AtomicU64::new(1),
            ipc_entries: ManuallyDrop::new(ipc_entries),
        }
    }

    /// Kills the `Thread`.
    /// 
    /// This assumes unique strong ownership to the backing task, and waits for termination. Calling `kill`
    /// from the thread itself will cause a deadlock.
    /// 
    /// Takes the current task's capability set and a temporary CPtr as a buffer.
    pub fn kill(mut self, drop_buffer: &spec::CPtr) {
        unsafe {
            // Fetch an endpoint to the thread task to observe whether the task is dropped.
            spec::to_result(self.cptr_set.new_task.fetch_task_endpoint(
                drop_buffer.index(), // No flags and not reply.
                0, // empty PC
                0, // empty user context
            )).expect("Thread::kill: Cannot fetch task endpoint.");

            // Drop the task capability.
            spec::to_result(self.cptr_set.owner_capset.drop_cap(self.cptr_set.new_task.cptr())).expect("Thread::kill: Cannot drop task capability.");

            // Wait until the backing task is actually released by the kernel.
            while spec::TaskEndpoint::new(*drop_buffer).ping() == 0 {
                // TODO: Scheduler yield?
            }

            // Drop the drop buffer.
            self.cptr_set.owner_capset.drop_cap(drop_buffer);

            // We can now safely release associated memory with this thread.
            ManuallyDrop::drop(&mut self.direct_tls);
            ManuallyDrop::drop(&mut self.stack);
            ManuallyDrop::drop(&mut self.ipc_entries);
        }
    }

    pub fn make_ipc_endpoint_raw<F: Fn(spec::BasicTask, u64) + Send + 'static>(&self, f: F) -> (u64, u64) {
        let mut ipc_entries = self.ipc_entries.write();
        let index = self.next_ipc_entry_index.fetch_add(1, Ordering::SeqCst);
        ipc_entries.insert(index, Arc::new(f));

        (ipc_entry as u64, index as u64)
    }

    /// Makes an IPC endpoint to this task with entry function `f`.
    /// 
    /// Returns the index of the entry.
    pub fn make_ipc_endpoint<F: Fn(spec::BasicTask, u64) + Send + 'static>(&self, flags: spec::TaskEndpointFlags, reply: bool, out: &spec::CPtr, f: F) -> u64 {
        let (entry, index) = self.make_ipc_endpoint_raw(f);

        unsafe {
            spec::to_result(
                self.cptr_set.new_task.fetch_task_endpoint(
                    out.index() | (flags.bits() << 48) | ((if reply { 1 } else { 0 }) << 63),
                    entry,
                    index, // context
                )
            ).expect("Thread::make_ipc_endpoint: Cannot fetch task endpoint.");

            // Entry parameters aren't used for reply. We need to set the registers directly.
            if reply {
                spec::to_result(self.cptr_set.new_task.set_register(PC_INDEX, entry)).unwrap();
                spec::to_result(self.cptr_set.new_task.set_register(FIRST_ARG_REG_INDEX, index)).unwrap();
            }
        }

        index
    }

    /// Drops an IPC endpoint.
    /// 
    /// Panics if the index doesn't exist.
    pub fn drop_ipc_endpoint(&self, index: u64) {
        let mut entries = self.ipc_entries.write();
        if entries.remove(&index).is_none() {
            panic!("Thread::drop_ipc_endpoint: Attempting to drop a non-existing entry.");
        }
    }
}

#[naked]
unsafe extern "C" fn ipc_entry() -> ! {
    asm!(
        r#"
            mov %gs:0, %rsp
            mov %gs:8, %rdx // task cptr
            mov %gs:16, %rcx // ipc entries
            jmp __flatrt_thread_ipc_entry
        "# :::: "volatile"
    );
    loop {}
}

#[no_mangle]
unsafe extern "C" fn __flatrt_thread_ipc_entry(
    context: u64,
    tag: u64,
    task: spec::CPtr,
    ipc_entries: &RwLock<BTreeMap<u64, Arc<ThreadEntry>>>,
) -> ! {
    let task = spec::BasicTask::new(task);

    // get() will return None if the endpoint is dropped.
    let entry = ipc_entries.read().get(&context).cloned();
    if let Some(entry) = entry {
        entry(task, tag);
    }

    task.ipc_return();
    unreachable!()
}
