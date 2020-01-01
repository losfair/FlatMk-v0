//! Shared memory service for FlatRt.

#![no_std]
#![no_main]
#![feature(naked_functions, asm, new_uninit)]

#[macro_use]
extern crate lazy_static;

extern crate alloc;

#[macro_use]
mod debug;

mod caps;

use flatmk_sys::spec;
use slab::Slab;
use spin::Mutex;
use alloc::boxed::Box;
use alloc::vec::Vec;
use flatrt_fastipc::FastIpcPayload;
use flatrt_thread::{Thread, ThreadCapSet, ThreadEndpointEnv};

/// Page size.
const PAGE_SIZE: usize = 4096;

/// Start address for heap allocation.
const HEAP_START: usize = 0x7fff00000000;

/// Start address for dynamic capability allocation.
const DYN_CAP_START: u64 = 0x100000;

/// Start address for shared memory pages.
const SHMEM_PAGE_START: u64 = 0x600000000000;

/// Maximum size in bytes for all shared memory.
const MAX_SHMEM_SIZE: usize = 1048576 * 64; // 64M

lazy_static! {
    /// Shared memory page allocation state.
    static ref PAGE_ALLOC: Mutex<Slab<()>> = Mutex::new(Slab::new());

    /// IPC handler thread.
    /// 
    /// Can only be used after the environment is initialized in `_start`.
    static ref IPC_HANDLER: Mutex<Thread> = Mutex::new(Thread::new(ThreadCapSet {
        owner_task: caps::ME,
        owner_capset: caps::CAPSET,
        new_task: caps::IPC_HANDLER,
    }));
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        caps::init();

        flatrt_allocator::init(HEAP_START, caps::RPT);
        flatrt_capalloc::init(caps::CAPSET, DYN_CAP_START);

        // shmem_create endpoint.
        IPC_HANDLER.try_lock().unwrap().make_ipc_endpoint(
            spec::TaskEndpointFlags::CAP_TRANSFER,
            false,
            caps::ENDPOINT_SHMEM_CREATE.cptr(),
            on_shmem_create,
        );

        caps::ME.ipc_return();
        unreachable!()
    }
}

/// Handles shared memory creation.
fn on_shmem_create(env: ThreadEndpointEnv) {
    let mut payload = FastIpcPayload::read();
    let command = payload.data[0];
    match command {
        0 => {
            // Create shared memory.
            let size = payload.data[1] as usize;
            let mut pages: Vec<u64> = Vec::new();

            // Allocate pages.
            for _ in (0..size).step_by(PAGE_SIZE) {
                match alloc_page() {
                    Some(va) => {
                        pages.push(va);
                    }
                    None => {
                        // Allocation failed. Rollback.
                        for &va in &pages {
                            unsafe {
                                dealloc_page(va);
                            }
                        }
                        drop(pages);

                        payload.data[0] = -1i64 as _;
                        payload.write();
                        return;
                    }
                }
            }

            // Allocate and create endpoint.
            let map_cptr = flatrt_capalloc::allocate();

            let map_endpoint = IPC_HANDLER.try_lock().unwrap().make_ipc_endpoint(
                // CAP_TRANSFER is needed to receive the remote task's root page table.
                spec::TaskEndpointFlags::CAP_TRANSFER,
                false,
                &map_cptr,
                move |env| {
                    on_shmem_map(env, map_cptr, &pages)
                }
            );

            // Transfer cap.
            unsafe {
                env.task.put_ipc_cap(&map_cptr, 1);
            }

            // Done. return code = 0
            payload.data[0] = 0;
            payload.write();
        }
        _ => {
            payload.data[0] = -1i64 as _;
            payload.write();
        }
    }
}

fn on_shmem_map(env: ThreadEndpointEnv, map_cptr: spec::CPtr, pages: &Vec<u64>) {
    let mut payload = FastIpcPayload::read();
    let command = payload.data[0];

    match command {
        0 => {
            // Map region.

            // Read start address and map len.
            let remote_start_address = payload.data[1] as usize;
            let remote_map_len = payload.data[2] as usize;

            // Check alignment and size.
            if
                remote_start_address % PAGE_SIZE != 0 ||
                remote_map_len % PAGE_SIZE != 0 ||
                remote_map_len > pages.len() * PAGE_SIZE
            {
                payload.data[0] = -1i64 as _;
                payload.write();
                return;
            }

            // Fetch IPC cap.
            let remote_rpt = flatrt_capalloc::allocate();
            unsafe {
                spec::to_result(env.task.fetch_ipc_cap(&remote_rpt, 1)).unwrap();
            }

            // Check type.
            if unsafe { caps::CAPSET.get_cap_type(&remote_rpt) } != spec::CapType::RootPageTable as i64 {
                flatrt_capalloc::release(remote_rpt);
                payload.data[0] = -1i64 as _;
                payload.write();
                return;
            }

            let remote_rpt = unsafe {
                spec::RootPageTable::new(remote_rpt)
            };

            // Map `pages` into remote VA space.
            for i in (0..remote_map_len).step_by(PAGE_SIZE) {
                unsafe {
                    if
                        remote_rpt.make_leaf((remote_start_address + i) as u64) < 0 ||
                        remote_rpt.put_page(
                            pages[i / PAGE_SIZE],
                            (remote_start_address + i) as u64,
                            spec::UserPteFlags::WRITABLE,
                        ) < 0 {
                            flatrt_capalloc::release(remote_rpt.into());
                            payload.data[0] = -1i64 as _;
                            payload.write();
                            return;
                        }
                }
            }
            
            flatrt_capalloc::release(remote_rpt.into());
            payload.data[0] = 0;
            payload.write();

            debug!("shmem: Mapped region starting from 0x{:016x}.", remote_start_address);
        }
        1 => {
            // Drop pages.
            for &va in &*pages {
                unsafe {
                    spec::to_result(caps::RPT.drop_page(va)).unwrap();
                }
            }

            // Drop the IPC endpoint.
            //
            // The page vec itself is released during endpoint drop.
            IPC_HANDLER.try_lock().unwrap().drop_ipc_endpoint(env.index);

            // Release cap pointer.
            flatrt_capalloc::release(map_cptr);

            payload.data[0] = 0;
            payload.write();

            debug!("shmem: Dropped shared memory {}.", env.index);
        }
        _ => {
            payload.data[0] = -1i64 as _;
            payload.write();
        }
    }
}

/// Allocates a page for shared memory.
/// 
/// Returns the virtual address of the page if succeeds.
fn alloc_page() -> Option<u64> {
    let mut state = PAGE_ALLOC.lock();

    if state.len() * PAGE_SIZE == MAX_SHMEM_SIZE {
        return None;
    } else if state.len() * PAGE_SIZE > MAX_SHMEM_SIZE {
        unreachable!();
    }

    let index = state.insert(());
    let page = SHMEM_PAGE_START + (index * PAGE_SIZE) as u64;
    unsafe {
        spec::to_result(caps::RPT.make_leaf(page)).unwrap();
        spec::to_result(caps::RPT.alloc_leaf(page, spec::UserPteFlags::WRITABLE)).unwrap();
    }
    return Some(page);
}

/// Deallocates a page for shared memory.
/// 
/// Unsafe because the caller needs to ensure `x` is a valid pointer to the shared memory region.
unsafe fn dealloc_page(x: u64) {
    let mut state = PAGE_ALLOC.lock();
    spec::to_result(caps::RPT.drop_page(x)).unwrap();
    let index = ((x - SHMEM_PAGE_START) as usize) / PAGE_SIZE;
    state.remove(index);
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        asm!("ud2" :::: "volatile");
    }
    loop {}
}