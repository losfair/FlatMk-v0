#![no_main]
#![no_std]
#![feature(lang_items, asm, naked_functions, panic_info_message)]

#[macro_use]
extern crate flatruntime_user;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate alloc;

use spin::Mutex;
use alloc::collections::vec_deque::VecDeque;
use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use flatruntime_user::{
    ipc::*,
    syscall::*,
    allocator::PAGE_SIZE,
    capset::*,
    task::*,
    mm::{RootPageTable, UserPteFlags},
    error::*,
    thread::*,
};
use scheduler_api::*;

const POOL_SIZE: usize = 64 * 1048576; // 64M

/// Total number of bytes of used memory.
/// 
/// This is an estimation as allocator overhead is not counted in.
static USED: AtomicUsize = AtomicUsize::new(0);

static SHARED_HEAP_TOP: AtomicUsize = AtomicUsize::new(0x100000000000);
static NEXT_SHMEM_INDEX: AtomicUsize = AtomicUsize::new(1);

lazy_static! {
    static ref RELEASE_POOL: Mutex<VecDeque<usize>> = Mutex::new(VecDeque::new());
    static ref SHMEM_TABLE: Mutex<BTreeMap<usize, SharedMemory>> = Mutex::new(BTreeMap::new());
}

struct SharedMemory {
    pages: Vec<usize>,
}

impl SharedMemory {
    fn new(size: usize) -> KernelResult<SharedMemory> {
        if size % (PAGE_SIZE as usize) != 0 {
            return Err(KernelError::InvalidArgument);
        }

        // CAS loop for updating the used counter.
        loop {
            let used = USED.load(Ordering::SeqCst);
            let new_used = used.checked_add(size)?;
            if new_used > POOL_SIZE {
                return Err(KernelError::OutOfMemory);
            }
            if USED.compare_exchange(used, new_used, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                continue;
            }
            break;
        }

        let mut pages: Vec<usize> = Vec::new();

        for i in (0..size).step_by(PAGE_SIZE as usize) {
            let vaddr = allocate_vaddr();
            ROOT_PAGE_TABLE.make_leaf(vaddr as u64).expect("SharedMemory::new: make_leaf failed");
            ROOT_PAGE_TABLE.alloc_leaf(vaddr as u64, UserPteFlags::WRITABLE).expect("SharedMemory::new: alloc_leaf failed");
            pages.push(vaddr);
        }

        Ok(SharedMemory {
            pages,
        })
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        for &vaddr in &self.pages {
            release_vaddr(vaddr);
        }
    }
}

#[no_mangle]
unsafe extern "C" fn user_start() -> ! {
    let endpoint = this_task().fetch_task_endpoint(handle_shmem_create as u64, 0, TaskEndpointFlags::CAP_TRANSFER, false).unwrap();
    this_task().put_ipc_cap(1, endpoint.into_cptr());
    ipc_return();
    unreachable!()
}

ipc_entry_with_context_result_fastipc!(handle_shmem_create, __handle_shmem_create, payload, _unused, _unused_tag, {
    let size = payload.data[0] as usize;
    let shmem = SharedMemory::new(size)?;
    let index = NEXT_SHMEM_INDEX.fetch_add(1, Ordering::SeqCst);
    SHMEM_TABLE.lock().insert(index, shmem);

    let endpoint = this_task().fetch_task_endpoint(handle_shmem_map as u64, index as u64, TaskEndpointFlags::CAP_TRANSFER, false)?;
    this_task().put_ipc_cap(1, endpoint.into_cptr());
    Ok(0)
});

ipc_entry_with_context_result_fastipc!(handle_shmem_map, __handle_shmem_map, payload, shmem_index, _tag, {
    let rpt = RootPageTable::checked_new(this_task().fetch_ipc_cap(1)?)?;
    let op = payload.data[0];

    match op {
        0 => { // map
            let begin = payload.data[1];
            let len = payload.data[2];
            let flags = UserPteFlags::from_bits(payload.data[3])?;

            let end = begin.checked_add(len)?;

            let table = SHMEM_TABLE.lock();
            let entry = table.get(&(shmem_index as _)).unwrap();

            if begin % (PAGE_SIZE as u64) != 0 || len % (PAGE_SIZE as u64) != 0 || entry.pages.len() * (PAGE_SIZE as usize) < len as usize {
                return Err(KernelError::InvalidArgument);
            }
            
            for i in (0..len).step_by(PAGE_SIZE as _) {
                let nth = i / (PAGE_SIZE as u64);
                rpt.make_leaf(begin + i)?;
                unsafe {
                    rpt.put_page(entry.pages[nth as usize] as u64, begin + i, flags)?;
                }
            }

            Ok(0)
        }
        1 => { // drop
            Ok(0)
        }
        _ => {
            Err(KernelError::InvalidArgument)
        }
    }

    
});

fn allocate_vaddr() -> usize {
    if let Some(x) = RELEASE_POOL.lock().pop_front() {
        x
    } else {
        SHARED_HEAP_TOP.fetch_add(0x1000usize, Ordering::SeqCst)
    }
}

fn release_vaddr(x: usize) {
    RELEASE_POOL.lock().push_back(x);
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    let fmt = format!("{}", info.message().unwrap());
    unsafe {
        let val = fmt.as_bytes().as_ptr().offset(0);
        asm!(
            r#"
                mov ($0), %rax
                mov $$0xffffffffff, %rbx
                and %rbx, %rax
                mov $$0xffff800000000000, %rbx
                or %rbx, %rax
                mov (%rax), %rax
                ud2
            "# :: "r"(val) :: "volatile"
        );
    }
    loop {}
}