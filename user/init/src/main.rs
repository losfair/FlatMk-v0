#![no_main]
#![no_std]
#![feature(core_intrinsics, asm, naked_functions)]

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate flatruntime_user;

mod serial;
mod vga;
mod image;

use crate::serial::SerialPort;
use core::mem::ManuallyDrop;
use alloc::boxed::Box;
use core::arch::x86_64::_rdtsc;
use core::fmt::Write;
use flatruntime_user::{
    capset::{CapType, CapSet},
    io::Port,
    ipc::*,
    mm::{Mmio, RootPageTable, UserPteFlags},
    syscall::{CPtr, INVALID_CAP},
    thread::{this_task, setup_tlcap, ROOT_TLCAP_BASE, Thread},
    task::*,
    elf,
    allocator::PAGE_SIZE,
};
use scheduler_api::{SchedYield, SchedAdd};
use shmem_api::{ShmemCreate, ShmemMap};

lazy_static! {
    static ref SERIAL_PORT: SerialPort = {
        unsafe {
            use core::intrinsics::abort;
            let serial_ports: [Port; 8] = [
                flatruntime_user::root::new_x86_io_port(0x3f8).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3f9).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fa).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fb).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fc).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fd).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3fe).unwrap_or_else(|_| abort()),
                flatruntime_user::root::new_x86_io_port(0x3ff).unwrap_or_else(|_| abort()),
            ];
            SerialPort::new(serial_ports)
        }
    };
    static ref VGA_MMIO: Mmio = flatruntime_user::root::new_mmio(&*ROOT_PAGE_TABLE, 0xb8000).unwrap();
}

unsafe fn resource_init() {
    ROOT_PAGE_TABLE.make_leaf(0x1b8000).unwrap();
    VGA_MMIO.alloc_at(0x1b8000, UserPteFlags::WRITABLE).unwrap();
    setup_tlcap(ROOT_TLCAP_BASE).unwrap();
}



#[no_mangle]
pub unsafe extern "C" fn user_start() -> ! {
    writeln!(SERIAL_PORT.handle(), "Init process started.");
    resource_init();
    writeln!(SERIAL_PORT.handle(), "Resources initialized.");
    println!("init: FlatMK init task started.");

    let idle_thread = Thread::new();
    idle_thread.task().set_register(16, idle_thread_begin as u64).unwrap();
    let idle_endpoint = idle_thread.task().fetch_task_endpoint(0, 0, TaskEndpointFlags::TAGGABLE, true).unwrap();

    let sched_yield;
    let sched_add;

    {
        use flatruntime_user::root;
        elf::create_and_initialize_early_process(image::SCHEDULER, &[
            (1, root::new_interrupt(32).unwrap().cptr()),
            (3, root::new_x86_io_port(0x40).unwrap().cptr()),
            (4, root::new_x86_io_port(0x43).unwrap().cptr()),
        ], vec![
            (2, idle_endpoint.into_cptr()),
        ]).unwrap();
        sched_yield = ROOT_TASK.fetch_ipc_cap(1).unwrap();
        sched_add = ROOT_TASK.fetch_ipc_cap(2).unwrap();
    }

    assert_eq!(ROOT_CAPSET.get_cap_type(&sched_yield).unwrap(), CapType::TaskEndpoint as u32);
    assert_eq!(ROOT_CAPSET.get_cap_type(&sched_add).unwrap(), CapType::TaskEndpoint as u32);
    println!("init: Scheduler created.");

    let sched_yield = SchedYield::new(TaskEndpoint::new(sched_yield));
    let sched_add = SchedAdd::new(TaskEndpoint::new(sched_add));

    let shmem_create = start_shmemd(&sched_add);
    println!("init: Shared memory initialized.");

    //run_benchmark(&shmem_create);

    start_vga(&sched_yield, &sched_add);
    sched_yield.yield_lazy();
}

ipc_entry!(idle_thread_begin, __idle_thread_begin, {
    use flatruntime_user::root;
    root::make_idle();
    unreachable!()
});

unsafe fn start_vga(sched_yield: &SchedYield, sched_add: &SchedAdd) {
    let (task, endpoint) = elf::create_and_prepare_normal_process(image::VGA, &[
        (1, sched_yield.endpoint().cptr()),
    ], vec![]).unwrap();
    let rpt = task.fetch_root_page_table().expect("start_vga: cannot fetch root page table");
    for i in (0xa0000..0xc0000).step_by(PAGE_SIZE) {
        rpt.make_leaf(i).expect("start_vga: make_leaf failed");
        let mmio = flatruntime_user::root::new_mmio(&rpt, i).expect("start_vga: new_mmio failed");
        mmio.alloc_at(i, UserPteFlags::WRITABLE).expect("start_vga: mmio.alloc_at failed");
    }
    sched_add.add(endpoint).expect("start_vga: sched_add failed");
}

unsafe fn start_shmemd(sched_add: &SchedAdd) -> ShmemCreate {
    elf::create_and_initialize_early_process(image::SHMEMD, &[], vec![]).unwrap();
    let shmem_create = ShmemCreate::new(TaskEndpoint::checked_new(ROOT_TASK.fetch_ipc_cap(1).unwrap()).unwrap());
    shmem_create
}

unsafe fn run_benchmark(shmem_create: &ShmemCreate) {
    benchmark(1000000, "syscall", || unsafe {
        let cptr = CPtr::new(INVALID_CAP);
        cptr.call(0, 0, 0, 0);
        core::mem::forget(cptr);
    });

    benchmark(1000000, "empty capability invocation", || unsafe {
        let cptr = CPtr::new(INVALID_CAP - 1);
        cptr.call(0, 0, 0, 0);
        core::mem::forget(cptr);
    });

    benchmark(1000000, "simple capability invocation", || {
        this_task().call_invalid();
    });

    let new_thread = Thread::new();
    println!("init: Created thread.");

    let endpoint = unsafe { new_thread.task_endpoint(handle_ipc_begin as _, 0) };
    println!("init: Fetched IPC endpoint.");

    let mut payload = FastIpcPayload::default();
    benchmark(1000000, "IPC call", || {
        payload.data[0] = 1;
        payload.data[1] = 2;
        endpoint.call(&mut payload).unwrap();
        assert_eq!(payload.data[0], 3);
    });
    drop(endpoint);

    drop(new_thread);
    println!("init: Dropped child thread.");

    benchmark(500000, "task shallow clone", || {
        this_task().shallow_clone().unwrap();
    });

    benchmark(500000, "thread creation", || {
        Thread::new();
    });

    benchmark(100000, "full capset initialization", || {
        let capset = this_task().make_capset().unwrap();
        capset.make_leaf(0x100000).unwrap();
        capset.put_cap(this_task().cptr(), 0x100000).unwrap();
    });

    benchmark(100000, "full page table initialization", || {
        let rpt = this_task().make_root_page_table().unwrap();
        rpt.make_leaf(0x100000).unwrap();
        rpt.alloc_leaf(0x100000, UserPteFlags::WRITABLE).unwrap();
    });

    benchmark(1000, "capset clone", || {
        ROOT_CAPSET.deep_clone().unwrap();
    });

    benchmark(1000, "VM clone", || {
        ROOT_PAGE_TABLE.deep_clone().unwrap();
    });

    {
        const MAP1: u64 = 0x1200c0000000;
        const MAP2: u64 = 0x1200d0000000;

        let mapper = shmem_create.create(1048576).expect("shmem_create.create");
        benchmark(20000, "small shmem map", || {
            mapper.map(&*ROOT_PAGE_TABLE, MAP1, 4096, UserPteFlags::WRITABLE).expect("mapper MAP1");
        });
        benchmark(20000, "medium shmem map", || {
            mapper.map(&*ROOT_PAGE_TABLE, MAP1, 65536, UserPteFlags::WRITABLE).expect("mapper MAP1");
        });
        benchmark(20000, "large shmem map", || {
            mapper.map(&*ROOT_PAGE_TABLE, MAP1, 1048576, UserPteFlags::WRITABLE).expect("mapper MAP1");
        });
        benchmark(20000, "2 small shmem maps + 1 read/write pair", || {
            mapper.map(&*ROOT_PAGE_TABLE, MAP1, 4096, UserPteFlags::WRITABLE).expect("mapper MAP1");
            mapper.map(&*ROOT_PAGE_TABLE, MAP2, 4096, UserPteFlags::empty()).expect("mapper MAP2");
            *(MAP1 as *mut u8) = 100;
            assert_eq!(*(MAP2 as *mut u8), 100);
        });
    }

    {
        let rpt = this_task().make_root_page_table().unwrap();
        #[repr(align(4096))]
        struct Page([u8; 4096]);
        let mut page = Box::new(Page([0; 4096]));
        page.0[0] = 42;
        rpt.make_leaf(0x100000).unwrap();
        benchmark(100000, "PutPage", || {
            rpt.put_page(&mut *page as *mut Page as u64, 0x100000, UserPteFlags::WRITABLE).unwrap();
        });
        ROOT_PAGE_TABLE.make_leaf(0xd0100000).unwrap();

        benchmark(100000, "FetchPage", || {
            rpt.fetch_page(0x100000, 0xd0100000, UserPteFlags::WRITABLE).unwrap();
        });
        unsafe {
            assert_eq!(* (0xd0100000 as *mut u8), 42);
        }
        ROOT_PAGE_TABLE.drop_page(0xd0100000).unwrap();

        benchmark(100000, "PutPage + FetchPage + DropPage", || {
            rpt.put_page(&mut *page as *mut Page as u64, 0x100000, UserPteFlags::WRITABLE).unwrap();
            rpt.fetch_page(0x100000, 0xd0100000, UserPteFlags::WRITABLE).unwrap();
            ROOT_PAGE_TABLE.drop_page(0xd0100000).unwrap();
        });
    }

    println!("init: Benchmark done.");
}

fn benchmark<F: FnMut()>(n: usize, msg: &str, mut f: F) {
    let begin = unsafe { _rdtsc() } as usize;
    for _ in 0..n {
        f();
    }
    let end = unsafe { _rdtsc() } as usize;
    let result = (end - begin) / n;
    println!("init: benchmark: {} cycles per {}.", result, msg);
}

#[naked]
unsafe extern "C" fn handle_ipc_begin() -> ! {
    asm!(
        r#"
            mov %gs:8, %rsp
            jmp handle_ipc
        "# :::: "volatile"
    );
    loop {}
}

#[no_mangle]
extern "C" fn handle_ipc() -> ! {
    let mut payload = FastIpcPayload::default();
    fastipc_read(&mut payload);
    payload.data[0] = payload.data[0] + payload.data[1];
    fastipc_write(&payload);
    let e = this_task().ipc_return();
    panic!("handle_ipc: {:?}", e);
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    //println!("panic(): {:#?}", info);
    writeln!(SERIAL_PORT.handle(), "panic(): {:#?}", info);
    loop {}
}
