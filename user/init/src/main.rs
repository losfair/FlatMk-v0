#![no_main]
#![no_std]
#![feature(core_intrinsics, asm, naked_functions)]

#[macro_use]
extern crate lazy_static;

extern crate alloc;

mod serial;
mod vga;

use crate::serial::SerialPort;
use alloc::boxed::Box;
use core::arch::x86_64::_rdtsc;
use core::fmt::Write;
use flatruntime_user::{
    capset::CapSet,
    io::Port,
    ipc::*,
    mm::{Mmio, RootPageTable},
    syscall::{CPtr, INVALID_CAP},
    thread::{this_ipc_base, this_task, Thread},
    task::{ROOT_PAGE_TABLE, ROOT_CAPSET},
};

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
    static ref VGA_MMIO: Mmio = flatruntime_user::root::new_mmio(0xb8000).unwrap();
}

unsafe fn resource_init() {
    ROOT_PAGE_TABLE.make_leaf(0x1b8000).unwrap();
    VGA_MMIO.alloc_at(0x1b8000).unwrap();
}

#[no_mangle]
pub unsafe extern "C" fn user_start() -> ! {
    writeln!(SERIAL_PORT.handle(), "Init process started.");
    resource_init();
    writeln!(SERIAL_PORT.handle(), "Resources initialized.");
    println!("init: FlatMK init task started.");

    benchmark(1000000, "syscall", || unsafe {
        let cptr = CPtr::new(INVALID_CAP);
        cptr.call(0, 0, 0, 0);
        core::mem::forget(cptr);
    });

    benchmark(1000000, "simple capability invocation", || {
        this_task().call_invalid();
    });

    let new_thread = Thread::new(0x300100);
    println!("init: Created thread.");

    unsafe {
        new_thread.task().unblock_ipc().unwrap();
    }

    let endpoint = unsafe { new_thread.task_endpoint(handle_ipc_begin as _) };
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
        Thread::new(0x300200);
    });

    benchmark(100000, "full capset initialization", || {
        let capset = this_task().make_capset().unwrap();
        capset.make_leaf(0x100000).unwrap();
        capset.put_cap(this_task().cptr(), 0x100000).unwrap();
    });

    benchmark(100000, "full page table initialization", || {
        let rpt = this_task().make_root_page_table().unwrap();
        rpt.make_leaf(0x100000).unwrap();
        rpt.alloc_leaf(0x100000).unwrap();
    });

    benchmark(1000, "capset clone", || {
        ROOT_CAPSET.deep_clone().unwrap();
    });

    benchmark(1000, "VM clone", || {
        ROOT_PAGE_TABLE.deep_clone().unwrap();
    });

    println!("Benchmark done.");

    loop {}
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
    let peer_endpoint = unsafe { CPtr::new(this_ipc_base()) };
    let mut payload = FastIpcPayload::default();
    fastipc_read(&mut payload);
    payload.data[0] = payload.data[0] + payload.data[1];
    fastipc_write(&payload);
    let code = unsafe {
        peer_endpoint.leaky_call(
            IpcRequest::SwitchToBlocking_UnblockLocalIpc as u32 as i64,
            INVALID_CAP as _,
            INVALID_CAP as _,
            INVALID_CAP as _,
        )
    };
    panic!("handle_ipc: {}", code);
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    //println!("panic(): {:#?}", info);
    writeln!(SERIAL_PORT.handle(), "panic(): {:#?}", info);
    loop {}
}
