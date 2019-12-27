#![no_std]
#![feature(asm)]
extern crate flatruntime_user;

use flatruntime_user::{
    syscall::CPtr,
    task::{Task, ROOT_TASK, ROOT_CAPSET, ROOT_PAGE_TABLE},
    ipc::*,
    thread::*,
    io,
};
use core::mem::ManuallyDrop;

const FLATRT_ENDPOINT_SCHED_YIELD: TaskEndpoint = unsafe { TaskEndpoint::new(CPtr::new(1)) };
const FLATRT_ENDPOINT_SCHED_ADD: TaskEndpoint = unsafe { TaskEndpoint::new(CPtr::new(2)) };

pub type cptr_t = i64;

unsafe fn borrowed_cptr(x: cptr_t) -> ManuallyDrop<CPtr> {
    ManuallyDrop::new(CPtr::new(x as u64))
}

macro_rules! borrowed_cptr_as {
    ($x:expr) => {
        ManuallyDrop::new(core::mem::transmute(CPtr::new($x as u64)))
    };
}

unsafe fn cptr_into_raw(x: CPtr) -> cptr_t {
    let index = x.index();
    core::mem::forget(x);
    index as _
}

#[no_mangle]
pub unsafe extern "C" fn flatmk_cptr_drop(cptr: cptr_t) {
    CPtr::new(cptr as u64);
}

#[no_mangle]
pub extern "C" fn flatmk_task_get_root_task() -> cptr_t {
    ROOT_TASK.cptr().index() as _
}

#[no_mangle]
pub extern "C" fn flatmk_task_get_root_capset() -> cptr_t {
    ROOT_CAPSET.cptr().index() as _
}

#[no_mangle]
pub extern "C" fn flatmk_task_get_root_page_table() -> cptr_t {
    ROOT_PAGE_TABLE.cptr().index() as _
}

#[no_mangle]
pub unsafe extern "C" fn flatmk_task_fetch_capset(task: cptr_t) -> cptr_t {
    let task: ManuallyDrop<Task> = borrowed_cptr_as!(task);
    match task.fetch_capset() {
        Ok(x) => cptr_into_raw(x.into_cptr()),
        Err(e) => e as i32 as i64
    }
}

#[no_mangle]
pub unsafe extern "C" fn flatmk_task_fetch_rpt(task: cptr_t) -> cptr_t {
    let task: ManuallyDrop<Task> = borrowed_cptr_as!(task);
    match task.fetch_root_page_table() {
        Ok(x) => cptr_into_raw(x.into_cptr()),
        Err(e) => e as i32 as i64
    }
}

#[no_mangle]
pub unsafe extern "C" fn flatmk_endpoint_set_tag(endpoint: cptr_t, tag: u64) -> i32 {
    let endpoint: ManuallyDrop<TaskEndpoint> = borrowed_cptr_as!(endpoint);
    match endpoint.set_tag(tag) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn flatmk_endpoint_get_tag(endpoint: cptr_t) -> i64 {
    let endpoint: ManuallyDrop<TaskEndpoint> = borrowed_cptr_as!(endpoint);
    match endpoint.get_tag() {
        Ok(x) => x as i64,
        Err(e) => e as i32 as i64,
    }
}

#[no_mangle]
pub unsafe extern "C" fn flatmk_task_shallow_clone(task: cptr_t) -> cptr_t {
    let task: ManuallyDrop<Task> = borrowed_cptr_as!(task);
    match task.shallow_clone() {
        Ok(x) => cptr_into_raw(x.into_cptr()),
        Err(e) => e as i32 as i64,
    }
}

#[no_mangle]
pub unsafe extern "C" fn flatmk_io_port_outb(port: cptr_t, byte: u8) -> i32 {
    let port: ManuallyDrop<io::Port> = borrowed_cptr_as!(port);
    match port.outb(byte) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn flatmk_io_port_inb(port: cptr_t) -> i32 {
    let port: ManuallyDrop<io::Port> = borrowed_cptr_as!(port);
    match port.inb() {
        Ok(x) => x as i32,
        Err(e) => e as i32,
    }
}

#[no_mangle]
pub extern "C" fn flatmk_thread_get_this_task() -> cptr_t {
    this_task().cptr().index() as _
}

#[no_mangle]
pub unsafe extern "C" fn flatrt_sched_yield_busy() {
    let mut payload = FastIpcPayload::default();
    payload.data[0] = 1;
    FLATRT_ENDPOINT_SCHED_YIELD.call(&mut payload).unwrap();
    assert_eq!(payload.data[0], 1); // xmm restore test
}

#[no_mangle]
pub unsafe extern "C" fn flatrt_sched_yield() -> ! {
    let mut payload = FastIpcPayload::default();
    payload.data[0] = 0;
    FLATRT_ENDPOINT_SCHED_YIELD.call(&mut payload).unwrap();
    unreachable!("flatrt_sched_yield: should never return");
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    unsafe {
        asm!("ud2" :::: "volatile");
    }
    loop {}
}
