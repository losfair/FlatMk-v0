use crate::capset::CapSet;
use crate::ipc::TaskEndpoint;
use crate::task::{Task, ROOT_TASK};
use alloc::boxed::Box;
use core::mem::ManuallyDrop;
use core::ops::Deref;
use core::sync::atomic::AtomicU8;

const GS_BASE: u32 = 59;
const ROOT_IPC_BASE: u64 = 0x300000;

#[repr(align(4096))]
pub struct ThreadStack(pub [u8; 65536]);

pub struct Thread {
    task: Box<Task>,
    tls_indirect: ManuallyDrop<Box<LowlevelTls>>,
}

impl Drop for Thread {
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.tls_indirect);
        }
    }
}

#[repr(C)]
pub struct Tls {
    current_task: *const Task,
    current_ipc_base: u64,
}

#[repr(C)]
pub struct LowlevelTls {
    inner: Box<Tls>,
    stack_end: *mut ThreadStack,
    stack: Box<ThreadStack>,
}

fn map_ipc_cap_range_leaky(task: &Task, ipc_base: u64) {
    let mut capset = task.fetch_capset().unwrap();
    capset.make_leaf(ipc_base).unwrap();
}

impl Thread {
    pub fn new(ipc_base: u64) -> Thread {
        let task = Box::new(this_task().shallow_clone().unwrap());
        let mut stack: Box<ThreadStack> = unsafe { Box::new_uninit().assume_init() };
        let stack_end = unsafe { (&mut *stack as *mut ThreadStack).offset(1) };
        let tls_indirect = ManuallyDrop::new(Box::new(LowlevelTls {
            inner: Box::new(Tls {
                current_task: &*task as *const Task,
                current_ipc_base: ipc_base,
            }),
            stack_end,
            stack,
        }));
        task.set_register(GS_BASE, &**tls_indirect as *const LowlevelTls as u64)
            .expect("Failed to set GS_BASE");
        task.set_ipc_base(ipc_base).unwrap();
        map_ipc_cap_range_leaky(&*task, ipc_base);
        Thread { task, tls_indirect }
    }
    pub unsafe fn task_endpoint(&self, pc: u64) -> TaskEndpoint {
        let cptr = self
            .task
            .fetch_task_endpoint(pc)
            .expect("fetch_task_endpoint failed");
        unsafe { TaskEndpoint::new(cptr) }
    }
    pub unsafe fn task(&self) -> &Task {
        &*self.task
    }
}

pub unsafe fn init_startup_thread() {
    let tls_indirect = Box::new(Box::new(Tls {
        current_task: &*ROOT_TASK as *const Task,
        current_ipc_base: ROOT_IPC_BASE,
    }));
    ROOT_TASK
        .set_register(GS_BASE, &*tls_indirect as *const Box<Tls> as u64)
        .expect("Failed to set GS_BASE for startup thread");
    ROOT_TASK.set_ipc_base(ROOT_IPC_BASE).unwrap();
    map_ipc_cap_range_leaky(&ROOT_TASK, ROOT_IPC_BASE);
    Box::leak(tls_indirect);
}

pub fn current_tls() -> *const Tls {
    let result: *const Tls;
    unsafe {
        asm!(
            "mov %gs:0, $0" : "=r"(result) : :
        );
    }
    result
}

pub struct ThreadLocalTaskRef(*const Task);

impl Deref for ThreadLocalTaskRef {
    type Target = Task;
    fn deref(&self) -> &Task {
        unsafe { &*self.0 }
    }
}

pub fn this_task() -> ThreadLocalTaskRef {
    let tls = current_tls();
    unsafe { ThreadLocalTaskRef((*tls).current_task) }
}

pub fn this_ipc_base() -> u64 {
    let tls = current_tls();
    unsafe { (*tls).current_ipc_base }
}
