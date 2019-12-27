use crate::capset::CapSet;
use crate::ipc::TaskEndpoint;
use crate::task::*;
use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use core::mem::ManuallyDrop;
use core::ops::Deref;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use crate::error::*;
use crate::layout;
use spin::Mutex;

const GS_BASE: u32 = 59;
pub const TLCAP_USER_OFFSET: u64 = 0;

pub const ROOT_TLCAP_BASE: u64 = 0x300000;
pub const ROOT_USER_BASE: u64 = ROOT_TLCAP_BASE + TLCAP_USER_OFFSET;

lazy_static! {
    static ref THREAD_CAP_RELEASE_POOL: Mutex<VecDeque<u64>> = Mutex::new(VecDeque::new());
}

static THREAD_CAP_TOP: AtomicU64 = AtomicU64::new(0x301000);

#[repr(align(4096))]
pub struct ThreadStack(pub [u8; 65536]);

pub struct Thread {
    task: Box<Task>,
    tls_indirect: ManuallyDrop<Box<LowlevelTls>>,
}

impl Drop for Thread {
    fn drop(&mut self) {
        release_thread_cap_base(self.tls_indirect.inner.current_cap_base);
        unsafe {
            ManuallyDrop::drop(&mut self.tls_indirect);
        }
    }
}

#[repr(C)]
pub struct Tls {
    current_task: *const Task,
    current_cap_base: u64,
}

#[repr(C)]
pub struct LowlevelTls {
    inner: Box<Tls>,
    stack_end: *mut ThreadStack,
    stack: Option<Box<ThreadStack>>,
}

fn map_tl_cap_range(task: &Task, base: u64) {
    let mut capset = task.fetch_capset().unwrap();
    capset.make_leaf(base + TLCAP_USER_OFFSET).unwrap();
}

impl Thread {
    pub fn new() -> Thread {
        let cap_base = allocate_thread_cap_base();
        let task = Box::new(this_task().shallow_clone().unwrap());
        let mut stack: Box<ThreadStack> = unsafe { Box::new_uninit().assume_init() };
        let stack_end = unsafe { (&mut *stack as *mut ThreadStack).offset(1) };
        let tls_indirect = ManuallyDrop::new(Box::new(LowlevelTls {
            inner: Box::new(Tls {
                current_task: &*task as *const Task,
                current_cap_base: cap_base,
            }),
            stack_end,
            stack: Some(stack),
        }));
        task.set_register(GS_BASE, &**tls_indirect as *const LowlevelTls as u64)
            .expect("Failed to set GS_BASE");
        map_tl_cap_range(&*task, cap_base);
        Thread { task, tls_indirect }
    }
    pub unsafe fn task_endpoint(&self, pc: u64, context: u64) -> TaskEndpoint {
        self
            .task
            .fetch_task_endpoint(pc, context, TaskEndpointFlags::empty(), false)
            .expect("fetch_task_endpoint failed")
    }
    pub unsafe fn task(&self) -> &Task {
        &*self.task
    }
}

pub unsafe fn init_startup_thread() {
    let tls_indirect = Box::new(LowlevelTls {
        inner: Box::new(Tls {
            current_task: &*ROOT_TASK as *const Task,
            current_cap_base: ROOT_TLCAP_BASE,
        }),
        stack_end: layout::STACK_END as *mut ThreadStack,
        stack: None,
    });
    ROOT_TASK
        .set_register(GS_BASE, &*tls_indirect as *const LowlevelTls as u64)
        .expect("Failed to set GS_BASE for startup thread");
    Box::leak(tls_indirect);
}

/// Manually sets up IPC for the current task.
/// 
/// Used during initialization.
pub fn setup_tlcap(base: u64) -> KernelResult<()> {
    let task = this_task();
    map_tl_cap_range(&*task, base);
    Ok(())
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

pub fn this_user_base() -> u64 {
    let tls = current_tls();
    unsafe { (*tls).current_cap_base + TLCAP_USER_OFFSET }
}

fn allocate_thread_cap_base() -> u64 {
    if let Some(x) = THREAD_CAP_RELEASE_POOL.lock().pop_front() {
        x
    } else {
        THREAD_CAP_TOP.fetch_add(0x1000u64, Ordering::SeqCst)
    }
}

fn release_thread_cap_base(x: u64) {
    THREAD_CAP_RELEASE_POOL.lock().push_back(x);
}
