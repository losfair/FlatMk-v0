//! flatrt-init is the first userspace task in FlatRt.
//! 
//! When the init task is started by FlatMk, its initial environment is as follows:
//! 
//! - Root page table: The flat binary converted from the `flatrt-init` ELF executable is mapped at `ROOT_TASK_FULL_MAP_BASE` (0x20000000).
//! - Capability set: The first leaf set is mapped. Location 0 contains a `BasicTask` capability to the task itself. Location 1 contains the `RootTask` capability.

#![no_std]
#![no_main]
#![feature(naked_functions, asm)]

#[macro_use]
mod debug;
mod caps;
mod image;
mod layout;

use flatmk_sys::spec::{self, KernelError};
use flatrt_thread::{Thread, ThreadCapSet};
use flatrt_elfloader::ElfTempMapBase;
use flatrt_fastipc::FastIpcPayload;

/// Start address for heap allocation.
const HEAP_START: usize = 0x7fff00000000;
static ELF_TEMP_MAP_BASE: ElfTempMapBase = unsafe { ElfTempMapBase::new(0x7f0000001000) };

/// The type of initial stack, aligned to the page size.
#[repr(align(4096))]
struct Stack([u8; 1048576]);

/// The initial environment doesn't contain a stack, so we need a static stack.
#[no_mangle]
static mut STACK: Stack = Stack([0; 1048576]);

/// The entry point.
/// 
/// Sets up the stack pointer, and jumps to `init_start`.
#[naked]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    asm!(r#"
        leaq STACK, %rsp
        addq $$1048576, %rsp
        jmp init_start
    "# :::: "volatile");
    loop {}
}

#[no_mangle]
unsafe extern "C" fn init_start() -> ! {
    caps::initialize_static_caps();

    ELF_TEMP_MAP_BASE.make_leaf(&caps::RPT).expect("Cannot make leaf entry for ELF_TEMP_MAP_BASE");

    flatrt_allocator::init(HEAP_START, caps::RPT);

    initialize_idle_task();

    start_scheduler();

    debug!("init: Finished setting up initial environment.");

    loop {
        let mut payload = FastIpcPayload::default();
        payload.data[0] = 1;
        payload.data[1] = 1_000_000_000; // 1 second
        payload.write();
        spec::to_result(caps::SCHED_YIELD.invoke()).unwrap();
        debug!("init: tick");
    }
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    debug!("panic(): {:#?}", info);
    loop {}
}

/// Creates a thread and makes it an idle task.
unsafe fn initialize_idle_task() {
    let mut th = Thread::new(ThreadCapSet {
        owner_task: caps::ME,
        owner_capset: caps::CAPSET,
        new_task: caps::IDLE,
    });
    th.make_ipc_endpoint(spec::TaskEndpointFlags::TAGGABLE, true, caps::IDLE_REPLY.cptr(), |task, x| {
        caps::ROOT_TASK.make_idle();
        unreachable!()
    });
}

/// Loads an ELF image for a task.
fn load_elf_task(
    image: &[u8],
    task: &spec::BasicTask,
    rpt: &spec::RootPageTable,
    capset: &spec::CapabilitySet,
    start_endpoint: &spec::TaskEndpoint,
) -> Result<(), KernelError> {
    unsafe {
        spec::to_result(caps::ME.fetch_shallow_clone(task.cptr()))?;
        spec::to_result(caps::ME.make_root_page_table(rpt.cptr()))?;
        spec::to_result(caps::ME.make_capset(capset.cptr()))?;
        spec::to_result(task.put_capset(capset))?;
        spec::to_result(task.put_root_page_table(rpt))?;
    }

    let metadata = flatrt_elfloader::load(image, &ELF_TEMP_MAP_BASE, rpt)?;
    metadata.apply_to_task(task)?;

    flatrt_elfloader::build_and_apply_stack(layout::STACK_START, layout::STACK_SIZE, rpt, task)?;

    let endpoint = unsafe {
        spec::to_result(task.fetch_task_endpoint(
            start_endpoint.cptr().index(),
            metadata.entry_address,
            0,
        ))?
    };
    Ok(())
}

/// Starts the `scheduler` task.
fn start_scheduler() {
    load_elf_task(
        image::SCHEDULER,
        &caps::scheduler::TASK,
        &caps::scheduler::RPT,
        &caps::scheduler::CAPSET,
        &caps::scheduler::ENDPOINT,
    ).expect("start_scheduler: Cannot load ELF for task.");

    unsafe {
        // The first leaf set.
        spec::to_result(caps::scheduler::CAPSET.make_leaf(&spec::CPtr::new(0))).unwrap();

        // The task itself.
        spec::to_result(caps::scheduler::TASK.fetch_weak(&caps::BUFFER)).unwrap();
        spec::to_result(caps::scheduler::CAPSET.put_cap(
            &caps::BUFFER,
            &spec::CPtr::new(0),
        )).unwrap();

        // The idle task.
        // This has to be moved instead of copied.
        spec::to_result(caps::scheduler::CAPSET.put_cap_move(
            &caps::IDLE_REPLY.cptr(),
            &spec::CPtr::new(1),
        )).unwrap();

        // Timer interrupt.
        spec::to_result(caps::ROOT_TASK.new_interrupt(&caps::BUFFER, 32)).unwrap();
        spec::to_result(caps::scheduler::CAPSET.put_cap(
            &caps::BUFFER,
            &spec::CPtr::new(2),
        )).unwrap();

        // PIT port 1.
        spec::to_result(caps::ROOT_TASK.new_x86_io_port(&caps::BUFFER, 0x40)).unwrap();
        spec::to_result(caps::scheduler::CAPSET.put_cap(
            &caps::BUFFER,
            &spec::CPtr::new(3),
        )).unwrap();

        // PIT port 2.
        spec::to_result(caps::ROOT_TASK.new_x86_io_port(&caps::BUFFER, 0x43)).unwrap();
        spec::to_result(caps::scheduler::CAPSET.put_cap(
            &caps::BUFFER,
            &spec::CPtr::new(4),
        )).unwrap();

        // Debug putchar.
        spec::to_result(caps::scheduler::CAPSET.put_cap(
            caps::PUTCHAR.cptr(),
            &spec::CPtr::new(5),
        )).unwrap();

        // Cleanup.
        spec::to_result(caps::CAPSET.drop_cap(&caps::BUFFER)).unwrap();

        // Call the initialize function.
        spec::to_result(caps::scheduler::ENDPOINT.invoke()).expect("start_scheduler: Cannot invoke task.");

        // SCHED_CREATE endpoint.
        fetch_and_check_remote_task_endpoint(0x11, &caps::SCHED_CREATE, &caps::scheduler::CAPSET);

        // SCHED_YIELD endpoint.
        fetch_and_check_remote_task_endpoint(0x13, &caps::SCHED_YIELD, &caps::scheduler::CAPSET);
    }
}

/// Fetches and checks a task endpoint from a remote capability set.
/// 
/// This function requires the fetch to succeed, and the endpoint to be a non-reply task endpoint.
/// 
/// Panics if failed.
fn fetch_and_check_remote_task_endpoint(src: u64, dst: &spec::TaskEndpoint, remote: &spec::CapabilitySet) {
    unsafe {
        spec::to_result(remote.fetch_cap(&spec::CPtr::new(src), dst.cptr())).expect("fetch_and_check_remote_task_endpoint: Cannot fetch remote capability.");
        assert_eq!(
            spec::to_result(caps::CAPSET.get_cap_type(dst.cptr())).expect("fetch_and_check_remote_task_endpoint: Cannot get capability type."),
            spec::CapType::TaskEndpoint as i64 as u64,
        );
        assert_eq!(
            spec::to_result(dst.is_reply()).expect("fetch_and_check_remote_task_endpoint: Cannot check task endpoint type."),
            0,
        );
    }
}
