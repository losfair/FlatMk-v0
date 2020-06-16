//! flatrt-init is the first userspace task in FlatRt.
//! 
//! When the init task is started by FlatMk, its initial environment is as follows:
//! 
//! - Root page table: The flat binary converted from the `flatrt-init` ELF executable is mapped at `ROOT_TASK_FULL_MAP_BASE` (0x20000000).
//! - Capability set: The first leaf set is mapped. Location 0 contains a `BasicTask` capability to the task itself. Location 1 contains the `RootTask` capability.

#![no_std]
#![no_main]
#![feature(naked_functions, llvm_asm)]

#[macro_use]
mod debug;
mod caps;
mod image;
mod layout;

use flatmk_sys::spec::{self, KernelError};
use flatrt_thread::{Thread, ThreadCapSet};
use flatrt_elfloader::ElfTempMapBase;
use flatrt_fastipc::FastIpcPayload;
use core::arch::x86_64::_rdtsc;

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
    llvm_asm!(r#"
        leaq STACK, %rsp
        addq $$1048576, %rsp
        jmp init_start
    "# :::: "volatile");
    loop {}
}

#[no_mangle]
unsafe extern "C" fn init_start() -> ! {
    caps::initialize_static_caps();
    debug!("init: Started.");

    ELF_TEMP_MAP_BASE.make_leaf(&caps::RPT).expect("Cannot make leaf entry for ELF_TEMP_MAP_BASE");

    flatrt_allocator::init(HEAP_START, caps::RPT);

    start_idle();
    debug!("init: Idle task started.");

    start_shmem();

    debug!("init: Finished setting up initial environment. Now starting drivers.");
    debug!("- benchmark");
    start_driver_benchmark();
    debug!("- vga");
    start_driver_vga();
    debug!("- input");
    start_driver_input();
    //debug!("- gclock");
    //start_driver_gclock();
    debug!("- sequencer-linux");
    start_driver_sequencer_linux();
    debug!("init: All drivers started.");

    spec::CAP_TRIVIAL_SYSCALL.sched_drop();
    unreachable!()
}

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    debug!("panic(): {:#?}", info);
    loop {}
}

/// Starts an idle task.
unsafe fn start_idle() {
    unsafe extern "C" fn __enter_idle() {
        spec::CAP_TRIVIAL_SYSCALL.softuser_enter(&RVCODE as *const _ as u64);
        loop {}
    }
    static mut STACK: [u64; 64] = [0; 64];
    static RVCODE: [u32; 2] = [
        0x10500073, // wfi
        0xffdff06f, // j
    ];

    spec::to_result(caps::ME.fetch_shallow_clone(caps::IDLE_TASK.cptr())).unwrap();

    spec::to_result(caps::IDLE_TASK.set_register(spec::SP_INDEX, &mut STACK as *mut _ as u64 + 512)).unwrap();
    spec::to_result(caps::IDLE_TASK.set_register(spec::PC_INDEX, __enter_idle as u64)).unwrap();

    spec::to_result(caps::IDLE_TASK.fetch_task_endpoint(caps::BUFFER.index() | (1u64 << 63), 0, 0)).unwrap();
    spec::to_result(spec::CAP_TRIVIAL_SYSCALL.sched_submit(&spec::TaskEndpoint::new(caps::BUFFER))).unwrap();
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

    let metadata = flatrt_elfloader::load(image, &ELF_TEMP_MAP_BASE, rpt, (0..core::usize::MAX), |_| Ok(()))?;
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

/// Starts the `shmem` task.
fn start_shmem() {
    load_elf_task(
        image::SHMEM,
        &caps::shmem::TASK,
        &caps::shmem::RPT,
        &caps::shmem::CAPSET,
        &caps::shmem::ENDPOINT,
    ).expect("start_shmem: Cannot load ELF for task.");

    unsafe {
        // The first leaf set.
        spec::to_result(caps::shmem::CAPSET.make_leaf(&spec::CPtr::new(0))).unwrap();

        // The task itself.
        spec::to_result(caps::shmem::TASK.fetch_weak(&caps::BUFFER)).unwrap();
        spec::to_result(caps::shmem::CAPSET.put_cap(
            &caps::BUFFER,
            &spec::CPtr::new(0),
        )).unwrap();

        // Debug putchar.
        spec::to_result(caps::shmem::CAPSET.put_cap(
            caps::PUTCHAR.cptr(),
            &spec::CPtr::new(1),
        )).unwrap();

        // Call the initialize function.
        spec::to_result(caps::shmem::ENDPOINT.invoke()).expect("start_shmem: Cannot invoke task.");

        // SHMEM_CREATE endpoint.
        fetch_and_check_remote_task_endpoint(0x0b, &caps::SHMEM_CREATE, &caps::shmem::CAPSET);
    }
}

unsafe fn initialize_driver_std(
    image: &[u8],
    task: &spec::BasicTask,
    rpt: &spec::RootPageTable,
    capset: &spec::CapabilitySet,
    start_endpoint: &spec::TaskEndpoint,
) {
    load_elf_task(
        image,
        task,
        rpt,
        capset,
        start_endpoint,
    ).expect("initialize_driver_std: Cannot load ELF for task.");

    // The first leaf set.
    spec::to_result(capset.make_leaf(&spec::CPtr::new(0))).unwrap();

    // The task itself.
    spec::to_result(task.fetch_weak(&caps::BUFFER)).unwrap();
    spec::to_result(capset.put_cap(
        &caps::BUFFER,
        &spec::CPtr::new(0),
    )).unwrap();

    // Debug putchar.
    spec::to_result(capset.put_cap(
        caps::PUTCHAR.cptr(),
        &spec::CPtr::new(1),
    )).unwrap();

    // SHMEM_CREATE
    spec::to_result(capset.put_cap(
        caps::SHMEM_CREATE.cptr(),
        &spec::CPtr::new(4),
    )).unwrap();
}

/// Starts the `vga` driver.
fn start_driver_vga() {
    unsafe {
        let start = _rdtsc();
        debug!("Loading VGA driver...");

        initialize_driver_std(
            image::DRIVER_VGA,
            &caps::driver_vga::TASK,
            &caps::driver_vga::RPT,
            &caps::driver_vga::CAPSET,
            &caps::driver_vga::ENDPOINT,
        );

        #[repr(C)]
        #[derive(Default)]
        struct FramebufferInfo {
            physical_address: u64,
            width: u32,
            height: u32,
        }

        let mut fb_info = FramebufferInfo::default();

        // Read framebuffer info provided by the bootloader.
        spec::to_result(caps::ROOT_TASK.get_boot_parameter(
            spec::BootParameterKey::FramebufferInfo as i64,
            &mut fb_info as *mut _ as u64,
            core::mem::size_of::<FramebufferInfo>() as u64,
        )).expect("init: Cannot fetch framebuffer info.");

        // 24-bit pixels
        let fb_size = (fb_info.width as u64) * (fb_info.height as u64) * 3;

        // Map into the VGA process.
        for i in (fb_info.physical_address..fb_info.physical_address + fb_size).step_by(4096) {
            let target_va = i - fb_info.physical_address + 0x3c0000000000u64;

            // Create an MMIO object for physical address `i`.
            spec::to_result(caps::ROOT_TASK.new_mmio(&caps::BUFFER, &caps::driver_vga::RPT, i)).unwrap();

            // Prepare a leaf entry at `target_va`.
            spec::to_result(caps::driver_vga::RPT.make_leaf(target_va)).unwrap();

            // Map the physical page into `target_va`.
            spec::to_result(spec::Mmio::new(caps::BUFFER).alloc_at(target_va, spec::UserPteFlags::WRITABLE)).unwrap();
        }

        // Cleanup.
        spec::to_result(caps::CAPSET.drop_cap(&caps::BUFFER)).unwrap();

        // Pass width and height.
        let mut payload = FastIpcPayload::default();
        payload.data[0] = fb_info.width as _;
        payload.data[1] = fb_info.height as _;
        payload.write();

        // Call the initialize function.
        spec::to_result(caps::driver_vga::ENDPOINT.invoke()).expect("start_driver_vga: Cannot invoke task.");

        // Fetch shared memory.
        fetch_and_check_remote_task_endpoint(0x12, &caps::DRIVER_VGA_SHMEM_MAP, &caps::driver_vga::CAPSET);

        let end = _rdtsc();
        debug!("VGA initialized in {} cycles.", end - start);
    }
}

/// Starts the `gclock` driver.
fn start_driver_gclock() {
    unsafe {
        debug!("Loading gclock driver...");

        initialize_driver_std(
            image::DRIVER_GCLOCK,
            &caps::driver_gclock::TASK,
            &caps::driver_gclock::RPT,
            &caps::driver_gclock::CAPSET,
            &caps::driver_gclock::ENDPOINT,
        );

        // VGA shared framebuffer memory.
        spec::to_result(caps::driver_gclock::CAPSET.put_cap(caps::DRIVER_VGA_SHMEM_MAP.cptr(), &spec::CPtr::new(0x10))).unwrap();

        // Call the initialize function.
        spec::to_result(caps::driver_gclock::ENDPOINT.invoke()).expect("start_driver_gclock: Cannot invoke task.");
    }
}

/// Starts the `input` driver.
fn start_driver_input() {
    unsafe {
        debug!("Loading input driver...");

        initialize_driver_std(
            image::DRIVER_INPUT,
            &caps::driver_input::TASK,
            &caps::driver_input::RPT,
            &caps::driver_input::CAPSET,
            &caps::driver_input::ENDPOINT,
        );

        // Keyboard interrupt.
        spec::to_result(caps::ROOT_TASK.new_interrupt(&caps::BUFFER, 33)).unwrap();
        spec::to_result(caps::driver_input::CAPSET.put_cap(
            &caps::BUFFER,
            &spec::CPtr::new(0x10),
        )).unwrap();

        // Port 0x60/0x61.
        spec::to_result(caps::ROOT_TASK.new_x86_io_port(&caps::BUFFER, 0x60)).unwrap();
        spec::to_result(caps::driver_input::CAPSET.put_cap(
            &caps::BUFFER,
            &spec::CPtr::new(0x13),
        )).unwrap();
        spec::to_result(caps::ROOT_TASK.new_x86_io_port(&caps::BUFFER, 0x61)).unwrap();
        spec::to_result(caps::driver_input::CAPSET.put_cap(
            &caps::BUFFER,
            &spec::CPtr::new(0x14),
        )).unwrap();

        // Call the initialize function.
        spec::to_result(caps::driver_input::ENDPOINT.invoke()).expect("start_driver_input: Cannot invoke task.");

        // Fetch poll endpoint.
        fetch_and_check_remote_task_endpoint(0x12, &caps::DRIVER_INPUT_POLL_INPUT, &caps::driver_input::CAPSET);
    }
}

/// Starts the `sequencer-linux` driver.
fn start_driver_sequencer_linux() {
    unsafe {
        debug!("Loading sequencer-linux driver...");

        initialize_driver_std(
            image::DRIVER_SEQUENCER_LINUX,
            &caps::driver_sequencer_linux::TASK,
            &caps::driver_sequencer_linux::RPT,
            &caps::driver_sequencer_linux::CAPSET,
            &caps::driver_sequencer_linux::ENDPOINT,
        );

        // VGA shared framebuffer memory.
        spec::to_result(caps::driver_sequencer_linux::CAPSET.put_cap(caps::DRIVER_VGA_SHMEM_MAP.cptr(), &spec::CPtr::new(0x10))).unwrap();

        // Input polling.
        spec::to_result(caps::driver_sequencer_linux::CAPSET.put_cap(caps::DRIVER_INPUT_POLL_INPUT.cptr(), &spec::CPtr::new(0x11))).unwrap();

        // Call the initialize function.
        spec::to_result(caps::driver_sequencer_linux::ENDPOINT.invoke()).expect("start_driver_sequencer_linux: Cannot invoke task.");
    }
}

/// Starts the `benchmark` driver.
fn start_driver_benchmark() {
    unsafe {
        debug!("Loading benchmark driver...");

        initialize_driver_std(
            image::DRIVER_BENCHMARK,
            &caps::driver_benchmark::TASK,
            &caps::driver_benchmark::RPT,
            &caps::driver_benchmark::CAPSET,
            &caps::driver_benchmark::ENDPOINT,
        );

        // Call the initialize function.
        spec::to_result(caps::driver_benchmark::ENDPOINT.invoke()).expect("start_driver_benchmark: Cannot invoke task.");
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
