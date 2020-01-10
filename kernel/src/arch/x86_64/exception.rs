use super::config::*;
use super::task::TaskRegisters;
use crate::serial::with_serial_port;
use crate::task::{invoke_interrupt, Task, enter_user_mode_with_registers, StateRestoreMode};
use crate::spec::TaskFaultReason;
use core::fmt::Write;
use x86_64::{
    registers::control::Cr2,
    structures::{
        gdt::{
            Descriptor as GlobalDescriptor, DescriptorFlags, GlobalDescriptorTable, SegmentSelector,
        },
        idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
        tss::TaskStateSegment,
    },
    PrivilegeLevel,
};

static mut GDT: Option<GlobalDescriptorTable> = None;
static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static mut SELECTORS: Option<Selectors> = None;

const DOUBLE_FAULT_IST_INDEX: u16 = 0;

#[derive(Debug)]
pub struct Selectors {
    pub kernel_code_selector: SegmentSelector,
    pub kernel_data_selector: SegmentSelector,
    pub user_data_selector: SegmentSelector,
    pub user_code_selector: SegmentSelector,
    pub tss_selector: SegmentSelector,
}

pub fn get_selectors() -> &'static Selectors {
    unsafe { SELECTORS.as_ref().unwrap() }
}

pub unsafe fn init_gdt() {
    use x86_64::instructions::{segmentation::set_cs, tables::load_tss};

    GDT = Some(GlobalDescriptorTable::new());
    let gdt = GDT.as_mut().unwrap();

    TSS.privilege_stack_table[0] = ::x86_64::VirtAddr::new(KERNEL_STACK_END);
    TSS.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        static mut STACK: [u8; 65536] = [0; 65536];
        let stack_start = ::x86_64::VirtAddr::from_ptr(&STACK);
        let stack_end = stack_start + STACK.len();
        stack_end
    };

    let kernel_code_selector = gdt.add_entry(GlobalDescriptor::kernel_code_segment());
    let kernel_data_selector = gdt.add_entry(GlobalDescriptor::UserSegment(
        (DescriptorFlags::USER_SEGMENT
            | DescriptorFlags::PRESENT
            | DescriptorFlags::WRITABLE
            | DescriptorFlags::LONG_MODE)
            .bits(),
    ));
    let user_data_selector = SegmentSelector::new(
        gdt.add_entry(GlobalDescriptor::user_data_segment()).index(),
        PrivilegeLevel::Ring3,
    );
    let user_code_selector = SegmentSelector::new(
        gdt.add_entry(GlobalDescriptor::user_code_segment()).index(),
        PrivilegeLevel::Ring3,
    );
    let tss_selector = gdt.add_entry(GlobalDescriptor::tss_segment(&TSS));

    gdt.load();
    set_cs(kernel_code_selector);
    load_tss(tss_selector);

    SELECTORS = Some(Selectors {
        kernel_code_selector,
        kernel_data_selector,
        user_code_selector,
        user_data_selector,
        tss_selector,
    });
}

pub unsafe fn init_idt() {
    IDT.double_fault
        .set_handler_fn(intr_double_fault)
        .set_stack_index(DOUBLE_FAULT_IST_INDEX);

    IDT.divide_error
        .set_handler_fn(core::mem::transmute(intr_divide_error as usize));
    IDT.device_not_available
        .set_handler_fn(core::mem::transmute(intr_device_not_available as usize));
    IDT.simd_floating_point
        .set_handler_fn(core::mem::transmute(intr_simd_floating_point as usize));
    IDT.invalid_opcode
        .set_handler_fn(core::mem::transmute(intr_invalid_opcode as usize));
    IDT.breakpoint
        .set_handler_fn(core::mem::transmute(intr_breakpoint as usize));
    IDT.page_fault
        .set_handler_fn(core::mem::transmute(intr_page_fault as usize));
    IDT.general_protection_fault
        .set_handler_fn(core::mem::transmute(intr_gpf as usize));
    IDT.stack_segment_fault
        .set_handler_fn(core::mem::transmute(intr_stack_segment_fault as usize));
    include!("../../../generated/interrupts_idt.rs");
    IDT.load();
}

fn is_user_fault(frame: &mut InterruptStackFrame) -> bool {
    let frame = unsafe { frame.as_mut() };
    (frame.code_segment >> 3) == get_selectors().user_code_selector.index() as u64
}

macro_rules! interrupt {
    ($name:ident, $internal_name:ident, $arg0:ident, $arg1:ident, $body:block) => {
        #[no_mangle]
        extern "C" fn $internal_name($arg0: &mut ::x86_64::structures::idt::InterruptStackFrame, $arg1: &mut $crate::arch::task::TaskRegisters) -> ! {
            $body
        }

        #[naked]
        unsafe extern "C" fn $name() {
            asm!(concat!(r#"
                swapgs

                push %rbp
                mov %rsp, %rbp

                pushq $$0 // fs
                pushq $$0 // gs
                push 24(%rbp) // rflags
                push 8(%rbp) // rip
                push 0(%rbp) // rbp
                push 32(%rbp) // rsp
                push %rdi
                push %rsi
                push %rdx
                push %rcx
                push %rbx
                push %rax
                push %r8
                push %r9
                push %r10
                push %r11
                push %r12
                push %r13
                push %r14
                push %r15

                leaq 8(%rbp), %rdi
                mov %rsp, %rsi
                call "#, stringify!($internal_name), r#"
                ud2
            "#) :::: "volatile");
        }
    };
}

macro_rules! interrupt_with_code {
    ($name:ident, $internal_name:ident, $arg0:ident, $arg1:ident, $arg2:ident, $body:block) => {
        #[no_mangle]
        extern "C" fn $internal_name($arg0: &mut ::x86_64::structures::idt::InterruptStackFrame, $arg1: &mut $crate::arch::task::TaskRegisters, $arg2: u64) -> ! {
            $body
        }

        #[naked]
        unsafe extern "C" fn $name() {
            asm!(concat!(r#"
                swapgs

                push %rbp
                mov %rsp, %rbp

                pushq $$0 // fs
                pushq $$0 // gs
                push 32(%rbp) // rflags
                push 16(%rbp) // rip
                push 0(%rbp) // rbp
                push 40(%rbp) // rsp
                push %rdi
                push %rsi
                push %rdx
                push %rcx
                push %rbx
                push %rax
                push %r8
                push %r9
                push %r10
                push %r11
                push %r12
                push %r13
                push %r14
                push %r15

                leaq 16(%rbp), %rdi
                mov %rsp, %rsi
                mov 8(%rbp), %rdx // error code
                call "#, stringify!($internal_name), r#"
                ud2
            "#) :::: "volatile");
        }
    };
}

/// Double fault. Entry/exit mode switch code should not run.
extern "x86-interrupt" fn intr_double_fault(frame: &mut InterruptStackFrame, code: u64) -> ! {
    with_serial_port(|p| {
        writeln!(p, "Double fault: code = {} {:#?}", code, frame).unwrap();
    });
    panic!("Double fault");
}

interrupt_with_code!(
    intr_breakpoint,
    __intr_breakpoint,
    _frame,
    _registers,
    _code,
    {
        panic!("breakpoint");
    }
);

interrupt!(intr_divide_error, __intr_divide_error, frame, registers, {
    if !is_user_fault(frame) {
        if fault_try_take_softuser_if_active() {
            // Divide error in softuser mode.
        }
        else {
            panic!("Kernel divide error: {:#?}", frame);
        }
    }
    Task::raise_fault(TaskFaultReason::InvalidOperation, 0, registers);
});

interrupt!(intr_device_not_available, __intr_device_not_available, frame, registers, {
    if !is_user_fault(frame) {
        panic!("Kernel device not available: {:#?}", frame);
    }
    Task::raise_fault(TaskFaultReason::InvalidOperation, 0, registers);
});

interrupt!(intr_simd_floating_point, __intr_simd_floating_point, frame, registers, {
    if !is_user_fault(frame) {
        panic!("Kernel SIMD floating point error: {:#?}", frame);
    }
    Task::raise_fault(TaskFaultReason::InvalidOperation, 0, registers);
});

interrupt!(
    intr_invalid_opcode,
    __intr_invalid_opcode,
    frame,
    registers,
    {
        if !is_user_fault(frame) {
            panic!("Kernel invalid opcode: {:#?}", frame);
        }
        Task::raise_fault(TaskFaultReason::IllegalInstruction, 0, registers);
    }
);

interrupt_with_code!(intr_gpf, __intr_gpf, frame, registers, code, {
    if !is_user_fault(frame) {
        panic!("Kernel GPF: code = {} {:#?}", code, frame);
    }
    Task::raise_fault(TaskFaultReason::InvalidOperation, 0, registers);
});

interrupt_with_code!(
    intr_page_fault,
    __intr_page_fault,
    frame,
    registers,
    code,
    {
        // Handle copy from/to user faults.
        //
        // Before jumping to the copy error handler, we need to do a `swapgs` because it was assumed that this was a user fault
        // and `gs` was swapped twice to the user gs.
        if !is_user_fault(frame) && registers.rip == super::asm_import::__copy_user_checked_argreversed__copyinst as u64 {
            unsafe {
                asm!(
                    r#"
                        swapgs
                        jmp *%rax
                    "# :
                    : "{rax}"(super::asm_import::__copy_user_checked_argreversed__copyend as u64),
                        "{r12}"(registers.r12), "{r13}"(registers.r13),
                        "{r14}"(registers.r14), "{r15}"(registers.r15),
                        "{rbx}"(registers.rbx), "{rbp}"(registers.rbp),
                        "{rsp}"(registers.rsp)
                        :: "volatile"
                );
                unreachable!()
            }
        }

        let fault_addr = Cr2::read().as_ptr::<u8>();
        if !is_user_fault(frame) {
            if fault_try_take_softuser_if_active() {
                // A softuser page fault can either happen from within the first 32-bit range, or
                // at `-1 as u64` (which indicates an invalid opcode).
                if (fault_addr as u64) <= (core::u32::MAX as u64) {
                    Task::raise_fault(TaskFaultReason::VMAccess, fault_addr as u64, registers);
                } else if (fault_addr as u64) == core::u64::MAX {
                    Task::raise_fault(TaskFaultReason::IllegalInstruction, 0, registers);
                } else {
                    panic!(
                        "Kernel page fault in softuser mode, but fault address is not in softuser range.\nADDR={:p} CODE={:?} RIP={:p}",
                        fault_addr,
                        PageFaultErrorCode::from_bits(code),
                        frame.instruction_pointer.as_ptr::<u8>(),
                    );
                }
            } else {
                panic!(
                    "Kernel page fault at {:p}. CODE={:?} RIP={:p}",
                    fault_addr,
                    PageFaultErrorCode::from_bits(code),
                    frame.instruction_pointer.as_ptr::<u8>(),
                );
            }
        }
        Task::raise_fault(TaskFaultReason::VMAccess, fault_addr as u64, registers);
    }
);

interrupt_with_code!(
    intr_stack_segment_fault,
    __intr_stack_segment_fault,
    frame,
    registers,
    code,
    {
        with_serial_port(|p| {
            writeln!(
                p,
                "Stack segment fault. code = {} {:#?}",
                code,
                frame
            )
            .unwrap();
        });
        if !is_user_fault(frame) {
            panic!("Kernel stack segment fault. code = {} {:#?}", code, frame);
        }
        Task::raise_fault(TaskFaultReason::VMAccess, 0, registers);
    }
);

include!("../../../generated/interrupts_impl.rs");

fn handle_external_interrupt(
    frame: &mut InterruptStackFrame,
    registers: &mut TaskRegisters,
    index: u8,
) -> ! {
    if !is_user_fault(frame) {
        // Interrupts are enabled in softuser mode, but we cannot preempt out execution until an opcode boundary.
        // So, we just set a flag and let the interpreter check it per cycle.
        //
        // The overhead of this method seems to be very low.
        unsafe {
            let state = Task::borrow_current().local_state();
            if state.softuser_active {
                state.softuser_context.set_pending_interrupt(index);
                super::task::arch_return_to_kernel_mode(registers);
            }
        }
        
        panic!("External interrupt in kernel mode");
    }

    unsafe {
        arch_handle_interrupt(registers, index)
    }
}

/// Handles a (possibly deferred) interrupt.
pub unsafe fn arch_handle_interrupt(
    registers: &TaskRegisters,
    index: u8
) -> ! {
    let wfi = {
        let state = Task::borrow_current().local_state();
        if state.wfi {
            state.wfi = false;
            true
        } else {
            false
        }
    };
    match index {
        32 => {
            // Timer interrupt
            super::task::arch_unblock_interrupt(index);
            (*super::task::arch_get_cpu_scheduler()).tick(1000000, registers, wfi); // 1 millisecond per tick
        }
        _ => {
            invoke_interrupt(index, registers);
            // If fails, ignore this interrupt.
            enter_user_mode_with_registers(StateRestoreMode::Full, registers);
        }
    }
}

/// In a fault case, try reading `softuser_active` field of the current task and reset it to false. If there is a
/// pending interrupt on this task, this function will call the interrupt handler and never returns.
/// 
/// This function exists to solve a race condition where an interrupt arrives between `cycle_will_run` checking the
/// pending interrupt flag and the opcode implementation throwing a fault. If in fault handlers we don't do another check
/// on the pending interrupt flag, we're likely to miss interrupts.
/// 
/// The fault will be triggered again next time the current task begins execution, if here we choose to handle a pending
/// interrupt instead.
fn fault_try_take_softuser_if_active() -> bool {
    unsafe {
        let state = Task::borrow_current().local_state();
        let active = state.softuser_active;
        if active {
            state.softuser_active = false;
            state.softuser_context.check_and_handle_pending_interrupt();
            true
        } else {
            false
        }
    }
}
