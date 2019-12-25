use super::config::*;
use super::task::{get_hlt, set_hlt, TaskRegisters};
use crate::serial::with_serial_port;
use crate::task::{invoke_interrupt, Task, TaskFaultState};
use core::fmt::Write;
use pic8259_simple::ChainedPics;
use spin::Mutex;
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

const PIC_1_OFFSET: u8 = 32;
const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;
static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

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
    IDT.invalid_opcode
        .set_handler_fn(core::mem::transmute(intr_invalid_opcode as usize));
    IDT.breakpoint
        .set_handler_fn(core::mem::transmute(intr_breakpoint as usize));
    IDT.page_fault
        .set_handler_fn(core::mem::transmute(intr_page_fault as usize));
    IDT.general_protection_fault
        .set_handler_fn(core::mem::transmute(intr_gpf as usize));
    include!("../../../generated/interrupts_idt.rs");
    IDT.load();
}

pub unsafe fn init_interrupts() {
    PICS.lock().initialize();
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

interrupt!(intr_divide_error, __intr_divide_error, frame, _registers, {
    with_serial_port(|p| {
        writeln!(p, "Divide error: {:#?}", frame).unwrap();
    });
    if !is_user_fault(frame) {
        panic!("Kernel divide error");
    }
    Task::current().raise_fault(TaskFaultState::IntegerDivision);
});

interrupt!(
    intr_invalid_opcode,
    __intr_invalid_opcode,
    frame,
    _registers,
    {
        with_serial_port(|p| {
            writeln!(p, "Invalid opcode: {:#?}", frame).unwrap();
        });
        if !is_user_fault(frame) {
            panic!("Kernel invalid opcode");
        }
        Task::current().raise_fault(TaskFaultState::IllegalInstruction);
    }
);

interrupt_with_code!(intr_gpf, __intr_gpf, frame, _registers, code, {
    with_serial_port(|p| {
        writeln!(p, "General protection fault: code = {} {:#?}", code, frame).unwrap();
    });
    if !is_user_fault(frame) {
        panic!("Kernel GPF");
    }
    Task::current().raise_fault(TaskFaultState::GeneralProtection);
});

interrupt_with_code!(
    intr_page_fault,
    __intr_page_fault,
    frame,
    _registers,
    code,
    {
        with_serial_port(|p| {
            writeln!(
                p,
                "Page fault at {:p}. code = {:?} {:#?}",
                Cr2::read().as_ptr::<u8>(),
                PageFaultErrorCode::from_bits(code),
                frame
            )
            .unwrap();
        });
        if !is_user_fault(frame) {
            panic!("Kernel page fault");
        }
        Task::current().raise_fault(TaskFaultState::PageFault);
    }
);

include!("../../../generated/interrupts_impl.rs");

fn handle_external_interrupt(
    frame: &mut InterruptStackFrame,
    registers: &mut TaskRegisters,
    index: u8,
) -> ! {
    if !is_user_fault(frame) && !get_hlt() {
        panic!("External interrupt in kernel mode");
    }
    unsafe {
        set_hlt(false);
        invoke_interrupt(index, registers, None);
        // If fails, ignore this interrupt.
        super::task::arch_enter_user_mode(registers);
    }
}
