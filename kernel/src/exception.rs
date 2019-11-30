use crate::serial::with_serial_port;
use crate::task::Task;
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
    PrivilegeLevel, VirtAddr,
};

// XXX: Keep this consistent with Cargo.toml
pub const KERNEL_STACK_START: u64 = 0xFFFFFF8000000000u64;
pub const KERNEL_STACK_SIZE: u64 = 4096 * 512;
pub const KERNEL_STACK_END: u64 = KERNEL_STACK_START + KERNEL_STACK_SIZE;

const PIC_1_OFFSET: u8 = 32;
const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;
static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

static mut GDT: Option<GlobalDescriptorTable> = None;
static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static mut SELECTORS: Option<Selectors> = None;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

#[derive(Debug)]
pub struct Selectors {
    pub kernel_code_selector: SegmentSelector,
    pub kernel_data_selector: SegmentSelector,
    pub user_data_selector: SegmentSelector,
    pub user_code_selector: SegmentSelector,
    pub tss_selector: SegmentSelector,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
}

pub fn get_selectors() -> &'static Selectors {
    unsafe { SELECTORS.as_ref().unwrap() }
}

pub unsafe fn init_gdt() {
    use x86_64::instructions::{segmentation::set_cs, tables::load_tss};

    GDT = Some(GlobalDescriptorTable::new());
    let gdt = GDT.as_mut().unwrap();

    TSS.privilege_stack_table[0] = VirtAddr::new(KERNEL_STACK_END);
    TSS.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        static mut STACK: [u8; 65536] = [0; 65536];
        let stack_start = VirtAddr::from_ptr(&STACK);
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

    IDT.breakpoint
        .set_handler_fn(intr_breakpoint)
        .disable_interrupts(false);
    IDT.page_fault
        .set_handler_fn(intr_page_fault)
        .disable_interrupts(false);
    IDT.general_protection_fault
        .set_handler_fn(intr_gpf)
        .disable_interrupts(false);
    IDT[InterruptIndex::Timer as u8 as usize]
        .set_handler_fn(core::mem::transmute(intr_timer as usize));
    IDT.load();
}

pub unsafe fn init_interrupts() {
    PICS.lock().initialize();
    x86_64::instructions::interrupts::enable();
}

fn is_user_fault(frame: &mut InterruptStackFrame) -> bool {
    let frame = unsafe { frame.as_mut() };
    (frame.code_segment >> 3) == get_selectors().user_code_selector.index() as u64
}

fn prepare_interrupt_entry(_frame: &mut InterruptStackFrame) {
    unsafe {
        crate::task::switch_task_mode();
    }
}

fn prepare_interrupt_exit(_frame: &mut InterruptStackFrame) {
    unsafe {
        crate::task::switch_task_mode();
    }
}

macro_rules! interrupt {
    ($name:ident, $internal_name:ident, $arg0:ident, $arg1:ident, $body:block) => {
        #[no_mangle]
        extern "C" fn $internal_name($arg0: &mut ::x86_64::structures::idt::InterruptStackFrame, $arg1: &mut $crate::task::TaskRegisters) {
            $body
        }

        #[naked]
        unsafe extern "C" fn $name() {
            asm!(concat!(r#"
                swapgs
                sti

                push %rbp
                mov %rsp, %rbp

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

                pop %r15
                pop %r14
                pop %r13
                pop %r12
                pop %r11
                pop %r10
                pop %r9
                pop %r8
                pop %rax
                pop %rbx
                pop %rcx
                pop %rdx
                pop %rsi
                pop %rdi
                add $$32, %rsp
                pop %rbp

                cli
                swapgs
                iretq
            "#) :::: "volatile");
        }
    };
}

extern "x86-interrupt" fn intr_breakpoint(frame: &mut InterruptStackFrame) {
    prepare_interrupt_entry(frame);

    with_serial_port(|p| {
        writeln!(p, "Breakpoint: {:#?}", frame).unwrap();
    });

    prepare_interrupt_exit(frame);
}

extern "x86-interrupt" fn intr_gpf(frame: &mut InterruptStackFrame, code: u64) {
    prepare_interrupt_entry(frame);

    with_serial_port(|p| {
        writeln!(p, "General protection fault: code = {} {:#?}", code, frame).unwrap();
    });
    if !is_user_fault(frame) {
        panic!("Kernel GPF");
    }
    let mut current = Task::current().expect("User GPF without current task");
    let current = unsafe { current.as_ref() };
    current.kill();
    unsafe {
        crate::task::schedule();
    }

    prepare_interrupt_exit(frame);
}

/// Double fault. Entry/exit mode switch code should not run.
extern "x86-interrupt" fn intr_double_fault(frame: &mut InterruptStackFrame, code: u64) {
    with_serial_port(|p| {
        writeln!(p, "Double fault: code = {} {:#?}", code, frame).unwrap();
    });
    panic!("Double fault");
}

interrupt!(intr_timer, __intr_timer, frame, registers, {
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer as u8);
    }
    if is_user_fault(frame) {
        unsafe {
            let current = crate::task::get_current_task().unwrap();
            *current.as_ref().registers.get() = *registers;
            crate::task::schedule();
        }
    }
});

extern "x86-interrupt" fn intr_page_fault(
    frame: &mut InterruptStackFrame,
    code: PageFaultErrorCode,
) {
    prepare_interrupt_entry(frame);

    with_serial_port(|p| {
        writeln!(
            p,
            "Page fault at {:p}. code = {:?} {:#?}",
            Cr2::read().as_ptr::<u8>(),
            code,
            frame
        )
        .unwrap();
    });
    if !is_user_fault(frame) {
        panic!("Kernel page fault");
    }
    let mut current = Task::current().expect("User page fault without current task");
    let current = unsafe { current.as_ref() };
    if current.pending_page_fault.get() {
        current.kill();
        unsafe {
            crate::task::schedule();
        }
    } else {
        current.pending_page_fault.set(true);
    }

    prepare_interrupt_exit(frame);
}
