use crate::capability::{CapPtr, CapabilityInvocation};
use crate::error::*;
use crate::kobj::*;
use crate::serial::with_serial_port;
use crate::task::TaskRegisters;
use core::convert::TryFrom;
use core::fmt::Write;
use num_enum::TryFromPrimitive;
use x86_64::{
    registers::{
        model_specific::{Efer, EferFlags, Msr},
        rflags::RFlags,
    },
    VirtAddr,
};

static mut IA32_FMASK: Msr = Msr::new(0xc0000084);
static mut IA32_LSTAR: Msr = Msr::new(0xc0000082);
static mut IA32_STAR: Msr = Msr::new(0xc0000081);

pub unsafe fn init() {
    let mut efer = Efer::read();
    efer |= EferFlags::SYSTEM_CALL_EXTENSIONS;
    Efer::write(efer);

    IA32_LSTAR.write(lowlevel_syscall_entry as usize as u64);

    // Disable interrupts during syscall.
    IA32_FMASK.write(RFlags::INTERRUPT_FLAG.bits());

    let selectors = crate::exception::get_selectors();
    IA32_STAR.write(
        ((selectors.kernel_code_selector.0 as u64) << 32)
            | ((selectors.kernel_data_selector.0 as u64) << 48),
    );

    with_serial_port(|p| writeln!(p, "System call enabled.").unwrap());
}

#[inline(never)]
#[no_mangle]
extern "C" fn syscall_entry(
    p0: i64,
    p1: i64,
    p2: i64,
    p3: i64,
    p4: i64,
    p5: i64,
    registers: &TaskRegisters,
) -> i64 {
    let cap = {
        let task = crate::task::get_current_task().unwrap();
        match task.capabilities.lookup(CapPtr(p0 as u64)) {
            Ok(x) => x,
            Err(e) => return e as i32 as i64,
        }
    };
    // TODO: Check rights.
    match cap.object.invoke(CapabilityInvocation {
        args: [p1, p2, p3, p4],
    }) {
        Ok(x) => x,
        Err(e) => e as i32 as i64,
    }
}

#[naked]
#[inline(never)]
unsafe extern "C" fn lowlevel_syscall_entry() {
    asm!(r#"
        swapgs
        mov %rsp, %gs:32
        mov %gs:24, %rsp

        push %r11 // rflags
        push %rcx // rip
        push %rbp // rbp
        push %gs:32 // rsp
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

        subq $$16, %rsp
        leaq 16(%rsp), %rax
        mov %rax, 0(%rsp) // saved registers
        mov %r10, %rcx
        call syscall_entry
        addq $$16, %rsp

        pop %r15
        pop %r14
        pop %r13
        pop %r12
        pop %r11
        pop %r10
        pop %r9
        pop %r8
        add $$8, %rsp // rax
        pop %rbx
        pop %rcx
        pop %rdx
        pop %rsi
        pop %rdi
        add $$8, %rsp // rsp
        pop %rbp
        pop %rcx
        pop %r11

        mov %gs:32, %rsp
        swapgs
        sysretq
    "# :::: "volatile");
}
