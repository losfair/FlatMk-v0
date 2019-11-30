use crate::serial::with_serial_port;
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
    // FIXME: Fix this
    //IA32_FMASK.write(!RFlags::INTERRUPT_FLAG.bits());

    let selectors = crate::exception::get_selectors();
    IA32_STAR.write(
        ((selectors.kernel_code_selector.0 as u64) << 32)
            | ((selectors.kernel_data_selector.0 as u64) << 48),
    );

    with_serial_port(|p| writeln!(p, "System call enabled.").unwrap());
}

#[derive(Copy, Clone, Debug, TryFromPrimitive)]
#[repr(u32)]
enum SyscallIndex {
    Call = 0,
}

#[inline(never)]
#[no_mangle]
extern "C" fn syscall_entry(p0: i64, p1: i64, p2: i64, p3: i64, p4: i64, p5: i64, nr: i64) -> i64 {
    let idx = match SyscallIndex::try_from(nr as u32) {
        Ok(x) => x,
        Err(_) => return -1,
    };
    match idx {
        SyscallIndex::Call => unsafe {
            // call
            let task = crate::task::get_current_task().unwrap();
            let task = task.as_ref();
            let caps = &*(*task.capabilities).capabilities.get();
            let index = if p0 >= 0 && (p0 as usize) < caps.len() {
                p0 as usize
            } else {
                return -1;
            };
            let cap = &caps[index];
            if cap.vtable.is_null() {
                return -1;
            }
            if let Some(call) = (*cap.vtable).call {
                let result = call(&*cap.object, p1, p2, p3, p4);
                //with_serial_port(|p| writeln!(p, "Call result = {}", result).unwrap());
                result
            } else {
                return -1;
            }
        },
    }
    //with_serial_port(|p| writeln!(p, "Syscall nr={}, params=[{}, {}, {}, {}, {}, {}]", nr, p0, p1, p2, p3, p4, p5).unwrap());
}

#[naked]
#[inline(never)]
unsafe extern "C" fn lowlevel_syscall_entry() {
    asm!(r#"
        swapgs
        mov %rsp, %gs:8
        mov %gs:0, %rsp
        pushq %rcx
        pushq %r11
        pushq %rbx
        pushq %rbp
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15

        subq $$16, %rsp
        mov %rax, (%rsp) // nr
        mov %r10, %rcx
        call syscall_entry
        addq $$16, %rsp

        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %rbp
        popq %rbx
        popq %r11
        popq %rcx

        cli
        mov %gs:8, %rsp
        swapgs
        sysretq
    "# :::: "volatile");
}
