use crate::error::*;
use crate::task::{Task};
use crate::spec::TaskFaultReason;
use x86_64::registers::{
    model_specific::{Efer, EferFlags, FsBase, GsBase, KernelGsBase, Msr},
    rflags::RFlags,
};
use crate::addr::*;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct TaskRegisters {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rip: u64,
    pub rflags: u64,
    pub gs_base: u64,
    pub fs_base: u64,
}

impl TaskRegisters {
    pub fn new() -> TaskRegisters {
        TaskRegisters {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rsp: 0,
            rbp: 0,
            rip: 0,
            rflags: RFlags::INTERRUPT_FLAG.bits(),
            gs_base: 0,
            fs_base: 0,
        }
    }

    #[inline]
    pub fn field_mut(&mut self, idx: usize) -> KernelResult<&mut u64> {
        Ok(match idx {
            0 => &mut self.rax,
            1 => &mut self.rdx,
            2 => &mut self.rcx,
            3 => &mut self.rbx,
            4 => &mut self.rsi,
            5 => &mut self.rdi,
            6 => &mut self.rbp,
            7 => &mut self.rsp,
            8 => &mut self.r8,
            9 => &mut self.r9,
            10 => &mut self.r10,
            11 => &mut self.r11,
            12 => &mut self.r12,
            13 => &mut self.r13,
            14 => &mut self.r14,
            15 => &mut self.r15,
            16 => &mut self.rip,
            58 => &mut self.fs_base,
            59 => &mut self.gs_base,
            _ => return Err(KernelError::InvalidArgument),
        })
    }

    #[inline]
    pub fn return_value_mut(&mut self) -> &mut u64 {
        &mut self.rax
    }

    #[inline]
    pub fn syscall_arg(&self, n: usize) -> KernelResult<u64> {
        Ok(match n {
            0 => self.rdi,
            1 => self.rsi,
            2 => self.rdx,
            3 => self.r10,
            4 => self.r8,
            5 => self.r9,
            _ => return Err(KernelError::InvalidArgument),
        })
    }

    #[inline]
    pub fn usermode_arg_mut(&mut self, n: usize) -> KernelResult<&mut u64> {
        // rcx is not used because it is clobbered during sysret.
        Ok(match n {
            0 => &mut self.rdi,
            1 => &mut self.rsi,
            2 => &mut self.rdx,
            3 => &mut self.r8,
            4 => &mut self.r9,
            _ => return Err(KernelError::InvalidArgument),
        })
    }

    #[inline]
    pub fn pc_mut(&mut self) -> &mut u64 {
        &mut self.rip
    }

    /// Loads part of the register set that are not touched by the kernel
    /// but can be used by the userspace.
    pub fn lazy_read(&mut self) {
        unsafe {
            self.fs_base = FsBase::MSR.read();
            self.gs_base = KernelGsBase::MSR.read();
        }
    }

    pub fn lazy_write(&self) {
        unsafe {
            FsBase::MSR.write(self.fs_base);
            KernelGsBase::MSR.write(self.gs_base);
        }
    }

    /// Call `f` on `self`, but preserve critical registers that are unsafe to modify from userspace.
    pub fn preserve_critical_registers<F: FnOnce(&mut Self) -> R, R>(&mut self, f: F) -> R {
        let rflags = self.rflags;
        let ret = f(self);
        self.rflags = rflags;
        ret
    }
}

#[repr(C)]
pub struct TlsIndirect {
    pub kernel_stack: u64,
    pub user_stack: u64,
    pub context: u64,
    pub(super) hlt: u64,
}

impl TlsIndirect {
    pub const fn new(kernel_stack: u64) -> TlsIndirect {
        TlsIndirect {
            kernel_stack,
            user_stack: 0,
            context: 0,
            hlt: 0,
        }
    }
}

pub unsafe fn arch_init_kernel_tls_for_cpu(tls_indirect: *mut TlsIndirect) {
    GsBase::write(::x86_64::VirtAddr::new_unchecked(tls_indirect as u64));
}

/// Returns the kernel thread local storage (TLS) pointer for the current CPU.
pub fn arch_get_kernel_tls() -> u64 {
    let result: u64;
    unsafe {
        asm!("mov %gs:16, $0" : "=r"(result) ::);
    }
    result
}

/// Sets the kernel thread local storage (TLS) pointer for the current CPU.
pub unsafe fn arch_set_kernel_tls(value: u64) {
    asm!("mov $0, %gs:16" :: "r"(value) :: "volatile");
}

pub(super) unsafe fn set_hlt(value: u64) {
    asm!("mov $0, %gs:24" :: "r"(value) :: "volatile");
}

pub(super) fn get_hlt() -> u64 {
    let result: u64;
    unsafe {
        asm!("mov %gs:24, $0" : "=r"(result) ::);
    }
    result
}

/// Safely copies a range of memory from userspace.
pub fn copy_from_user(uaddr: UserAddr, out: &mut [u8]) -> KernelResult<()> {
    let end = match uaddr.get().checked_add(out.len() as u64) {
        Some(x) => x,
        None => return Err(KernelError::InvalidAddress)
    };

    // `end` is exclusive.
    if end > super::config::KERNEL_VM_START {
        return Err(KernelError::InvalidAddress);
    }

    let out_len = out.len();
    let n = unsafe {
        super::asm_import::__copy_user_checked_argreversed(out.as_mut_ptr() as u64, uaddr.get(), out_len as u64)
    };
    if n != 0 {
        Err(KernelError::InvalidAddress)
    } else {
        Ok(())
    }
}

/// Copies a range of typed values from userspace.
/// 
/// This function is unsafe because the caller must ensure that `T` is valid for any bit patterns.
pub unsafe fn copy_from_user_typed<T>(uaddr: UserAddr, out: &mut [T]) -> KernelResult<()> {
    let len = out.len() * core::mem::size_of::<T>();
    copy_from_user(uaddr, core::slice::from_raw_parts_mut(
        out.as_mut_ptr() as *mut u8, len
    ))
}

/// Safely copies a range of memory to userspace.
pub fn copy_to_user(data: &[u8], uaddr: UserAddr) -> KernelResult<()> {
    let end = match uaddr.get().checked_add(data.len() as u64) {
        Some(x) => x,
        None => return Err(KernelError::InvalidAddress)
    };

    // `end` is exclusive.
    if end > super::config::KERNEL_VM_START {
        return Err(KernelError::InvalidAddress);
    }

    let data_len = data.len();
    let n = unsafe {
        super::asm_import::__copy_user_checked_argreversed(uaddr.get(), data.as_ptr() as u64, data_len as u64)
    };
    if n != 0 {
        Err(KernelError::InvalidAddress)
    } else {
        Ok(())
    }
}

/// Safely copies a few typed values to userspace.
pub fn copy_to_user_typed<T>(data: &[T], uaddr: UserAddr) -> KernelResult<()> {
    let len = data.len() * core::mem::size_of::<T>();
    copy_to_user(unsafe {
        core::slice::from_raw_parts(data.as_ptr() as *const u8, len)
    }, uaddr)
}

/// The syscall path of entering user mode.
///
/// Invalidates registers as defined by the calling convention, but is usually faster.
pub unsafe fn arch_enter_user_mode_syscall(registers: *const TaskRegisters) -> ! {
    if !super::addr::address_is_canonical((*registers).rip) {
        Task::raise_fault(Task::current(), TaskFaultReason::VMAccess, (*registers).rip, &*registers);
    }

    asm!(
        r#"
            mov 136(%rsi), %r11 // rflags
            mov 128(%rsi), %rcx // rip

            mov 0(%rsi), %r15
            mov 8(%rsi), %r14
            mov 16(%rsi), %r13
            mov 24(%rsi), %r12
            //mov 32(%rsi), %r11
            mov 40(%rsi), %r10
            mov 48(%rsi), %r9
            mov 56(%rsi), %r8
            mov 64(%rsi), %rax
            mov 72(%rsi), %rbx
            //mov 80(%rsi), %rcx
            mov 88(%rsi), %rdx
            mov 104(%rsi), %rdi
            mov 120(%rsi), %rbp
            mov 112(%rsi), %rsp
            mov 96(%rsi), %rsi
            swapgs
            sysretq
        "# : :
            "{rsi}"(registers)
            :: "volatile"
    );
    unreachable!()
}

pub unsafe fn arch_enter_user_mode(registers: *const TaskRegisters) -> ! {
    let selectors = super::exception::get_selectors();
    assert_eq!(core::mem::size_of::<TaskRegisters>(), 160);

    asm!(
        r#"
            pushq %rcx // ds
            pushq %rcx // ss
            pushq 112(%rsi) // rsp
            pushq 136(%rsi) // rflags
            pushq %rdx // cs
            pushq 128(%rsi) // rip
            mov 0(%rsi), %r15
            mov 8(%rsi), %r14
            mov 16(%rsi), %r13
            mov 24(%rsi), %r12
            mov 32(%rsi), %r11
            mov 40(%rsi), %r10
            mov 48(%rsi), %r9
            mov 56(%rsi), %r8
            mov 64(%rsi), %rax
            mov 72(%rsi), %rbx
            mov 80(%rsi), %rcx
            mov 88(%rsi), %rdx
            mov 104(%rsi), %rdi
            mov 120(%rsi), %rbp
            mov 96(%rsi), %rsi
            swapgs
            iretq
        "# : :
            "{rsi}"(registers),
            "{rdx}"(selectors.user_code_selector.0),
            "{rcx}"(selectors.user_data_selector.0)
            :: "volatile"
    );
    unreachable!()
}

#[naked]
#[inline(never)]
unsafe extern "C" fn arch_lowlevel_syscall_entry() {
    asm!(r#"
        swapgs
        mov %rsp, %gs:8
        mov %gs:0, %rsp

        pushq $$0 // fs
        pushq $$0 // gs
        push %r11 // rflags
        push %rcx // rip
        push %rbp // rbp
        push %gs:8 // rsp
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

        mov %rsp, %rdi
        jmp syscall_entry
    "# :::: "volatile");
}

pub unsafe fn arch_init_syscall() {
    static mut IA32_FMASK: Msr = Msr::new(0xc0000084);
    static mut IA32_LSTAR: Msr = Msr::new(0xc0000082);
    static mut IA32_STAR: Msr = Msr::new(0xc0000081);

    let mut efer = Efer::read();
    efer |= EferFlags::SYSTEM_CALL_EXTENSIONS;
    Efer::write(efer);

    IA32_LSTAR.write(arch_lowlevel_syscall_entry as usize as u64);

    // Mask usermode rflags on entry to syscalls.
    IA32_FMASK.write(RFlags::all().bits());

    let selectors = super::exception::get_selectors();
    IA32_STAR.write(
        ((selectors.kernel_code_selector.0 as u64) << 32)
            | ((selectors.kernel_data_selector.0 as u64) << 48),
    );
}

/// Waits for an interrupt. Never returns because the interrupt handler will return to usermode.
pub fn wait_for_interrupt() -> ! {
    unsafe {
        set_hlt(1);
        asm!(
            r#"
                mov %gs:0, %rsp // In case we recursively enter wait_for_interrupt without going through ring 3.
                swapgs
                sti
                hlt
                ud2
            "# :::: "volatile"
        );
    }

    unreachable!()
}

/// Low-level routine that notifies the hardware interrupt controller an interrupt unblock event.
pub unsafe fn arch_unblock_interrupt(index: u8) {
    use x86::io;
    const PIC_EOI: u8 = 0x20;

    // Notify both PICs.
    if index >= 40 {
        io::outb(0xa0, PIC_EOI); // PIC 2
    }

    if index >= 32 {
        io::outb(0x20, PIC_EOI); // PIC 1
    } else {
        panic!("arch_unblock_interrupt: Unexpected interrupt index.");
    }
}
