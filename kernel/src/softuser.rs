//! Architecture-independent part of the "softuser" execution mode.
//! 
//! "softuser" is a special, software-defined state in privileged mode. The kernel executes userspace RISC-V (RV32IM)
//! code with an interpreter, with enabled interrupts and some architecture-specific usermode context (`gs_base`
//! on x86-64, for example).

use flatrv::exec::{Machine, Host, Exception, GlobalContext, LowerAddressSpaceToken, EcallOutput};
use crate::task::Task;
use crate::spec::TaskFaultReason;
use crate::capability::CapabilityInvocation;
use crate::arch::softuser::*;
use crate::arch::arch_handle_interrupt;
use crate::arch::task::TaskRegisters;
use core::sync::atomic::{AtomicU8, Ordering};

static EMPTY_TASK_REGISTERS: TaskRegisters = TaskRegisters::new();

impl From<Exception> for TaskFaultReason {
    fn from(other: Exception) -> TaskFaultReason {
        match other {
            Exception::InvalidOpcode => TaskFaultReason::IllegalInstruction,
            Exception::InvalidMemoryReference => TaskFaultReason::VMAccess,
            Exception::InstructionAddressMisaligned => TaskFaultReason::InvalidOperation,
            Exception::Ebreak => TaskFaultReason::InvalidOperation,
        }
    }
}

#[repr(transparent)]
pub struct SoftuserContext {
    machine: Machine<KernelHost>,
}

#[derive(Default)]
struct KernelHost {
    pc: u32,
    pending_interrupt: AtomicU8,
}

impl Host for KernelHost {
    #[inline(never)]
    fn raise_exception(m: &mut Machine<Self>, pc: u32, exc: Exception) -> ! {
        unsafe {
            arch_softuser_hostcall_enter();
            Task::borrow_current().local_state().softuser_active = false;
        }
        m.host.pc = pc;
        unsafe {
            check_and_handle_pending_interrupt(&mut m.host);
        }
        Task::raise_fault_opt_registers(TaskFaultReason::from(exc), 0, None)
    }

    #[inline(never)]
    fn ecall(m: &mut Machine<Self>, pc: u32) -> EcallOutput {
        unsafe {
            arch_softuser_hostcall_enter();
            Task::borrow_current().local_state().softuser_active = false;
        }

        // ecall() receives the `pc` after the `ecall` instruction. To allow
        // restarting ecall() after the pending interrupt (if any) is handled, we
        // set `m.host.pc` to `pc - 4` ahead of time.
        m.host.pc = pc - 4;
        unsafe {
            check_and_handle_pending_interrupt(&mut m.host);
        }
        m.host.pc = pc;

        let mut invocation: CapabilityInvocation = unsafe {
            core::mem::zeroed()
        };
        invocation.has_softuser_args = 1;
        invocation.softuser_args[0] = build_u64(m.gregs[10], m.gregs[11]);
        invocation.softuser_args[1] = build_u64(m.gregs[12], m.gregs[13]);
        invocation.softuser_args[2] = build_u64(m.gregs[14], m.gregs[15]);
        invocation.softuser_args[3] = build_u64(m.gregs[16], m.gregs[17]);
        invocation.softuser_args[4] = build_u64(m.gregs[5], m.gregs[6]);
        invocation.softuser_args[5] = build_u64(m.gregs[7], m.gregs[28]);

        let result = crate::syscall::dispatch_syscall(&mut invocation) as u64;
        m.gregs[10] = result as u32;
        m.gregs[11] = (result >> 32) as u32;

        unsafe {
            Task::borrow_current().local_state().softuser_active = true;
            arch_softuser_hostcall_leave();
        }
        EcallOutput::default()
    }

    fn global_context() -> &'static GlobalContext<Self> {
        static GC: GlobalContext<KernelHost> = GlobalContext::new();
        &GC
    }

    /// This function is executed for each RISC-V instruction, so it must be inlined and short.
    #[inline(always)]
    fn cycle_will_run(m: &mut Machine<Self>, pc: u32) {
        use core::intrinsics::unlikely;

        m.host.pc = pc;
        
        let pending = m.host.pending_interrupt.load(Ordering::Relaxed);
        if unlikely(pending != 0) {
            unsafe {
                enter_hostcall_and_handle_interrupt(m, pending);
            }
        }
    }
}

/// Assuming we are not yet in host mode AND there is a pending interrupt, enters host mode and
/// handles the pending interrupt.
/// 
/// Marked `#[inline(never)]` to prevent being inlined into `cycle_will_run` and increasing code size
/// too much.
#[inline(never)]
unsafe fn enter_hostcall_and_handle_interrupt(m: &mut Machine<KernelHost>, index: u8) -> ! {
    arch_softuser_hostcall_enter();
    Task::borrow_current().local_state().softuser_active = false;

    m.host.pending_interrupt.store(0, Ordering::Relaxed);
    arch_handle_interrupt(&EMPTY_TASK_REGISTERS, index);
}


/// Checks and handles a pending interrupt, assuming we are already in host mode and `softuser_active` is
/// false.
unsafe fn check_and_handle_pending_interrupt(host: &mut KernelHost) {
    let pending = host.pending_interrupt.load(Ordering::Relaxed);
    if pending != 0 {
        host.pending_interrupt.store(0, Ordering::Relaxed);
        arch_handle_interrupt(&EMPTY_TASK_REGISTERS, pending);
    }
}

impl Default for SoftuserContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftuserContext {
    pub fn new() -> SoftuserContext {
        SoftuserContext {
            machine: Machine::new(KernelHost::default()),
        }
    }

    pub fn enter(&mut self) -> ! {
        unsafe {
            Task::borrow_current().local_state().softuser_active = true;
            arch_softuser_enter(self)
        }
    }

    pub fn pc_mut(&mut self) -> &mut u32 {
        &mut self.machine.host.pc
    }

    pub fn gregs_mut(&mut self) -> &mut [u32; 32] {
        &mut self.machine.gregs
    }

    pub fn set_usermode_arg_64(&mut self, i: usize, val: u64) {
        let (lo, hi): (usize, usize) = match i {
            0 => (10, 11),
            1 => (12, 13),
            2 => (14, 15),
            3 => (16, 17),
            _ => panic!("SoftuserContext::set_usermode_arg_64: Index out of bounds."),
        };
        self.machine.gregs[lo] = val as u32;
        self.machine.gregs[hi] = (val >> 32) as u32;
    }

    pub fn set_pending_interrupt(&mut self, val: u8) {
        self.machine.host.pending_interrupt.store(val, Ordering::Relaxed);
    }

    /// Checks and handles any pending interrupt on this task. If there is a pending interrupt,
    /// this function never returns.
    pub unsafe fn check_and_handle_pending_interrupt(&mut self) {
        check_and_handle_pending_interrupt(&mut self.machine.host)
    }
}

#[no_mangle]
extern "C" fn softuser_context_lowlevel_entry(me: &mut SoftuserContext) -> ! {
    let token = unsafe {
        LowerAddressSpaceToken::new()
    };
    let pc = me.machine.host.pc;
    me.machine.run(pc, &token);
    unreachable!()
}

fn build_u64(lo: u32, hi: u32) -> u64 {
    (lo as u64) | ((hi as u64) << 32)
}