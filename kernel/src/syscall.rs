use crate::arch::task::{arch_get_cpu_scheduler, arch_init_syscall};
use crate::capability::{CapPtr, CapabilityEndpointObject, CapabilityInvocation, INVALID_CAP};
use crate::task::{Task, EntryType, enter_user_mode, enter_user_mode_with_registers, StateRestoreMode};
use crate::spec::{TaskFaultReason, TrivialSyscall};
use crate::scheduler::PreviousTaskStateChange;
use core::convert::TryFrom;
use crate::error::*;

pub unsafe fn init() {
    arch_init_syscall();
}

pub fn dispatch_syscall(invocation: &mut CapabilityInvocation) -> i64 {
    let task = unsafe {
        Task::borrow_current()
    };

    if task.get_syscall_delegated() {
        Task::raise_fault(TaskFaultReason::InvalidCapability, 0, &invocation.registers);
    }

    let cptr = invocation.cptr();
    if cptr.0 == INVALID_CAP {
        match handle_trivial_syscall(invocation) {
            Ok(x) => x as i64,
            Err(e) => e as i32 as i64,
        }
    } else {
        let cap = {
            let maybe_cap = task.capabilities.get().lookup_cptr_no_check_clone(cptr);
            match maybe_cap {
                Ok(x) => x,
                Err(_) => {
                    Task::raise_fault(TaskFaultReason::InvalidCapability, 0, &invocation.registers);
                }
            }
        };
        match cap.object.invoke(invocation) {
            Ok(x) => x,
            Err(e) => e as i32 as i64,
        }
    }
}

#[inline(never)]
#[no_mangle]
extern "C" fn syscall_entry(invocation: &mut CapabilityInvocation) -> ! {
    let result = dispatch_syscall(invocation);

    *invocation.registers.return_value_mut() = result as _;
    enter_user_mode_with_registers(StateRestoreMode::Syscall, &invocation.registers);
}

fn handle_trivial_syscall(invocation: &mut CapabilityInvocation) -> KernelResult<u64> {
    let current = unsafe { Task::borrow_current() };
    let ty = TrivialSyscall::try_from(invocation.arg(0)? as i64)?;
    match ty {
        TrivialSyscall::SchedYield => {
            unsafe {
                (*arch_get_cpu_scheduler()).reschedule(&invocation.registers, PreviousTaskStateChange::Yield);
            }
        }
        TrivialSyscall::SchedDrop => {
            unsafe {
                (*arch_get_cpu_scheduler()).reschedule(&invocation.registers, PreviousTaskStateChange::Drop);
            }
        }
        TrivialSyscall::SchedNanosleep => {
            let ns = invocation.arg(1)?;
            let scheduler = unsafe {
                &mut *arch_get_cpu_scheduler()
            };
            let deadline = match scheduler.current_time().checked_add(ns) {
                Some(x) => x,
                None => return Err(KernelError::InvalidArgument)
            };
            current.set_nanosleep_deadline(deadline);
            scheduler.reschedule(&invocation.registers, PreviousTaskStateChange::Yield);
        }
        TrivialSyscall::SchedSubmit => {
            let target = CapPtr(invocation.arg(1)?);
            let cap = current.capabilities.get().lookup_cptr_take(target)?;

            // Require reply endpoint so a task can only appear once in the scheduling queue.
            let task = match cap.object {
                CapabilityEndpointObject::TaskEndpoint(endpoint) => {
                    match endpoint.entry {
                        EntryType::PreemptiveReply(t) => t,
                        EntryType::CooperativeReply(t) => t,
                        _ => return Err(KernelError::InvalidArgument),
                    }
                }
                _ => return Err(KernelError::InvalidArgument),
            };
            unsafe {
                (*arch_get_cpu_scheduler()).push(task.into())?;
            }
            Ok(0)
        }
        TrivialSyscall::SoftuserEnter => {
            let pc = invocation.arg(1)? as u32;
            let local_state = unsafe {
                current.local_state()
            };
            if local_state.softuser_enabled {
                Err(KernelError::InvalidState)
            } else {
                local_state.registers = invocation.registers.clone();
                local_state.softuser_enabled = true;
                *local_state.softuser_context.pc_mut() = pc;
                enter_user_mode(StateRestoreMode::Full);
            }
        }
        TrivialSyscall::SoftuserLeave => {
            let local_state = unsafe {
                current.local_state()
            };
            if !local_state.softuser_enabled {
                Err(KernelError::InvalidState)
            } else {
                local_state.softuser_enabled = false;
                enter_user_mode(StateRestoreMode::Full);
            }
        }
    }
}