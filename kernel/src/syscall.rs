use crate::arch::task::arch_init_syscall;
use crate::capability::{CapabilityInvocation, INVALID_CAP};
use crate::task::{Task};
use crate::spec::TaskFaultReason;

pub unsafe fn init() {
    arch_init_syscall();
}

fn dispatch_syscall(invocation: &mut CapabilityInvocation) -> i64 {
    let cptr = invocation.cptr();
    if cptr.0 == INVALID_CAP {
        Task::raise_fault(Task::current(), TaskFaultReason::InvalidCapability, 0, &invocation.registers);
    } else {
        let cap = {
            let task = Task::current();
            let maybe_cap = task.capabilities.get().lookup_cptr_no_check_clone(cptr);
            match maybe_cap {
                Ok(x) => x,
                Err(_) => {
                    Task::raise_fault(task, TaskFaultReason::InvalidCapability, 0, &invocation.registers);
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
    unsafe {
        crate::arch::task::arch_enter_user_mode_syscall(&invocation.registers);
    }
}
