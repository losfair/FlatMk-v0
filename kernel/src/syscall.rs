use crate::arch::task::arch_init_syscall;
use crate::capability::{CapabilityInvocation, INVALID_CAP};
use crate::error::*;
use crate::serial::with_serial_port;
use crate::task::Task;
use core::fmt::Write;

pub unsafe fn init() {
    arch_init_syscall();
    with_serial_port(|p| writeln!(p, "System call enabled.").unwrap());
}

fn dispatch_syscall(invocation: &mut CapabilityInvocation) -> i64 {
    let cptr = invocation.cptr();
    if cptr.0 == INVALID_CAP {
        KernelError::InvalidArgument as i32 as i64
    } else {
        let cap = {
            let task = Task::current();
            match task.capabilities.get().lookup_cptr(cptr) {
                Ok(x) => x,
                Err(e) => return e as i32 as i64,
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
