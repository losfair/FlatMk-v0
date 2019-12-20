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

#[inline(never)]
#[no_mangle]
extern "C" fn syscall_entry(invocation: &mut CapabilityInvocation) -> i64 {
    let cptr = invocation.cptr();
    if cptr.0 == INVALID_CAP {
        return handle_trivial_syscall(invocation);
    }

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

fn handle_trivial_syscall(_invocation: &mut CapabilityInvocation) -> i64 {
    KernelError::InvalidArgument as i32 as i64
}
