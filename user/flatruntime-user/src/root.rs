use crate::error::*;
use crate::io::Port;
use crate::mm::Mmio;
use crate::syscall::*;
use crate::task::*;
use core::convert::TryFrom;

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum RootTaskCapRequest {
    X86IoPort = 0,
    Mmio = 1,
}

static CAP_ROOT: CPtr = unsafe { CPtr::new_twolevel(0, 1) };

pub fn new_mmio(phys_addr: u64) -> KernelResult<Mmio> {
    let (cptr, _) = allocate_cptr(|cptr| {
        let result = unsafe {
            CAP_ROOT.call(
                RootTaskCapRequest::Mmio as u32 as i64,
                cptr.index() as i64,
                phys_addr as _,
                0,
            )
        };
        if result < 0 {
            Err(KernelError::try_from(result as i32).unwrap())
        } else {
            Ok(())
        }
    })?;
    Ok(unsafe { Mmio::new(cptr) })
}

pub fn new_x86_io_port(port: u16) -> KernelResult<Port> {
    let (cptr, _) = allocate_cptr(|cptr| {
        let result = unsafe {
            CAP_ROOT.call(
                RootTaskCapRequest::X86IoPort as u32 as i64,
                cptr.index() as i64,
                port as _,
                0,
            )
        };
        if result < 0 {
            Err(KernelError::try_from(result as i32).unwrap())
        } else {
            Ok(())
        }
    })?;
    Ok(unsafe { Port::new(cptr) })
}
