use crate::error::*;
use crate::io::Port;
use crate::mm::Mmio;
use crate::syscall::*;
use crate::task::*;
use core::convert::TryFrom;
use crate::interrupt::*;

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum RootTaskCapRequest {
    X86IoPort = 0,
    Mmio = 1,
    WaitForInterrupt = 2,
    Interrupt = 3,
}

static CAP_ROOT: CPtr = unsafe { CPtr::new(1) };

pub fn new_mmio(phys_addr: u64) -> KernelResult<Mmio> {
    let (cptr, _) = allocate_cptr(|cptr| unsafe {
        CAP_ROOT
            .call_result(
                RootTaskCapRequest::Mmio as u32 as i64,
                cptr.index() as i64,
                phys_addr as _,
                0,
            )
            .map(|_| ())
    })?;
    Ok(unsafe { Mmio::new(cptr) })
}

pub fn new_x86_io_port(port: u16) -> KernelResult<Port> {
    let (cptr, _) = allocate_cptr(|cptr| unsafe {
        CAP_ROOT
            .call_result(
                RootTaskCapRequest::X86IoPort as u32 as i64,
                cptr.index() as i64,
                port as _,
                0,
            )
            .map(|_| ())
    })?;
    Ok(unsafe { Port::new(cptr) })
}

pub fn new_wait_for_interrupt() -> KernelResult<WaitForInterrupt> {
    let (cptr, _) = allocate_cptr(|cptr| unsafe {
        CAP_ROOT
            .call_result(
                RootTaskCapRequest::WaitForInterrupt as u32 as i64,
                cptr.index() as i64,
                0,
                0,
            )
            .map(|_| ())
    })?;
    Ok(unsafe { WaitForInterrupt::new(cptr) })
}

pub fn new_interrupt(index: u8) -> KernelResult<Interrupt> {
    let (cptr, _) = allocate_cptr(|cptr| unsafe {
        CAP_ROOT
            .call_result(
                RootTaskCapRequest::Interrupt as u32 as i64,
                cptr.index() as i64,
                index as i64,
                0,
            )
            .map(|_| ())
    })?;
    Ok(unsafe { Interrupt::new(cptr) })
}
