use bootloader::BootInfo;
use crate::error::*;

static mut BOOT_INFO: Option<&'static BootInfo> = None;

pub fn boot_info() -> &'static BootInfo {
    unsafe { BOOT_INFO.unwrap() }
}

pub unsafe fn set_boot_info(info: &'static BootInfo) {
    BOOT_INFO = Some(info);
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct BootParameter_FramebufferInfo {
    pub physical_address: u64,
    pub width: u32,
    pub height: u32,
}

impl BootParameter_FramebufferInfo {
    pub fn read() -> KernelResult<Self> {
        let boot = boot_info();
        if boot.vesa_framebuffer_addr == 0 {
            Err(KernelError::EmptyObject)
        } else {
            Ok(Self {
                physical_address: boot.vesa_framebuffer_addr,
                width: 1024,
                height: 768,
            })
        }
    }
}
