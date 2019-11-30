use bootloader::BootInfo;

static mut BOOT_INFO: Option<&'static BootInfo> = None;

pub fn boot_info() -> &'static BootInfo {
    unsafe { BOOT_INFO.unwrap() }
}

pub unsafe fn set_boot_info(info: &'static BootInfo) {
    BOOT_INFO = Some(info);
}
