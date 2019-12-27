// Early usermode
pub static SCHEDULER: &'static [u8] = include_bytes!("../../scheduler/target/x86_64-flatmk/release/scheduler");
pub static SHMEMD: &'static [u8] = include_bytes!("../../shmemd/target/x86_64-flatmk/release/shmemd");

// Late usermode
pub static VGA: &'static [u8] = include_bytes!("../../vga/target/x86_64-flatmk/release/vga");
