pub static SCHEDULER: &'static [u8] = include_bytes!("../../flatrt-scheduler/target/x86_64-flatmk-early/release/flatrt-scheduler");
pub static SHMEM: &'static [u8] = include_bytes!("../../flatrt-shmem/target/x86_64-flatmk-early/release/flatrt-shmem");

pub static DRIVER_VGA: &'static [u8] = include_bytes!("../../../drivers/bin/vga.driver");
pub static DRIVER_GCLOCK: &'static [u8] = include_bytes!("../../../drivers/bin/gclock.driver");
pub static DRIVER_SEQUENCER_LINUX: &'static [u8] = include_bytes!("../../../drivers/bin/sequencer-linux.driver");
