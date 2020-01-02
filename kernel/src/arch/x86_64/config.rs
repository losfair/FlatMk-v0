// XXX: Keep this consistent with Cargo.toml
pub const KERNEL_STACK_START: u64 = 0xFFFFFF8000000000u64;
pub const KERNEL_STACK_SIZE: u64 = 4096 * 512;
pub const KERNEL_STACK_END: u64 = KERNEL_STACK_START + KERNEL_STACK_SIZE;

pub const KERNEL_VM_START: u64 = core::u64::MAX / 2 + 1;