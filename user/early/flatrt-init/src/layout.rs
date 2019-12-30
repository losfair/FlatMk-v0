//! Layout of a non-init task.

/// End address (the upper bound) of a stack.
pub const STACK_END: u64 = 0x800000000000;

/// Size of a stack.
pub const STACK_SIZE: u64 = 1048576;

/// Start address (the lower bound) of a stack.
pub const STACK_START: u64 = STACK_END - STACK_SIZE;
