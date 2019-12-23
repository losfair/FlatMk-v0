use num_enum::TryFromPrimitive;

#[repr(i32)]
#[derive(Copy, Clone, Debug, TryFromPrimitive)]
pub enum KernelError {
    /// General error that indicates at least one argument is invalid.
    InvalidArgument = -1,
    /// Not implemented.
    NotImplemented = -2,
    /// Some state is invalid for the requested operation.
    InvalidState = -3,
    /// Invalid memory address.
    InvalidAddress = -4,
    /// Some object is empty when processing invocation request.
    EmptyObject = -5,
    /// An IPC operation would block, but non-blocking mode is requested.
    WouldBlock = -6,
    /// An empty capability is invoked.
    EmptyCapability = -7,
    /// A race condition is detected.
    RaceRetry = -8,
    /// No available memory.
    OutOfMemory = -9,
}

pub type KernelResult<T> = Result<T, KernelError>;
