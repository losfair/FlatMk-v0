use core::option::NoneError;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

#[repr(i32)]
#[derive(Copy, Clone, Debug)]
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
    /// An empty capability is invoked.
    EmptyCapability = -7,
    /// The object referred to by a weak reference is no longer valid.
    InvalidReference = -8,
    /// No available memory.
    OutOfMemory = -9,
}

pub type KernelResult<T> = Result<T, KernelError>;

impl<T: TryFromPrimitive> From<TryFromPrimitiveError<T>> for KernelError {
    fn from(_: TryFromPrimitiveError<T>) -> KernelError {
        KernelError::InvalidArgument
    }
}

impl From<NoneError> for KernelError {
    fn from(_: NoneError) -> KernelError {
        KernelError::EmptyObject
    }
}
