use core::option::NoneError;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

#[repr(i32)]
#[derive(Copy, Clone, Debug)]
pub enum KernelError {
    /// General error that indicates at least one argument is invalid.
    InvalidArgument = -1,
    /// Invalid memory delegation.
    InvalidDelegation = -2,
    /// Invalid object type. Usually indicates a failure during retyping.
    //InvalidType = -3,
    /// Not implemented.
    NotImplemented = -4,
    /// The type for a kernel object has a size larger than one page.
    //KernelObjectTooLarge = -5,
    /// Some state is invalid for the requested operation.
    InvalidState = -6,
    /// Invalid memory address.
    InvalidAddress = -7,
    /// Some object is empty when processing invocation request.
    EmptyObject = -8,
    /// An address provided is not aligned to a required boundary.
    NotAligned = -9,
    /// An IPC operation would block, but non-blocking mode is requested.
    WouldBlock = -10,
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
