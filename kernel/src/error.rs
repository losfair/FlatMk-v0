use core::option::NoneError;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
pub use crate::spec::KernelError;

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
