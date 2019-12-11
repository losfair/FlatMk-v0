use num_enum::TryFromPrimitive;

#[repr(i32)]
#[derive(Copy, Clone, Debug, TryFromPrimitive)]
pub enum KernelError {
    /// General error that indicates at least one argument is invalid.
    InvalidArgument = -1,
    /// Invalid memory delegation.
    InvalidDelegation = -2,
    /// Invalid object type. Usually indicates a failure during retyping.
    InvalidType = -3,
    /// Not implemented.
    NotImplemented = -4,
    /// The type for a kernel object has a size larger than one page.
    KernelObjectTooLarge = -5,
    /// Some state is invalid for the requested operation.
    InvalidState = -6,
    /// Invalid memory address.
    InvalidAddress = -7,
    /// The provided capability slot is empty.
    EmptyCapability = -8,
    /// An address provided is not aligned to page boundary.
    NotAligned = -9,
}

pub type KernelResult<T> = Result<T, KernelError>;
