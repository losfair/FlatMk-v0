use crate::error::*;
use bit_field::BitField;

#[inline]
pub fn arch_validate_virtual_address(addr: u64) -> KernelResult<()> {
    if !address_is_canonical(addr) {
        Err(KernelError::InvalidAddress)
    } else {
        Ok(())
    }
}

#[inline]
pub(super) fn address_is_canonical(addr: u64) -> bool {
    match addr.get_bits(47..64) {
        0 | 0x1ffff => true,
        _ => false,
    }
}
