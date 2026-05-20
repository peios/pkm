use crate::error::{LcsError, LcsResult};

/// Validates that a reserved or padding ABI input field is all zero.
pub fn validate_abi_reserved_zero(field: &'static str, bytes: &[u8]) -> LcsResult<()> {
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(LcsError::NonZeroReservedBytes { field });
    }
    Ok(())
}

/// Zeros a reserved or padding ABI output field before userspace copyout.
pub fn zero_abi_reserved(bytes: &mut [u8]) {
    bytes.fill(0);
}
