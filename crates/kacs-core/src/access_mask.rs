use crate::error::{KacsError, KacsResult};

pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

const RESERVED_ACCESS_MASK_BITS: u32 = 0x0ce0_0000;
const GENERIC_MASK: u32 = GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericMapping {
    pub read: u32,
    pub write: u32,
    pub execute: u32,
    pub all: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedDesiredAccess {
    pub requested: u32,
    pub mapped: u32,
    pub maximum_allowed: bool,
}

impl GenericMapping {
    pub fn map_mask(&self, mask: u32) -> KacsResult<u32> {
        validate_no_reserved_bits(mask)?;

        let mut mapped = mask & !GENERIC_MASK;
        if (mask & GENERIC_READ) != 0 {
            mapped |= self.read;
        }
        if (mask & GENERIC_WRITE) != 0 {
            mapped |= self.write;
        }
        if (mask & GENERIC_EXECUTE) != 0 {
            mapped |= self.execute;
        }
        if (mask & GENERIC_ALL) != 0 {
            mapped |= self.all;
        }

        Ok(mapped)
    }

    pub fn normalize_desired_access(&self, requested: u32) -> KacsResult<NormalizedDesiredAccess> {
        validate_no_reserved_bits(requested)?;

        let maximum_allowed = (requested & MAXIMUM_ALLOWED) != 0;
        let stripped = requested & !MAXIMUM_ALLOWED;
        let mapped = self.map_mask(stripped)?;

        Ok(NormalizedDesiredAccess {
            requested,
            mapped,
            maximum_allowed,
        })
    }
}

pub fn validate_ace_mask(mask: u32) -> KacsResult<()> {
    validate_no_reserved_bits(mask)?;
    if (mask & MAXIMUM_ALLOWED) != 0 {
        return Err(KacsError::MaximumAllowedInAce(mask));
    }
    Ok(())
}

fn validate_no_reserved_bits(mask: u32) -> KacsResult<()> {
    let reserved = mask & RESERVED_ACCESS_MASK_BITS;
    if reserved != 0 {
        return Err(KacsError::ReservedAccessMaskBits(reserved));
    }
    Ok(())
}
