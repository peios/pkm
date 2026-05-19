use crate::constants::{
    ACCESS_SYSTEM_SECURITY, DELETE, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
    KEY_ALL_ACCESS, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_QUERY_VALUE,
    KEY_SET_VALUE, MAXIMUM_ALLOWED, READ_CONTROL, REG_VALID_ACE_ACCESS_MASK,
    REG_VALID_DESIRED_ACCESS_MASK, REG_VALID_MAPPED_ACCESS_MASK, WRITE_DAC, WRITE_OWNER,
};
use crate::error::{LcsError, LcsResult};

const GENERIC_MASK: u32 = GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;

/// PSD-005 registry GenericMapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryGenericMapping {
    pub read: u32,
    pub write: u32,
    pub execute: u32,
    pub all: u32,
}

/// Registry key mapping from raw generic bits to concrete rights.
pub const REGISTRY_GENERIC_MAPPING: RegistryGenericMapping = RegistryGenericMapping {
    read: KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL,
    write: KEY_SET_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL,
    execute: 0,
    all: KEY_ALL_ACCESS,
};

/// A caller request after PSD-005 registry validation and generic mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedRegistryAccess {
    pub requested: u32,
    pub mapped: u32,
    pub maximum_allowed: bool,
}

/// Expands raw generic access bits using the registry key GenericMapping.
pub fn map_registry_generic_bits(mask: u32) -> u32 {
    let mut mapped = mask & !GENERIC_MASK;
    if (mask & GENERIC_READ) != 0 {
        mapped |= REGISTRY_GENERIC_MAPPING.read;
    }
    if (mask & GENERIC_WRITE) != 0 {
        mapped |= REGISTRY_GENERIC_MAPPING.write;
    }
    if (mask & GENERIC_EXECUTE) != 0 {
        mapped |= REGISTRY_GENERIC_MAPPING.execute;
    }
    if (mask & GENERIC_ALL) != 0 {
        mapped |= REGISTRY_GENERIC_MAPPING.all;
    }
    mapped
}

/// Validates caller-supplied desired_access before path resolution.
pub fn validate_registry_desired_access(requested: u32) -> LcsResult<NormalizedRegistryAccess> {
    if requested == 0 {
        return Err(LcsError::ZeroDesiredAccess);
    }
    validate_mask_subset(requested, REG_VALID_DESIRED_ACCESS_MASK)?;

    let maximum_allowed = (requested & MAXIMUM_ALLOWED) != 0;
    let mapped = map_registry_generic_bits(requested & !MAXIMUM_ALLOWED);
    validate_mapped_registry_mask(mapped)?;

    Ok(NormalizedRegistryAccess {
        requested,
        mapped,
        maximum_allowed,
    })
}

/// Validates a registry SD ACE mask returned by a source and returns its mapped
/// concrete form.
pub fn validate_registry_ace_mask(mask: u32) -> LcsResult<u32> {
    if (mask & MAXIMUM_ALLOWED) != 0 {
        return Err(LcsError::MaximumAllowedInAce(mask));
    }
    validate_mask_subset(mask, REG_VALID_ACE_ACCESS_MASK)?;

    let mapped = map_registry_generic_bits(mask);
    if (mapped & !REG_VALID_MAPPED_ACCESS_MASK) != 0 {
        return Err(LcsError::AceMaskMapsOutsideRegistryRights(mapped));
    }
    Ok(mapped)
}

/// Checks a key fd's cached granted mask for one ioctl-required right.
pub fn registry_fd_has_right(granted: u32, required: u32) -> bool {
    (granted & required) == required
}

/// Validates a concrete granted mask stored on a key fd after AccessCheck.
pub fn validate_registry_granted_access(granted: u32) -> LcsResult<u32> {
    validate_mask_subset(granted, REG_VALID_MAPPED_ACCESS_MASK)?;
    Ok(granted)
}

fn validate_mask_subset(mask: u32, valid: u32) -> LcsResult<()> {
    let invalid = mask & !valid;
    if invalid != 0 {
        return Err(LcsError::UnknownAccessBits(invalid));
    }
    Ok(())
}

fn validate_mapped_registry_mask(mask: u32) -> LcsResult<()> {
    let invalid = mask & !REG_VALID_MAPPED_ACCESS_MASK;
    if invalid != 0 {
        return Err(LcsError::UnknownAccessBits(invalid));
    }
    Ok(())
}

const _: () = {
    assert!(KEY_ALL_ACCESS == 0x000f_003f);
    assert!(
        REG_VALID_MAPPED_ACCESS_MASK
            == (KEY_QUERY_VALUE
                | KEY_SET_VALUE
                | KEY_CREATE_SUB_KEY
                | KEY_ENUMERATE_SUB_KEYS
                | KEY_NOTIFY
                | DELETE
                | READ_CONTROL
                | WRITE_DAC
                | WRITE_OWNER
                | ACCESS_SYSTEM_SECURITY
                | crate::constants::KEY_CREATE_LINK)
    );
};
