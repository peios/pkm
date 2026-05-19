use crate::constants::{
    ACCESS_SYSTEM_SECURITY, DELETE, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
    KEY_ALL_ACCESS, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_QUERY_VALUE,
    KEY_SET_VALUE, MAXIMUM_ALLOWED, READ_CONTROL, REG_VALID_ACE_ACCESS_MASK,
    REG_VALID_DESIRED_ACCESS_MASK, REG_VALID_MAPPED_ACCESS_MASK, WRITE_DAC, WRITE_OWNER,
};
use crate::error::{LcsError, LcsResult};
use kacs_core::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, Ace, AceKind,
    SYSTEM_ALARM_ACE_TYPE, SYSTEM_ALARM_CALLBACK_ACE_TYPE, SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, SecurityDescriptor,
};

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

/// PSD-005 registry key `GenericMapping` in the shape consumed by KACS.
pub fn registry_kacs_generic_mapping() -> kacs_core::GenericMapping {
    kacs_core::GenericMapping {
        read: REGISTRY_GENERIC_MAPPING.read,
        write: REGISTRY_GENERIC_MAPPING.write,
        execute: REGISTRY_GENERIC_MAPPING.execute,
        all: REGISTRY_GENERIC_MAPPING.all,
    }
}

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

/// Parses and validates a source-returned registry SD before AccessCheck use.
pub fn parse_registry_source_security_descriptor<'a>(
    bytes: &'a [u8],
    field: &'static str,
) -> LcsResult<SecurityDescriptor<'a>> {
    let sd = SecurityDescriptor::parse(bytes)
        .map_err(|_| LcsError::MalformedSecurityDescriptor { field })?;
    validate_registry_source_security_descriptor(&sd, field)?;
    Ok(sd)
}

/// Validates source-returned registry SD fields that are specific to PSD-005.
pub fn validate_registry_source_security_descriptor(
    sd: &SecurityDescriptor<'_>,
    field: &'static str,
) -> LcsResult<()> {
    if sd.owner().is_none() {
        return Err(LcsError::MalformedSecurityDescriptor { field });
    }

    if let Some(dacl) = sd.dacl() {
        for ace in dacl.entries() {
            let ace = ace.map_err(|_| LcsError::MalformedSecurityDescriptor { field })?;
            validate_registry_source_ace_mask(&ace, field)?;
        }
    }

    if let Some(sacl) = sd.sacl() {
        for ace in sacl.entries() {
            let ace = ace.map_err(|_| LcsError::MalformedSecurityDescriptor { field })?;
            validate_registry_source_ace_mask(&ace, field)?;
        }
    }

    Ok(())
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

fn validate_registry_source_ace_mask(ace: &Ace<'_>, field: &'static str) -> LcsResult<()> {
    let Some(mask) = registry_access_mask_from_source_ace(ace) else {
        return Ok(());
    };
    validate_registry_ace_mask(mask)
        .map(|_| ())
        .map_err(|_| LcsError::MalformedSecurityDescriptor { field })
}

fn registry_access_mask_from_source_ace(ace: &Ace<'_>) -> Option<u32> {
    match ace.ace_type() {
        ACCESS_ALLOWED_ACE_TYPE
        | ACCESS_DENIED_ACE_TYPE
        | ACCESS_ALLOWED_OBJECT_ACE_TYPE
        | ACCESS_DENIED_OBJECT_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
        | SYSTEM_AUDIT_ACE_TYPE
        | SYSTEM_ALARM_ACE_TYPE
        | SYSTEM_AUDIT_OBJECT_ACE_TYPE
        | SYSTEM_ALARM_OBJECT_ACE_TYPE
        | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
        | SYSTEM_ALARM_CALLBACK_ACE_TYPE
        | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
        | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
        | SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE => match ace.kind() {
            AceKind::SingleSid { mask, .. }
            | AceKind::Object { mask, .. }
            | AceKind::Callback { mask, .. }
            | AceKind::CallbackObject { mask, .. } => Some(mask),
            AceKind::ResourceAttribute { .. } | AceKind::Opaque => None,
        },
        _ => None,
    }
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
