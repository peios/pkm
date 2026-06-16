use crate::error::{KacsError, KacsResult};

/// Standard access-mask bit for deleting the target object.
pub const DELETE: u32 = peios_uapi::KACS_ACCESS_DELETE;
/// Standard access-mask bit for reading owner/group/DACL metadata.
pub const READ_CONTROL: u32 = peios_uapi::KACS_ACCESS_READ_CONTROL;
/// Standard access-mask bit for writing the DACL.
pub const WRITE_DAC: u32 = peios_uapi::KACS_ACCESS_WRITE_DAC;
/// Standard access-mask bit for changing the owner.
pub const WRITE_OWNER: u32 = peios_uapi::KACS_ACCESS_WRITE_OWNER;
/// Standard access-mask bit for synchronization rights.
pub const SYNCHRONIZE: u32 = peios_uapi::KACS_ACCESS_SYNCHRONIZE;
/// Standard access-mask bit for SACL access.
pub const ACCESS_SYSTEM_SECURITY: u32 = peios_uapi::KACS_ACCESS_ACCESS_SYSTEM_SECURITY;
/// Standard access-mask bit requesting maximum-allowed evaluation.
pub const MAXIMUM_ALLOWED: u32 = peios_uapi::KACS_ACCESS_MAXIMUM_ALLOWED;
/// Generic access bit for "all access."
pub const GENERIC_ALL: u32 = peios_uapi::KACS_ACCESS_GENERIC_ALL;
/// Generic access bit for execute rights.
pub const GENERIC_EXECUTE: u32 = peios_uapi::KACS_ACCESS_GENERIC_EXECUTE;
/// Generic access bit for write rights.
pub const GENERIC_WRITE: u32 = peios_uapi::KACS_ACCESS_GENERIC_WRITE;
/// Generic access bit for read rights.
pub const GENERIC_READ: u32 = peios_uapi::KACS_ACCESS_GENERIC_READ;

/// Process right permitting termination-style signals.
pub const PROCESS_TERMINATE: u32 = peios_uapi::KACS_PROCESS_TERMINATE;
/// Process right permitting informational signals.
pub const PROCESS_SIGNAL: u32 = peios_uapi::KACS_PROCESS_SIGNAL;
/// Process right permitting virtual-memory reads.
pub const PROCESS_VM_READ: u32 = peios_uapi::KACS_PROCESS_VM_READ;
/// Process right permitting virtual-memory writes / invasive attach.
pub const PROCESS_VM_WRITE: u32 = peios_uapi::KACS_PROCESS_VM_WRITE;
/// Process right permitting handle extraction.
pub const PROCESS_DUP_HANDLE: u32 = peios_uapi::KACS_PROCESS_DUP_HANDLE;
/// Process right permitting process-attribute mutation.
pub const PROCESS_SET_INFORMATION: u32 = peios_uapi::KACS_PROCESS_SET_INFORMATION;
/// Process right permitting detailed process inspection.
pub const PROCESS_QUERY_INFORMATION: u32 = peios_uapi::KACS_PROCESS_QUERY_INFORMATION;
/// Process right permitting suspend / resume signals.
pub const PROCESS_SUSPEND_RESUME: u32 = peios_uapi::KACS_PROCESS_SUSPEND_RESUME;
/// Process right permitting limited process inspection.
pub const PROCESS_QUERY_LIMITED: u32 = peios_uapi::KACS_PROCESS_QUERY_LIMITED;

/// File right permitting file data reads.
pub const FILE_READ_DATA: u32 = peios_uapi::KACS_FILE_READ_DATA;
/// File right permitting file data writes.
pub const FILE_WRITE_DATA: u32 = peios_uapi::KACS_FILE_WRITE_DATA;
/// File right permitting append-only writes.
pub const FILE_APPEND_DATA: u32 = peios_uapi::KACS_FILE_APPEND_DATA;
/// File right permitting named-attribute reads.
pub const FILE_READ_EA: u32 = peios_uapi::KACS_FILE_READ_EA;
/// File right permitting named-attribute writes.
pub const FILE_WRITE_EA: u32 = peios_uapi::KACS_FILE_WRITE_EA;
/// File right permitting execution / directory traversal.
pub const FILE_EXECUTE: u32 = peios_uapi::KACS_FILE_EXECUTE;
/// File right permitting directory child deletion.
pub const FILE_DELETE_CHILD: u32 = peios_uapi::KACS_FILE_DELETE_CHILD;
/// File right permitting basic attribute reads.
pub const FILE_READ_ATTRIBUTES: u32 = peios_uapi::KACS_FILE_READ_ATTRIBUTES;
/// File right permitting basic attribute writes.
pub const FILE_WRITE_ATTRIBUTES: u32 = peios_uapi::KACS_FILE_WRITE_ATTRIBUTES;

const RESERVED_ACCESS_MASK_BITS: u32 = 0x0ce0_0000;
const GENERIC_MASK: u32 = GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;

/// Generic mapping for process security descriptors.
pub const PROCESS_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL,
    write: PROCESS_SET_INFORMATION | PROCESS_VM_WRITE | WRITE_DAC,
    execute: PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED,
    all: PROCESS_TERMINATE
        | PROCESS_SIGNAL
        | PROCESS_SUSPEND_RESUME
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_DUP_HANDLE
        | PROCESS_SET_INFORMATION
        | PROCESS_QUERY_INFORMATION
        | PROCESS_QUERY_LIMITED
        | READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER,
};

/// Generic mapping for file and directory security descriptors.
pub const FILE_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
    write: FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_ATTRIBUTES
        | FILE_WRITE_EA
        | READ_CONTROL
        | SYNCHRONIZE,
    execute: FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    all: FILE_READ_DATA
        | FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_READ_EA
        | FILE_WRITE_EA
        | FILE_EXECUTE
        | FILE_DELETE_CHILD
        | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | SYNCHRONIZE,
};

/// Maps generic access bits onto object-specific rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericMapping {
    /// Concrete rights substituted for `GENERIC_READ`.
    pub read: u32,
    /// Concrete rights substituted for `GENERIC_WRITE`.
    pub write: u32,
    /// Concrete rights substituted for `GENERIC_EXECUTE`.
    pub execute: u32,
    /// Concrete rights substituted for `GENERIC_ALL`.
    pub all: u32,
}

/// A desired-access request after generic mapping and `MAXIMUM_ALLOWED`
/// detection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedDesiredAccess {
    /// The caller-supplied desired mask before stripping `MAXIMUM_ALLOWED`.
    pub requested: u32,
    /// The mapped desired mask with generic bits expanded and
    /// `MAXIMUM_ALLOWED` removed.
    pub mapped: u32,
    /// Whether the original request included `MAXIMUM_ALLOWED`.
    pub maximum_allowed: bool,
}

impl GenericMapping {
    /// Expands generic bits in `mask` using this mapping and rejects reserved
    /// bits.
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

    /// Validates and normalizes a desired-access request for later AccessCheck
    /// stages.
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

/// Validates an ACE mask, including the rule that `MAXIMUM_ALLOWED` must not
/// appear in ACEs.
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
