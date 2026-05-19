use crate::access::registry_fd_has_right;
use crate::config::LcsLimits;
use crate::constants::{
    KEY_CREATE_LINK, KEY_CREATE_SUB_KEY, REG_OPTION_CREATE_LINK, REG_OPTION_VOLATILE,
};
use crate::error::{LcsError, LcsResult};
use crate::path::validate_key_component_bytes;
use crate::resolution::Guid;
use crate::source::NIL_GUID;

const REG_CREATE_KEY_KNOWN_FLAGS: u32 = REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK;

/// Parent identity recorded on a key object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyParent {
    HiveRoot,
    Parent(Guid),
}

/// Source-returned key record metadata after RSI copy-in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyRecordView<'a> {
    pub guid: Guid,
    pub name: &'a str,
    pub parent: KeyParent,
    pub volatile: bool,
    pub symlink: bool,
}

/// Parsed reg_create_key creation options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCreateOptions {
    pub volatile: bool,
    pub symlink: bool,
}

/// Pure key creation inputs after path resolution and parent AccessCheck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCreateRequest<'a> {
    pub parent_guid: Guid,
    pub parent_is_volatile: bool,
    pub parent_granted_access: u32,
    pub child_name: &'a str,
    pub child_guid: Guid,
    pub flags: u32,
    pub caller_has_tcb_or_admin: bool,
}

/// Validated immutable key record fields for a new child key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCreatePlan<'a> {
    pub guid: Guid,
    pub name: &'a str,
    pub parent_guid: Guid,
    pub volatile: bool,
    pub symlink: bool,
}

/// Validates immutable source-returned key record metadata.
pub fn validate_key_record<'a>(
    limits: &LcsLimits,
    record: &KeyRecordView<'a>,
) -> LcsResult<KeyRecordView<'a>> {
    validate_key_guid(record.guid)?;
    validate_key_component_bytes(record.name.as_bytes(), limits)?;
    validate_key_parent(record.parent)?;
    Ok(*record)
}

/// Parses and validates reg_create_key REG_OPTION_* flags.
pub fn validate_key_create_flags(flags: u32) -> LcsResult<KeyCreateOptions> {
    let unknown = flags & !REG_CREATE_KEY_KNOWN_FLAGS;
    if unknown != 0 {
        return Err(LcsError::UnknownCreateFlags { flags, unknown });
    }

    Ok(KeyCreateOptions {
        volatile: (flags & REG_OPTION_VOLATILE) != 0,
        symlink: (flags & REG_OPTION_CREATE_LINK) != 0,
    })
}

/// Validates a new child key's immutable metadata and creation gates.
pub fn validate_key_create_request<'a>(
    limits: &LcsLimits,
    request: &KeyCreateRequest<'a>,
) -> LcsResult<KeyCreatePlan<'a>> {
    let options = validate_key_create_flags(request.flags)?;
    validate_parent_guid(request.parent_guid)?;
    validate_key_guid(request.child_guid)?;
    let name = validate_key_component_bytes(request.child_name.as_bytes(), limits)?;

    if !registry_fd_has_right(request.parent_granted_access, KEY_CREATE_SUB_KEY) {
        return Err(LcsError::MissingKeyCreateSubKey);
    }

    if request.parent_is_volatile && !options.volatile {
        return Err(LcsError::NonVolatileChildUnderVolatile);
    }

    if options.symlink {
        validate_symlink_create_authority(
            request.parent_granted_access,
            request.caller_has_tcb_or_admin,
        )?;
    }

    Ok(KeyCreatePlan {
        guid: request.child_guid,
        name,
        parent_guid: request.parent_guid,
        volatile: options.volatile,
        symlink: options.symlink,
    })
}

/// Validates the additional gates for creating a symlink key.
pub fn validate_symlink_create_authority(
    parent_granted_access: u32,
    caller_has_tcb_or_admin: bool,
) -> LcsResult<()> {
    if !registry_fd_has_right(parent_granted_access, KEY_CREATE_LINK) {
        return Err(LcsError::MissingKeyCreateLink);
    }
    if !caller_has_tcb_or_admin {
        return Err(LcsError::MissingSymlinkCreationAuthority);
    }
    Ok(())
}

fn validate_key_parent(parent: KeyParent) -> LcsResult<()> {
    match parent {
        KeyParent::HiveRoot => Ok(()),
        KeyParent::Parent(guid) => validate_parent_guid(guid),
    }
}

fn validate_key_guid(guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::NilKeyGuid);
    }
    Ok(())
}

fn validate_parent_guid(guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::NilParentGuid);
    }
    Ok(())
}
