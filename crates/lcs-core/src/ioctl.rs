use crate::access::{registry_fd_has_right, validate_registry_granted_access};
use crate::constants::{
    ACCESS_SYSTEM_SECURITY, DACL_SECURITY_INFORMATION, DELETE, GROUP_SECURITY_INFORMATION,
    KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_QUERY_VALUE, KEY_SET_VALUE, OWNER_SECURITY_INFORMATION,
    READ_CONTROL, REG_IOC_BACKUP, REG_IOC_BLANKET_TOMBSTONE, REG_IOC_COMMIT, REG_IOC_DELETE_KEY,
    REG_IOC_DELETE_VALUE, REG_IOC_ENUM_SUBKEYS, REG_IOC_ENUM_VALUES, REG_IOC_FLUSH,
    REG_IOC_GET_SECURITY, REG_IOC_HIDE_KEY, REG_IOC_NOTIFY, REG_IOC_QUERY_KEY_INFO,
    REG_IOC_QUERY_VALUE, REG_IOC_QUERY_VALUES_BATCH, REG_IOC_RESTORE, REG_IOC_SET_SECURITY,
    REG_IOC_SET_VALUE, REG_IOC_TXN_STATUS, REG_VALID_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION, WRITE_DAC, WRITE_OWNER,
};
use crate::error::{LcsError, LcsResult};

/// Privilege-only LCS ioctl gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryIoctlPrivilege {
    Backup,
    Restore,
}

/// Security descriptor operation class for component-derived rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrySecurityOperation {
    Get,
    Set,
}

/// Access gate class for a PSD-005 registry ioctl number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryIoctlAccessRequirement {
    /// A key fd must carry this cached granted mask.
    KeyGrantedMask(u32),
    /// A key fd mask is computed from `security_info` for get/set security.
    KeySecurityInfo(RegistrySecurityOperation),
    /// Caller privilege is required; no per-key AccessCheck is performed.
    Privilege(RegistryIoctlPrivilege),
    /// The command is valid only on a transaction fd.
    TransactionFd,
}

/// Caller-visible errno for a cached key-fd ioctl access failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryIoctlFdAccessErrno {
    Eacces,
}

/// Source-contact decision after checking a key fd's cached granted mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryIoctlFdAccessGatePlan {
    Allowed {
        required_access: u32,
        source_contact_allowed: bool,
    },
    Denied {
        required_access: u32,
        errno: RegistryIoctlFdAccessErrno,
        source_contact_allowed: bool,
    },
}

/// Classifies a PSD-005 registry ioctl command number by its first access gate.
pub fn registry_ioctl_access_requirement(
    ioctl_number: u8,
) -> LcsResult<RegistryIoctlAccessRequirement> {
    match ioctl_number {
        REG_IOC_QUERY_VALUE | REG_IOC_QUERY_VALUES_BATCH | REG_IOC_ENUM_VALUES => Ok(
            RegistryIoctlAccessRequirement::KeyGrantedMask(KEY_QUERY_VALUE),
        ),
        REG_IOC_SET_VALUE | REG_IOC_DELETE_VALUE | REG_IOC_BLANKET_TOMBSTONE | REG_IOC_FLUSH => Ok(
            RegistryIoctlAccessRequirement::KeyGrantedMask(KEY_SET_VALUE),
        ),
        REG_IOC_ENUM_SUBKEYS => Ok(RegistryIoctlAccessRequirement::KeyGrantedMask(
            KEY_ENUMERATE_SUB_KEYS,
        )),
        REG_IOC_QUERY_KEY_INFO => Ok(RegistryIoctlAccessRequirement::KeyGrantedMask(READ_CONTROL)),
        REG_IOC_DELETE_KEY | REG_IOC_HIDE_KEY => {
            Ok(RegistryIoctlAccessRequirement::KeyGrantedMask(DELETE))
        }
        REG_IOC_GET_SECURITY => Ok(RegistryIoctlAccessRequirement::KeySecurityInfo(
            RegistrySecurityOperation::Get,
        )),
        REG_IOC_SET_SECURITY => Ok(RegistryIoctlAccessRequirement::KeySecurityInfo(
            RegistrySecurityOperation::Set,
        )),
        REG_IOC_NOTIFY => Ok(RegistryIoctlAccessRequirement::KeyGrantedMask(KEY_NOTIFY)),
        REG_IOC_BACKUP => Ok(RegistryIoctlAccessRequirement::Privilege(
            RegistryIoctlPrivilege::Backup,
        )),
        REG_IOC_RESTORE => Ok(RegistryIoctlAccessRequirement::Privilege(
            RegistryIoctlPrivilege::Restore,
        )),
        REG_IOC_COMMIT | REG_IOC_TXN_STATUS => Ok(RegistryIoctlAccessRequirement::TransactionFd),
        _ => Err(LcsError::UnknownRegistryIoctl(ioctl_number)),
    }
}

/// Validates PSD-005 LCS security selector flags.
pub fn validate_registry_security_info(security_info: u32) -> LcsResult<()> {
    if security_info == 0 {
        return Err(LcsError::ZeroSecurityInfo);
    }

    let unknown = security_info & !REG_VALID_SECURITY_INFORMATION;
    if unknown != 0 {
        return Err(LcsError::UnknownSecurityInfoFlags {
            flags: security_info,
            unknown,
        });
    }

    Ok(())
}

/// Computes the granted mask required for a get/set-security operation.
pub fn registry_security_info_required_access(
    operation: RegistrySecurityOperation,
    security_info: u32,
) -> LcsResult<u32> {
    validate_registry_security_info(security_info)?;

    let mut required = 0;
    match operation {
        RegistrySecurityOperation::Get => {
            if (security_info
                & (OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION))
                != 0
            {
                required |= READ_CONTROL;
            }
            if (security_info & SACL_SECURITY_INFORMATION) != 0 {
                required |= ACCESS_SYSTEM_SECURITY;
            }
        }
        RegistrySecurityOperation::Set => {
            if (security_info & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION)) != 0 {
                required |= WRITE_OWNER;
            }
            if (security_info & DACL_SECURITY_INFORMATION) != 0 {
                required |= WRITE_DAC;
            }
            if (security_info & SACL_SECURITY_INFORMATION) != 0 {
                required |= ACCESS_SYSTEM_SECURITY;
            }
        }
    }

    Ok(required)
}

/// Checks fixed-right key-fd ioctls against a cached granted mask.
///
/// Returns `None` for security-info, privilege-only, and transaction-fd
/// commands because those require additional non-fixed inputs or non-key gates.
pub fn registry_ioctl_fixed_granted_mask_allows(
    granted: u32,
    ioctl_number: u8,
) -> LcsResult<Option<bool>> {
    match registry_ioctl_access_requirement(ioctl_number)? {
        RegistryIoctlAccessRequirement::KeyGrantedMask(required) => {
            Ok(Some(registry_fd_has_right(granted, required)))
        }
        RegistryIoctlAccessRequirement::KeySecurityInfo(_)
        | RegistryIoctlAccessRequirement::Privilege(_)
        | RegistryIoctlAccessRequirement::TransactionFd => Ok(None),
    }
}

/// Plans cached key-fd access gating for fixed-right ioctls.
pub fn plan_registry_ioctl_fixed_fd_access_gate(
    granted: u32,
    ioctl_number: u8,
) -> LcsResult<Option<RegistryIoctlFdAccessGatePlan>> {
    validate_registry_granted_access(granted)?;
    match registry_ioctl_access_requirement(ioctl_number)? {
        RegistryIoctlAccessRequirement::KeyGrantedMask(required) => {
            Ok(Some(registry_ioctl_fd_access_gate(granted, required)))
        }
        RegistryIoctlAccessRequirement::KeySecurityInfo(_)
        | RegistryIoctlAccessRequirement::Privilege(_)
        | RegistryIoctlAccessRequirement::TransactionFd => Ok(None),
    }
}

/// Checks a security-info-derived key-fd ioctl against a cached granted mask.
pub fn registry_security_info_granted_mask_allows(
    granted: u32,
    operation: RegistrySecurityOperation,
    security_info: u32,
) -> LcsResult<bool> {
    let required = registry_security_info_required_access(operation, security_info)?;
    Ok(registry_fd_has_right(granted, required))
}

/// Plans cached key-fd access gating for security-info-derived ioctls.
pub fn plan_registry_security_info_fd_access_gate(
    granted: u32,
    operation: RegistrySecurityOperation,
    security_info: u32,
) -> LcsResult<RegistryIoctlFdAccessGatePlan> {
    validate_registry_granted_access(granted)?;
    let required = registry_security_info_required_access(operation, security_info)?;
    Ok(registry_ioctl_fd_access_gate(granted, required))
}

fn registry_ioctl_fd_access_gate(granted: u32, required: u32) -> RegistryIoctlFdAccessGatePlan {
    if registry_fd_has_right(granted, required) {
        RegistryIoctlFdAccessGatePlan::Allowed {
            required_access: required,
            source_contact_allowed: true,
        }
    } else {
        RegistryIoctlFdAccessGatePlan::Denied {
            required_access: required,
            errno: RegistryIoctlFdAccessErrno::Eacces,
            source_contact_allowed: false,
        }
    }
}
