use lcs_core::{
    ACCESS_SYSTEM_SECURITY, DACL_SECURITY_INFORMATION, DELETE, GROUP_SECURITY_INFORMATION,
    KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_QUERY_VALUE, KEY_SET_VALUE, LcsError,
    OWNER_SECURITY_INFORMATION, READ_CONTROL, REG_IOC_BACKUP, REG_IOC_BLANKET_TOMBSTONE,
    REG_IOC_COMMIT, REG_IOC_DELETE_KEY, REG_IOC_DELETE_VALUE, REG_IOC_ENUM_SUBKEYS,
    REG_IOC_ENUM_VALUES, REG_IOC_FLUSH, REG_IOC_GET_SECURITY, REG_IOC_HIDE_KEY, REG_IOC_NOTIFY,
    REG_IOC_QUERY_KEY_INFO, REG_IOC_QUERY_VALUE, REG_IOC_QUERY_VALUES_BATCH, REG_IOC_RESTORE,
    REG_IOC_SET_SECURITY, REG_IOC_SET_VALUE, REG_IOC_TXN_STATUS, RegistryIoctlAccessRequirement,
    RegistryIoctlPrivilege, RegistrySecurityOperation, SACL_SECURITY_INFORMATION, WRITE_DAC,
    WRITE_OWNER, registry_ioctl_access_requirement, registry_ioctl_fixed_granted_mask_allows,
    registry_security_info_granted_mask_allows, registry_security_info_required_access,
    validate_registry_security_info,
};

#[test]
fn fixed_key_fd_ioctl_requirements_match_psd_005_table() {
    let cases = [
        (REG_IOC_QUERY_VALUE, KEY_QUERY_VALUE),
        (REG_IOC_SET_VALUE, KEY_SET_VALUE),
        (REG_IOC_DELETE_VALUE, KEY_SET_VALUE),
        (REG_IOC_BLANKET_TOMBSTONE, KEY_SET_VALUE),
        (REG_IOC_QUERY_VALUES_BATCH, KEY_QUERY_VALUE),
        (REG_IOC_ENUM_VALUES, KEY_QUERY_VALUE),
        (REG_IOC_ENUM_SUBKEYS, KEY_ENUMERATE_SUB_KEYS),
        (REG_IOC_QUERY_KEY_INFO, READ_CONTROL),
        (REG_IOC_DELETE_KEY, DELETE),
        (REG_IOC_HIDE_KEY, DELETE),
        (REG_IOC_NOTIFY, KEY_NOTIFY),
        (REG_IOC_FLUSH, KEY_SET_VALUE),
    ];

    for (ioctl_number, required) in cases {
        assert_eq!(
            registry_ioctl_access_requirement(ioctl_number),
            Ok(RegistryIoctlAccessRequirement::KeyGrantedMask(required))
        );
        assert_eq!(
            registry_ioctl_fixed_granted_mask_allows(required, ioctl_number),
            Ok(Some(true))
        );
        assert_eq!(
            registry_ioctl_fixed_granted_mask_allows(required & !required, ioctl_number),
            Ok(Some(false))
        );
    }
}

#[test]
fn non_fixed_ioctl_requirements_are_classified_without_guessing_masks() {
    assert_eq!(
        registry_ioctl_access_requirement(REG_IOC_GET_SECURITY),
        Ok(RegistryIoctlAccessRequirement::KeySecurityInfo(
            RegistrySecurityOperation::Get
        ))
    );
    assert_eq!(
        registry_ioctl_access_requirement(REG_IOC_SET_SECURITY),
        Ok(RegistryIoctlAccessRequirement::KeySecurityInfo(
            RegistrySecurityOperation::Set
        ))
    );
    assert_eq!(
        registry_ioctl_access_requirement(REG_IOC_BACKUP),
        Ok(RegistryIoctlAccessRequirement::Privilege(
            RegistryIoctlPrivilege::Backup
        ))
    );
    assert_eq!(
        registry_ioctl_access_requirement(REG_IOC_RESTORE),
        Ok(RegistryIoctlAccessRequirement::Privilege(
            RegistryIoctlPrivilege::Restore
        ))
    );
    assert_eq!(
        registry_ioctl_access_requirement(REG_IOC_COMMIT),
        Ok(RegistryIoctlAccessRequirement::TransactionFd)
    );
    assert_eq!(
        registry_ioctl_access_requirement(REG_IOC_TXN_STATUS),
        Ok(RegistryIoctlAccessRequirement::TransactionFd)
    );

    for ioctl_number in [
        REG_IOC_GET_SECURITY,
        REG_IOC_SET_SECURITY,
        REG_IOC_BACKUP,
        REG_IOC_RESTORE,
        REG_IOC_COMMIT,
        REG_IOC_TXN_STATUS,
    ] {
        assert_eq!(
            registry_ioctl_fixed_granted_mask_allows(u32::MAX, ioctl_number),
            Ok(None)
        );
    }
}

#[test]
fn security_info_validation_rejects_zero_label_and_unknown_bits() {
    assert_eq!(
        validate_registry_security_info(0),
        Err(LcsError::ZeroSecurityInfo)
    );

    let label_security_information = 0x0000_0010;
    assert_eq!(
        validate_registry_security_info(label_security_information),
        Err(LcsError::UnknownSecurityInfoFlags {
            flags: label_security_information,
            unknown: label_security_information,
        })
    );

    let unknown = 0x8000_0000;
    assert_eq!(
        validate_registry_security_info(OWNER_SECURITY_INFORMATION | unknown),
        Err(LcsError::UnknownSecurityInfoFlags {
            flags: OWNER_SECURITY_INFORMATION | unknown,
            unknown,
        })
    );
}

#[test]
fn get_security_rights_are_derived_from_requested_components() {
    let read_components =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    assert_eq!(
        registry_security_info_required_access(RegistrySecurityOperation::Get, read_components),
        Ok(READ_CONTROL)
    );
    assert_eq!(
        registry_security_info_required_access(
            RegistrySecurityOperation::Get,
            SACL_SECURITY_INFORMATION
        ),
        Ok(ACCESS_SYSTEM_SECURITY)
    );
    assert_eq!(
        registry_security_info_required_access(
            RegistrySecurityOperation::Get,
            OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
        ),
        Ok(READ_CONTROL | ACCESS_SYSTEM_SECURITY)
    );

    assert_eq!(
        registry_security_info_granted_mask_allows(
            READ_CONTROL,
            RegistrySecurityOperation::Get,
            DACL_SECURITY_INFORMATION
        ),
        Ok(true)
    );
    assert_eq!(
        registry_security_info_granted_mask_allows(
            READ_CONTROL,
            RegistrySecurityOperation::Get,
            SACL_SECURITY_INFORMATION
        ),
        Ok(false)
    );
}

#[test]
fn set_security_rights_are_derived_from_requested_components() {
    assert_eq!(
        registry_security_info_required_access(
            RegistrySecurityOperation::Set,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
        ),
        Ok(WRITE_OWNER)
    );
    assert_eq!(
        registry_security_info_required_access(
            RegistrySecurityOperation::Set,
            DACL_SECURITY_INFORMATION
        ),
        Ok(WRITE_DAC)
    );
    assert_eq!(
        registry_security_info_required_access(
            RegistrySecurityOperation::Set,
            SACL_SECURITY_INFORMATION
        ),
        Ok(ACCESS_SYSTEM_SECURITY)
    );
    assert_eq!(
        registry_security_info_required_access(
            RegistrySecurityOperation::Set,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
        ),
        Ok(WRITE_OWNER | WRITE_DAC | ACCESS_SYSTEM_SECURITY)
    );

    assert_eq!(
        registry_security_info_granted_mask_allows(
            WRITE_OWNER | WRITE_DAC,
            RegistrySecurityOperation::Set,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        ),
        Ok(true)
    );
    assert_eq!(
        registry_security_info_granted_mask_allows(
            WRITE_DAC,
            RegistrySecurityOperation::Set,
            GROUP_SECURITY_INFORMATION
        ),
        Ok(false)
    );
}

#[test]
fn unknown_registry_ioctl_numbers_fail_closed() {
    assert_eq!(
        registry_ioctl_access_requirement(18),
        Err(LcsError::UnknownRegistryIoctl(18))
    );
    assert_eq!(
        registry_ioctl_fixed_granted_mask_allows(u32::MAX, u8::MAX),
        Err(LcsError::UnknownRegistryIoctl(u8::MAX))
    );
}
