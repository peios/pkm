use lcs_core::{
    ACCESS_SYSTEM_SECURITY, KEY_QUERY_VALUE, KEY_SET_VALUE, READ_CONTROL, REG_IOC_BACKUP,
    REG_IOC_QUERY_VALUE, REG_IOC_SET_VALUE, RegistryIoctlFdAccessErrno,
    RegistryIoctlFdAccessGatePlan, RegistrySecurityOperation, SACL_SECURITY_INFORMATION,
    plan_registry_ioctl_fixed_fd_access_gate, plan_registry_security_info_fd_access_gate,
};

#[test]
fn fixed_right_ioctl_denial_blocks_source_contact_with_eacces() {
    assert_eq!(
        plan_registry_ioctl_fixed_fd_access_gate(KEY_QUERY_VALUE, REG_IOC_SET_VALUE),
        Ok(Some(RegistryIoctlFdAccessGatePlan::Denied {
            required_access: KEY_SET_VALUE,
            errno: RegistryIoctlFdAccessErrno::Eacces,
            source_contact_allowed: false,
        }))
    );
}

#[test]
fn fixed_right_ioctl_success_allows_later_source_contact() {
    assert_eq!(
        plan_registry_ioctl_fixed_fd_access_gate(KEY_QUERY_VALUE, REG_IOC_QUERY_VALUE),
        Ok(Some(RegistryIoctlFdAccessGatePlan::Allowed {
            required_access: KEY_QUERY_VALUE,
            source_contact_allowed: true,
        }))
    );
}

#[test]
fn privilege_only_ioctl_is_not_a_key_fd_access_gate() {
    assert_eq!(
        plan_registry_ioctl_fixed_fd_access_gate(KEY_QUERY_VALUE, REG_IOC_BACKUP),
        Ok(None)
    );
}

#[test]
fn security_info_ioctl_denial_blocks_source_contact_with_eacces() {
    assert_eq!(
        plan_registry_security_info_fd_access_gate(
            READ_CONTROL,
            RegistrySecurityOperation::Get,
            SACL_SECURITY_INFORMATION,
        ),
        Ok(RegistryIoctlFdAccessGatePlan::Denied {
            required_access: ACCESS_SYSTEM_SECURITY,
            errno: RegistryIoctlFdAccessErrno::Eacces,
            source_contact_allowed: false,
        })
    );
}

#[test]
fn security_info_ioctl_success_allows_later_source_contact() {
    assert_eq!(
        plan_registry_security_info_fd_access_gate(
            READ_CONTROL | ACCESS_SYSTEM_SECURITY,
            RegistrySecurityOperation::Get,
            SACL_SECURITY_INFORMATION,
        ),
        Ok(RegistryIoctlFdAccessGatePlan::Allowed {
            required_access: ACCESS_SYSTEM_SECURITY,
            source_contact_allowed: true,
        })
    );
}
