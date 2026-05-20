use lcs_core::{
    ACCESS_SYSTEM_SECURITY, KEY_QUERY_VALUE, KEY_SET_VALUE, LinuxErrno, READ_CONTROL,
    REG_IOC_QUERY_VALUE, REG_IOC_SET_VALUE, RegistryIoctlFdAccessErrno,
    RegistryIoctlFdAccessGatePlan, RegistrySecurityOperation, SACL_SECURITY_INFORMATION,
    plan_registry_ioctl_fixed_fd_access_gate, plan_registry_security_info_fd_access_gate,
    registry_ioctl_fd_access_gate_errno,
};

#[test]
fn fixed_right_denial_projects_to_linux_eacces() {
    let plan = plan_registry_ioctl_fixed_fd_access_gate(KEY_QUERY_VALUE, REG_IOC_SET_VALUE)
        .unwrap()
        .unwrap();

    assert_eq!(
        plan,
        RegistryIoctlFdAccessGatePlan::Denied {
            required_access: KEY_SET_VALUE,
            errno: RegistryIoctlFdAccessErrno::Eacces,
            source_contact_allowed: false,
        }
    );
    assert_eq!(
        registry_ioctl_fd_access_gate_errno(&plan),
        Some(LinuxErrno::Eacces)
    );
}

#[test]
fn security_info_denial_projects_to_linux_eacces() {
    let plan = plan_registry_security_info_fd_access_gate(
        READ_CONTROL,
        RegistrySecurityOperation::Get,
        SACL_SECURITY_INFORMATION,
    )
    .unwrap();

    assert_eq!(
        plan,
        RegistryIoctlFdAccessGatePlan::Denied {
            required_access: ACCESS_SYSTEM_SECURITY,
            errno: RegistryIoctlFdAccessErrno::Eacces,
            source_contact_allowed: false,
        }
    );
    assert_eq!(
        registry_ioctl_fd_access_gate_errno(&plan),
        Some(LinuxErrno::Eacces)
    );
}

#[test]
fn allowed_ioctl_gates_have_no_errno() {
    let fixed = plan_registry_ioctl_fixed_fd_access_gate(KEY_QUERY_VALUE, REG_IOC_QUERY_VALUE)
        .unwrap()
        .unwrap();
    let security = plan_registry_security_info_fd_access_gate(
        READ_CONTROL | ACCESS_SYSTEM_SECURITY,
        RegistrySecurityOperation::Get,
        SACL_SECURITY_INFORMATION,
    )
    .unwrap();

    assert_eq!(registry_ioctl_fd_access_gate_errno(&fixed), None);
    assert_eq!(registry_ioctl_fd_access_gate_errno(&security), None);
}
