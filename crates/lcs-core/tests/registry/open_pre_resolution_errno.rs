use lcs_core::{
    GENERIC_READ, KEY_QUERY_VALUE, LinuxErrno, MAXIMUM_ALLOWED, SYNCHRONIZE,
    plan_registry_open_pre_resolution_access, registry_open_pre_resolution_linux_errno,
};

#[test]
fn invalid_pre_resolution_desired_access_projects_to_linux_einval() {
    let zero = plan_registry_open_pre_resolution_access(0);
    assert_eq!(
        registry_open_pre_resolution_linux_errno(&zero),
        Some(LinuxErrno::Einval)
    );

    let synchronize = plan_registry_open_pre_resolution_access(SYNCHRONIZE);
    assert_eq!(
        registry_open_pre_resolution_linux_errno(&synchronize),
        Some(LinuxErrno::Einval)
    );

    let unknown_bit = plan_registry_open_pre_resolution_access(0x0000_0040);
    assert_eq!(
        registry_open_pre_resolution_linux_errno(&unknown_bit),
        Some(LinuxErrno::Einval)
    );
}

#[test]
fn valid_pre_resolution_desired_access_has_no_errno() {
    let specific = plan_registry_open_pre_resolution_access(KEY_QUERY_VALUE);
    assert_eq!(registry_open_pre_resolution_linux_errno(&specific), None);

    let generic = plan_registry_open_pre_resolution_access(GENERIC_READ);
    assert_eq!(registry_open_pre_resolution_linux_errno(&generic), None);

    let maximum_allowed =
        plan_registry_open_pre_resolution_access(MAXIMUM_ALLOWED | KEY_QUERY_VALUE);
    assert_eq!(
        registry_open_pre_resolution_linux_errno(&maximum_allowed),
        None
    );
}
