use lcs_core::{
    GENERIC_EXECUTE, KEY_QUERY_VALUE, MAXIMUM_ALLOWED, RegistryOpenPreResolutionAccessPlan,
    RegistryOpenPreResolutionErrno, SYNCHRONIZE, plan_registry_open_pre_resolution_access,
};

#[test]
fn valid_desired_access_allows_path_resolution_after_normalization() {
    assert_eq!(
        plan_registry_open_pre_resolution_access(MAXIMUM_ALLOWED | KEY_QUERY_VALUE),
        RegistryOpenPreResolutionAccessPlan::Continue {
            requested_access: MAXIMUM_ALLOWED | KEY_QUERY_VALUE,
            mapped_desired_access: KEY_QUERY_VALUE,
            maximum_allowed: true,
            path_resolution_allowed: true,
        }
    );
}

#[test]
fn generic_execute_is_valid_and_maps_to_zero_before_path_resolution() {
    assert_eq!(
        plan_registry_open_pre_resolution_access(GENERIC_EXECUTE),
        RegistryOpenPreResolutionAccessPlan::Continue {
            requested_access: GENERIC_EXECUTE,
            mapped_desired_access: 0,
            maximum_allowed: false,
            path_resolution_allowed: true,
        }
    );
}

#[test]
fn zero_desired_access_rejects_before_path_resolution() {
    assert_eq!(
        plan_registry_open_pre_resolution_access(0),
        RegistryOpenPreResolutionAccessPlan::Reject {
            errno: RegistryOpenPreResolutionErrno::Einval,
            path_resolution_allowed: false,
        }
    );
}

#[test]
fn synchronize_desired_access_rejects_before_path_resolution() {
    assert_eq!(
        plan_registry_open_pre_resolution_access(SYNCHRONIZE),
        RegistryOpenPreResolutionAccessPlan::Reject {
            errno: RegistryOpenPreResolutionErrno::Einval,
            path_resolution_allowed: false,
        }
    );
}

#[test]
fn unknown_desired_access_bits_reject_before_path_resolution() {
    assert_eq!(
        plan_registry_open_pre_resolution_access(0x0400_0000),
        RegistryOpenPreResolutionAccessPlan::Reject {
            errno: RegistryOpenPreResolutionErrno::Einval,
            path_resolution_allowed: false,
        }
    );
}
