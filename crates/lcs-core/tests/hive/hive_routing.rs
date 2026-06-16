use crate::common::{limits};
use lcs_core::{
    CurrentUserRewrite, Guid, HiveRoute, HiveScope, HiveStatus, HiveView, LcsError,
    for_each_routable_path_component, route_hive, validate_hive_table, validate_scope_guid_set,
};

const MACHINE_GUID: Guid = [0x10; 16];
const USERS_GUID: Guid = [0x11; 16];
const PRIVATE_A_GUID: Guid = [0x20; 16];
const PRIVATE_B_GUID: Guid = [0x21; 16];
const SCOPE_A: Guid = [0xaa; 16];
const SCOPE_B: Guid = [0xbb; 16];


fn global_hive<'a>(name: &'a str, root_guid: Guid, source_id: u32) -> HiveView<'a> {
    HiveView {
        name,
        root_guid,
        source_id,
        status: HiveStatus::Active,
        scope: HiveScope::Global,
    }
}

fn private_hive<'a>(name: &'a str, root_guid: Guid, source_id: u32, scope: Guid) -> HiveView<'a> {
    HiveView {
        name,
        root_guid,
        source_id,
        status: HiveStatus::Active,
        scope: HiveScope::Private(scope),
    }
}

#[test]
fn global_hive_routing_distinguishes_active_unavailable_and_absent() {
    let limits = limits();
    let hives = [
        global_hive("Machine", MACHINE_GUID, 1),
        HiveView {
            name: "Users",
            root_guid: USERS_GUID,
            source_id: 2,
            status: HiveStatus::Unavailable,
            scope: HiveScope::Global,
        },
    ];

    assert_eq!(
        route_hive(&limits, &hives, "machine", &[]),
        Ok(HiveRoute::Active(lcs_core::RoutedHive {
            name: "Machine",
            root_guid: MACHINE_GUID,
            source_id: 1,
            scope: HiveScope::Global,
        }))
    );
    assert_eq!(
        route_hive(&limits, &hives, "Users", &[]),
        Ok(HiveRoute::Unavailable(lcs_core::RoutedHive {
            name: "Users",
            root_guid: USERS_GUID,
            source_id: 2,
            scope: HiveScope::Global,
        }))
    );
    assert_eq!(
        route_hive(&limits, &hives, "Software", &[]),
        Ok(HiveRoute::NotRegistered)
    );
}

#[test]
fn private_hives_shadow_globals_in_scope_order() {
    let limits = limits();
    let hives = [
        global_hive("Machine", MACHINE_GUID, 1),
        private_hive("Machine", PRIVATE_A_GUID, 2, SCOPE_A),
        private_hive("Machine", PRIVATE_B_GUID, 3, SCOPE_B),
    ];

    assert_eq!(
        route_hive(&limits, &hives, "machine", &[SCOPE_B, SCOPE_A]),
        Ok(HiveRoute::Active(lcs_core::RoutedHive {
            name: "Machine",
            root_guid: PRIVATE_B_GUID,
            source_id: 3,
            scope: HiveScope::Private(SCOPE_B),
        }))
    );
    assert_eq!(
        route_hive(&limits, &hives, "machine", &[SCOPE_A]),
        Ok(HiveRoute::Active(lcs_core::RoutedHive {
            name: "Machine",
            root_guid: PRIVATE_A_GUID,
            source_id: 2,
            scope: HiveScope::Private(SCOPE_A),
        }))
    );
    assert_eq!(
        route_hive(&limits, &hives, "machine", &[]),
        Ok(HiveRoute::Active(lcs_core::RoutedHive {
            name: "Machine",
            root_guid: MACHINE_GUID,
            source_id: 1,
            scope: HiveScope::Global,
        }))
    );
}

#[test]
fn unavailable_private_hive_does_not_fall_back_to_global() {
    let limits = limits();
    let hives = [
        global_hive("Machine", MACHINE_GUID, 1),
        HiveView {
            name: "Machine",
            root_guid: PRIVATE_A_GUID,
            source_id: 2,
            status: HiveStatus::Unavailable,
            scope: HiveScope::Private(SCOPE_A),
        },
    ];

    assert_eq!(
        route_hive(&limits, &hives, "Machine", &[SCOPE_A]),
        Ok(HiveRoute::Unavailable(lcs_core::RoutedHive {
            name: "Machine",
            root_guid: PRIVATE_A_GUID,
            source_id: 2,
            scope: HiveScope::Private(SCOPE_A),
        }))
    );
}

#[test]
fn hive_table_validation_rejects_reserved_malformed_and_duplicate_names() {
    let limits = limits();

    assert_eq!(
        validate_hive_table(&limits, &[global_hive("CurrentUser", MACHINE_GUID, 1)]),
        Err(LcsError::ReservedHiveName)
    );
    assert_eq!(
        validate_hive_table(&limits, &[global_hive("bad/name", MACHINE_GUID, 1)]),
        Err(LcsError::NameContainsSeparator { field: "hive_name" })
    );
    assert_eq!(
        validate_hive_table(
            &limits,
            &[
                global_hive("Machine", MACHINE_GUID, 1),
                global_hive("machine", USERS_GUID, 2),
            ],
        ),
        Err(LcsError::DuplicateHiveIdentity)
    );
    assert_eq!(
        validate_hive_table(
            &limits,
            &[
                private_hive("Machine", PRIVATE_A_GUID, 1, SCOPE_A),
                private_hive("machine", PRIVATE_B_GUID, 2, SCOPE_A),
            ],
        ),
        Err(LcsError::DuplicateHiveIdentity)
    );
    assert_eq!(
        validate_hive_table(
            &limits,
            &[
                global_hive("Machine", MACHINE_GUID, 1),
                private_hive("machine", PRIVATE_A_GUID, 2, SCOPE_A),
                private_hive("machine", PRIVATE_B_GUID, 3, SCOPE_B),
            ],
        ),
        Ok(())
    );
}

#[test]
fn scope_guid_set_validation_enforces_ordered_set_bound() {
    let limits = limits();

    assert_eq!(
        validate_scope_guid_set(&limits, &[SCOPE_A, SCOPE_B]),
        Ok(())
    );
    assert_eq!(
        validate_scope_guid_set(&limits, &[SCOPE_A, SCOPE_A]),
        Err(LcsError::DuplicateScopeGuid)
    );

    let mut tight_limits = limits;
    tight_limits.max_scope_guids_per_token = 1;
    assert_eq!(
        validate_scope_guid_set(&tight_limits, &[SCOPE_A, SCOPE_B]),
        Err(LcsError::TooManyScopeGuids { count: 2, max: 1 })
    );
}

#[test]
fn current_user_rewrite_applies_only_to_initial_caller_paths() {
    let limits = limits();
    let mut components = Vec::<&str>::new();

    let count = for_each_routable_path_component(
        &limits,
        "currentuser/Software/App",
        CurrentUserRewrite::InitialCallerPath {
            user_sid_component: "S-1-5-21-1-2-3-1000",
        },
        |component| {
            components.push(component);
            Ok(())
        },
    )
    .expect("CurrentUser rewrite should succeed");

    assert_eq!(count, 4);
    assert_eq!(
        components,
        ["Users", "S-1-5-21-1-2-3-1000", "Software", "App"]
    );

    components.clear();
    let count = for_each_routable_path_component(
        &limits,
        "CurrentUser\\Software",
        CurrentUserRewrite::Literal,
        |component| {
            components.push(component);
            Ok(())
        },
    )
    .expect("literal symlink target should not rewrite");

    assert_eq!(count, 2);
    assert_eq!(components, ["CurrentUser", "Software"]);
}

#[test]
fn current_user_rewrite_validates_sid_component_and_rewritten_length() {
    let limits = limits();

    assert_eq!(
        for_each_routable_path_component(
            &limits,
            "CurrentUser\\Software",
            CurrentUserRewrite::InitialCallerPath {
                user_sid_component: "S-1-5/18",
            },
            |_| Ok(()),
        ),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );

    let mut tight_limits = limits;
    tight_limits.max_total_path_length = "CurrentUser\\A".len();
    assert_eq!(
        for_each_routable_path_component(
            &tight_limits,
            "CurrentUser\\A",
            CurrentUserRewrite::InitialCallerPath {
                user_sid_component: "S-1-5-18",
            },
            |_| Ok(()),
        ),
        Err(LcsError::PathTooLong {
            len: "Users\\S-1-5-18\\A".len(),
            max: "CurrentUser\\A".len(),
        })
    );
}
