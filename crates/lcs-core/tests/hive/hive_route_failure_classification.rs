use lcs_core::{
    CurrentUserRewrite, Guid, HiveRouteErrno, HiveRouteOutcome, HiveScope, HiveStatus, HiveView,
    LcsLimits, RoutedHive, route_routable_path_hive,
};

const MACHINE_GUID: Guid = [0x10; 16];
const USERS_GUID: Guid = [0x11; 16];
const SOFTWARE_GUID: Guid = [0x12; 16];
const PRIVATE_MACHINE_GUID: Guid = [0x20; 16];
const SCOPE_A: Guid = [0xaa; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn hive<'a>(
    name: &'a str,
    root_guid: Guid,
    source_id: u32,
    status: HiveStatus,
    scope: HiveScope,
) -> HiveView<'a> {
    HiveView {
        name,
        root_guid,
        source_id,
        status,
        scope,
    }
}

#[test]
fn routable_path_dispatches_by_first_component_only() {
    let limits = limits();
    let hives = [
        hive(
            "Machine",
            MACHINE_GUID,
            1,
            HiveStatus::Active,
            HiveScope::Global,
        ),
        hive(
            "Software",
            SOFTWARE_GUID,
            2,
            HiveStatus::Unavailable,
            HiveScope::Global,
        ),
    ];

    assert_eq!(
        route_routable_path_hive(
            &limits,
            &hives,
            "Machine\\Software\\Vendor",
            CurrentUserRewrite::Literal,
            &[],
        ),
        Ok(HiveRouteOutcome::Dispatch(RoutedHive {
            name: "Machine",
            root_guid: MACHINE_GUID,
            source_id: 1,
            scope: HiveScope::Global,
        }))
    );
}

#[test]
fn unregistered_hive_classifies_as_enoent() {
    let limits = limits();
    let hives = [hive(
        "Machine",
        MACHINE_GUID,
        1,
        HiveStatus::Active,
        HiveScope::Global,
    )];

    assert_eq!(
        route_routable_path_hive(
            &limits,
            &hives,
            "Users\\S-1-5-18",
            CurrentUserRewrite::Literal,
            &[],
        ),
        Ok(HiveRouteOutcome::Failure(HiveRouteErrno::Enoent))
    );
}

#[test]
fn unavailable_hive_classifies_as_eio_without_fallback() {
    let limits = limits();
    let hives = [
        hive(
            "Machine",
            MACHINE_GUID,
            1,
            HiveStatus::Active,
            HiveScope::Global,
        ),
        hive(
            "Machine",
            PRIVATE_MACHINE_GUID,
            2,
            HiveStatus::Unavailable,
            HiveScope::Private(SCOPE_A),
        ),
    ];

    assert_eq!(
        route_routable_path_hive(
            &limits,
            &hives,
            "machine\\Software",
            CurrentUserRewrite::Literal,
            &[SCOPE_A],
        ),
        Ok(HiveRouteOutcome::Failure(HiveRouteErrno::Eio))
    );
}

#[test]
fn current_user_rewrite_routes_through_users_hive() {
    let limits = limits();
    let hives = [hive(
        "Users",
        USERS_GUID,
        3,
        HiveStatus::Active,
        HiveScope::Global,
    )];

    assert_eq!(
        route_routable_path_hive(
            &limits,
            &hives,
            "CurrentUser\\Software",
            CurrentUserRewrite::InitialCallerPath {
                user_sid_component: "S-1-5-18",
            },
            &[],
        ),
        Ok(HiveRouteOutcome::Dispatch(RoutedHive {
            name: "Users",
            root_guid: USERS_GUID,
            source_id: 3,
            scope: HiveScope::Global,
        }))
    );
}
