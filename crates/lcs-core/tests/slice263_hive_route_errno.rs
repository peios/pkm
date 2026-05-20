use lcs_core::{
    CurrentUserRewrite, Guid, HiveRouteOutcome, HiveScope, HiveStatus, HiveView, LcsLimits,
    LinuxErrno, RoutedHive, hive_route_outcome_errno, route_routable_path_hive,
};

const MACHINE_GUID: Guid = [0x10; 16];
const PRIVATE_MACHINE_GUID: Guid = [0x20; 16];
const SCOPE_A: Guid = [0xaa; 16];

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
fn active_hive_route_dispatch_has_no_errno() {
    let limits = LcsLimits::default();
    let hives = [hive(
        "Machine",
        MACHINE_GUID,
        1,
        HiveStatus::Active,
        HiveScope::Global,
    )];

    let outcome = route_routable_path_hive(
        &limits,
        &hives,
        "Machine\\Software",
        CurrentUserRewrite::Literal,
        &[],
    )
    .expect("valid path");

    assert_eq!(
        outcome,
        HiveRouteOutcome::Dispatch(RoutedHive {
            name: "Machine",
            root_guid: MACHINE_GUID,
            source_id: 1,
            scope: HiveScope::Global,
        })
    );
    assert_eq!(hive_route_outcome_errno(outcome), None);
}

#[test]
fn unregistered_hive_route_projects_to_enoent() {
    let limits = LcsLimits::default();
    let hives = [hive(
        "Machine",
        MACHINE_GUID,
        1,
        HiveStatus::Active,
        HiveScope::Global,
    )];

    let outcome = route_routable_path_hive(
        &limits,
        &hives,
        "Users\\S-1-5-18",
        CurrentUserRewrite::Literal,
        &[],
    )
    .expect("valid path");

    assert_eq!(hive_route_outcome_errno(outcome), Some(LinuxErrno::Enoent));
}

#[test]
fn unavailable_hive_route_projects_to_eio_without_fallback() {
    let limits = LcsLimits::default();
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

    let outcome = route_routable_path_hive(
        &limits,
        &hives,
        "machine\\Software",
        CurrentUserRewrite::Literal,
        &[SCOPE_A],
    )
    .expect("valid path");

    assert_eq!(hive_route_outcome_errno(outcome), Some(LinuxErrno::Eio));
}
