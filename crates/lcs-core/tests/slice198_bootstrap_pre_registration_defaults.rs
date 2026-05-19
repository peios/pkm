use lcs_core::{
    CurrentUserRewrite, Guid, HiveRouteErrno, HiveRouteOutcome, HiveScope, HiveStatus, HiveView,
    LcsLimits, MAX_VALUE_SIZE, REQUEST_TIMEOUT_MS, RoutedHive, route_routable_path_hive,
};

const MACHINE_ROOT: Guid = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];

fn machine_hive() -> HiveView<'static> {
    HiveView {
        name: "Machine",
        root_guid: MACHINE_ROOT,
        source_id: 12,
        status: HiveStatus::Active,
        scope: HiveScope::Global,
    }
}

#[test]
fn bootstrap_without_registered_sources_routes_registry_operations_to_enoent() {
    let limits = LcsLimits::default();
    let no_sources = [];

    assert_eq!(
        route_routable_path_hive(
            &limits,
            &no_sources,
            "Machine\\Software\\Policy",
            CurrentUserRewrite::Literal,
            &[],
        ),
        Ok(HiveRouteOutcome::Failure(HiveRouteErrno::Enoent))
    );
    assert_eq!(
        route_routable_path_hive(
            &limits,
            &no_sources,
            "ArbitraryHive\\Key",
            CurrentUserRewrite::Literal,
            &[],
        ),
        Ok(HiveRouteOutcome::Failure(HiveRouteErrno::Enoent))
    );
}

#[test]
fn bootstrap_after_source_registration_routes_with_compiled_in_defaults() {
    let limits = LcsLimits::default();
    let hives = [machine_hive()];

    assert_eq!(limits.request_timeout_ms, REQUEST_TIMEOUT_MS.default);
    assert_eq!(limits.max_value_size as u32, MAX_VALUE_SIZE.default);
    assert_eq!(
        route_routable_path_hive(
            &limits,
            &hives,
            "machine\\System\\Registry",
            CurrentUserRewrite::Literal,
            &[],
        ),
        Ok(HiveRouteOutcome::Dispatch(RoutedHive {
            name: "Machine",
            root_guid: MACHINE_ROOT,
            source_id: 12,
            scope: HiveScope::Global,
        }))
    );
}
