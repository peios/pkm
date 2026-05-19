use lcs_core::{
    CurrentUserRewrite, Guid, HiveRouteErrno, HiveRouteOutcome, HiveScope, HiveStatus, HiveView,
    LcsLimits, RoutedHive, route_routable_path_hive,
};

const CUSTOM_ROOT: Guid = [0x39; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn hive<'a>(name: &'a str, root_guid: Guid) -> HiveView<'a> {
    HiveView {
        name,
        root_guid,
        source_id: 9,
        status: HiveStatus::Active,
        scope: HiveScope::Global,
    }
}

#[test]
fn conventional_default_names_are_not_hardcoded_routes() {
    let limits = limits();
    let no_registered_hives = [];

    assert_eq!(
        route_routable_path_hive(
            &limits,
            &no_registered_hives,
            "Machine\\System",
            CurrentUserRewrite::Literal,
            &[],
        ),
        Ok(HiveRouteOutcome::Failure(HiveRouteErrno::Enoent))
    );
    assert_eq!(
        route_routable_path_hive(
            &limits,
            &no_registered_hives,
            "Users\\S-1-5-18",
            CurrentUserRewrite::Literal,
            &[],
        ),
        Ok(HiveRouteOutcome::Failure(HiveRouteErrno::Enoent))
    );
}

#[test]
fn arbitrary_source_registered_hive_name_routes_normally() {
    let limits = limits();
    let hives = [hive("VendorHive", CUSTOM_ROOT)];

    assert_eq!(
        route_routable_path_hive(
            &limits,
            &hives,
            "vendorhive\\Software",
            CurrentUserRewrite::Literal,
            &[],
        ),
        Ok(HiveRouteOutcome::Dispatch(RoutedHive {
            name: "VendorHive",
            root_guid: CUSTOM_ROOT,
            source_id: 9,
            scope: HiveScope::Global,
        }))
    );
}
