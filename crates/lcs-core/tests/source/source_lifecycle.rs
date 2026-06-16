use lcs_core::{
    Guid, HiveScope, HiveStatus, HiveView, LcsError, LcsLimits, NIL_GUID, RegisteredHiveIdentity,
    SourceSlotStatus, SourceSlotView, for_each_source_slot_hive, route_hive,
    source_slot_hive_status, validate_source_registration, validate_source_slots,
};

const MACHINE_GUID: Guid = [0x10; 16];
const USERS_GUID: Guid = [0x11; 16];
const PRIVATE_GUID: Guid = [0x12; 16];
const SCOPE_A: Guid = [0xaa; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn existing_global<'a>(name: &'a str, root_guid: Guid) -> RegisteredHiveIdentity<'a> {
    RegisteredHiveIdentity {
        name,
        root_guid,
        scope: HiveScope::Global,
    }
}

fn existing_private<'a>(name: &'a str, root_guid: Guid, scope: Guid) -> RegisteredHiveIdentity<'a> {
    RegisteredHiveIdentity {
        name,
        root_guid,
        scope: HiveScope::Private(scope),
    }
}

#[test]
fn source_lifecycle_maps_slots_to_published_hive_status() {
    assert_eq!(
        source_slot_hive_status(SourceSlotStatus::Active),
        HiveStatus::Active
    );
    assert_eq!(
        source_slot_hive_status(SourceSlotStatus::Down),
        HiveStatus::Unavailable
    );
}

#[test]
fn source_lifecycle_projects_active_and_down_slots_into_route_views() {
    let limits = limits();
    let active_hives = [
        existing_global("Machine", MACHINE_GUID),
        existing_private("Machine", PRIVATE_GUID, SCOPE_A),
    ];
    let down_hives = [existing_global("Users", USERS_GUID)];
    let slots = [
        SourceSlotView {
            source_id: 7,
            status: SourceSlotStatus::Active,
            hives: &active_hives,
        },
        SourceSlotView {
            source_id: 9,
            status: SourceSlotStatus::Down,
            hives: &down_hives,
        },
    ];

    let mut published = Vec::new();
    let emitted = for_each_source_slot_hive(&limits, &slots, |hive| {
        published.push(hive);
        Ok(())
    })
    .expect("valid source slots should publish hive views");

    assert_eq!(emitted, 3);
    assert_eq!(
        published,
        [
            HiveView {
                name: "Machine",
                root_guid: MACHINE_GUID,
                source_id: 7,
                status: HiveStatus::Active,
                scope: HiveScope::Global,
            },
            HiveView {
                name: "Machine",
                root_guid: PRIVATE_GUID,
                source_id: 7,
                status: HiveStatus::Active,
                scope: HiveScope::Private(SCOPE_A),
            },
            HiveView {
                name: "Users",
                root_guid: USERS_GUID,
                source_id: 9,
                status: HiveStatus::Unavailable,
                scope: HiveScope::Global,
            },
        ]
    );

    assert_eq!(
        route_hive(&limits, &published, "Machine", &[SCOPE_A]),
        Ok(lcs_core::HiveRoute::Active(lcs_core::RoutedHive {
            name: "Machine",
            root_guid: PRIVATE_GUID,
            source_id: 7,
            scope: HiveScope::Private(SCOPE_A),
        }))
    );
    assert_eq!(
        route_hive(&limits, &published, "Users", &[]),
        Ok(lcs_core::HiveRoute::Unavailable(lcs_core::RoutedHive {
            name: "Users",
            root_guid: USERS_GUID,
            source_id: 9,
            scope: HiveScope::Global,
        }))
    );
}

#[test]
fn source_lifecycle_validation_rejects_corrupt_slot_snapshots() {
    let limits = limits();

    assert_eq!(
        validate_source_slots(
            &limits,
            &[SourceSlotView {
                source_id: 1,
                status: SourceSlotStatus::Active,
                hives: &[],
            }],
        ),
        Err(LcsError::ZeroHiveCount)
    );

    assert_eq!(
        validate_source_slots(
            &limits,
            &[SourceSlotView {
                source_id: 1,
                status: SourceSlotStatus::Down,
                hives: &[existing_global("Machine", NIL_GUID)],
            }],
        ),
        Err(LcsError::NilHiveRootGuid)
    );

    assert_eq!(
        validate_source_slots(
            &limits,
            &[SourceSlotView {
                source_id: 1,
                status: SourceSlotStatus::Active,
                hives: &[existing_global("Machine", MACHINE_GUID)],
            }],
        ),
        Ok(())
    );
}

#[test]
fn source_lifecycle_validation_rejects_duplicate_reserved_identity_and_root_guid() {
    let limits = limits();
    let duplicate_identity = [
        existing_global("Machine", MACHINE_GUID),
        existing_global("machine", USERS_GUID),
    ];
    let duplicate_root = [
        existing_global("Machine", MACHINE_GUID),
        existing_private("Users", MACHINE_GUID, SCOPE_A),
    ];

    assert_eq!(
        validate_source_slots(
            &limits,
            &[SourceSlotView {
                source_id: 1,
                status: SourceSlotStatus::Active,
                hives: &duplicate_identity,
            }],
        ),
        Err(LcsError::DuplicateHiveIdentity)
    );
    assert_eq!(
        validate_source_slots(
            &limits,
            &[SourceSlotView {
                source_id: 1,
                status: SourceSlotStatus::Active,
                hives: &duplicate_root,
            }],
        ),
        Err(LcsError::DuplicateHiveRootGuid)
    );
}

#[test]
fn source_registration_now_fails_closed_on_existing_same_slot_root_corruption() {
    let limits = limits();
    let duplicate_root = [
        existing_global("Machine", MACHINE_GUID),
        existing_private("Users", MACHINE_GUID, SCOPE_A),
    ];
    let slots = [SourceSlotView {
        source_id: 1,
        status: SourceSlotStatus::Down,
        hives: &duplicate_root,
    }];
    let requested_hives = [lcs_core::SourceRegistrationHive {
        name: "Software",
        root_guid: USERS_GUID,
        flags: 0,
        scope_guid: NIL_GUID,
    }];
    let request = lcs_core::SourceRegistrationRequest {
        hives: &requested_hives,
        max_sequence: 0,
        caller_has_tcb: true,
    };

    assert_eq!(
        validate_source_registration(&limits, &slots, &request),
        Err(LcsError::DuplicateHiveRootGuid)
    );
}
