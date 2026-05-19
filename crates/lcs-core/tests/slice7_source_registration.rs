use lcs_core::{
    Guid, HiveScope, LcsError, LcsLimits, NIL_GUID, RSI_HIVE_PRIVATE, RegisteredHiveIdentity,
    SourceRegistrationDecision, SourceRegistrationHive, SourceRegistrationPlan,
    SourceRegistrationRequest, SourceSlotStatus, SourceSlotView, validate_source_registration,
};

const MACHINE_GUID: Guid = [0x10; 16];
const USERS_GUID: Guid = [0x11; 16];
const PRIVATE_GUID: Guid = [0x12; 16];
const OTHER_GUID: Guid = [0x13; 16];
const STALE_GUID: Guid = [0x14; 16];
const SCOPE_A: Guid = [0xaa; 16];
const SCOPE_B: Guid = [0xbb; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn global_hive<'a>(name: &'a str, root_guid: Guid) -> SourceRegistrationHive<'a> {
    SourceRegistrationHive {
        name,
        root_guid,
        flags: 0,
        scope_guid: NIL_GUID,
    }
}

fn private_hive<'a>(
    name: &'a str,
    root_guid: Guid,
    scope_guid: Guid,
) -> SourceRegistrationHive<'a> {
    SourceRegistrationHive {
        name,
        root_guid,
        flags: RSI_HIVE_PRIVATE,
        scope_guid,
    }
}

fn request<'a>(
    hives: &'a [SourceRegistrationHive<'a>],
    max_sequence: u64,
) -> SourceRegistrationRequest<'a> {
    SourceRegistrationRequest {
        hives,
        max_sequence,
        caller_has_tcb: true,
    }
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
fn source_registration_accepts_new_slot_and_sequence_floor() {
    let limits = limits();
    let hives = [
        global_hive("Machine", MACHINE_GUID),
        private_hive("Machine", PRIVATE_GUID, SCOPE_A),
        private_hive("Machine", USERS_GUID, NIL_GUID),
    ];

    assert_eq!(
        validate_source_registration(&limits, &[], &request(&hives, 41)),
        Ok(SourceRegistrationPlan {
            decision: SourceRegistrationDecision::NewSlot,
            hive_count: 3,
            source_next_sequence: 42,
        })
    );
}

#[test]
fn source_registration_rejects_privilege_count_and_sequence_failures() {
    let limits = limits();
    let hives = [global_hive("Machine", MACHINE_GUID)];
    let missing_tcb = SourceRegistrationRequest {
        hives: &hives,
        max_sequence: 0,
        caller_has_tcb: false,
    };
    assert_eq!(
        validate_source_registration(&limits, &[], &missing_tcb),
        Err(LcsError::MissingTcbPrivilege)
    );

    assert_eq!(
        validate_source_registration(&limits, &[], &request(&[], 0)),
        Err(LcsError::ZeroHiveCount)
    );

    let mut tight_limits = limits;
    tight_limits.max_hives_per_source = 1;
    let too_many = [
        global_hive("Machine", MACHINE_GUID),
        global_hive("Users", USERS_GUID),
    ];
    assert_eq!(
        validate_source_registration(&tight_limits, &[], &request(&too_many, 0)),
        Err(LcsError::TooManyHives { count: 2, max: 1 })
    );

    assert_eq!(
        validate_source_registration(&limits, &[], &request(&hives, u64::MAX)),
        Err(LcsError::SequenceOverflow)
    );
}

#[test]
fn source_registration_rejects_malformed_hive_entries() {
    let limits = limits();

    let unknown_flags = [SourceRegistrationHive {
        name: "Machine",
        root_guid: MACHINE_GUID,
        flags: RSI_HIVE_PRIVATE | 0x04,
        scope_guid: SCOPE_A,
    }];
    assert_eq!(
        validate_source_registration(&limits, &[], &request(&unknown_flags, 0)),
        Err(LcsError::UnknownHiveFlags {
            flags: RSI_HIVE_PRIVATE | 0x04,
            unknown: 0x04,
        })
    );

    let global_with_scope = [SourceRegistrationHive {
        name: "Machine",
        root_guid: MACHINE_GUID,
        flags: 0,
        scope_guid: SCOPE_A,
    }];
    assert_eq!(
        validate_source_registration(&limits, &[], &request(&global_with_scope, 0)),
        Err(LcsError::GlobalHiveHasScopeGuid)
    );

    assert_eq!(
        validate_source_registration(
            &limits,
            &[],
            &request(&[global_hive("Machine", NIL_GUID)], 0)
        ),
        Err(LcsError::NilHiveRootGuid)
    );

    let duplicate_root = [
        global_hive("Machine", MACHINE_GUID),
        global_hive("Users", MACHINE_GUID),
    ];
    assert_eq!(
        validate_source_registration(&limits, &[], &request(&duplicate_root, 0)),
        Err(LcsError::DuplicateHiveRootGuid)
    );

    let duplicate_global = [
        global_hive("Machine", MACHINE_GUID),
        global_hive("machine", USERS_GUID),
    ];
    assert_eq!(
        validate_source_registration(&limits, &[], &request(&duplicate_global, 0)),
        Err(LcsError::DuplicateHiveIdentity)
    );

    assert_eq!(
        validate_source_registration(
            &limits,
            &[],
            &request(&[global_hive("CurrentUser", MACHINE_GUID)], 0),
        ),
        Err(LcsError::ReservedHiveName)
    );
}

#[test]
fn source_registration_rejects_active_slot_collisions() {
    let limits = limits();
    let existing_hives = [existing_global("Machine", MACHINE_GUID)];
    let existing = [SourceSlotView {
        source_id: 7,
        status: SourceSlotStatus::Active,
        hives: &existing_hives,
    }];
    let requested = [global_hive("machine", USERS_GUID)];

    assert_eq!(
        validate_source_registration(&limits, &existing, &request(&requested, 0)),
        Err(LcsError::HiveIdentityCollision)
    );
}

#[test]
fn source_registration_fails_closed_on_inconsistent_existing_slots() {
    let limits = limits();
    let first_hives = [existing_global("Machine", MACHINE_GUID)];
    let duplicate_name_hives = [existing_global("machine", USERS_GUID)];
    let duplicate_root_hives = [existing_global("Users", MACHINE_GUID)];

    let duplicate_identity = [
        SourceSlotView {
            source_id: 1,
            status: SourceSlotStatus::Active,
            hives: &first_hives,
        },
        SourceSlotView {
            source_id: 2,
            status: SourceSlotStatus::Down,
            hives: &duplicate_name_hives,
        },
    ];
    assert_eq!(
        validate_source_registration(
            &limits,
            &duplicate_identity,
            &request(&[global_hive("Software", OTHER_GUID)], 0),
        ),
        Err(LcsError::DuplicateHiveIdentity)
    );

    let duplicate_root = [
        SourceSlotView {
            source_id: 1,
            status: SourceSlotStatus::Active,
            hives: &first_hives,
        },
        SourceSlotView {
            source_id: 2,
            status: SourceSlotStatus::Down,
            hives: &duplicate_root_hives,
        },
    ];
    assert_eq!(
        validate_source_registration(
            &limits,
            &duplicate_root,
            &request(&[global_hive("Software", OTHER_GUID)], 0),
        ),
        Err(LcsError::DuplicateHiveRootGuid)
    );
}

#[test]
fn source_registration_resumes_exact_down_slot_order_independently() {
    let mut limits = limits();
    limits.max_registered_sources = 1;
    let existing_hives = [
        existing_global("Machine", MACHINE_GUID),
        existing_private("Users", USERS_GUID, SCOPE_A),
    ];
    let existing = [SourceSlotView {
        source_id: 9,
        status: SourceSlotStatus::Down,
        hives: &existing_hives,
    }];
    let requested = [
        private_hive("users", USERS_GUID, SCOPE_A),
        global_hive("machine", MACHINE_GUID),
    ];

    assert_eq!(
        validate_source_registration(&limits, &existing, &request(&requested, 99)),
        Ok(SourceRegistrationPlan {
            decision: SourceRegistrationDecision::ResumeDownSlot(9),
            hive_count: 2,
            source_next_sequence: 100,
        })
    );
}

#[test]
fn source_registration_rejects_stale_and_partial_down_slot_resumes() {
    let limits = limits();
    let existing_hives = [
        existing_global("Machine", MACHINE_GUID),
        existing_private("Users", USERS_GUID, SCOPE_A),
    ];
    let existing = [SourceSlotView {
        source_id: 9,
        status: SourceSlotStatus::Down,
        hives: &existing_hives,
    }];

    assert_eq!(
        validate_source_registration(
            &limits,
            &existing,
            &request(&[global_hive("Machine", STALE_GUID)], 0),
        ),
        Err(LcsError::StaleSourceHiveIdentity)
    );

    assert_eq!(
        validate_source_registration(
            &limits,
            &existing,
            &request(&[global_hive("Machine", MACHINE_GUID)], 0),
        ),
        Err(LcsError::PartialSourceResume)
    );

    let extra_hive = [
        global_hive("Machine", MACHINE_GUID),
        private_hive("Users", USERS_GUID, SCOPE_A),
        private_hive("Users", PRIVATE_GUID, SCOPE_B),
    ];
    assert_eq!(
        validate_source_registration(&limits, &existing, &request(&extra_hive, 0)),
        Err(LcsError::PartialSourceResume)
    );
}

#[test]
fn source_registration_enforces_new_source_slot_cap_after_resume_check() {
    let mut limits = limits();
    limits.max_registered_sources = 1;
    let existing_hives = [existing_global("Machine", MACHINE_GUID)];
    let existing = [SourceSlotView {
        source_id: 1,
        status: SourceSlotStatus::Active,
        hives: &existing_hives,
    }];
    let requested = [global_hive("Users", USERS_GUID)];

    assert_eq!(
        validate_source_registration(&limits, &existing, &request(&requested, 0)),
        Err(LcsError::TooManyRegisteredSources { count: 2, max: 1 })
    );
}
