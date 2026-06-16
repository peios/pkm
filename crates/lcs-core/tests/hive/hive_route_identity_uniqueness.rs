use crate::common::{limits};
use lcs_core::{
    Guid, HiveScope, LcsError, NIL_GUID, RSI_HIVE_PRIVATE, RegisteredHiveIdentity,
    SourceRegistrationDecision, SourceRegistrationHive, SourceRegistrationPlan,
    SourceRegistrationRequest, SourceSlotStatus, SourceSlotView, validate_source_registration,
};

const GLOBAL_ROOT: Guid = [0x20; 16];
const PRIVATE_A_ROOT: Guid = [0x21; 16];
const PRIVATE_B_ROOT: Guid = [0x22; 16];
const OTHER_ROOT: Guid = [0x23; 16];
const SCOPE_A: Guid = [0xa1; 16];
const SCOPE_B: Guid = [0xb2; 16];


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

fn active_slot<'a>(source_id: u32, hives: &'a [RegisteredHiveIdentity<'a>]) -> SourceSlotView<'a> {
    SourceSlotView {
        source_id,
        status: SourceSlotStatus::Active,
        hives,
    }
}

#[test]
fn same_folded_hive_name_is_allowed_in_distinct_route_scopes() {
    let limits = limits();
    let global_hives = [existing_global("Machine", GLOBAL_ROOT)];
    let existing_global_slot = [active_slot(1, &global_hives)];
    let requested_private = [private_hive("machine", PRIVATE_A_ROOT, SCOPE_A)];

    assert_eq!(
        validate_source_registration(
            &limits,
            &existing_global_slot,
            &request(&requested_private, 9)
        ),
        Ok(SourceRegistrationPlan {
            decision: SourceRegistrationDecision::NewSlot,
            hive_count: 1,
            source_next_sequence: 10,
        })
    );

    let private_a_hives = [existing_private("Machine", PRIVATE_A_ROOT, SCOPE_A)];
    let existing_private_slot = [active_slot(2, &private_a_hives)];
    let requested_private_b = [private_hive("machine", PRIVATE_B_ROOT, SCOPE_B)];

    assert_eq!(
        validate_source_registration(
            &limits,
            &existing_private_slot,
            &request(&requested_private_b, 10),
        ),
        Ok(SourceRegistrationPlan {
            decision: SourceRegistrationDecision::NewSlot,
            hive_count: 1,
            source_next_sequence: 11,
        })
    );
}

#[test]
fn same_folded_hive_name_is_rejected_inside_the_same_route_scope() {
    let limits = limits();
    let global_hives = [existing_global("Machine", GLOBAL_ROOT)];
    let existing_global_slot = [active_slot(1, &global_hives)];
    let duplicate_global = [global_hive("machine", OTHER_ROOT)];

    assert_eq!(
        validate_source_registration(
            &limits,
            &existing_global_slot,
            &request(&duplicate_global, 0)
        ),
        Err(LcsError::HiveIdentityCollision)
    );

    let private_a_hives = [existing_private("Machine", PRIVATE_A_ROOT, SCOPE_A)];
    let existing_private_slot = [active_slot(2, &private_a_hives)];
    let duplicate_private = [private_hive("machine", OTHER_ROOT, SCOPE_A)];

    assert_eq!(
        validate_source_registration(
            &limits,
            &existing_private_slot,
            &request(&duplicate_private, 0),
        ),
        Err(LcsError::HiveIdentityCollision)
    );
}

#[test]
fn one_registration_request_rejects_duplicate_route_identities_but_allows_shadowing() {
    let limits = limits();
    let valid_shadowing_request = [
        global_hive("Machine", GLOBAL_ROOT),
        private_hive("machine", PRIVATE_A_ROOT, SCOPE_A),
        private_hive("machine", PRIVATE_B_ROOT, SCOPE_B),
    ];

    assert_eq!(
        validate_source_registration(&limits, &[], &request(&valid_shadowing_request, 0)),
        Ok(SourceRegistrationPlan {
            decision: SourceRegistrationDecision::NewSlot,
            hive_count: 3,
            source_next_sequence: 1,
        })
    );

    let duplicate_private_scope = [
        private_hive("Machine", PRIVATE_A_ROOT, SCOPE_A),
        private_hive("machine", OTHER_ROOT, SCOPE_A),
    ];

    assert_eq!(
        validate_source_registration(&limits, &[], &request(&duplicate_private_scope, 0)),
        Err(LcsError::DuplicateHiveIdentity)
    );
}
