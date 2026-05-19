use lcs_core::{
    Guid, HiveRoute, HiveScope, HiveStatus, LcsError, LcsLimits, NIL_GUID, RegisteredHiveIdentity,
    SourceRegistrationDecision, SourceRegistrationHive, SourceRegistrationPlan,
    SourceRegistrationRequest, SourceSlotStatus, SourceSlotView, TransactionBinding,
    TransactionMutationBindingPlan, TransactionReadPlan, TransactionState, TransactionUseFailure,
    for_each_source_slot_hive, plan_transaction_mutation_binding, plan_transaction_read,
    route_hive, validate_source_registration,
};

const MACHINE_ROOT: Guid = [0x31; 16];
const USERS_ROOT: Guid = [0x32; 16];
const OTHER_ROOT: Guid = [0x33; 16];

fn source_hive(name: &str, root_guid: Guid) -> SourceRegistrationHive<'_> {
    SourceRegistrationHive {
        name,
        root_guid,
        flags: 0,
        scope_guid: NIL_GUID,
    }
}

fn request<'a>(hives: &'a [SourceRegistrationHive<'a>]) -> SourceRegistrationRequest<'a> {
    SourceRegistrationRequest {
        hives,
        max_sequence: 10,
        caller_has_tcb: true,
    }
}

fn registered(name: &str, root_guid: Guid) -> RegisteredHiveIdentity<'_> {
    RegisteredHiveIdentity {
        name,
        root_guid,
        scope: HiveScope::Global,
    }
}

fn binding(
    source_id: u32,
    hive_name: &'static str,
    hive_root_guid: Guid,
) -> TransactionBinding<'static> {
    TransactionBinding {
        source_id,
        hive_name,
        hive_root_guid,
    }
}

#[test]
fn one_source_may_back_multiple_unique_hives() {
    let limits = LcsLimits::default();
    let hives = [
        source_hive("Machine", MACHINE_ROOT),
        source_hive("Users", USERS_ROOT),
    ];

    assert_eq!(
        validate_source_registration(&limits, &[], &request(&hives)),
        Ok(SourceRegistrationPlan {
            decision: SourceRegistrationDecision::NewSlot,
            hive_count: 2,
            source_next_sequence: 11,
        })
    );
}

#[test]
fn hive_identity_collision_rejects_claims_by_another_source() {
    let limits = LcsLimits::default();
    let existing_hives = [registered("Machine", MACHINE_ROOT)];
    let existing = [SourceSlotView {
        source_id: 7,
        status: SourceSlotStatus::Active,
        hives: &existing_hives,
    }];
    let requested = [source_hive("machine", OTHER_ROOT)];

    assert_eq!(
        validate_source_registration(&limits, &existing, &request(&requested)),
        Err(LcsError::HiveIdentityCollision)
    );
}

#[test]
fn source_slot_projection_preserves_each_hive_single_source_owner() {
    let limits = LcsLimits::default();
    let registered_hives = [
        registered("Machine", MACHINE_ROOT),
        registered("Users", USERS_ROOT),
    ];
    let slots = [SourceSlotView {
        source_id: 42,
        status: SourceSlotStatus::Active,
        hives: &registered_hives,
    }];
    let mut projected = Vec::new();

    let count = for_each_source_slot_hive(&limits, &slots, |hive| {
        projected.push((hive.name, hive.source_id, hive.root_guid, hive.status));
        Ok(())
    })
    .expect("valid source slot should project hives");

    assert_eq!(count, 2);
    assert_eq!(
        projected,
        vec![
            ("Machine", 42, MACHINE_ROOT, HiveStatus::Active),
            ("Users", 42, USERS_ROOT, HiveStatus::Active),
        ]
    );

    let projected_hives = projected_hives(&projected);
    match route_hive(&limits, &projected_hives, "Machine", &[]) {
        Ok(HiveRoute::Active(hive)) => {
            assert_eq!(hive.source_id, 42);
            assert_eq!(hive.root_guid, MACHINE_ROOT);
        }
        other => panic!("expected active Machine hive, got {other:?}"),
    }
}

#[test]
fn transaction_binding_is_single_hive_even_when_source_backs_multiple_hives() {
    let limits = LcsLimits::default();
    let machine = binding(42, "Machine", MACHINE_ROOT);
    let users_same_source = binding(42, "Users", USERS_ROOT);

    assert_eq!(
        plan_transaction_mutation_binding(
            &limits,
            TransactionState::ActiveUnbound,
            machine,
            true,
            0,
        ),
        Ok(TransactionMutationBindingPlan::BindNew(machine))
    );
    assert_eq!(
        plan_transaction_mutation_binding(
            &limits,
            TransactionState::ActiveBound(machine),
            users_same_source,
            true,
            0,
        ),
        Err(TransactionUseFailure::CrossHive)
    );
    assert_eq!(
        plan_transaction_read(
            &limits,
            TransactionState::ActiveBound(machine),
            users_same_source,
        ),
        Err(TransactionUseFailure::CrossHive)
    );
    assert_eq!(
        plan_transaction_read(&limits, TransactionState::ActiveUnbound, users_same_source),
        Ok(TransactionReadPlan::NonTransactional)
    );
}

fn projected_hives<'a>(
    projected: &'a [(&'a str, u32, Guid, HiveStatus)],
) -> Vec<lcs_core::HiveView<'a>> {
    projected
        .iter()
        .map(|(name, source_id, root_guid, status)| lcs_core::HiveView {
            name,
            root_guid: *root_guid,
            source_id: *source_id,
            status: *status,
            scope: HiveScope::Global,
        })
        .collect()
}
