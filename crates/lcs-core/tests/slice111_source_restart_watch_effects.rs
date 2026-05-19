use lcs_core::{
    Guid, HiveScope, LcsError, LcsLimits, NIL_GUID, RegisteredHiveIdentity,
    SourceRegistrationDecision, SourceRegistrationHive, SourceRegistrationLifecycleEffects,
    SourceRegistrationPlan, SourceRegistrationRequest, SourceRoundTripPlan, SourceSlotStatus,
    SourceSlotView, plan_source_disconnect, plan_source_registration_lifecycle_effects,
    plan_source_round_trip, validate_source_registration,
};

const MACHINE_GUID: Guid = [0x10; 16];
const USERS_GUID: Guid = [0x11; 16];

fn global_hive<'a>(name: &'a str, root_guid: Guid) -> SourceRegistrationHive<'a> {
    SourceRegistrationHive {
        name,
        root_guid,
        flags: 0,
        scope_guid: NIL_GUID,
    }
}

fn existing_global<'a>(name: &'a str, root_guid: Guid) -> RegisteredHiveIdentity<'a> {
    RegisteredHiveIdentity {
        name,
        root_guid,
        scope: HiveScope::Global,
    }
}

fn request<'a>(hives: &'a [SourceRegistrationHive<'a>]) -> SourceRegistrationRequest<'a> {
    SourceRegistrationRequest {
        hives,
        max_sequence: 50,
        caller_has_tcb: true,
    }
}

#[test]
fn source_disconnect_keeps_watches_armed_without_overflow_until_reregistration() {
    let plan = plan_source_disconnect();

    assert!(plan.mark_hives_unavailable);
    assert!(plan.fail_pending_requests_with_eio);
    assert!(plan.keep_key_fds_valid);
    assert!(plan.source_round_trips_return_eio);
    assert!(plan.mark_bound_transactions_source_down);
    assert!(plan.wake_transaction_pollers);
    assert!(plan.keep_watches_armed);
    assert!(!plan.deliver_watch_overflow);
}

#[test]
fn source_round_trips_dispatch_only_while_slot_is_active() {
    assert_eq!(
        plan_source_round_trip(SourceSlotStatus::Active),
        Ok(SourceRoundTripPlan {
            dispatch_to_source: true,
        })
    );
    assert_eq!(
        plan_source_round_trip(SourceSlotStatus::Down),
        Err(LcsError::HiveSourceUnavailable)
    );
}

#[test]
fn new_source_registration_does_not_deliver_restart_overflow() {
    let registration = SourceRegistrationPlan {
        decision: SourceRegistrationDecision::NewSlot,
        hive_count: 1,
        source_next_sequence: 51,
    };

    assert_eq!(
        plan_source_registration_lifecycle_effects(registration),
        SourceRegistrationLifecycleEffects {
            resumed_source_id: None,
            mark_hives_active: true,
            deliver_overflow_to_affected_watches: false,
            existing_fds_resume: false,
        }
    );
}

#[test]
fn exact_down_slot_resume_reactivates_hives_and_delivers_overflow_to_affected_watches() {
    let limits = LcsLimits::default();
    let existing_hives = [
        existing_global("Machine", MACHINE_GUID),
        existing_global("Users", USERS_GUID),
    ];
    let down_slot = [SourceSlotView {
        source_id: 17,
        status: SourceSlotStatus::Down,
        hives: &existing_hives,
    }];
    let requested = [
        global_hive("users", USERS_GUID),
        global_hive("machine", MACHINE_GUID),
    ];
    let registration = validate_source_registration(&limits, &down_slot, &request(&requested))
        .expect("exact Down slot registration should resume");

    assert_eq!(
        registration.decision,
        SourceRegistrationDecision::ResumeDownSlot(17)
    );
    assert_eq!(
        plan_source_registration_lifecycle_effects(registration),
        SourceRegistrationLifecycleEffects {
            resumed_source_id: Some(17),
            mark_hives_active: true,
            deliver_overflow_to_affected_watches: true,
            existing_fds_resume: true,
        }
    );
}
