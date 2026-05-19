use lcs_core::{
    BlanketTombstoneAction, BlanketTombstoneInput, Guid, LcsError, LcsLimits, NIL_GUID,
    SequenceCounter, ValueDeleteRequest, plan_blanket_tombstone, plan_value_delete,
};

const KEY_GUID: Guid = [0x18; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

#[test]
fn value_delete_planner_validates_shape_and_marks_last_write_update() {
    let limits = limits();
    let planned = plan_value_delete(
        &limits,
        &ValueDeleteRequest {
            key_guid: KEY_GUID,
            name: "Setting",
            layer: "base",
        },
    )
    .expect("delete should plan");

    assert_eq!(planned.delete.key_guid, KEY_GUID);
    assert_eq!(planned.delete.name, "Setting");
    assert_eq!(planned.delete.layer, "base");
    assert!(planned.updates_last_write_time);
}

#[test]
fn blanket_tombstone_set_allocates_sequence_and_marks_side_effects() {
    let limits = limits();
    let mut counter = SequenceCounter::new(80);
    let planned = plan_blanket_tombstone(
        &limits,
        &mut counter,
        &BlanketTombstoneInput {
            key_guid: KEY_GUID,
            layer: "policy",
            set: true,
        },
    )
    .expect("blanket set should plan");

    assert_eq!(planned.blanket.key_guid, KEY_GUID);
    assert_eq!(planned.blanket.layer, "policy");
    assert_eq!(
        planned.blanket.action,
        BlanketTombstoneAction::Set { sequence: 80 }
    );
    assert!(planned.updates_last_write_time);
    assert!(planned.recomputes_effective_value_events);
    assert_eq!(counter.next_sequence(), 81);
}

#[test]
fn blanket_tombstone_remove_does_not_allocate_sequence() {
    let limits = limits();
    let mut counter = SequenceCounter::new(80);
    let planned = plan_blanket_tombstone(
        &limits,
        &mut counter,
        &BlanketTombstoneInput {
            key_guid: KEY_GUID,
            layer: "policy",
            set: false,
        },
    )
    .expect("blanket remove should plan");

    assert_eq!(planned.blanket.action, BlanketTombstoneAction::Remove);
    assert!(planned.updates_last_write_time);
    assert!(planned.recomputes_effective_value_events);
    assert_eq!(counter.next_sequence(), 80);
}

#[test]
fn blanket_tombstone_set_fails_closed_on_sequence_overflow() {
    let limits = limits();
    let mut counter = SequenceCounter::new(u64::MAX);

    assert_eq!(
        plan_blanket_tombstone(
            &limits,
            &mut counter,
            &BlanketTombstoneInput {
                key_guid: KEY_GUID,
                layer: "base",
                set: true,
            },
        ),
        Err(LcsError::SequenceOverflow)
    );
    assert_eq!(counter.next_sequence(), u64::MAX);
}

#[test]
fn malformed_blanket_tombstones_do_not_consume_sequence() {
    let limits = limits();
    let mut counter = SequenceCounter::new(9);

    assert_eq!(
        plan_blanket_tombstone(
            &limits,
            &mut counter,
            &BlanketTombstoneInput {
                key_guid: NIL_GUID,
                layer: "base",
                set: true,
            },
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(counter.next_sequence(), 9);

    assert_eq!(
        plan_blanket_tombstone(
            &limits,
            &mut counter,
            &BlanketTombstoneInput {
                key_guid: KEY_GUID,
                layer: "bad/layer",
                set: true,
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
    assert_eq!(counter.next_sequence(), 9);
}
