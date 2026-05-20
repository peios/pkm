use lcs_core::{
    BlanketTombstoneInput, Guid, LcsError, LcsLimits, NIL_GUID, REG_SZ, SequenceCounter,
    TransactionMutationLogKind, TransactionOperationIndexCounter, ValueDeleteRequest,
    ValueWriteInput, WatchAncestryContext, plan_blanket_tombstone,
    plan_blanket_tombstone_transaction_log_entry, plan_value_delete,
    plan_value_delete_transaction_log_entry, plan_value_write,
    plan_value_write_transaction_log_entry,
};

const ROOT_GUID: Guid = [0x24; 16];
const KEY_GUID: Guid = [
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
];
const KEY_ANCESTORS: [Guid; 2] = [ROOT_GUID, KEY_GUID];
const KEY_PATH: [&str; 2] = ["Machine", "Policy"];

fn value_watch_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &KEY_ANCESTORS,
        path_components: &KEY_PATH,
    }
}

#[test]
fn value_write_log_entry_preserves_value_layer_sequence_and_commit_effects() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(42);
    let planned = plan_value_write(
        &limits,
        &mut sequence_counter,
        &ValueWriteInput {
            key_guid: KEY_GUID,
            name: "Setting",
            layer: "base",
            value_type: REG_SZ,
            data: b"enabled",
            explicit_tombstone_operation: false,
            expected_sequence: Some(7),
        },
    )
    .expect("value write plan");
    let mut operation_counter = TransactionOperationIndexCounter::new();

    let entry = plan_value_write_transaction_log_entry(
        &limits,
        &planned,
        value_watch_context(),
        &mut operation_counter,
    )
    .expect("value write transaction log entry");

    assert_eq!(entry.operation_index, 1);
    assert_eq!(operation_counter.next_index(), 2);
    assert_eq!(entry.kind, TransactionMutationLogKind::SetValue);
    assert_eq!(entry.key_guid, KEY_GUID);
    assert_eq!(entry.watch_context, value_watch_context());
    assert_eq!(entry.value_name, Some("Setting"));
    assert_eq!(entry.layer, "base");
    assert_eq!(entry.sequence, Some(42));
    assert!(entry.update_hive_generation_on_commit);
    assert!(entry.update_last_write_time_on_commit);
    assert!(entry.recompute_effective_value_events_on_commit);
}

#[test]
fn delete_and_blanket_log_entries_capture_layer_and_sequence_shape() {
    let limits = LcsLimits::default();
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let delete = plan_value_delete(
        &limits,
        &ValueDeleteRequest {
            key_guid: KEY_GUID,
            name: "Setting",
            layer: "base",
        },
    )
    .expect("delete plan");
    let delete_entry = plan_value_delete_transaction_log_entry(
        &limits,
        &delete,
        value_watch_context(),
        &mut operation_counter,
    )
    .expect("delete transaction log entry");
    assert_eq!(delete_entry.operation_index, 1);
    assert_eq!(delete_entry.kind, TransactionMutationLogKind::DeleteValue);
    assert_eq!(delete_entry.value_name, Some("Setting"));
    assert_eq!(delete_entry.layer, "base");
    assert_eq!(delete_entry.sequence, None);

    let mut sequence_counter = SequenceCounter::new(99);
    let blanket_set = plan_blanket_tombstone(
        &limits,
        &mut sequence_counter,
        &BlanketTombstoneInput {
            key_guid: KEY_GUID,
            layer: "policy",
            set: true,
        },
    )
    .expect("blanket set plan");
    let set_entry = plan_blanket_tombstone_transaction_log_entry(
        &limits,
        &blanket_set,
        value_watch_context(),
        &mut operation_counter,
    )
    .expect("blanket set transaction log entry");
    assert_eq!(set_entry.operation_index, 2);
    assert_eq!(set_entry.kind, TransactionMutationLogKind::BlanketTombstone);
    assert_eq!(set_entry.value_name, None);
    assert_eq!(set_entry.layer, "policy");
    assert_eq!(set_entry.sequence, Some(99));

    let blanket_remove = plan_blanket_tombstone(
        &limits,
        &mut sequence_counter,
        &BlanketTombstoneInput {
            key_guid: KEY_GUID,
            layer: "policy",
            set: false,
        },
    )
    .expect("blanket remove plan");
    let remove_entry = plan_blanket_tombstone_transaction_log_entry(
        &limits,
        &blanket_remove,
        value_watch_context(),
        &mut operation_counter,
    )
    .expect("blanket remove transaction log entry");
    assert_eq!(remove_entry.operation_index, 3);
    assert_eq!(
        remove_entry.kind,
        TransactionMutationLogKind::BlanketTombstone
    );
    assert_eq!(remove_entry.value_name, None);
    assert_eq!(remove_entry.layer, "policy");
    assert_eq!(remove_entry.sequence, None);
}

#[test]
fn corrupt_value_side_effect_flags_fail_before_operation_index_allocation() {
    let limits = LcsLimits::default();
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let mut delete = plan_value_delete(
        &limits,
        &ValueDeleteRequest {
            key_guid: KEY_GUID,
            name: "Setting",
            layer: "base",
        },
    )
    .expect("delete plan");
    delete.updates_last_write_time = false;

    assert_eq!(
        plan_value_delete_transaction_log_entry(
            &limits,
            &delete,
            value_watch_context(),
            &mut operation_counter,
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "updates_last_write_time",
        })
    );
    assert_eq!(operation_counter.next_index(), 1);

    let mut sequence_counter = SequenceCounter::new(1);
    let mut blanket = plan_blanket_tombstone(
        &limits,
        &mut sequence_counter,
        &BlanketTombstoneInput {
            key_guid: KEY_GUID,
            layer: "base",
            set: true,
        },
    )
    .expect("blanket plan");
    blanket.recomputes_effective_value_events = false;

    assert_eq!(
        plan_blanket_tombstone_transaction_log_entry(
            &limits,
            &blanket,
            value_watch_context(),
            &mut operation_counter,
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "recomputes_effective_value_events",
        })
    );
    assert_eq!(operation_counter.next_index(), 1);
}

#[test]
fn invalid_value_log_metadata_reuses_value_validation_before_allocation() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(1);
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let mut planned = plan_value_write(
        &limits,
        &mut sequence_counter,
        &ValueWriteInput {
            key_guid: KEY_GUID,
            name: "Setting",
            layer: "base",
            value_type: REG_SZ,
            data: b"enabled",
            explicit_tombstone_operation: false,
            expected_sequence: None,
        },
    )
    .expect("value write plan");
    planned.write.key_guid = NIL_GUID;

    assert_eq!(
        plan_value_write_transaction_log_entry(
            &limits,
            &planned,
            value_watch_context(),
            &mut operation_counter,
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(operation_counter.next_index(), 1);
}

#[test]
fn operation_index_exhaustion_prevents_value_log_entry() {
    let limits = LcsLimits::default();
    let delete = plan_value_delete(
        &limits,
        &ValueDeleteRequest {
            key_guid: KEY_GUID,
            name: "Setting",
            layer: "base",
        },
    )
    .expect("delete plan");
    let mut operation_counter = TransactionOperationIndexCounter::from_next_index(u64::MAX)
        .expect("maximum next operation index is representable until allocation");

    assert_eq!(
        plan_value_delete_transaction_log_entry(
            &limits,
            &delete,
            value_watch_context(),
            &mut operation_counter,
        ),
        Err(LcsError::TransactionOperationIndexOverflow)
    );
    assert_eq!(operation_counter.next_index(), u64::MAX);
}
