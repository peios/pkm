use lcs_core::{
    DeleteKeyInput, Guid, HideKeyInput, KEY_CREATE_SUB_KEY, KeyCreateRecordsRequest,
    KeyFdNamespaceView, KeyPathMutationInput, LcsError, LcsLimits, PathTarget, REG_OPTION_VOLATILE,
    SequenceCounter, TransactionMutationLogKind, TransactionOperationIndexCounter,
    plan_key_create_records, plan_key_create_transaction_log_entry, plan_key_delete,
    plan_key_delete_transaction_log_entry, plan_key_hide, plan_key_hide_transaction_log_entry,
};

const ROOT_GUID: Guid = [0x10; 16];
const PARENT_GUID: Guid = [0x20; 16];
const CHILD_GUID: Guid = [0x30; 16];
const OTHER_GUID: Guid = [0x40; 16];
static CHILD_ANCESTORS: [Guid; 3] = [ROOT_GUID, PARENT_GUID, CHILD_GUID];

fn child_fd<'a>(path: &'a [&'a str]) -> KeyFdNamespaceView<'a> {
    KeyFdNamespaceView {
        resolved_path: path,
        ancestor_guids: &CHILD_ANCESTORS,
        orphaned: false,
    }
}

fn create_request<'a>(layer: &'a str) -> KeyCreateRecordsRequest<'a> {
    KeyCreateRecordsRequest {
        parent_guid: PARENT_GUID,
        parent_is_volatile: false,
        parent_granted_access: KEY_CREATE_SUB_KEY,
        child_name: "Child",
        candidate_guid: CHILD_GUID,
        active_key_guids: &[],
        retired_key_guids: &[],
        layer,
        flags: REG_OPTION_VOLATILE,
        caller_has_tcb_or_admin: false,
    }
}

#[test]
fn key_create_log_entry_preserves_path_target_sequence_and_commit_effects() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(77);
    let plan = plan_key_create_records(&limits, &mut sequence_counter, &create_request("policy"))
        .expect("create record plan");
    let mut operation_counter = TransactionOperationIndexCounter::new();

    let entry = plan_key_create_transaction_log_entry(&limits, &plan, &mut operation_counter)
        .expect("create transaction log entry");

    assert_eq!(entry.operation_index, 1);
    assert_eq!(operation_counter.next_index(), 2);
    assert_eq!(entry.kind, TransactionMutationLogKind::CreateKey);
    assert_eq!(entry.parent_guid, PARENT_GUID);
    assert_eq!(entry.child_name, "Child");
    assert_eq!(entry.layer, "policy");
    assert_eq!(entry.target_guid, Some(CHILD_GUID));
    assert_eq!(entry.sequence, Some(77));
    assert!(entry.update_hive_generation_on_commit);
    assert!(!entry.update_parent_last_write_time_on_commit);
    assert!(entry.recompute_effective_subkey_events_on_commit);
    assert!(!entry.evaluate_orphaning_on_commit);
    assert!(entry.publish_new_key_guid_on_commit);
}

#[test]
fn delete_and_hide_log_entries_capture_path_layer_sequence_and_orphan_shape() {
    let limits = LcsLimits::default();
    let path = ["Machine", "Parent", "Child"];
    let mutation = KeyPathMutationInput {
        fd: child_fd(&path),
        layer: "base",
    };
    let delete = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation,
            visible_child_count: 0,
        },
    )
    .expect("delete plan");
    let mut operation_counter = TransactionOperationIndexCounter::new();

    let delete_entry =
        plan_key_delete_transaction_log_entry(&limits, &delete, &mut operation_counter)
            .expect("delete transaction log entry");
    assert_eq!(delete_entry.operation_index, 1);
    assert_eq!(delete_entry.kind, TransactionMutationLogKind::DeleteKey);
    assert_eq!(delete_entry.parent_guid, PARENT_GUID);
    assert_eq!(delete_entry.child_name, "Child");
    assert_eq!(delete_entry.layer, "base");
    assert_eq!(delete_entry.target_guid, None);
    assert_eq!(delete_entry.sequence, None);
    assert!(delete_entry.update_hive_generation_on_commit);
    assert!(delete_entry.update_parent_last_write_time_on_commit);
    assert!(delete_entry.recompute_effective_subkey_events_on_commit);
    assert!(delete_entry.evaluate_orphaning_on_commit);
    assert!(!delete_entry.publish_new_key_guid_on_commit);

    let mut sequence_counter = SequenceCounter::new(88);
    let hide = plan_key_hide(&limits, &mut sequence_counter, &HideKeyInput { mutation })
        .expect("hide plan");
    let hide_entry = plan_key_hide_transaction_log_entry(&limits, &hide, &mut operation_counter)
        .expect("hide transaction log entry");
    assert_eq!(hide_entry.operation_index, 2);
    assert_eq!(hide_entry.kind, TransactionMutationLogKind::HideKey);
    assert_eq!(hide_entry.parent_guid, PARENT_GUID);
    assert_eq!(hide_entry.child_name, "Child");
    assert_eq!(hide_entry.layer, "base");
    assert_eq!(hide_entry.target_guid, None);
    assert_eq!(hide_entry.sequence, Some(88));
    assert!(hide_entry.update_hive_generation_on_commit);
    assert!(!hide_entry.update_parent_last_write_time_on_commit);
    assert!(hide_entry.recompute_effective_subkey_events_on_commit);
    assert!(!hide_entry.evaluate_orphaning_on_commit);
    assert!(!hide_entry.publish_new_key_guid_on_commit);
}

#[test]
fn corrupt_key_path_side_effects_fail_before_operation_index_allocation() {
    let limits = LcsLimits::default();
    let path = ["Machine", "Parent", "Child"];
    let mutation = KeyPathMutationInput {
        fd: child_fd(&path),
        layer: "base",
    };
    let mut delete = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation,
            visible_child_count: 0,
        },
    )
    .expect("delete plan");
    delete.effects.preserves_key_data = false;
    let mut operation_counter = TransactionOperationIndexCounter::new();

    assert_eq!(
        plan_key_delete_transaction_log_entry(&limits, &delete, &mut operation_counter),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "delete_key.effects",
        })
    );
    assert_eq!(operation_counter.next_index(), 1);

    let mut sequence_counter = SequenceCounter::new(1);
    let mut hide = plan_key_hide(&limits, &mut sequence_counter, &HideKeyInput { mutation })
        .expect("hide plan");
    hide.masks_lower_layers = false;
    assert_eq!(
        plan_key_hide_transaction_log_entry(&limits, &hide, &mut operation_counter),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "masks_lower_layers",
        })
    );
    assert_eq!(operation_counter.next_index(), 1);
}

#[test]
fn mismatched_create_records_fail_before_operation_index_allocation() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(1);
    let mut plan = plan_key_create_records(&limits, &mut sequence_counter, &create_request("base"))
        .expect("create record plan");
    plan.path_entry.target = PathTarget::Guid(OTHER_GUID);
    let mut operation_counter = TransactionOperationIndexCounter::new();

    assert_eq!(
        plan_key_create_transaction_log_entry(&limits, &plan, &mut operation_counter),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_create.records",
        })
    );
    assert_eq!(operation_counter.next_index(), 1);
}

#[test]
fn operation_index_exhaustion_prevents_key_path_log_entry() {
    let limits = LcsLimits::default();
    let path = ["Machine", "Parent", "Child"];
    let delete = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(&path),
                layer: "base",
            },
            visible_child_count: 0,
        },
    )
    .expect("delete plan");
    let mut operation_counter = TransactionOperationIndexCounter::from_next_index(u64::MAX)
        .expect("maximum next operation index is representable until allocation");

    assert_eq!(
        plan_key_delete_transaction_log_entry(&limits, &delete, &mut operation_counter),
        Err(LcsError::TransactionOperationIndexOverflow)
    );
    assert_eq!(operation_counter.next_index(), u64::MAX);
}
