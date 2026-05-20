use lcs_core::{
    DeleteKeyInput, Guid, KEY_CREATE_SUB_KEY, KeyCreateRecordsRequest, KeyFdNamespaceView,
    KeyPathMutationInput, LcsError, LcsLimits, NIL_GUID, REG_OPTION_VOLATILE, REG_SZ,
    SequenceCounter, TransactionMutationLogKind, TransactionMutationLogRecord,
    TransactionOperationIndexCounter, TransactionReplayWatchInput, ValueWriteInput,
    WatchAncestryContext, plan_key_create_records, plan_key_create_transaction_log_entry,
    plan_key_delete, plan_key_delete_transaction_log_entry, plan_value_write,
    plan_value_write_transaction_log_entry, transaction_mutation_log_record_watch_replay_input,
};

const ROOT_GUID: Guid = [0x10; 16];
const PARENT_GUID: Guid = [0x20; 16];
const CHILD_GUID: Guid = [0x30; 16];
const KEY_GUID: Guid = [0x40; 16];
const OTHER_GUID: Guid = [0x50; 16];
const KEY_ANCESTORS: [Guid; 2] = [ROOT_GUID, KEY_GUID];
const KEY_PATH: [&str; 2] = ["Machine", "Policy"];
const PARENT_ANCESTORS: [Guid; 2] = [ROOT_GUID, PARENT_GUID];
const PARENT_PATH: [&str; 2] = ["Machine", "Parent"];
const CHILD_ANCESTORS: [Guid; 3] = [ROOT_GUID, PARENT_GUID, CHILD_GUID];
const CHILD_PATH: [&str; 3] = ["Machine", "Parent", "Child"];

fn value_watch_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &KEY_ANCESTORS,
        path_components: &KEY_PATH,
    }
}

fn parent_watch_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: PARENT_GUID,
        ancestor_guids: &PARENT_ANCESTORS,
        path_components: &PARENT_PATH,
    }
}

fn child_visibility_watch_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: CHILD_GUID,
        ancestor_guids: &CHILD_ANCESTORS,
        path_components: &CHILD_PATH,
    }
}

fn child_fd() -> KeyFdNamespaceView<'static> {
    KeyFdNamespaceView {
        resolved_path: &CHILD_PATH,
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
fn value_log_entry_rejects_context_for_different_key_before_allocation() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(1);
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
            expected_sequence: None,
        },
    )
    .expect("value write plan");
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let wrong_context = WatchAncestryContext {
        changed_key_guid: OTHER_GUID,
        ancestor_guids: &[ROOT_GUID, OTHER_GUID],
        path_components: &["Machine", "Other"],
    };

    assert_eq!(
        plan_value_write_transaction_log_entry(
            &limits,
            &planned,
            wrong_context,
            &mut operation_counter,
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.watch_context.changed_key_guid",
        })
    );
    assert_eq!(operation_counter.next_index(), 1);
}

#[test]
fn value_log_entry_rejects_nil_context_guid_before_allocation() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(1);
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
            expected_sequence: None,
        },
    )
    .expect("value write plan");
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let nil_context = WatchAncestryContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &[NIL_GUID, KEY_GUID],
        path_components: &["Machine", "Policy"],
    };

    assert_eq!(
        plan_value_write_transaction_log_entry(
            &limits,
            &planned,
            nil_context,
            &mut operation_counter
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.watch_context",
        })
    );
    assert_eq!(operation_counter.next_index(), 1);
}

#[test]
fn key_create_log_entry_rejects_context_for_different_parent_before_allocation() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(10);
    let planned =
        plan_key_create_records(&limits, &mut sequence_counter, &create_request("policy"))
            .expect("create records plan");
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let wrong_parent_context = WatchAncestryContext {
        changed_key_guid: ROOT_GUID,
        ancestor_guids: &[ROOT_GUID],
        path_components: &["Machine"],
    };

    assert_eq!(
        plan_key_create_transaction_log_entry(
            &limits,
            &planned,
            wrong_parent_context,
            &mut operation_counter,
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_path.parent_watch_context.changed_key_guid",
        })
    );
    assert_eq!(operation_counter.next_index(), 1);
}

#[test]
fn key_delete_replay_input_preserves_parent_and_child_fd_contexts() {
    let limits = LcsLimits::default();
    let planned = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(),
                layer: "base",
            },
            visible_child_count: 0,
        },
    )
    .expect("delete key plan");
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let entry = plan_key_delete_transaction_log_entry(&limits, &planned, &mut operation_counter)
        .expect("delete log entry");

    assert_eq!(entry.parent_watch_context, parent_watch_context());
    assert_eq!(
        entry.child_visibility_watch_context,
        Some(child_visibility_watch_context())
    );
    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(
            &limits,
            &TransactionMutationLogRecord::KeyPath(entry),
        ),
        Ok(TransactionReplayWatchInput::EffectiveSubkey {
            operation_index: 1,
            kind: TransactionMutationLogKind::DeleteKey,
            parent_guid: PARENT_GUID,
            parent_watch_context: parent_watch_context(),
            child_visibility_watch_context: Some(child_visibility_watch_context()),
            child_name: "Child",
            layer: "base",
            target_guid: None,
            sequence: None,
            requires_before_snapshot: true,
            requires_after_snapshot: true,
            evaluate_orphaning: true,
            publish_new_key_guid: false,
        })
    );
}

#[test]
fn delete_log_entry_missing_child_visibility_context_fails_closed() {
    let limits = LcsLimits::default();
    let planned = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(),
                layer: "base",
            },
            visible_child_count: 0,
        },
    )
    .expect("delete key plan");
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let mut entry =
        plan_key_delete_transaction_log_entry(&limits, &planned, &mut operation_counter)
            .expect("delete log entry");
    entry.child_visibility_watch_context = None;

    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(
            &limits,
            &TransactionMutationLogRecord::KeyPath(entry),
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "delete_key.shape",
        })
    );
}

#[test]
fn delete_log_entry_child_visibility_context_must_extend_parent_context() {
    let limits = LcsLimits::default();
    let planned = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(),
                layer: "base",
            },
            visible_child_count: 0,
        },
    )
    .expect("delete key plan");
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let mut entry =
        plan_key_delete_transaction_log_entry(&limits, &planned, &mut operation_counter)
            .expect("delete log entry");
    entry.child_visibility_watch_context = Some(WatchAncestryContext {
        changed_key_guid: OTHER_GUID,
        ancestor_guids: &[ROOT_GUID, OTHER_GUID],
        path_components: &["Machine", "Other"],
    });

    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(
            &limits,
            &TransactionMutationLogRecord::KeyPath(entry),
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_path.child_visibility_watch_context",
        })
    );
}

#[test]
fn value_replay_input_preserves_captured_key_context() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(20);
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
            expected_sequence: None,
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
    .expect("value log entry");

    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(
            &limits,
            &TransactionMutationLogRecord::Value(entry),
        ),
        Ok(TransactionReplayWatchInput::EffectiveValue {
            operation_index: 1,
            kind: TransactionMutationLogKind::SetValue,
            key_guid: KEY_GUID,
            watch_context: value_watch_context(),
            scope: lcs_core::TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
            layer: "base",
            sequence: Some(20),
            requires_before_snapshot: true,
            requires_after_snapshot: true,
        })
    );
}
