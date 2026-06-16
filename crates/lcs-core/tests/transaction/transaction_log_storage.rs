use lcs_core::{
    DeleteKeyInput, Guid, HideKeyInput, KEY_CREATE_SUB_KEY, KeyCreateRecordsRequest,
    KeyFdNamespaceView, KeyPathMutationInput, LcsError, LcsLimits, REG_OPTION_VOLATILE, REG_SZ,
    REG_WATCH_SD_CHANGED, RegistrySetSecurityCommitEffects, SequenceCounter,
    TransactionKernelEffectsPlan, TransactionMutationLogKind, TransactionMutationLogRecord,
    TransactionOperationIndexCounter, ValueWriteInput, WatchAncestryContext, WatchMutationContext,
    append_transaction_mutation_log_record, clear_transaction_mutation_log,
    plan_key_create_records, plan_key_create_transaction_log_entry, plan_key_delete,
    plan_key_delete_transaction_log_entry, plan_key_hide, plan_key_hide_transaction_log_entry,
    plan_registry_set_security_transaction_log_entry, plan_transaction_mutation_log_disposition,
    plan_value_write, plan_value_write_transaction_log_entry, summarize_transaction_mutation_log,
};

const ROOT_GUID: Guid = [0x10; 16];
const PARENT_GUID: Guid = [0x20; 16];
const CHILD_GUID: Guid = [0x30; 16];
const KEY_GUID: Guid = [0x40; 16];
const SECURITY_ANCESTORS: [Guid; 2] = [ROOT_GUID, KEY_GUID];
const SECURITY_PATH: [&str; 2] = ["Machine", "Policy"];
const CHILD_ANCESTORS: [Guid; 3] = [ROOT_GUID, PARENT_GUID, CHILD_GUID];
const CHILD_PATH: [&str; 3] = ["Machine", "Parent", "Child"];
const PARENT_ANCESTORS: [Guid; 2] = [ROOT_GUID, PARENT_GUID];
const PARENT_PATH: [&str; 2] = ["Machine", "Parent"];

fn value_watch_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &SECURITY_ANCESTORS,
        path_components: &SECURITY_PATH,
    }
}

fn parent_watch_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: PARENT_GUID,
        ancestor_guids: &PARENT_ANCESTORS,
        path_components: &PARENT_PATH,
    }
}

fn pending_set_security_effects<'a>() -> RegistrySetSecurityCommitEffects<'a> {
    RegistrySetSecurityCommitEffects {
        update_hive_generation: false,
        dispatch_watch_events: false,
        record_transaction_mutation_log: true,
        commit_visible_last_write_time_update: false,
        retain_existing_fd_grants: true,
        watch_mutation: Some(WatchMutationContext {
            changed_key_guid: KEY_GUID,
            ancestor_guids: &SECURITY_ANCESTORS,
            path_components: &SECURITY_PATH,
            event_type: REG_WATCH_SD_CHANGED,
        }),
    }
}

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
        layer,
        flags: REG_OPTION_VOLATILE,
        caller_has_tcb_or_admin: false,
    }
}

fn security_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    TransactionMutationLogRecord::Security(
        plan_registry_set_security_transaction_log_entry(&pending_set_security_effects(), counter)
            .expect("security log entry"),
    )
}

fn value_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
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
            expected_sequence: None,
        },
    )
    .expect("value write plan");
    TransactionMutationLogRecord::Value(
        plan_value_write_transaction_log_entry(&limits, &planned, value_watch_context(), counter)
            .expect("value log entry"),
    )
}

fn create_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(77);
    let planned =
        plan_key_create_records(&limits, &mut sequence_counter, &create_request("policy"))
            .expect("create records plan");
    TransactionMutationLogRecord::KeyPath(
        plan_key_create_transaction_log_entry(&limits, &planned, parent_watch_context(), counter)
            .expect("create key log entry"),
    )
}

fn delete_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let planned = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(&CHILD_PATH),
                layer: "base",
            },
            visible_child_count: 0,
        },
    )
    .expect("delete key plan");
    TransactionMutationLogRecord::KeyPath(
        plan_key_delete_transaction_log_entry(&limits, &planned, counter)
            .expect("delete key log entry"),
    )
}

fn hide_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(88);
    let planned = plan_key_hide(
        &limits,
        &mut sequence_counter,
        &HideKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(&CHILD_PATH),
                layer: "base",
            },
        },
    )
    .expect("hide key plan");
    TransactionMutationLogRecord::KeyPath(
        plan_key_hide_transaction_log_entry(&limits, &planned, counter)
            .expect("hide key log entry"),
    )
}

#[test]
fn append_records_builds_dense_bounded_log_in_operation_order() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut storage = [None; 3];

    let first = append_transaction_mutation_log_record(&mut storage, security_record(&mut counter))
        .expect("append security");
    assert_eq!(first.slot, 0);
    assert_eq!(first.operation_index, 1);
    assert_eq!(first.entries, 1);
    assert!(!first.full);

    let second = append_transaction_mutation_log_record(&mut storage, value_record(&mut counter))
        .expect("append value");
    assert_eq!(second.slot, 1);
    assert_eq!(second.operation_index, 2);
    assert_eq!(second.entries, 2);
    assert!(!second.full);

    let third =
        append_transaction_mutation_log_record(&mut storage, create_key_record(&mut counter))
            .expect("append create key");
    assert_eq!(third.slot, 2);
    assert_eq!(third.operation_index, 3);
    assert_eq!(third.entries, 3);
    assert!(third.full);

    assert_eq!(
        summarize_transaction_mutation_log(&storage)
            .expect("summary")
            .entries,
        3
    );
    assert_eq!(
        storage[0].expect("slot 0").kind(),
        TransactionMutationLogKind::SetSecurity
    );
    assert_eq!(
        storage[1].expect("slot 1").kind(),
        TransactionMutationLogKind::SetValue
    );
    assert_eq!(
        storage[2].expect("slot 2").kind(),
        TransactionMutationLogKind::CreateKey
    );
}

#[test]
fn full_storage_fails_before_mutating_existing_log() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut storage = [None; 1];
    append_transaction_mutation_log_record(&mut storage, security_record(&mut counter))
        .expect("append initial entry");
    let before = storage;

    assert_eq!(
        append_transaction_mutation_log_record(&mut storage, value_record(&mut counter)),
        Err(LcsError::TransactionMutationLogFull { capacity: 1 })
    );
    assert_eq!(storage, before);
}

#[test]
fn sparse_storage_fails_closed_without_appending() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut storage = [None; 3];
    storage[1] = Some(value_record(&mut counter));
    let before = storage;

    assert_eq!(
        summarize_transaction_mutation_log(&storage),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "transaction_log.dense_prefix",
        })
    );
    assert_eq!(
        append_transaction_mutation_log_record(&mut storage, security_record(&mut counter)),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "transaction_log.dense_prefix",
        })
    );
    assert_eq!(storage, before);
}

#[test]
fn disposition_plans_apply_discard_and_retained_log_cases() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut storage = [None; 2];
    append_transaction_mutation_log_record(&mut storage, delete_key_record(&mut counter))
        .expect("append delete");
    append_transaction_mutation_log_record(&mut storage, hide_key_record(&mut counter))
        .expect("append hide");

    let apply = plan_transaction_mutation_log_disposition(
        TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects,
        &storage,
    )
    .expect("apply disposition");
    assert_eq!(apply.entries, 2);
    assert!(apply.apply_commit_effects);
    assert!(apply.emit_normal_watch_events);
    assert!(apply.clear_entries_after_effects);
    assert!(!apply.retain_entries);

    let retain = plan_transaction_mutation_log_disposition(
        TransactionKernelEffectsPlan::RetainMutationLogForLateResponse,
        &storage,
    )
    .expect("retain disposition");
    assert_eq!(retain.entries, 2);
    assert!(!retain.apply_commit_effects);
    assert!(!retain.emit_normal_watch_events);
    assert!(!retain.clear_entries_after_effects);
    assert!(retain.retain_entries);
    assert!(storage.iter().all(Option::is_some));

    let discard = plan_transaction_mutation_log_disposition(
        TransactionKernelEffectsPlan::DiscardMutationLogWithoutEvents,
        &storage,
    )
    .expect("discard disposition");
    assert_eq!(discard.entries, 2);
    assert!(!discard.apply_commit_effects);
    assert!(!discard.emit_normal_watch_events);
    assert!(discard.clear_entries_after_effects);
    assert!(!discard.retain_entries);

    let cleared = clear_transaction_mutation_log(&mut storage).expect("clear storage");
    assert_eq!(cleared.entries, 0);
    assert_eq!(cleared.capacity, 2);
    assert!(!cleared.full);
    assert!(storage.iter().all(Option::is_none));
}

#[test]
fn corrupt_record_shape_fails_before_storage_mutation() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut corrupt = security_record(&mut counter);
    let TransactionMutationLogRecord::Security(entry) = &mut corrupt else {
        unreachable!();
    };
    entry.operation_index = 0;
    let mut storage = [None; 1];

    assert_eq!(
        append_transaction_mutation_log_record(&mut storage, corrupt),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "operation_index",
        })
    );
    assert_eq!(storage, [None; 1]);
}
