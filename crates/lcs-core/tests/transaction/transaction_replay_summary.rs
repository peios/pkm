use lcs_core::{
    DeleteKeyInput, Guid, HideKeyInput, KEY_CREATE_SUB_KEY, KeyCreateRecordsRequest,
    KeyFdNamespaceView, KeyPathMutationInput, LcsError, LcsLimits, REG_OPTION_VOLATILE, REG_SZ,
    REG_WATCH_SD_CHANGED, RegistrySetSecurityCommitEffects, SequenceCounter,
    TransactionMutationLogRecord, TransactionMutationReplaySummary,
    TransactionOperationIndexCounter, ValueWriteInput, WatchAncestryContext, WatchMutationContext,
    append_transaction_mutation_log_record, plan_key_create_records,
    plan_key_create_transaction_log_entry, plan_key_delete, plan_key_delete_transaction_log_entry,
    plan_key_hide, plan_key_hide_transaction_log_entry,
    plan_registry_set_security_transaction_log_entry, plan_value_write,
    plan_value_write_transaction_log_entry, summarize_transaction_mutation_log_replay,
};

const ROOT_GUID: Guid = [0x11; 16];
const PARENT_GUID: Guid = [0x22; 16];
const CHILD_GUID: Guid = [0x33; 16];
const KEY_GUID: Guid = [0x44; 16];
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

fn child_fd<'a>() -> KeyFdNamespaceView<'a> {
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
    let mut sequence_counter = SequenceCounter::new(10);
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
    let mut sequence_counter = SequenceCounter::new(20);
    let planned =
        plan_key_create_records(&limits, &mut sequence_counter, &create_request("policy"))
            .expect("create records plan");
    TransactionMutationLogRecord::KeyPath(
        plan_key_create_transaction_log_entry(&limits, &planned, parent_watch_context(), counter)
            .expect("create log entry"),
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
                fd: child_fd(),
                layer: "base",
            },
            visible_child_count: 0,
        },
    )
    .expect("delete key plan");
    TransactionMutationLogRecord::KeyPath(
        plan_key_delete_transaction_log_entry(&limits, &planned, counter)
            .expect("delete log entry"),
    )
}

fn hide_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(30);
    let planned = plan_key_hide(
        &limits,
        &mut sequence_counter,
        &HideKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(),
                layer: "base",
            },
        },
    )
    .expect("hide key plan");
    TransactionMutationLogRecord::KeyPath(
        plan_key_hide_transaction_log_entry(&limits, &planned, counter).expect("hide log entry"),
    )
}

#[test]
fn replay_summary_counts_work_but_collapses_generation_to_one_increment() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut storage = [None; 6];
    append_transaction_mutation_log_record(&mut storage, security_record(&mut counter))
        .expect("append security");
    append_transaction_mutation_log_record(&mut storage, value_record(&mut counter))
        .expect("append value");
    append_transaction_mutation_log_record(&mut storage, create_key_record(&mut counter))
        .expect("append create");
    append_transaction_mutation_log_record(&mut storage, delete_key_record(&mut counter))
        .expect("append delete");
    append_transaction_mutation_log_record(&mut storage, hide_key_record(&mut counter))
        .expect("append hide");

    assert_eq!(
        summarize_transaction_mutation_log_replay(&storage),
        Ok(TransactionMutationReplaySummary {
            entries: 5,
            capacity: 6,
            increment_hive_generation_once: true,
            key_last_write_updates: 2,
            parent_last_write_updates: 1,
            security_watch_mutations: 1,
            effective_value_recomputations: 1,
            effective_subkey_recomputations: 3,
            orphan_evaluations: 1,
            new_key_publications: 1,
        })
    );
}

#[test]
fn empty_replay_summary_has_no_generation_or_commit_work() {
    let storage = [None; 2];

    assert_eq!(
        summarize_transaction_mutation_log_replay(&storage),
        Ok(TransactionMutationReplaySummary {
            entries: 0,
            capacity: 2,
            increment_hive_generation_once: false,
            key_last_write_updates: 0,
            parent_last_write_updates: 0,
            security_watch_mutations: 0,
            effective_value_recomputations: 0,
            effective_subkey_recomputations: 0,
            orphan_evaluations: 0,
            new_key_publications: 0,
        })
    );
}

#[test]
fn replay_summary_fails_closed_on_sparse_or_corrupt_logs() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut sparse = [None; 3];
    sparse[0] = Some(security_record(&mut counter));
    sparse[2] = Some(value_record(&mut counter));
    assert_eq!(
        summarize_transaction_mutation_log_replay(&sparse),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "transaction_log.dense_prefix",
        })
    );

    let mut corrupt_record = value_record(&mut counter);
    let TransactionMutationLogRecord::Value(ref mut entry) = corrupt_record else {
        panic!("helper should create value record");
    };
    entry.update_hive_generation_on_commit = false;
    let corrupt = [Some(corrupt_record)];
    assert_eq!(
        summarize_transaction_mutation_log_replay(&corrupt),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.commit_effects",
        })
    );
}
