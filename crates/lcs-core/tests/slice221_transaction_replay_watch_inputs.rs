use lcs_core::{
    BlanketTombstoneInput, DeleteKeyInput, Guid, HideKeyInput, KEY_CREATE_SUB_KEY,
    KeyCreateRecordsRequest, KeyFdNamespaceView, KeyPathMutationInput, LcsError, LcsLimits,
    NIL_GUID, REG_OPTION_VOLATILE, REG_SZ, REG_WATCH_SD_CHANGED, RegistrySetSecurityCommitEffects,
    SequenceCounter, TransactionMutationLogRecord, TransactionOperationIndexCounter,
    TransactionReplayValueWatchScope, TransactionReplayWatchInput,
    TransactionReplayWatchInputSummary, ValueWriteInput, WatchAncestryContext,
    WatchMutationContext, append_transaction_mutation_log_record, plan_blanket_tombstone,
    plan_blanket_tombstone_transaction_log_entry, plan_key_create_records,
    plan_key_create_transaction_log_entry, plan_key_delete, plan_key_delete_transaction_log_entry,
    plan_key_hide, plan_key_hide_transaction_log_entry,
    plan_registry_set_security_transaction_log_entry, plan_value_write,
    plan_value_write_transaction_log_entry, summarize_transaction_replay_watch_inputs,
    transaction_mutation_log_record_watch_replay_input,
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

fn child_visibility_watch_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: CHILD_GUID,
        ancestor_guids: &CHILD_ANCESTORS,
        path_components: &CHILD_PATH,
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

fn named_value_record(
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

fn blanket_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(20);
    let planned = plan_blanket_tombstone(
        &limits,
        &mut sequence_counter,
        &BlanketTombstoneInput {
            key_guid: KEY_GUID,
            layer: "base",
            set: true,
        },
    )
    .expect("blanket tombstone plan");
    TransactionMutationLogRecord::Value(
        plan_blanket_tombstone_transaction_log_entry(
            &limits,
            &planned,
            value_watch_context(),
            counter,
        )
        .expect("blanket log entry"),
    )
}

fn create_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(30);
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
    let mut sequence_counter = SequenceCounter::new(40);
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
fn watch_replay_inputs_preserve_operation_order_and_query_shapes() {
    let limits = LcsLimits::default();
    let mut counter = TransactionOperationIndexCounter::new();
    let security = security_record(&mut counter);
    let named_value = named_value_record(&mut counter);
    let blanket = blanket_record(&mut counter);
    let create = create_key_record(&mut counter);
    let delete = delete_key_record(&mut counter);
    let hide = hide_key_record(&mut counter);

    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(&limits, &security),
        Ok(TransactionReplayWatchInput::DirectSecurity {
            operation_index: 1,
            changed_key_guid: KEY_GUID,
            watch_mutation: WatchMutationContext {
                changed_key_guid: KEY_GUID,
                ancestor_guids: &SECURITY_ANCESTORS,
                path_components: &SECURITY_PATH,
                event_type: REG_WATCH_SD_CHANGED,
            },
        })
    );
    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(&limits, &named_value),
        Ok(TransactionReplayWatchInput::EffectiveValue {
            operation_index: 2,
            kind: lcs_core::TransactionMutationLogKind::SetValue,
            key_guid: KEY_GUID,
            watch_context: value_watch_context(),
            scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
            layer: "base",
            sequence: Some(10),
            requires_before_snapshot: true,
            requires_after_snapshot: true,
        })
    );
    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(&limits, &blanket),
        Ok(TransactionReplayWatchInput::EffectiveValue {
            operation_index: 3,
            kind: lcs_core::TransactionMutationLogKind::BlanketTombstone,
            key_guid: KEY_GUID,
            watch_context: value_watch_context(),
            scope: TransactionReplayValueWatchScope::AllValues,
            layer: "base",
            sequence: Some(20),
            requires_before_snapshot: true,
            requires_after_snapshot: true,
        })
    );
    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(&limits, &create),
        Ok(TransactionReplayWatchInput::EffectiveSubkey {
            operation_index: 4,
            kind: lcs_core::TransactionMutationLogKind::CreateKey,
            parent_guid: PARENT_GUID,
            parent_watch_context: parent_watch_context(),
            child_visibility_watch_context: None,
            child_name: "Child",
            layer: "policy",
            target_guid: Some(CHILD_GUID),
            sequence: Some(30),
            requires_before_snapshot: true,
            requires_after_snapshot: true,
            evaluate_orphaning: false,
            publish_new_key_guid: true,
        })
    );
    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(&limits, &delete),
        Ok(TransactionReplayWatchInput::EffectiveSubkey {
            operation_index: 5,
            kind: lcs_core::TransactionMutationLogKind::DeleteKey,
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
    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(&limits, &hide),
        Ok(TransactionReplayWatchInput::EffectiveSubkey {
            operation_index: 6,
            kind: lcs_core::TransactionMutationLogKind::HideKey,
            parent_guid: PARENT_GUID,
            parent_watch_context: parent_watch_context(),
            child_visibility_watch_context: Some(child_visibility_watch_context()),
            child_name: "Child",
            layer: "base",
            target_guid: None,
            sequence: Some(40),
            requires_before_snapshot: true,
            requires_after_snapshot: true,
            evaluate_orphaning: false,
            publish_new_key_guid: false,
        })
    );
}

#[test]
fn watch_input_summary_counts_only_effective_work_as_source_queries() {
    let limits = LcsLimits::default();
    let mut counter = TransactionOperationIndexCounter::new();
    let mut storage = [None; 7];
    append_transaction_mutation_log_record(&mut storage, security_record(&mut counter))
        .expect("append security");
    append_transaction_mutation_log_record(&mut storage, named_value_record(&mut counter))
        .expect("append named value");
    append_transaction_mutation_log_record(&mut storage, blanket_record(&mut counter))
        .expect("append blanket");
    append_transaction_mutation_log_record(&mut storage, create_key_record(&mut counter))
        .expect("append create");
    append_transaction_mutation_log_record(&mut storage, delete_key_record(&mut counter))
        .expect("append delete");
    append_transaction_mutation_log_record(&mut storage, hide_key_record(&mut counter))
        .expect("append hide");

    assert_eq!(
        summarize_transaction_replay_watch_inputs(&limits, &storage),
        Ok(TransactionReplayWatchInputSummary {
            entries: 6,
            capacity: 7,
            direct_security_mutations: 1,
            named_value_snapshot_inputs: 1,
            all_value_snapshot_inputs: 1,
            effective_subkey_snapshot_inputs: 3,
            requires_before_commit_source_queries: true,
            requires_after_commit_source_queries: true,
        })
    );
}

#[test]
fn empty_watch_input_summary_requires_no_source_queries() {
    assert_eq!(
        summarize_transaction_replay_watch_inputs(&LcsLimits::default(), &[None; 2]),
        Ok(TransactionReplayWatchInputSummary {
            entries: 0,
            capacity: 2,
            direct_security_mutations: 0,
            named_value_snapshot_inputs: 0,
            all_value_snapshot_inputs: 0,
            effective_subkey_snapshot_inputs: 0,
            requires_before_commit_source_queries: false,
            requires_after_commit_source_queries: false,
        })
    );
}

#[test]
fn watch_input_projection_fails_closed_on_corrupt_query_fields() {
    let limits = LcsLimits::default();
    let mut counter = TransactionOperationIndexCounter::new();

    let mut corrupt_value = named_value_record(&mut counter);
    let TransactionMutationLogRecord::Value(ref mut entry) = corrupt_value else {
        panic!("helper should create value record");
    };
    entry.key_guid = NIL_GUID;
    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(&limits, &corrupt_value),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.key_guid",
        })
    );

    let mut corrupt_create = create_key_record(&mut counter);
    let TransactionMutationLogRecord::KeyPath(ref mut entry) = corrupt_create else {
        panic!("helper should create key-path record");
    };
    entry.target_guid = Some(NIL_GUID);
    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(&limits, &corrupt_create),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_path.target_guid",
        })
    );

    let bad_ancestors = [ROOT_GUID, NIL_GUID];
    let mut corrupt_security = security_record(&mut counter);
    let TransactionMutationLogRecord::Security(ref mut entry) = corrupt_security else {
        panic!("helper should create security record");
    };
    entry.watch_mutation = WatchMutationContext {
        changed_key_guid: NIL_GUID,
        ancestor_guids: &bad_ancestors,
        path_components: &SECURITY_PATH,
        event_type: REG_WATCH_SD_CHANGED,
    };
    assert_eq!(
        transaction_mutation_log_record_watch_replay_input(&limits, &corrupt_security),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_mutation.changed_key_guid",
        })
    );
}

#[test]
fn watch_input_summary_fails_closed_on_sparse_logs() {
    let limits = LcsLimits::default();
    let mut counter = TransactionOperationIndexCounter::new();
    let mut storage = [None; 3];
    storage[0] = Some(security_record(&mut counter));
    storage[2] = Some(named_value_record(&mut counter));

    assert_eq!(
        summarize_transaction_replay_watch_inputs(&limits, &storage),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "transaction_log.dense_prefix",
        })
    );
}
