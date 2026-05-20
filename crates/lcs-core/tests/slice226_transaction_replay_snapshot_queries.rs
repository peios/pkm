use lcs_core::{
    BlanketTombstoneInput, DeleteKeyInput, Guid, HideKeyInput, KEY_CREATE_SUB_KEY,
    KeyCreateRecordsRequest, KeyFdNamespaceView, KeyPathMutationInput, LcsError, LcsLimits,
    NIL_GUID, REG_OPTION_VOLATILE, REG_SZ, REG_WATCH_SD_CHANGED, RegistrySetSecurityCommitEffects,
    SequenceCounter, TransactionMutationLogRecord, TransactionOperationIndexCounter,
    TransactionReplaySnapshotPhase, TransactionReplaySnapshotQuery,
    TransactionReplaySnapshotQueryKind, TransactionReplaySnapshotQuerySummary,
    TransactionReplayValueWatchScope, ValueWriteInput, WatchAncestryContext, WatchMutationContext,
    append_transaction_mutation_log_record, for_each_transaction_replay_snapshot_query,
    plan_blanket_tombstone, plan_blanket_tombstone_transaction_log_entry, plan_key_create_records,
    plan_key_create_transaction_log_entry, plan_key_delete, plan_key_delete_transaction_log_entry,
    plan_key_hide, plan_key_hide_transaction_log_entry,
    plan_registry_set_security_transaction_log_entry, plan_value_write,
    plan_value_write_transaction_log_entry,
};

const ROOT_GUID: Guid = [0x10; 16];
const PARENT_GUID: Guid = [0x20; 16];
const CHILD_GUID: Guid = [0x30; 16];
const KEY_GUID: Guid = [0x40; 16];
const KEY_ANCESTORS: [Guid; 2] = [ROOT_GUID, KEY_GUID];
const KEY_PATH: [&str; 2] = ["Machine", "Policy"];
const PARENT_ANCESTORS: [Guid; 2] = [ROOT_GUID, PARENT_GUID];
const PARENT_PATH: [&str; 2] = ["Machine", "Parent"];
const CHILD_ANCESTORS: [Guid; 3] = [ROOT_GUID, PARENT_GUID, CHILD_GUID];
const CHILD_PATH: [&str; 3] = ["Machine", "Parent", "Child"];

fn key_watch_context() -> WatchAncestryContext<'static> {
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

fn security_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let effects = RegistrySetSecurityCommitEffects {
        update_hive_generation: false,
        dispatch_watch_events: false,
        record_transaction_mutation_log: true,
        commit_visible_last_write_time_update: false,
        retain_existing_fd_grants: true,
        watch_mutation: Some(WatchMutationContext {
            changed_key_guid: KEY_GUID,
            ancestor_guids: &KEY_ANCESTORS,
            path_components: &KEY_PATH,
            event_type: REG_WATCH_SD_CHANGED,
        }),
    };
    TransactionMutationLogRecord::Security(
        plan_registry_set_security_transaction_log_entry(&effects, counter)
            .expect("security transaction log entry"),
    )
}

fn named_value_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(10);
    let plan = plan_value_write(
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
        plan_value_write_transaction_log_entry(&limits, &plan, key_watch_context(), counter)
            .expect("value transaction log entry"),
    )
}

fn blanket_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(20);
    let plan = plan_blanket_tombstone(
        &limits,
        &mut sequence_counter,
        &BlanketTombstoneInput {
            key_guid: KEY_GUID,
            layer: "base",
            set: true,
        },
    )
    .expect("blanket plan");
    TransactionMutationLogRecord::Value(
        plan_blanket_tombstone_transaction_log_entry(&limits, &plan, key_watch_context(), counter)
            .expect("blanket transaction log entry"),
    )
}

fn child_fd<'a>() -> KeyFdNamespaceView<'a> {
    KeyFdNamespaceView {
        resolved_path: &CHILD_PATH,
        ancestor_guids: &CHILD_ANCESTORS,
        orphaned: false,
    }
}

fn create_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(30);
    let plan = plan_key_create_records(
        &limits,
        &mut sequence_counter,
        &KeyCreateRecordsRequest {
            parent_guid: PARENT_GUID,
            parent_is_volatile: false,
            parent_granted_access: KEY_CREATE_SUB_KEY,
            child_name: "Child",
            candidate_guid: CHILD_GUID,
            active_key_guids: &[],
            retired_key_guids: &[],
            layer: "policy",
            flags: REG_OPTION_VOLATILE,
            caller_has_tcb_or_admin: false,
        },
    )
    .expect("key create plan");
    TransactionMutationLogRecord::KeyPath(
        plan_key_create_transaction_log_entry(&limits, &plan, parent_watch_context(), counter)
            .expect("create transaction log entry"),
    )
}

fn delete_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let plan = plan_key_delete(
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
        plan_key_delete_transaction_log_entry(&limits, &plan, counter)
            .expect("delete transaction log entry"),
    )
}

fn hide_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(40);
    let plan = plan_key_hide(
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
        plan_key_hide_transaction_log_entry(&limits, &plan, counter)
            .expect("hide transaction log entry"),
    )
}

fn populated_storage() -> [Option<TransactionMutationLogRecord<'static>>; 7] {
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
    storage
}

fn collect_queries(
    phase: TransactionReplaySnapshotPhase,
    storage: &[Option<TransactionMutationLogRecord<'static>>],
) -> (
    TransactionReplaySnapshotQuerySummary,
    Vec<TransactionReplaySnapshotQuery<'static>>,
) {
    let mut queries = Vec::new();
    let summary = for_each_transaction_replay_snapshot_query(
        &LcsLimits::default(),
        storage,
        phase,
        |query| {
            queries.push(query);
            Ok(())
        },
    )
    .expect("snapshot query planning");
    (summary, queries)
}

#[test]
fn before_commit_snapshot_queries_preserve_operation_order_and_shapes() {
    let storage = populated_storage();
    let (summary, queries) =
        collect_queries(TransactionReplaySnapshotPhase::BeforeCommit, &storage);

    assert_eq!(
        summary,
        TransactionReplaySnapshotQuerySummary {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            entries: 6,
            capacity: 7,
            emitted_queries: 7,
            effective_value_queries: 2,
            effective_subkey_queries: 3,
            child_visibility_queries: 2,
            direct_security_inputs: 1,
            inputs_without_queries: 1,
        }
    );
    assert_eq!(
        queries,
        vec![
            TransactionReplaySnapshotQuery {
                phase: TransactionReplaySnapshotPhase::BeforeCommit,
                operation_index: 2,
                kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
                    key_guid: KEY_GUID,
                    scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
                },
            },
            TransactionReplaySnapshotQuery {
                phase: TransactionReplaySnapshotPhase::BeforeCommit,
                operation_index: 3,
                kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
                    key_guid: KEY_GUID,
                    scope: TransactionReplayValueWatchScope::AllValues,
                },
            },
            TransactionReplaySnapshotQuery {
                phase: TransactionReplaySnapshotPhase::BeforeCommit,
                operation_index: 4,
                kind: TransactionReplaySnapshotQueryKind::EffectiveSubkeys {
                    parent_guid: PARENT_GUID,
                },
            },
            TransactionReplaySnapshotQuery {
                phase: TransactionReplaySnapshotPhase::BeforeCommit,
                operation_index: 5,
                kind: TransactionReplaySnapshotQueryKind::EffectiveSubkeys {
                    parent_guid: PARENT_GUID,
                },
            },
            TransactionReplaySnapshotQuery {
                phase: TransactionReplaySnapshotPhase::BeforeCommit,
                operation_index: 5,
                kind: TransactionReplaySnapshotQueryKind::ChildVisibility {
                    parent_guid: PARENT_GUID,
                    child_name: "Child",
                },
            },
            TransactionReplaySnapshotQuery {
                phase: TransactionReplaySnapshotPhase::BeforeCommit,
                operation_index: 6,
                kind: TransactionReplaySnapshotQueryKind::EffectiveSubkeys {
                    parent_guid: PARENT_GUID,
                },
            },
            TransactionReplaySnapshotQuery {
                phase: TransactionReplaySnapshotPhase::BeforeCommit,
                operation_index: 6,
                kind: TransactionReplaySnapshotQueryKind::ChildVisibility {
                    parent_guid: PARENT_GUID,
                    child_name: "Child",
                },
            },
        ]
    );
}

#[test]
fn after_commit_snapshot_queries_use_the_same_retained_log_order() {
    let storage = populated_storage();
    let (summary, queries) = collect_queries(TransactionReplaySnapshotPhase::AfterCommit, &storage);

    assert_eq!(
        summary,
        TransactionReplaySnapshotQuerySummary {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            entries: 6,
            capacity: 7,
            emitted_queries: 7,
            effective_value_queries: 2,
            effective_subkey_queries: 3,
            child_visibility_queries: 2,
            direct_security_inputs: 1,
            inputs_without_queries: 1,
        }
    );
    assert_eq!(
        queries[0],
        TransactionReplaySnapshotQuery {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 2,
            kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
            },
        }
    );
    assert!(
        queries
            .iter()
            .all(|query| query.phase == TransactionReplaySnapshotPhase::AfterCommit)
    );
}

#[test]
fn direct_security_inputs_emit_no_snapshot_queries() {
    let mut counter = TransactionOperationIndexCounter::new();
    let security = security_record(&mut counter);
    let storage = [Some(security), None];
    let (summary, queries) =
        collect_queries(TransactionReplaySnapshotPhase::BeforeCommit, &storage);

    assert_eq!(
        summary,
        TransactionReplaySnapshotQuerySummary {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            entries: 1,
            capacity: 2,
            emitted_queries: 0,
            effective_value_queries: 0,
            effective_subkey_queries: 0,
            child_visibility_queries: 0,
            direct_security_inputs: 1,
            inputs_without_queries: 1,
        }
    );
    assert!(queries.is_empty());
}

#[test]
fn snapshot_query_planning_fails_before_partial_emission_on_corrupt_log() {
    let mut counter = TransactionOperationIndexCounter::new();
    let security = security_record(&mut counter);
    let mut corrupt = named_value_record(&mut counter);
    let TransactionMutationLogRecord::Value(ref mut entry) = corrupt else {
        panic!("helper should produce a value record");
    };
    entry.key_guid = NIL_GUID;
    let storage = [Some(security), Some(corrupt), None];
    let mut emitted = Vec::new();

    assert_eq!(
        for_each_transaction_replay_snapshot_query(
            &LcsLimits::default(),
            &storage,
            TransactionReplaySnapshotPhase::BeforeCommit,
            |query| {
                emitted.push(query);
                Ok(())
            },
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.key_guid",
        })
    );
    assert!(emitted.is_empty());
}
