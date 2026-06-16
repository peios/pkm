use lcs_core::{
    EnumeratedSubkey, EnumeratedValue, Guid, LcsError, LcsLimits, REG_WATCH_KEY_DELETED,
    REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_DELETED, REG_WATCH_VALUE_SET, RegistryValueType,
    ResolvedPathEntry, ResolvedValueEntry, TransactionKeyPathMutationLogEntry,
    TransactionMutationLogEntry, TransactionMutationLogKind, TransactionMutationLogRecord,
    TransactionReplaySnapshotPhase, TransactionReplaySnapshotResult,
    TransactionReplaySnapshotResultKind, TransactionReplayValueWatchScope,
    TransactionReplayWatchEvent, TransactionReplayWatchEventStreamSummary,
    TransactionValueMutationLogEntry, WatchAncestryContext,
    for_each_transaction_replay_watch_event_stream,
    summarize_transaction_replay_watch_event_stream,
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

fn key_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &KEY_ANCESTORS,
        path_components: &KEY_PATH,
    }
}

fn parent_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: PARENT_GUID,
        ancestor_guids: &PARENT_ANCESTORS,
        path_components: &PARENT_PATH,
    }
}

fn child_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: CHILD_GUID,
        ancestor_guids: &CHILD_ANCESTORS,
        path_components: &CHILD_PATH,
    }
}

fn value_record(operation_index: u64, key_guid: Guid) -> TransactionMutationLogRecord<'static> {
    TransactionMutationLogRecord::Value(TransactionValueMutationLogEntry {
        operation_index,
        kind: TransactionMutationLogKind::SetValue,
        key_guid,
        watch_context: key_context(),
        value_name: Some("Setting"),
        layer: "base",
        sequence: Some(10),
        update_hive_generation_on_commit: true,
        update_last_write_time_on_commit: true,
        recompute_effective_value_events_on_commit: true,
    })
}

fn storage() -> [Option<TransactionMutationLogRecord<'static>>; 4] {
    [
        Some(TransactionMutationLogRecord::Security(
            TransactionMutationLogEntry {
                operation_index: 1,
                kind: TransactionMutationLogKind::SetSecurity,
                watch_mutation: key_context().with_event(REG_WATCH_SD_CHANGED),
                update_hive_generation_on_commit: true,
                update_last_write_time_on_commit: true,
            },
        )),
        Some(value_record(2, KEY_GUID)),
        Some(TransactionMutationLogRecord::KeyPath(
            TransactionKeyPathMutationLogEntry {
                operation_index: 3,
                kind: TransactionMutationLogKind::DeleteKey,
                parent_guid: PARENT_GUID,
                parent_watch_context: parent_context(),
                child_visibility_watch_context: Some(child_context()),
                child_name: "Child",
                layer: "base",
                target_guid: None,
                sequence: None,
                update_hive_generation_on_commit: true,
                update_parent_last_write_time_on_commit: true,
                recompute_effective_subkey_events_on_commit: true,
                evaluate_orphaning_on_commit: true,
                publish_new_key_guid_on_commit: false,
            },
        )),
        None,
    ]
}

fn value(name: &'static str, data: &'static [u8], sequence: u64) -> EnumeratedValue<'static> {
    EnumeratedValue {
        name,
        value: ResolvedValueEntry {
            value_type: RegistryValueType::Sz,
            data,
            layer: "base",
            precedence: 0,
            sequence,
        },
    }
}

fn path(guid: Guid, sequence: u64) -> ResolvedPathEntry<'static> {
    ResolvedPathEntry {
        guid,
        layer: "base",
        precedence: 0,
        sequence,
    }
}

fn subkey(name: &'static str, guid: Guid, sequence: u64) -> EnumeratedSubkey<'static> {
    EnumeratedSubkey {
        child_name: name,
        path: path(guid, sequence),
    }
}

#[test]
fn replay_event_stream_prevalidates_and_emits_in_operation_order() {
    let storage = storage();
    let before_value = [value("Setting", b"old", 1)];
    let after_value = [value("Setting", b"new", 10)];
    let before_children = [subkey("Child", CHILD_GUID, 1)];
    let after_children = [];
    let results = [
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 2,
            kind: TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
                values: &before_value,
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 2,
            kind: TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
                values: &after_value,
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 3,
            kind: TransactionReplaySnapshotResultKind::EffectiveSubkeys {
                parent_guid: PARENT_GUID,
                children: &before_children,
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 3,
            kind: TransactionReplaySnapshotResultKind::ChildVisibility {
                parent_guid: PARENT_GUID,
                child_name: "Child",
                child: Some(path(CHILD_GUID, 1)),
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 3,
            kind: TransactionReplaySnapshotResultKind::EffectiveSubkeys {
                parent_guid: PARENT_GUID,
                children: &after_children,
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 3,
            kind: TransactionReplaySnapshotResultKind::ChildVisibility {
                parent_guid: PARENT_GUID,
                child_name: "Child",
                child: None,
            },
        },
    ];

    assert_eq!(
        summarize_transaction_replay_watch_event_stream(&LcsLimits::default(), &storage, &results),
        Ok(TransactionReplayWatchEventStreamSummary {
            entries: 3,
            capacity: 4,
            direct_security_inputs: 1,
            effective_value_inputs: 1,
            effective_subkey_inputs: 1,
            emitted_events: 4,
        })
    );

    let mut events = Vec::new();
    let summary = for_each_transaction_replay_watch_event_stream(
        &LcsLimits::default(),
        &storage,
        &results,
        |event| {
            events.push(event);
            Ok(())
        },
    )
    .expect("event stream");

    assert_eq!(summary.emitted_events, 4);
    assert_eq!(
        events,
        vec![
            TransactionReplayWatchEvent {
                operation_index: 1,
                mutation: key_context().with_event(REG_WATCH_SD_CHANGED),
                name: "",
            },
            TransactionReplayWatchEvent {
                operation_index: 2,
                mutation: key_context().with_event(REG_WATCH_VALUE_SET),
                name: "Setting",
            },
            TransactionReplayWatchEvent {
                operation_index: 3,
                mutation: parent_context().with_event(REG_WATCH_SUBKEY_DELETED),
                name: "Child",
            },
            TransactionReplayWatchEvent {
                operation_index: 3,
                mutation: child_context().with_event(REG_WATCH_KEY_DELETED),
                name: "",
            },
        ]
    );
}

#[test]
fn replay_event_stream_rejects_missing_snapshots_before_partial_emit() {
    let mut storage = storage();
    storage[2] = None;
    let before_value = [value("Setting", b"old", 1)];
    let results = [TransactionReplaySnapshotResult {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: 2,
        kind: TransactionReplaySnapshotResultKind::EffectiveValue {
            key_guid: KEY_GUID,
            scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
            values: &before_value,
        },
    }];
    let mut events = Vec::new();

    assert_eq!(
        for_each_transaction_replay_watch_event_stream(
            &LcsLimits::default(),
            &storage,
            &results,
            |event| {
                events.push(event);
                Ok(())
            },
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_missing",
        })
    );
    assert!(events.is_empty());
}

#[test]
fn replay_event_stream_rejects_corrupt_later_log_record_before_partial_emit() {
    let storage = [
        storage()[0],
        Some(value_record(2, lcs_core::NIL_GUID)),
        None,
        None,
    ];
    let mut events = Vec::new();

    assert_eq!(
        for_each_transaction_replay_watch_event_stream(
            &LcsLimits::default(),
            &storage,
            &[],
            |event| {
                events.push(event);
                Ok(())
            },
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.key_guid",
        })
    );
    assert!(events.is_empty());
}
