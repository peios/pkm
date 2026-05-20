use lcs_core::{
    EnumeratedSubkey, EnumeratedValue, Guid, LcsError, LcsLimits, REG_WATCH_KEY_DELETED,
    REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_DELETED, REG_WATCH_VALUE_SET, RegistryValueType,
    ResolvedPathEntry, ResolvedValueEntry, TransactionMutationLogKind,
    TransactionReplaySnapshotPhase, TransactionReplaySnapshotResult,
    TransactionReplaySnapshotResultKind, TransactionReplayValueWatchScope,
    TransactionReplayWatchEvent, TransactionReplayWatchInput, TransactionReplayWatchSnapshots,
    WatchAncestryContext, for_each_transaction_replay_watch_event,
    resolve_transaction_replay_watch_snapshots,
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

fn collect_events<'a>(
    input: &TransactionReplayWatchInput<'a>,
    snapshots: TransactionReplayWatchSnapshots<'a>,
) -> Result<Vec<TransactionReplayWatchEvent<'a>>, LcsError> {
    let mut events = Vec::new();
    for_each_transaction_replay_watch_event(&LcsLimits::default(), input, snapshots, |event| {
        events.push(event);
        Ok(())
    })?;
    Ok(events)
}

#[test]
fn matching_value_snapshots_feeds_replay_event_derivation() {
    let input = TransactionReplayWatchInput::EffectiveValue {
        operation_index: 2,
        kind: TransactionMutationLogKind::SetValue,
        key_guid: KEY_GUID,
        watch_context: key_context(),
        scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
        layer: "base",
        sequence: Some(10),
        requires_before_snapshot: true,
        requires_after_snapshot: true,
    };
    let before = [value("Setting", b"old", 1)];
    let after = [value("Setting", b"new", 10)];
    let results = [
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 2,
            kind: TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
                values: &before,
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 2,
            kind: TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
                values: &after,
            },
        },
    ];

    let snapshots =
        resolve_transaction_replay_watch_snapshots(&LcsLimits::default(), &input, &results)
            .expect("matched snapshots");

    assert_eq!(
        collect_events(&input, snapshots),
        Ok(vec![TransactionReplayWatchEvent {
            operation_index: 2,
            mutation: key_context().with_event(REG_WATCH_VALUE_SET),
            name: "Setting",
        }])
    );
}

#[test]
fn matching_subkey_snapshots_preserves_child_visibility_results() {
    let input = TransactionReplayWatchInput::EffectiveSubkey {
        operation_index: 4,
        kind: TransactionMutationLogKind::DeleteKey,
        parent_guid: PARENT_GUID,
        parent_watch_context: parent_context(),
        child_visibility_watch_context: Some(child_context()),
        child_name: "Child",
        layer: "base",
        target_guid: None,
        sequence: None,
        requires_before_snapshot: true,
        requires_after_snapshot: true,
        evaluate_orphaning: true,
        publish_new_key_guid: false,
    };
    let before_children = [subkey("Child", CHILD_GUID, 1)];
    let after_children = [];
    let results = [
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 4,
            kind: TransactionReplaySnapshotResultKind::EffectiveSubkeys {
                parent_guid: PARENT_GUID,
                children: &before_children,
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 4,
            kind: TransactionReplaySnapshotResultKind::ChildVisibility {
                parent_guid: PARENT_GUID,
                child_name: "Child",
                child: Some(path(CHILD_GUID, 1)),
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 4,
            kind: TransactionReplaySnapshotResultKind::EffectiveSubkeys {
                parent_guid: PARENT_GUID,
                children: &after_children,
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 4,
            kind: TransactionReplaySnapshotResultKind::ChildVisibility {
                parent_guid: PARENT_GUID,
                child_name: "Child",
                child: None,
            },
        },
    ];

    let snapshots =
        resolve_transaction_replay_watch_snapshots(&LcsLimits::default(), &input, &results)
            .expect("matched snapshots");

    assert_eq!(
        collect_events(&input, snapshots),
        Ok(vec![
            TransactionReplayWatchEvent {
                operation_index: 4,
                mutation: parent_context().with_event(REG_WATCH_SUBKEY_DELETED),
                name: "Child",
            },
            TransactionReplayWatchEvent {
                operation_index: 4,
                mutation: child_context().with_event(REG_WATCH_KEY_DELETED),
                name: "",
            },
        ])
    );
}

#[test]
fn missing_required_snapshot_fails_before_event_derivation() {
    let input = TransactionReplayWatchInput::EffectiveValue {
        operation_index: 5,
        kind: TransactionMutationLogKind::SetValue,
        key_guid: KEY_GUID,
        watch_context: key_context(),
        scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
        layer: "base",
        sequence: Some(10),
        requires_before_snapshot: true,
        requires_after_snapshot: true,
    };
    let before = [value("Setting", b"old", 1)];
    let results = [TransactionReplaySnapshotResult {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: 5,
        kind: TransactionReplaySnapshotResultKind::EffectiveValue {
            key_guid: KEY_GUID,
            scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
            values: &before,
        },
    }];

    assert_eq!(
        resolve_transaction_replay_watch_snapshots(&LcsLimits::default(), &input, &results),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_missing",
        })
    );
}

#[test]
fn duplicate_and_wrong_kind_snapshot_results_fail_closed() {
    let input = TransactionReplayWatchInput::EffectiveValue {
        operation_index: 6,
        kind: TransactionMutationLogKind::SetValue,
        key_guid: KEY_GUID,
        watch_context: key_context(),
        scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
        layer: "base",
        sequence: Some(10),
        requires_before_snapshot: true,
        requires_after_snapshot: true,
    };
    let before = [value("Setting", b"old", 1)];
    let after = [value("Setting", b"new", 10)];
    let duplicate = [
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 6,
            kind: TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
                values: &before,
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 6,
            kind: TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
                values: &before,
            },
        },
        TransactionReplaySnapshotResult {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 6,
            kind: TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
                values: &after,
            },
        },
    ];
    assert_eq!(
        resolve_transaction_replay_watch_snapshots(&LcsLimits::default(), &input, &duplicate),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_duplicate",
        })
    );

    let wrong_kind = [TransactionReplaySnapshotResult {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: 6,
        kind: TransactionReplaySnapshotResultKind::EffectiveSubkeys {
            parent_guid: PARENT_GUID,
            children: &[],
        },
    }];
    assert_eq!(
        resolve_transaction_replay_watch_snapshots(&LcsLimits::default(), &input, &wrong_kind),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_kind",
        })
    );
}

#[test]
fn direct_security_rejects_unexpected_snapshot_results() {
    let input = TransactionReplayWatchInput::DirectSecurity {
        operation_index: 7,
        changed_key_guid: KEY_GUID,
        watch_mutation: key_context().with_event(REG_WATCH_SD_CHANGED),
    };
    let results = [TransactionReplaySnapshotResult {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: 7,
        kind: TransactionReplaySnapshotResultKind::EffectiveValue {
            key_guid: KEY_GUID,
            scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
            values: &[],
        },
    }];

    assert_eq!(
        resolve_transaction_replay_watch_snapshots(&LcsLimits::default(), &input, &results),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_unexpected",
        })
    );
}
