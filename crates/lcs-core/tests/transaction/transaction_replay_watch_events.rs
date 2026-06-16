use lcs_core::{
    EffectiveValueWatchEvent, EnumeratedSubkey, EnumeratedValue, Guid, LcsError, LcsLimits,
    REG_DWORD, REG_SZ, REG_WATCH_KEY_DELETED, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED,
    REG_WATCH_SUBKEY_DELETED, REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET, RegistryValueType,
    ResolvedPathEntry, ResolvedValueEntry, TransactionReplaySubkeySnapshots,
    TransactionReplayValueSnapshots, TransactionReplayValueWatchScope, TransactionReplayWatchEvent,
    TransactionReplayWatchInput, TransactionReplayWatchSnapshots, WatchAncestryContext,
    WatchMutationContext, for_each_transaction_replay_watch_event,
};

const ROOT_GUID: Guid = [0x10; 16];
const PARENT_GUID: Guid = [0x20; 16];
const CHILD_GUID: Guid = [0x30; 16];
const KEY_GUID: Guid = [0x40; 16];
const SECURITY_ANCESTORS: [Guid; 2] = [ROOT_GUID, KEY_GUID];
const SECURITY_PATH: [&str; 2] = ["Machine", "Policy"];
const PARENT_ANCESTORS: [Guid; 2] = [ROOT_GUID, PARENT_GUID];
const PARENT_PATH: [&str; 2] = ["Machine", "Parent"];
const CHILD_ANCESTORS: [Guid; 3] = [ROOT_GUID, PARENT_GUID, CHILD_GUID];
const CHILD_PATH: [&str; 3] = ["Machine", "Parent", "Child"];

fn key_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &SECURITY_ANCESTORS,
        path_components: &SECURITY_PATH,
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

fn value(
    name: &'static str,
    value_type: u32,
    data: &'static [u8],
    layer: &'static str,
    sequence: u64,
) -> EnumeratedValue<'static> {
    EnumeratedValue {
        name,
        value: ResolvedValueEntry {
            value_type: RegistryValueType::from_code(value_type).expect("known value type"),
            data,
            layer,
            precedence: 0,
            sequence,
        },
    }
}

fn path(guid: Guid, layer: &'static str, sequence: u64) -> ResolvedPathEntry<'static> {
    ResolvedPathEntry {
        guid,
        layer,
        precedence: 0,
        sequence,
    }
}

fn subkey(name: &'static str, guid: Guid, sequence: u64) -> EnumeratedSubkey<'static> {
    EnumeratedSubkey {
        child_name: name,
        path: path(guid, "base", sequence),
    }
}

fn collect_events<'a>(
    input: &TransactionReplayWatchInput<'a>,
    snapshots: TransactionReplayWatchSnapshots<'a>,
) -> Result<(usize, Vec<TransactionReplayWatchEvent<'a>>), LcsError> {
    let mut events = Vec::new();
    let count = for_each_transaction_replay_watch_event(
        &LcsLimits::default(),
        input,
        snapshots,
        |event| {
            events.push(event);
            Ok(())
        },
    )?;
    Ok((count, events))
}

#[test]
fn direct_security_replay_emits_retained_sd_changed_event() {
    let mutation = WatchMutationContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &SECURITY_ANCESTORS,
        path_components: &SECURITY_PATH,
        event_type: REG_WATCH_SD_CHANGED,
    };
    let input = TransactionReplayWatchInput::DirectSecurity {
        operation_index: 1,
        changed_key_guid: KEY_GUID,
        watch_mutation: mutation,
    };

    assert_eq!(
        collect_events(&input, TransactionReplayWatchSnapshots::DirectSecurity),
        Ok((
            1,
            vec![TransactionReplayWatchEvent {
                operation_index: 1,
                mutation,
                name: "",
            }],
        ))
    );
}

#[test]
fn named_value_replay_diffs_snapshots_using_retained_key_context() {
    let input = TransactionReplayWatchInput::EffectiveValue {
        operation_index: 2,
        kind: lcs_core::TransactionMutationLogKind::SetValue,
        key_guid: KEY_GUID,
        watch_context: key_context(),
        scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
        layer: "base",
        sequence: Some(10),
        requires_before_snapshot: true,
        requires_after_snapshot: true,
    };
    let before = [value("Setting", REG_SZ, b"old", "base", 1)];
    let after = [value("Setting", REG_SZ, b"new", "base", 10)];

    assert_eq!(
        collect_events(
            &input,
            TransactionReplayWatchSnapshots::EffectiveValue(TransactionReplayValueSnapshots {
                before: &before,
                after: &after,
            }),
        ),
        Ok((
            1,
            vec![TransactionReplayWatchEvent {
                operation_index: 2,
                mutation: key_context().with_event(REG_WATCH_VALUE_SET),
                name: "Setting",
            }],
        ))
    );
}

#[test]
fn all_value_replay_emits_each_effective_value_change() {
    let input = TransactionReplayWatchInput::EffectiveValue {
        operation_index: 3,
        kind: lcs_core::TransactionMutationLogKind::BlanketTombstone,
        key_guid: KEY_GUID,
        watch_context: key_context(),
        scope: TransactionReplayValueWatchScope::AllValues,
        layer: "base",
        sequence: Some(20),
        requires_before_snapshot: true,
        requires_after_snapshot: true,
    };
    let before = [
        value("Old", REG_DWORD, &[1, 0, 0, 0], "base", 1),
        value("Changed", REG_SZ, b"old", "base", 2),
    ];
    let after = [
        value("Changed", REG_SZ, b"new", "policy", 20),
        value("New", REG_DWORD, &[2, 0, 0, 0], "policy", 21),
    ];

    assert_eq!(
        collect_events(
            &input,
            TransactionReplayWatchSnapshots::EffectiveValue(TransactionReplayValueSnapshots {
                before: &before,
                after: &after,
            }),
        ),
        Ok((
            3,
            vec![
                TransactionReplayWatchEvent {
                    operation_index: 3,
                    mutation: key_context().with_event(REG_WATCH_VALUE_DELETED),
                    name: "Old",
                },
                TransactionReplayWatchEvent {
                    operation_index: 3,
                    mutation: key_context().with_event(REG_WATCH_VALUE_SET),
                    name: "Changed",
                },
                TransactionReplayWatchEvent {
                    operation_index: 3,
                    mutation: key_context().with_event(REG_WATCH_VALUE_SET),
                    name: "New",
                },
            ],
        ))
    );
}

#[test]
fn subkey_replay_emits_parent_event_and_child_key_deleted_event() {
    let input = TransactionReplayWatchInput::EffectiveSubkey {
        operation_index: 4,
        kind: lcs_core::TransactionMutationLogKind::DeleteKey,
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
    let before = [subkey("Child", CHILD_GUID, 1)];
    let after = [];

    assert_eq!(
        collect_events(
            &input,
            TransactionReplayWatchSnapshots::EffectiveSubkey(TransactionReplaySubkeySnapshots {
                before_children: &before,
                after_children: &after,
                child_before: Some(path(CHILD_GUID, "base", 1)),
                child_after: None,
            }),
        ),
        Ok((
            2,
            vec![
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
            ],
        ))
    );
}

#[test]
fn create_key_replay_rejects_unexpected_child_visibility_snapshots_before_emit() {
    let input = TransactionReplayWatchInput::EffectiveSubkey {
        operation_index: 5,
        kind: lcs_core::TransactionMutationLogKind::CreateKey,
        parent_guid: PARENT_GUID,
        parent_watch_context: parent_context(),
        child_visibility_watch_context: None,
        child_name: "Child",
        layer: "policy",
        target_guid: Some(CHILD_GUID),
        sequence: Some(30),
        requires_before_snapshot: true,
        requires_after_snapshot: true,
        evaluate_orphaning: false,
        publish_new_key_guid: true,
    };
    let before = [];
    let after = [subkey("Child", CHILD_GUID, 30)];
    let mut emitted = Vec::new();

    assert_eq!(
        for_each_transaction_replay_watch_event(
            &LcsLimits::default(),
            &input,
            TransactionReplayWatchSnapshots::EffectiveSubkey(TransactionReplaySubkeySnapshots {
                before_children: &before,
                after_children: &after,
                child_before: None,
                child_after: Some(path(CHILD_GUID, "policy", 30)),
            }),
            |event| {
                emitted.push(event);
                Ok(())
            },
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_path.child_visibility_snapshot",
        })
    );
    assert!(emitted.is_empty());
}

#[test]
fn create_key_replay_emits_subkey_created_without_child_visibility_context() {
    let input = TransactionReplayWatchInput::EffectiveSubkey {
        operation_index: 6,
        kind: lcs_core::TransactionMutationLogKind::CreateKey,
        parent_guid: PARENT_GUID,
        parent_watch_context: parent_context(),
        child_visibility_watch_context: None,
        child_name: "Child",
        layer: "policy",
        target_guid: Some(CHILD_GUID),
        sequence: Some(30),
        requires_before_snapshot: true,
        requires_after_snapshot: true,
        evaluate_orphaning: false,
        publish_new_key_guid: true,
    };
    let before = [];
    let after = [subkey("Child", CHILD_GUID, 30)];

    assert_eq!(
        collect_events(
            &input,
            TransactionReplayWatchSnapshots::EffectiveSubkey(TransactionReplaySubkeySnapshots {
                before_children: &before,
                after_children: &after,
                child_before: None,
                child_after: None,
            }),
        ),
        Ok((
            1,
            vec![TransactionReplayWatchEvent {
                operation_index: 6,
                mutation: parent_context().with_event(REG_WATCH_SUBKEY_CREATED),
                name: "Child",
            }],
        ))
    );
}

#[test]
fn replay_event_derivation_fails_closed_on_snapshot_kind_mismatch() {
    let input = TransactionReplayWatchInput::DirectSecurity {
        operation_index: 7,
        changed_key_guid: KEY_GUID,
        watch_mutation: key_context().with_event(REG_WATCH_SD_CHANGED),
    };

    assert_eq!(
        collect_events(
            &input,
            TransactionReplayWatchSnapshots::EffectiveValue(TransactionReplayValueSnapshots {
                before: &[],
                after: &[],
            }),
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_kind",
        })
    );
}

#[test]
fn direct_security_replay_rejects_non_sd_changed_event_before_emit() {
    let input = TransactionReplayWatchInput::DirectSecurity {
        operation_index: 8,
        changed_key_guid: KEY_GUID,
        watch_mutation: key_context().with_event(REG_WATCH_VALUE_SET),
    };
    let mut emitted = Vec::new();

    assert_eq!(
        for_each_transaction_replay_watch_event(
            &LcsLimits::default(),
            &input,
            TransactionReplayWatchSnapshots::DirectSecurity,
            |event| {
                emitted.push(event);
                Ok(())
            },
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_mutation.event_type",
        })
    );
    assert!(emitted.is_empty());
}

#[test]
fn named_value_replay_rejects_out_of_scope_snapshots_before_emit() {
    let input = TransactionReplayWatchInput::EffectiveValue {
        operation_index: 9,
        kind: lcs_core::TransactionMutationLogKind::SetValue,
        key_guid: KEY_GUID,
        watch_context: key_context(),
        scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
        layer: "base",
        sequence: Some(10),
        requires_before_snapshot: true,
        requires_after_snapshot: true,
    };
    let after = [value("Other", REG_SZ, b"new", "base", 10)];
    let mut emitted = Vec::new();

    assert_eq!(
        for_each_transaction_replay_watch_event(
            &LcsLimits::default(),
            &input,
            TransactionReplayWatchSnapshots::EffectiveValue(TransactionReplayValueSnapshots {
                before: &[],
                after: &after,
            }),
            |event| {
                emitted.push(event);
                Ok(())
            },
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.snapshot_scope",
        })
    );
    assert!(emitted.is_empty());
}

#[test]
fn event_type_helpers_still_match_emitted_value_event_vocabulary() {
    assert_eq!(
        EffectiveValueWatchEvent::ValueSet { name: "Setting" }.event_type(),
        REG_WATCH_VALUE_SET
    );
    assert_eq!(
        EffectiveValueWatchEvent::ValueDeleted { name: "Setting" }.event_type(),
        REG_WATCH_VALUE_DELETED
    );
}
