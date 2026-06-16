use lcs_core::{
    Guid, LcsError, NIL_GUID, ResolvedPathEntry, TransactionReplaySnapshotPhase,
    TransactionReplaySnapshotResult, TransactionReplaySnapshotResultKind,
    TransactionReplaySnapshotResultTableSummary, TransactionReplayValueWatchScope,
    for_each_transaction_replay_snapshot_result, insert_transaction_replay_snapshot_result,
    summarize_transaction_replay_snapshot_result_table,
};

const KEY_GUID: Guid = [0x40; 16];
const OTHER_KEY_GUID: Guid = [0x41; 16];
const PARENT_GUID: Guid = [0x20; 16];
const CHILD_GUID: Guid = [0x30; 16];

fn value_result(
    op: u64,
    key_guid: Guid,
    name: &'static str,
) -> TransactionReplaySnapshotResult<'static> {
    TransactionReplaySnapshotResult {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotResultKind::EffectiveValue {
            key_guid,
            scope: TransactionReplayValueWatchScope::NamedValue { name },
            values: &[],
        },
    }
}

fn subkey_result(op: u64) -> TransactionReplaySnapshotResult<'static> {
    TransactionReplaySnapshotResult {
        phase: TransactionReplaySnapshotPhase::AfterCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotResultKind::EffectiveSubkeys {
            parent_guid: PARENT_GUID,
            children: &[],
        },
    }
}

fn child_result(op: u64, child_name: &'static str) -> TransactionReplaySnapshotResult<'static> {
    TransactionReplaySnapshotResult {
        phase: TransactionReplaySnapshotPhase::AfterCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotResultKind::ChildVisibility {
            parent_guid: PARENT_GUID,
            child_name,
            child: Some(ResolvedPathEntry {
                guid: CHILD_GUID,
                layer: "policy",
                precedence: 10,
                sequence: 70,
            }),
        },
    }
}

#[test]
fn result_table_insert_summarize_and_iteration_preserve_dense_order() {
    let value = value_result(1, KEY_GUID, "Setting");
    let child = child_result(2, "Child");
    let subkey = subkey_result(3);
    let mut storage = [None; 4];

    assert_eq!(
        insert_transaction_replay_snapshot_result(&mut storage, value),
        Ok(TransactionReplaySnapshotResultTableSummary {
            entries: 1,
            capacity: 4,
            effective_value_results: 1,
            effective_subkey_results: 0,
            child_visibility_results: 0,
        }),
    );
    assert_eq!(
        insert_transaction_replay_snapshot_result(&mut storage, child),
        Ok(TransactionReplaySnapshotResultTableSummary {
            entries: 2,
            capacity: 4,
            effective_value_results: 1,
            effective_subkey_results: 0,
            child_visibility_results: 1,
        }),
    );
    assert_eq!(
        insert_transaction_replay_snapshot_result(&mut storage, subkey),
        Ok(TransactionReplaySnapshotResultTableSummary {
            entries: 3,
            capacity: 4,
            effective_value_results: 1,
            effective_subkey_results: 1,
            child_visibility_results: 1,
        }),
    );

    let mut visited = Vec::new();
    assert_eq!(
        for_each_transaction_replay_snapshot_result(&storage, |result| {
            visited.push(result.operation_index);
            Ok(())
        }),
        Ok(TransactionReplaySnapshotResultTableSummary {
            entries: 3,
            capacity: 4,
            effective_value_results: 1,
            effective_subkey_results: 1,
            child_visibility_results: 1,
        }),
    );
    assert_eq!(visited, vec![1, 2, 3]);
}

#[test]
fn duplicate_result_identity_is_rejected_before_mutation() {
    let first = child_result(4, "Child");
    let duplicate_folded_name = child_result(4, "child");
    let mut storage = [None; 2];

    assert_eq!(
        insert_transaction_replay_snapshot_result(&mut storage, first),
        Ok(TransactionReplaySnapshotResultTableSummary {
            entries: 1,
            capacity: 2,
            effective_value_results: 0,
            effective_subkey_results: 0,
            child_visibility_results: 1,
        }),
    );
    assert_eq!(
        insert_transaction_replay_snapshot_result(&mut storage, duplicate_folded_name),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_snapshot.result_duplicate",
        }),
    );
    assert_eq!(storage[0], Some(first));
    assert_eq!(storage[1], None);
}

#[test]
fn full_result_table_fails_before_mutation() {
    let first = value_result(5, KEY_GUID, "One");
    let second = value_result(6, OTHER_KEY_GUID, "Two");
    let mut storage = [None; 1];

    assert_eq!(
        insert_transaction_replay_snapshot_result(&mut storage, first),
        Ok(TransactionReplaySnapshotResultTableSummary {
            entries: 1,
            capacity: 1,
            effective_value_results: 1,
            effective_subkey_results: 0,
            child_visibility_results: 0,
        }),
    );
    assert_eq!(
        insert_transaction_replay_snapshot_result(&mut storage, second),
        Err(LcsError::TransactionReplaySnapshotStorageFull {
            field: "replay_snapshot.results",
            required: 2,
            capacity: 1,
        }),
    );
    assert_eq!(storage, [Some(first)]);
}

#[test]
fn sparse_result_table_is_corrupt_and_fails_closed() {
    let storage = [None, Some(value_result(7, KEY_GUID, "Setting"))];

    assert_eq!(
        summarize_transaction_replay_snapshot_result_table(&storage),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_snapshot.result_table_dense_prefix",
        }),
    );
}

#[test]
fn invalid_result_identity_is_rejected() {
    let mut storage = [None; 1];
    let zero_operation = value_result(0, KEY_GUID, "Setting");
    let nil_guid = value_result(8, NIL_GUID, "Setting");

    assert_eq!(
        insert_transaction_replay_snapshot_result(&mut storage, zero_operation),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_snapshot.operation_index",
        }),
    );
    assert_eq!(
        insert_transaction_replay_snapshot_result(&mut storage, nil_guid),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_snapshot.key_guid",
        }),
    );
    assert_eq!(storage, [None]);
}

#[test]
fn result_iteration_propagates_visitor_failure() {
    let mut storage = [None; 2];
    insert_transaction_replay_snapshot_result(&mut storage, value_result(9, KEY_GUID, "Setting"))
        .expect("insert value");

    assert_eq!(
        for_each_transaction_replay_snapshot_result(&storage, |_| {
            Err(LcsError::InvalidTransactionMutationLogEntry { field: "visitor" })
        }),
        Err(LcsError::InvalidTransactionMutationLogEntry { field: "visitor" }),
    );
}
