use lcs_core::{
    Guid, LcsError, TransactionReplaySnapshotPhase, TransactionReplaySnapshotResult,
    TransactionReplaySnapshotResultKind, TransactionReplaySnapshotResultTableSummary,
    TransactionReplayValueWatchScope, copy_transaction_replay_snapshot_results,
    insert_transaction_replay_snapshot_result,
};

const KEY_GUID: Guid = [0x40; 16];
const OTHER_KEY_GUID: Guid = [0x41; 16];

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

fn dummy_result() -> TransactionReplaySnapshotResult<'static> {
    value_result(99, OTHER_KEY_GUID, "Dummy")
}

#[test]
fn result_table_packs_dense_prefix_in_table_order() {
    let first = value_result(1, KEY_GUID, "One");
    let second = value_result(2, OTHER_KEY_GUID, "Two");
    let mut table = [None; 4];
    insert_transaction_replay_snapshot_result(&mut table, first).expect("insert first");
    insert_transaction_replay_snapshot_result(&mut table, second).expect("insert second");
    let mut output = [dummy_result(); 4];

    let summary =
        copy_transaction_replay_snapshot_results(&table, &mut output).expect("copy results");

    assert_eq!(
        summary,
        TransactionReplaySnapshotResultTableSummary {
            entries: 2,
            capacity: 4,
            effective_value_results: 2,
            effective_subkey_results: 0,
            child_visibility_results: 0,
        },
    );
    assert_eq!(&output[..summary.entries], &[first, second]);
    assert_eq!(output[2], dummy_result());
    assert_eq!(output[3], dummy_result());
}

#[test]
fn result_table_pack_rejects_small_output_before_mutation() {
    let first = value_result(3, KEY_GUID, "One");
    let second = value_result(4, OTHER_KEY_GUID, "Two");
    let mut table = [None; 2];
    insert_transaction_replay_snapshot_result(&mut table, first).expect("insert first");
    insert_transaction_replay_snapshot_result(&mut table, second).expect("insert second");
    let original = dummy_result();
    let mut output = [original; 1];

    assert_eq!(
        copy_transaction_replay_snapshot_results(&table, &mut output),
        Err(LcsError::TransactionReplaySnapshotStorageFull {
            field: "replay_snapshot.result_output",
            required: 2,
            capacity: 1,
        }),
    );
    assert_eq!(output, [original]);
}

#[test]
fn result_table_pack_rejects_sparse_source_before_mutation() {
    let table = [None, Some(value_result(5, KEY_GUID, "One"))];
    let original = dummy_result();
    let mut output = [original; 2];

    assert_eq!(
        copy_transaction_replay_snapshot_results(&table, &mut output),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_snapshot.result_table_dense_prefix",
        }),
    );
    assert_eq!(output, [original; 2]);
}
