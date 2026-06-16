use lcs_core::{
    Guid, LcsError, RSI_ENUM_CHILDREN, RSI_QUERY_VALUES, RsiTransactionReplaySnapshotRequestRecord,
    RsiTransactionReplaySnapshotRequestTableSummary, TransactionReplaySnapshotPhase,
    TransactionReplaySnapshotQuery, TransactionReplaySnapshotQueryKind,
    TransactionReplayValueWatchScope, find_transaction_replay_snapshot_request_record,
    insert_transaction_replay_snapshot_request_record,
    release_transaction_replay_snapshot_request_record, retain_transaction_replay_snapshot_request,
    summarize_transaction_replay_snapshot_request_table,
};

const KEY_GUID: Guid = [0x40; 16];
const PARENT_GUID: Guid = [0x20; 16];

fn value_query(op: u64, name: &'static str) -> TransactionReplaySnapshotQuery<'static> {
    TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
            key_guid: KEY_GUID,
            scope: TransactionReplayValueWatchScope::NamedValue { name },
        },
    }
}

fn subkey_query(op: u64) -> TransactionReplaySnapshotQuery<'static> {
    TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::AfterCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotQueryKind::EffectiveSubkeys {
            parent_guid: PARENT_GUID,
        },
    }
}

fn record(
    request_id: u64,
    query: TransactionReplaySnapshotQuery<'static>,
) -> RsiTransactionReplaySnapshotRequestRecord<'static> {
    retain_transaction_replay_snapshot_request(request_id, query)
}

#[test]
fn request_table_inserts_finds_and_releases_out_of_order() {
    let mut storage = [None; 3];

    assert_eq!(
        insert_transaction_replay_snapshot_request_record(
            &mut storage,
            record(10, value_query(1, "Setting"))
        ),
        Ok(RsiTransactionReplaySnapshotRequestTableSummary {
            entries: 1,
            capacity: 3,
            full: false,
        })
    );
    assert_eq!(
        insert_transaction_replay_snapshot_request_record(
            &mut storage,
            record(11, subkey_query(2))
        ),
        Ok(RsiTransactionReplaySnapshotRequestTableSummary {
            entries: 2,
            capacity: 3,
            full: false,
        })
    );

    let found = find_transaction_replay_snapshot_request_record(&storage, 11)
        .expect("request 11 must be present");
    assert_eq!(found.request_id, 11);
    assert_eq!(found.retained.op_code, RSI_ENUM_CHILDREN);

    let released = release_transaction_replay_snapshot_request_record(&mut storage, 10)
        .expect("request 10 must release");
    assert_eq!(released.request_id, 10);
    assert_eq!(released.retained.op_code, RSI_QUERY_VALUES);
    assert_eq!(
        summarize_transaction_replay_snapshot_request_table(&storage),
        Ok(RsiTransactionReplaySnapshotRequestTableSummary {
            entries: 1,
            capacity: 3,
            full: false,
        })
    );

    assert_eq!(
        insert_transaction_replay_snapshot_request_record(
            &mut storage,
            record(12, value_query(3, "Other"))
        ),
        Ok(RsiTransactionReplaySnapshotRequestTableSummary {
            entries: 2,
            capacity: 3,
            full: false,
        })
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 12)
            .expect("request 12 must reuse a free slot")
            .retained
            .op_code,
        RSI_QUERY_VALUES
    );
}

#[test]
fn request_table_rejects_duplicate_without_mutation() {
    let mut storage = [None; 2];
    let original = value_query(4, "Original");

    insert_transaction_replay_snapshot_request_record(&mut storage, record(20, original))
        .expect("initial insert");

    assert_eq!(
        insert_transaction_replay_snapshot_request_record(
            &mut storage,
            record(20, subkey_query(5))
        ),
        Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id: 20 })
    );

    let found = find_transaction_replay_snapshot_request_record(&storage, 20)
        .expect("duplicate insert must not replace the original");
    assert_eq!(found.query, original);
    assert_eq!(found.retained.op_code, RSI_QUERY_VALUES);
    assert_eq!(
        summarize_transaction_replay_snapshot_request_table(&storage)
            .expect("table remains valid")
            .entries,
        1
    );
}

#[test]
fn request_table_rejects_full_without_mutation() {
    let mut storage = [None; 1];

    insert_transaction_replay_snapshot_request_record(
        &mut storage,
        record(30, value_query(6, "Only")),
    )
    .expect("initial insert");

    assert_eq!(
        insert_transaction_replay_snapshot_request_record(
            &mut storage,
            record(31, subkey_query(7))
        ),
        Err(LcsError::TransactionReplaySnapshotRequestTableFull { capacity: 1 })
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 30)
            .expect("full insert must not evict existing record")
            .query,
        value_query(6, "Only")
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 31),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 31 })
    );
}

#[test]
fn request_table_missing_lookup_and_release_fail_closed() {
    let mut storage = [None; 1];

    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 99),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 99 })
    );
    assert_eq!(
        release_transaction_replay_snapshot_request_record(&mut storage, 99),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 99 })
    );
}

#[test]
fn summary_rejects_corrupt_duplicate_existing_records() {
    let duplicate = record(40, value_query(8, "Setting"));
    let storage = [Some(duplicate), Some(duplicate)];

    assert_eq!(
        summarize_transaction_replay_snapshot_request_table(&storage),
        Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id: 40 })
    );
}

#[test]
fn insert_rejects_corrupt_duplicate_existing_records_without_mutation() {
    let duplicate = record(40, value_query(8, "Setting"));
    let mut storage = [Some(duplicate), Some(duplicate), None];

    assert_eq!(
        insert_transaction_replay_snapshot_request_record(
            &mut storage,
            record(41, value_query(9, "New"))
        ),
        Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id: 40 })
    );
    assert_eq!(storage[2], None);
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 41),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 41 })
    );
}
