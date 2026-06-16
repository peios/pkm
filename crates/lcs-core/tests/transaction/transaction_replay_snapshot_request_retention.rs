use lcs_core::{
    Guid, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_QUERY_VALUES, RsiRetainedRequest,
    TransactionReplaySnapshotPhase, TransactionReplaySnapshotQuery,
    TransactionReplaySnapshotQueryKind, TransactionReplayValueWatchScope,
    retain_transaction_replay_snapshot_request,
    write_transaction_replay_snapshot_query_request_frame,
};

const KEY_GUID: Guid = [0x40; 16];
const PARENT_GUID: Guid = [0x20; 16];

fn assert_retained_record_matches_frame(query: TransactionReplaySnapshotQuery<'static>) {
    let retained = retain_transaction_replay_snapshot_request(901, query);
    let mut frame = [0xaa; 128];
    let built = write_transaction_replay_snapshot_query_request_frame(&mut frame, 901, query)
        .expect("snapshot query frame");

    assert_eq!(retained.request_id, 901);
    assert_eq!(retained.query, query);
    assert_eq!(retained.retained, built.retained);
}

#[test]
fn retained_named_value_snapshot_request_preserves_query_identity_and_opcode() {
    let query = TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: 2,
        kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
            key_guid: KEY_GUID,
            scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
        },
    };

    let retained = retain_transaction_replay_snapshot_request(902, query);

    assert_eq!(retained.request_id, 902);
    assert_eq!(retained.query, query);
    assert_eq!(
        retained.retained,
        RsiRetainedRequest {
            request_id: 902,
            op_code: RSI_QUERY_VALUES,
        }
    );
    assert_retained_record_matches_frame(query);
}

#[test]
fn retained_all_values_snapshot_request_uses_query_values_opcode() {
    let query = TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::AfterCommit,
        operation_index: 3,
        kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
            key_guid: KEY_GUID,
            scope: TransactionReplayValueWatchScope::AllValues,
        },
    };

    let retained = retain_transaction_replay_snapshot_request(903, query);

    assert_eq!(
        retained.retained,
        RsiRetainedRequest {
            request_id: 903,
            op_code: RSI_QUERY_VALUES,
        }
    );
    assert_retained_record_matches_frame(query);
}

#[test]
fn retained_effective_subkey_snapshot_request_uses_enum_children_opcode() {
    let query = TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: 4,
        kind: TransactionReplaySnapshotQueryKind::EffectiveSubkeys {
            parent_guid: PARENT_GUID,
        },
    };

    let retained = retain_transaction_replay_snapshot_request(904, query);

    assert_eq!(
        retained.retained,
        RsiRetainedRequest {
            request_id: 904,
            op_code: RSI_ENUM_CHILDREN,
        }
    );
    assert_retained_record_matches_frame(query);
}

#[test]
fn retained_child_visibility_snapshot_request_uses_lookup_opcode() {
    let query = TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::AfterCommit,
        operation_index: 5,
        kind: TransactionReplaySnapshotQueryKind::ChildVisibility {
            parent_guid: PARENT_GUID,
            child_name: "Child",
        },
    };

    let retained = retain_transaction_replay_snapshot_request(905, query);

    assert_eq!(
        retained.retained,
        RsiRetainedRequest {
            request_id: 905,
            op_code: RSI_LOOKUP,
        }
    );
    assert_retained_record_matches_frame(query);
}
