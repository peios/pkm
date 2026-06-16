use crate::common::{field};
use lcs_core::{
    LcsAuditEventKind, LcsLimits, RSI_WRITE_KEY_FIELD_SD, RsiAbortTransactionRequestPayload,
    RsiBeginTransactionRequestPayload, RsiCommitTransactionRequestPayload,
    RsiCreateEntryRequestPayload, RsiCreateKeyRequestPayload, RsiDeleteEntryRequestPayload,
    RsiDeleteLayerRequestPayload, RsiDeleteValueEntryRequestPayload, RsiDropKeyRequestPayload,
    RsiEnumChildrenRequestPayload, RsiFlushRequestPayload, RsiHideEntryRequestPayload, RsiLookupRequestPayload, RsiQueryValuesRequestPayload,
    RsiReadKeyRequestPayload, RsiRequestHeader, RsiSetBlanketTombstoneRequestPayload,
    RsiSetValueRequestPayload, RsiSourceDataValidationFailure, RsiTrailingOptionalFieldsPlan,
    RsiTransactionMode, RsiWriteKeyRequestPayload, plan_source_validation_failure_audit_record,
};

const ROOT_GUID: [u8; 16] = [0x10; 16];
const CHILD_GUID: [u8; 16] = [0x20; 16];


fn trailing() -> RsiTrailingOptionalFieldsPlan {
    RsiTrailingOptionalFieldsPlan {
        ignored_trailing_len: 0,
    }
}

#[test]
fn rsi_common_header_contains_routing_not_caller_identity() {
    let header = RsiRequestHeader {
        total_len: 22,
        request_id: 7,
        op_code: 0x01,
        txn_id: 0,
    };

    assert_eq!(header.total_len, 22);
    assert_eq!(header.request_id, 7);
    assert_eq!(header.op_code, 0x01);
    assert_eq!(header.txn_id, 0);
}

#[test]
fn path_and_key_rsi_requests_do_not_include_caller_identity() {
    let child_name = field(b"Software");
    let layer_name = field(b"base");
    let sd = field(b"self-relative-sd");

    let lookup = RsiLookupRequestPayload {
        parent_guid: ROOT_GUID,
        child_name,
        trailing: trailing(),
    };
    let create_entry = RsiCreateEntryRequestPayload {
        parent_guid: ROOT_GUID,
        child_name,
        layer_name,
        child_guid: CHILD_GUID,
        sequence: 11,
        trailing: trailing(),
    };
    let hide_entry = RsiHideEntryRequestPayload {
        parent_guid: ROOT_GUID,
        child_name,
        layer_name,
        sequence: 12,
        trailing: trailing(),
    };
    let delete_entry = RsiDeleteEntryRequestPayload {
        parent_guid: ROOT_GUID,
        child_name,
        layer_name,
        trailing: trailing(),
    };
    let enum_children = RsiEnumChildrenRequestPayload {
        parent_guid: ROOT_GUID,
        trailing: trailing(),
    };
    let create_key = RsiCreateKeyRequestPayload {
        guid: CHILD_GUID,
        name: child_name,
        parent_guid: ROOT_GUID,
        sd,
        volatile: false,
        symlink: false,
        trailing: trailing(),
    };
    let read_key = RsiReadKeyRequestPayload {
        guid: CHILD_GUID,
        trailing: trailing(),
    };
    let write_key = RsiWriteKeyRequestPayload {
        guid: CHILD_GUID,
        field_mask: RSI_WRITE_KEY_FIELD_SD,
        sd: Some(sd),
        last_write_time: None,
        trailing: trailing(),
    };
    let drop_key = RsiDropKeyRequestPayload {
        guid: CHILD_GUID,
        trailing: trailing(),
    };

    assert_eq!(lookup.parent_guid, ROOT_GUID);
    assert_eq!(create_entry.child_guid, CHILD_GUID);
    assert_eq!(hide_entry.sequence, 12);
    assert_eq!(delete_entry.layer_name.data, b"base");
    assert_eq!(enum_children.parent_guid, ROOT_GUID);
    assert_eq!(create_key.sd.data, b"self-relative-sd");
    assert_eq!(read_key.guid, CHILD_GUID);
    assert_eq!(write_key.field_mask, RSI_WRITE_KEY_FIELD_SD);
    assert_eq!(drop_key.guid, CHILD_GUID);
}

#[test]
fn value_transaction_layer_and_flush_rsi_requests_do_not_include_caller_identity() {
    let value_name = field(b"Setting");
    let layer_name = field(b"base");
    let data = field(&[1, 2, 3]);
    let hive_name = field(b"Machine");

    let query_values = RsiQueryValuesRequestPayload {
        guid: CHILD_GUID,
        value_name,
        query_all: false,
        trailing: trailing(),
    };
    let set_value = RsiSetValueRequestPayload {
        guid: CHILD_GUID,
        value_name,
        layer_name,
        value_type: 3,
        data,
        sequence: 21,
        expected_sequence: 0,
        trailing: trailing(),
    };
    let delete_value = RsiDeleteValueEntryRequestPayload {
        guid: CHILD_GUID,
        value_name,
        layer_name,
        trailing: trailing(),
    };
    let blanket = RsiSetBlanketTombstoneRequestPayload {
        guid: CHILD_GUID,
        layer_name,
        set: true,
        sequence: 22,
        trailing: trailing(),
    };
    let begin = RsiBeginTransactionRequestPayload {
        transaction_id: 100,
        mode: RsiTransactionMode::ReadWrite,
        trailing: trailing(),
    };
    let commit = RsiCommitTransactionRequestPayload {
        transaction_id: 100,
        trailing: trailing(),
    };
    let abort = RsiAbortTransactionRequestPayload {
        transaction_id: 100,
        trailing: trailing(),
    };
    let delete_layer = RsiDeleteLayerRequestPayload {
        layer_name,
        trailing: trailing(),
    };
    let flush = RsiFlushRequestPayload {
        hive_name,
        trailing: trailing(),
    };

    assert_eq!(query_values.guid, CHILD_GUID);
    assert_eq!(set_value.data.data, &[1, 2, 3]);
    assert_eq!(delete_value.value_name.data, b"Setting");
    assert!(blanket.set);
    assert_eq!(begin.mode, RsiTransactionMode::ReadWrite);
    assert_eq!(commit.transaction_id, 100);
    assert_eq!(abort.transaction_id, 100);
    assert_eq!(delete_layer.layer_name.data, b"base");
    assert_eq!(flush.hive_name.data, b"Machine");
}

#[test]
fn source_validation_audit_is_source_scoped_not_caller_scoped() {
    let record = plan_source_validation_failure_audit_record(
        &LcsLimits::default(),
        3,
        Some("Machine"),
        Some(77),
        Some(0x20),
        Some(CHILD_GUID),
        RsiSourceDataValidationFailure::FutureSequenceNumber,
    )
    .expect("valid source-validation audit record");

    assert_eq!(
        record.event_kind,
        LcsAuditEventKind::SourceValidationFailure
    );
    assert_eq!(record.source_slot, 3);
    assert_eq!(record.hive_name, Some("Machine"));
    assert_eq!(record.request_id, Some(77));
    assert_eq!(record.op_code, Some(0x20));
    assert_eq!(record.key_guid, Some(CHILD_GUID));
}
