use lcs_core::{
    LcsError, RSI_TXN_READ_ONLY, RSI_TXN_READ_WRITE, RsiLengthPrefixedField, RsiTransactionMode,
    parse_rsi_abort_transaction_request_payload, parse_rsi_begin_transaction_request_payload,
    parse_rsi_commit_transaction_request_payload, parse_rsi_delete_layer_request_payload,
    parse_rsi_flush_request_payload,
};

fn push_len_prefixed(payload: &mut Vec<u8>, data: &[u8]) {
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
}

fn field<'a>(data: &'a [u8]) -> RsiLengthPrefixedField<'a> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
    }
}

#[test]
fn begin_transaction_request_payload_reads_id_and_mode() {
    let mut read_write = Vec::new();
    read_write.extend_from_slice(&77u64.to_le_bytes());
    read_write.extend_from_slice(&RSI_TXN_READ_WRITE.to_le_bytes());
    read_write.push(0xaa);

    let parsed_read_write = parse_rsi_begin_transaction_request_payload(&read_write).unwrap();
    assert_eq!(parsed_read_write.transaction_id, 77);
    assert_eq!(parsed_read_write.mode, RsiTransactionMode::ReadWrite);
    assert_eq!(parsed_read_write.mode.code(), RSI_TXN_READ_WRITE);
    assert_eq!(parsed_read_write.trailing.ignored_trailing_len, 1);

    let mut read_only = Vec::new();
    read_only.extend_from_slice(&78u64.to_le_bytes());
    read_only.extend_from_slice(&RSI_TXN_READ_ONLY.to_le_bytes());
    assert_eq!(
        parse_rsi_begin_transaction_request_payload(&read_only)
            .unwrap()
            .mode,
        RsiTransactionMode::ReadOnly
    );
}

#[test]
fn commit_and_abort_transaction_payloads_are_transaction_id_only() {
    let mut commit = Vec::new();
    commit.extend_from_slice(&88u64.to_le_bytes());
    commit.extend_from_slice(&[0xbb, 0xcc]);
    let parsed_commit = parse_rsi_commit_transaction_request_payload(&commit).unwrap();
    assert_eq!(parsed_commit.transaction_id, 88);
    assert_eq!(parsed_commit.trailing.ignored_trailing_len, 2);

    let mut abort = Vec::new();
    abort.extend_from_slice(&99u64.to_le_bytes());
    let parsed_abort = parse_rsi_abort_transaction_request_payload(&abort).unwrap();
    assert_eq!(parsed_abort.transaction_id, 99);
    assert_eq!(parsed_abort.trailing.ignored_trailing_len, 0);
}

#[test]
fn delete_layer_and_flush_payloads_are_length_prefixed_names() {
    let mut delete_layer = Vec::new();
    push_len_prefixed(&mut delete_layer, b"MachinePolicy");
    delete_layer.push(0xdd);
    let parsed_delete = parse_rsi_delete_layer_request_payload(&delete_layer).unwrap();
    assert_eq!(parsed_delete.layer_name, field(b"MachinePolicy"));
    assert_eq!(parsed_delete.trailing.ignored_trailing_len, 1);

    let mut flush = Vec::new();
    push_len_prefixed(&mut flush, b"Machine");
    let parsed_flush = parse_rsi_flush_request_payload(&flush).unwrap();
    assert_eq!(parsed_flush.hive_name, field(b"Machine"));
    assert_eq!(parsed_flush.trailing.ignored_trailing_len, 0);
}

#[test]
fn transaction_layer_and_flush_parsers_reject_unknown_mode_and_truncation() {
    let mut unknown_mode = Vec::new();
    unknown_mode.extend_from_slice(&1u64.to_le_bytes());
    unknown_mode.extend_from_slice(&2u32.to_le_bytes());
    assert_eq!(
        parse_rsi_begin_transaction_request_payload(&unknown_mode),
        Err(LcsError::UnknownRsiTransactionMode(2))
    );

    assert_eq!(
        parse_rsi_commit_transaction_request_payload(&[0; 7]),
        Err(LcsError::RsiMessageTooShort { len: 7, min: 8 })
    );

    let mut truncated_layer = Vec::new();
    truncated_layer.extend_from_slice(&4u32.to_le_bytes());
    truncated_layer.extend_from_slice(b"abc");
    assert_eq!(
        parse_rsi_delete_layer_request_payload(&truncated_layer),
        Err(LcsError::RsiMessageTooShort { len: 7, min: 8 })
    );
}
