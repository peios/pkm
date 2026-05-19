use lcs_core::{
    LcsError, RSI_ABORT_TRANSACTION, RSI_BEGIN_TRANSACTION, RSI_COMMIT_TRANSACTION,
    RSI_DELETE_LAYER, RSI_FLUSH, RSI_REQUEST_HEADER_LEN, RsiLengthPrefixedField,
    RsiTransactionMode, parse_rsi_abort_transaction_request_payload,
    parse_rsi_begin_transaction_request_payload, parse_rsi_commit_transaction_request_payload,
    parse_rsi_delete_layer_request_payload, parse_rsi_flush_request_payload,
    parse_rsi_request_header, write_rsi_abort_transaction_request_frame,
    write_rsi_begin_transaction_request_frame, write_rsi_commit_transaction_request_frame,
    write_rsi_delete_layer_request_frame, write_rsi_flush_request_frame,
};

fn field(data: &[u8]) -> RsiLengthPrefixedField<'_> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
    }
}

#[test]
fn begin_transaction_request_frame_writes_id_and_mode() {
    let mut frame = [0u8; 64];
    let built = write_rsi_begin_transaction_request_frame(
        &mut frame,
        301,
        0,
        0x0102_0304_0506_0708,
        RsiTransactionMode::ReadOnly,
    )
    .unwrap();

    let header = parse_rsi_request_header(&frame[..built.len]).unwrap();
    assert_eq!(header.total_len, built.len as u32);
    assert_eq!(header.request_id, 301);
    assert_eq!(header.op_code, RSI_BEGIN_TRANSACTION);
    assert_eq!(header.txn_id, 0);
    assert_eq!(built.retained.op_code, RSI_BEGIN_TRANSACTION);

    let payload =
        parse_rsi_begin_transaction_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len])
            .unwrap();
    assert_eq!(payload.transaction_id, 0x0102_0304_0506_0708);
    assert_eq!(payload.mode, RsiTransactionMode::ReadOnly);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn commit_and_abort_transaction_request_frames_are_transaction_id_only() {
    let mut commit = [0u8; 64];
    let built = write_rsi_commit_transaction_request_frame(&mut commit, 302, 9, 77).unwrap();
    let header = parse_rsi_request_header(&commit[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_COMMIT_TRANSACTION);
    assert_eq!(header.txn_id, 9);
    let payload =
        parse_rsi_commit_transaction_request_payload(&commit[RSI_REQUEST_HEADER_LEN..built.len])
            .unwrap();
    assert_eq!(payload.transaction_id, 77);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut abort = [0u8; 64];
    let built = write_rsi_abort_transaction_request_frame(&mut abort, 303, 10, 88).unwrap();
    let header = parse_rsi_request_header(&abort[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_ABORT_TRANSACTION);
    assert_eq!(header.txn_id, 10);
    let payload =
        parse_rsi_abort_transaction_request_payload(&abort[RSI_REQUEST_HEADER_LEN..built.len])
            .unwrap();
    assert_eq!(payload.transaction_id, 88);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn delete_layer_and_flush_request_frames_are_length_prefixed_names() {
    let mut delete = [0u8; 64];
    let built =
        write_rsi_delete_layer_request_frame(&mut delete, 304, 0, b"MachinePolicy").unwrap();
    let header = parse_rsi_request_header(&delete[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_DELETE_LAYER);
    assert_eq!(header.txn_id, 0);
    let payload =
        parse_rsi_delete_layer_request_payload(&delete[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.layer_name, field(b"MachinePolicy"));
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut flush = [0u8; 64];
    let built = write_rsi_flush_request_frame(&mut flush, 305, 0, b"Machine").unwrap();
    let header = parse_rsi_request_header(&flush[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_FLUSH);
    assert_eq!(header.txn_id, 0);
    let payload =
        parse_rsi_flush_request_payload(&flush[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.hive_name, field(b"Machine"));
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn transaction_layer_flush_frame_construction_rejects_short_output_buffers() {
    let required = RSI_REQUEST_HEADER_LEN + 4 + b"MachinePolicy".len();
    let mut frame = [0xaa; RSI_REQUEST_HEADER_LEN + 4 + 12];

    assert_eq!(
        write_rsi_delete_layer_request_frame(&mut frame, 306, 0, b"MachinePolicy"),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: required - 1,
            required,
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
