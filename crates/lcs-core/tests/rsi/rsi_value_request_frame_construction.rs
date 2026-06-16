use crate::common::{field};
use lcs_core::{
    LcsError, REG_SZ, RSI_DELETE_VALUE_ENTRY, RSI_QUERY_VALUES, RSI_REQUEST_HEADER_LEN,
    RSI_SET_BLANKET_TOMBSTONE, RSI_SET_VALUE,
    parse_rsi_delete_value_entry_request_payload, parse_rsi_query_values_request_payload,
    parse_rsi_request_header, parse_rsi_set_blanket_tombstone_request_payload,
    parse_rsi_set_value_request_payload, write_rsi_delete_value_entry_request_frame,
    write_rsi_query_values_request_frame, write_rsi_set_blanket_tombstone_request_frame,
    write_rsi_set_value_request_frame,
};

const KEY_GUID: [u8; 16] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];


#[test]
fn query_values_request_frame_writes_guid_name_and_query_all_flag() {
    let mut frame = [0u8; 96];
    let built =
        write_rsi_query_values_request_frame(&mut frame, 201, 31, KEY_GUID, b"", true).unwrap();

    let header = parse_rsi_request_header(&frame[..built.len]).unwrap();
    assert_eq!(header.total_len, built.len as u32);
    assert_eq!(header.request_id, 201);
    assert_eq!(header.op_code, RSI_QUERY_VALUES);
    assert_eq!(header.txn_id, 31);
    assert_eq!(built.retained.op_code, RSI_QUERY_VALUES);

    let payload =
        parse_rsi_query_values_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.value_name, field(b""));
    assert!(payload.query_all);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn set_value_request_frame_writes_value_payload_and_sequences() {
    let mut frame = [0u8; 128];
    let built = write_rsi_set_value_request_frame(
        &mut frame,
        202,
        32,
        KEY_GUID,
        b"Value",
        b"base",
        REG_SZ,
        b"data",
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
    )
    .unwrap();

    let header = parse_rsi_request_header(&frame[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_SET_VALUE);
    assert_eq!(header.txn_id, 32);
    let payload =
        parse_rsi_set_value_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.value_name, field(b"Value"));
    assert_eq!(payload.layer_name, field(b"base"));
    assert_eq!(payload.value_type, REG_SZ);
    assert_eq!(payload.data, field(b"data"));
    assert_eq!(payload.sequence, 0x0102_0304_0506_0708);
    assert_eq!(payload.expected_sequence, 0x1112_1314_1516_1718);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn delete_value_and_blanket_request_frames_match_wire_order() {
    let mut delete = [0u8; 96];
    let built = write_rsi_delete_value_entry_request_frame(
        &mut delete,
        203,
        33,
        KEY_GUID,
        b"Value",
        b"base",
    )
    .unwrap();
    let header = parse_rsi_request_header(&delete[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_DELETE_VALUE_ENTRY);
    assert_eq!(header.txn_id, 33);
    let payload =
        parse_rsi_delete_value_entry_request_payload(&delete[RSI_REQUEST_HEADER_LEN..built.len])
            .unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.value_name, field(b"Value"));
    assert_eq!(payload.layer_name, field(b"base"));
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut blanket = [0u8; 96];
    let built = write_rsi_set_blanket_tombstone_request_frame(
        &mut blanket,
        204,
        34,
        KEY_GUID,
        b"base",
        true,
        99,
    )
    .unwrap();
    let header = parse_rsi_request_header(&blanket[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_SET_BLANKET_TOMBSTONE);
    assert_eq!(header.txn_id, 34);
    let payload = parse_rsi_set_blanket_tombstone_request_payload(
        &blanket[RSI_REQUEST_HEADER_LEN..built.len],
    )
    .unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.layer_name, field(b"base"));
    assert!(payload.set);
    assert_eq!(payload.sequence, 99);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn value_request_frame_construction_rejects_short_output_buffers() {
    let required = RSI_REQUEST_HEADER_LEN + 16 + 4 + b"Value".len() + 4 + b"base".len();
    let mut frame = [0xaa; RSI_REQUEST_HEADER_LEN + 16 + 4 + 5 + 4 + 3];

    assert_eq!(
        write_rsi_delete_value_entry_request_frame(&mut frame, 205, 0, KEY_GUID, b"Value", b"base",),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: required - 1,
            required,
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
