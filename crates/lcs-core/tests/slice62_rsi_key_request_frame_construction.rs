use lcs_core::{
    LcsError, RSI_CREATE_KEY, RSI_DROP_KEY, RSI_READ_KEY, RSI_REQUEST_HEADER_LEN, RSI_WRITE_KEY,
    RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME, RSI_WRITE_KEY_FIELD_SD, RsiLengthPrefixedField,
    parse_rsi_create_key_request_payload, parse_rsi_drop_key_request_payload,
    parse_rsi_read_key_request_payload, parse_rsi_request_header,
    parse_rsi_write_key_request_payload, write_rsi_create_key_request_frame,
    write_rsi_drop_key_request_frame, write_rsi_read_key_request_frame,
    write_rsi_write_key_request_frame,
};

const KEY_GUID: [u8; 16] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const PARENT_GUID: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];

fn field(data: &[u8]) -> RsiLengthPrefixedField<'_> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
    }
}

#[test]
fn create_key_request_frame_writes_header_payload_and_boolean_shape() {
    let mut frame = [0u8; 128];
    let built = write_rsi_create_key_request_frame(
        &mut frame,
        101,
        77,
        KEY_GUID,
        b"Child",
        PARENT_GUID,
        b"self-relative-sd",
        true,
        false,
    )
    .unwrap();

    let header = parse_rsi_request_header(&frame[..built.len]).unwrap();
    assert_eq!(header.total_len, built.len as u32);
    assert_eq!(header.request_id, 101);
    assert_eq!(header.op_code, RSI_CREATE_KEY);
    assert_eq!(header.txn_id, 77);
    assert_eq!(built.retained.request_id, 101);
    assert_eq!(built.retained.op_code, RSI_CREATE_KEY);

    let payload =
        parse_rsi_create_key_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.name, field(b"Child"));
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.sd, field(b"self-relative-sd"));
    assert!(payload.volatile);
    assert!(!payload.symlink);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn read_and_drop_key_request_frames_are_guid_only_payloads() {
    let mut read = [0u8; 64];
    let built = write_rsi_read_key_request_frame(&mut read, 102, 78, KEY_GUID).unwrap();
    let header = parse_rsi_request_header(&read[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_READ_KEY);
    assert_eq!(header.txn_id, 78);
    let payload =
        parse_rsi_read_key_request_payload(&read[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut drop = [0u8; 64];
    let built = write_rsi_drop_key_request_frame(&mut drop, 103, 79, KEY_GUID).unwrap();
    let header = parse_rsi_request_header(&drop[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_DROP_KEY);
    assert_eq!(header.txn_id, 79);
    let payload =
        parse_rsi_drop_key_request_payload(&drop[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn write_key_request_frame_writes_masked_fields_in_bit_order() {
    let mut both = [0u8; 128];
    let built = write_rsi_write_key_request_frame(
        &mut both,
        104,
        80,
        KEY_GUID,
        Some(b"new-sd"),
        Some(0x1122_3344_5566_7788),
    )
    .unwrap();
    let header = parse_rsi_request_header(&both[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_WRITE_KEY);
    assert_eq!(header.txn_id, 80);
    let payload =
        parse_rsi_write_key_request_payload(&both[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(
        payload.field_mask,
        RSI_WRITE_KEY_FIELD_SD | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME
    );
    assert_eq!(payload.sd, Some(field(b"new-sd")));
    assert_eq!(payload.last_write_time, Some(0x1122_3344_5566_7788));
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut time_only = [0u8; 64];
    let built =
        write_rsi_write_key_request_frame(&mut time_only, 105, 81, KEY_GUID, None, Some(1234))
            .unwrap();
    let payload =
        parse_rsi_write_key_request_payload(&time_only[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.field_mask, RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME);
    assert_eq!(payload.sd, None);
    assert_eq!(payload.last_write_time, Some(1234));
}

#[test]
fn key_request_frame_construction_rejects_short_output_buffers() {
    let required = RSI_REQUEST_HEADER_LEN + 16 + 4 + b"Child".len() + 16 + 4 + b"sd".len() + 2;
    let mut frame = [0xaa; RSI_REQUEST_HEADER_LEN + 16 + 4 + 5 + 16 + 4 + 2 + 1];

    assert_eq!(
        write_rsi_create_key_request_frame(
            &mut frame,
            106,
            0,
            KEY_GUID,
            b"Child",
            PARENT_GUID,
            b"sd",
            false,
            false,
        ),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: required - 1,
            required,
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
