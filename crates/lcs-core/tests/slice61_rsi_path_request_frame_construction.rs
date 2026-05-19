use lcs_core::{
    LcsError, RSI_CREATE_ENTRY, RSI_DELETE_ENTRY, RSI_ENUM_CHILDREN, RSI_HIDE_ENTRY, RSI_LOOKUP,
    RSI_REQUEST_HEADER_LEN, RsiLengthPrefixedField, RsiRetainedRequest,
    parse_rsi_create_entry_request_payload, parse_rsi_delete_entry_request_payload,
    parse_rsi_enum_children_request_payload, parse_rsi_hide_entry_request_payload,
    parse_rsi_lookup_request_payload, parse_rsi_request_header,
    write_rsi_create_entry_request_frame, write_rsi_delete_entry_request_frame,
    write_rsi_enum_children_request_frame, write_rsi_hide_entry_request_frame,
    write_rsi_lookup_request_frame,
};

const PARENT_GUID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const CHILD_GUID: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

fn field(data: &[u8]) -> RsiLengthPrefixedField<'_> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
    }
}

#[test]
fn lookup_request_frame_writes_common_header_and_payload() {
    let mut frame = [0xcc; 96];
    let built = write_rsi_lookup_request_frame(
        &mut frame,
        0x1112_1314_1516_1718,
        99,
        PARENT_GUID,
        b"Child",
    )
    .unwrap();

    assert_eq!(built.len, RSI_REQUEST_HEADER_LEN + 16 + 4 + b"Child".len());
    assert_eq!(
        built.retained,
        RsiRetainedRequest {
            request_id: 0x1112_1314_1516_1718,
            op_code: RSI_LOOKUP,
        }
    );

    let header = parse_rsi_request_header(&frame[..built.len]).unwrap();
    assert_eq!(header.total_len, built.len as u32);
    assert_eq!(header.request_id, 0x1112_1314_1516_1718);
    assert_eq!(header.op_code, RSI_LOOKUP);
    assert_eq!(header.txn_id, 99);

    let payload =
        parse_rsi_lookup_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.child_name, field(b"Child"));
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
    assert!(frame[built.len..].iter().all(|byte| *byte == 0xcc));
}

#[test]
fn path_mutation_request_frames_round_trip_through_existing_parsers() {
    let mut create = [0u8; 128];
    let built = write_rsi_create_entry_request_frame(
        &mut create,
        41,
        7,
        PARENT_GUID,
        b"Child",
        b"base",
        CHILD_GUID,
        0x0102_0304_0506_0708,
    )
    .unwrap();
    let header = parse_rsi_request_header(&create[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_CREATE_ENTRY);
    assert_eq!(header.txn_id, 7);
    let payload =
        parse_rsi_create_entry_request_payload(&create[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.child_name, field(b"Child"));
    assert_eq!(payload.layer_name, field(b"base"));
    assert_eq!(payload.child_guid, CHILD_GUID);
    assert_eq!(payload.sequence, 0x0102_0304_0506_0708);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut hide = [0u8; 96];
    let built =
        write_rsi_hide_entry_request_frame(&mut hide, 42, 8, PARENT_GUID, b"Child", b"base", 77)
            .unwrap();
    let header = parse_rsi_request_header(&hide[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_HIDE_ENTRY);
    assert_eq!(header.txn_id, 8);
    let payload =
        parse_rsi_hide_entry_request_payload(&hide[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.child_name, field(b"Child"));
    assert_eq!(payload.layer_name, field(b"base"));
    assert_eq!(payload.sequence, 77);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut delete = [0u8; 96];
    let built =
        write_rsi_delete_entry_request_frame(&mut delete, 43, 9, PARENT_GUID, b"Child", b"base")
            .unwrap();
    let header = parse_rsi_request_header(&delete[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_DELETE_ENTRY);
    assert_eq!(header.txn_id, 9);
    let payload =
        parse_rsi_delete_entry_request_payload(&delete[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.child_name, field(b"Child"));
    assert_eq!(payload.layer_name, field(b"base"));
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut enum_children = [0u8; 64];
    let built =
        write_rsi_enum_children_request_frame(&mut enum_children, 44, 10, PARENT_GUID).unwrap();
    let header = parse_rsi_request_header(&enum_children[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_ENUM_CHILDREN);
    assert_eq!(header.txn_id, 10);
    let payload =
        parse_rsi_enum_children_request_payload(&enum_children[RSI_REQUEST_HEADER_LEN..built.len])
            .unwrap();
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn path_request_frame_construction_rejects_short_output_buffers() {
    let required = RSI_REQUEST_HEADER_LEN + 16 + 4 + b"Child".len();
    let mut frame = [0xaa; RSI_REQUEST_HEADER_LEN + 16 + 4 + 4];

    assert_eq!(
        write_rsi_lookup_request_frame(&mut frame, 55, 0, PARENT_GUID, b"Child"),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: required - 1,
            required,
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
