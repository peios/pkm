use lcs_core::{
    REG_DWORD, RSI_CREATE_KEY, RSI_DELETE_VALUE_ENTRY, RSI_DROP_KEY, RSI_QUERY_VALUES,
    RSI_READ_KEY, RSI_REQUEST_HEADER_LEN, RSI_SET_BLANKET_TOMBSTONE, RSI_SET_VALUE, RSI_WRITE_KEY,
    RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME, parse_rsi_create_key_request_payload,
    parse_rsi_delete_value_entry_request_payload, parse_rsi_drop_key_request_payload,
    parse_rsi_query_values_request_payload, parse_rsi_read_key_request_payload,
    parse_rsi_request_header, parse_rsi_set_blanket_tombstone_request_payload,
    parse_rsi_set_value_request_payload, parse_rsi_write_key_request_payload,
    write_rsi_create_key_request_frame, write_rsi_delete_value_entry_request_frame,
    write_rsi_drop_key_request_frame, write_rsi_query_values_request_frame,
    write_rsi_read_key_request_frame, write_rsi_set_blanket_tombstone_request_frame,
    write_rsi_set_value_request_frame, write_rsi_write_key_request_frame,
};

const KEY_GUID: [u8; 16] = [
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
];
const PARENT_GUID: [u8; 16] = [
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
];

#[test]
fn resolved_key_rsi_key_operations_are_guid_addressed() {
    let mut create = [0u8; 128];
    let built = write_rsi_create_key_request_frame(
        &mut create,
        1410,
        11,
        KEY_GUID,
        b"Child",
        PARENT_GUID,
        b"sd",
        false,
        false,
    )
    .unwrap();
    let header = parse_rsi_request_header(&create[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_CREATE_KEY);
    let payload =
        parse_rsi_create_key_request_payload(&create[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.parent_guid, PARENT_GUID);

    let mut read = [0u8; 64];
    let built = write_rsi_read_key_request_frame(&mut read, 1411, 12, KEY_GUID).unwrap();
    let header = parse_rsi_request_header(&read[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_READ_KEY);
    let payload =
        parse_rsi_read_key_request_payload(&read[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);

    let mut write = [0u8; 96];
    let built =
        write_rsi_write_key_request_frame(&mut write, 1412, 13, KEY_GUID, None, Some(99)).unwrap();
    let header = parse_rsi_request_header(&write[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_WRITE_KEY);
    let payload =
        parse_rsi_write_key_request_payload(&write[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.field_mask, RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME);

    let mut drop = [0u8; 64];
    let built = write_rsi_drop_key_request_frame(&mut drop, 1413, 14, KEY_GUID).unwrap();
    let header = parse_rsi_request_header(&drop[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_DROP_KEY);
    let payload =
        parse_rsi_drop_key_request_payload(&drop[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
}

#[test]
fn resolved_key_rsi_value_operations_are_guid_addressed() {
    let mut query = [0u8; 96];
    let built =
        write_rsi_query_values_request_frame(&mut query, 1420, 21, KEY_GUID, b"Value", false)
            .unwrap();
    let header = parse_rsi_request_header(&query[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_QUERY_VALUES);
    let payload =
        parse_rsi_query_values_request_payload(&query[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);

    let mut set = [0u8; 128];
    let built = write_rsi_set_value_request_frame(
        &mut set,
        1421,
        22,
        KEY_GUID,
        b"Value",
        b"base",
        REG_DWORD,
        &1u32.to_le_bytes(),
        10,
        9,
    )
    .unwrap();
    let header = parse_rsi_request_header(&set[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_SET_VALUE);
    let payload =
        parse_rsi_set_value_request_payload(&set[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);

    let mut delete = [0u8; 96];
    let built = write_rsi_delete_value_entry_request_frame(
        &mut delete,
        1422,
        23,
        KEY_GUID,
        b"Value",
        b"base",
    )
    .unwrap();
    let header = parse_rsi_request_header(&delete[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_DELETE_VALUE_ENTRY);
    let payload =
        parse_rsi_delete_value_entry_request_payload(&delete[RSI_REQUEST_HEADER_LEN..built.len])
            .unwrap();
    assert_eq!(payload.guid, KEY_GUID);

    let mut blanket = [0u8; 96];
    let built = write_rsi_set_blanket_tombstone_request_frame(
        &mut blanket,
        1423,
        24,
        KEY_GUID,
        b"base",
        true,
        11,
    )
    .unwrap();
    let header = parse_rsi_request_header(&blanket[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_SET_BLANKET_TOMBSTONE);
    let payload = parse_rsi_set_blanket_tombstone_request_payload(
        &blanket[RSI_REQUEST_HEADER_LEN..built.len],
    )
    .unwrap();
    assert_eq!(payload.guid, KEY_GUID);
}
