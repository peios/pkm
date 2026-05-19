use lcs_core::{
    Guid, LcsError, LcsLimits, PathEntryWriteRequest, PathTarget, RSI_CREATE_ENTRY, RSI_HIDE_ENTRY,
    RSI_REQUEST_HEADER_LEN, RsiLengthPrefixedField, parse_rsi_create_entry_request_payload,
    parse_rsi_hide_entry_request_payload, parse_rsi_request_header,
    validate_path_entry_write_request, write_rsi_path_entry_request_frame,
};

const PARENT_GUID: Guid = [0x41; 16];
const CHILD_GUID: Guid = [0x42; 16];

fn field(data: &'static [u8]) -> RsiLengthPrefixedField<'static> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
    }
}

fn validated_path_entry(
    target: PathTarget,
    sequence: u64,
) -> lcs_core::ValidatedPathEntryWrite<'static> {
    validate_path_entry_write_request(
        &LcsLimits::default(),
        &PathEntryWriteRequest {
            parent_guid: PARENT_GUID,
            child_name: "Child",
            layer: "base",
            sequence,
            target,
        },
    )
    .unwrap()
}

#[test]
fn guid_path_entry_dispatches_create_entry_with_assigned_sequence() {
    let path_entry = validated_path_entry(PathTarget::Guid(CHILD_GUID), 0x0102_0304_0506_0708);
    let mut frame = [0u8; 128];

    let built = write_rsi_path_entry_request_frame(&mut frame, 77, 9, path_entry).unwrap();
    let header = parse_rsi_request_header(&frame[..built.len]).unwrap();
    let payload =
        parse_rsi_create_entry_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();

    assert_eq!(header.op_code, RSI_CREATE_ENTRY);
    assert_eq!(header.request_id, 77);
    assert_eq!(header.txn_id, 9);
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.child_name, field(b"Child"));
    assert_eq!(payload.layer_name, field(b"base"));
    assert_eq!(payload.child_guid, CHILD_GUID);
    assert_eq!(payload.sequence, 0x0102_0304_0506_0708);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn hidden_path_entry_dispatches_hide_entry_with_assigned_sequence() {
    let path_entry = validated_path_entry(PathTarget::Hidden, 33);
    let mut frame = [0u8; 96];

    let built = write_rsi_path_entry_request_frame(&mut frame, 78, 10, path_entry).unwrap();
    let header = parse_rsi_request_header(&frame[..built.len]).unwrap();
    let payload =
        parse_rsi_hide_entry_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();

    assert_eq!(header.op_code, RSI_HIDE_ENTRY);
    assert_eq!(header.request_id, 78);
    assert_eq!(header.txn_id, 10);
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.child_name, field(b"Child"));
    assert_eq!(payload.layer_name, field(b"base"));
    assert_eq!(payload.sequence, 33);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn path_entry_dispatch_rejects_short_output_buffers_without_mutation() {
    let path_entry = validated_path_entry(PathTarget::Guid(CHILD_GUID), 44);
    let required = RSI_REQUEST_HEADER_LEN + 16 + 4 + b"Child".len() + 4 + b"base".len() + 16 + 8;
    let mut frame = vec![0xaa; required - 1];

    assert_eq!(
        write_rsi_path_entry_request_frame(&mut frame, 79, 11, path_entry),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: required - 1,
            required,
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
