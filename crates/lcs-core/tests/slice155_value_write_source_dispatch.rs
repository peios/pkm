use lcs_core::{
    Guid, LcsError, LcsLimits, REG_BINARY, REG_DWORD, REG_TOMBSTONE, RSI_REQUEST_HEADER_LEN,
    RSI_SET_VALUE, RsiLengthPrefixedField, SequenceCounter, ValueWriteInput,
    parse_rsi_request_header, parse_rsi_set_value_request_payload, plan_value_write,
    write_planned_rsi_set_value_request_frame,
};

const KEY_GUID: Guid = [0x55; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn field(data: &[u8]) -> RsiLengthPrefixedField<'_> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
    }
}

fn input<'a>(value_type: u32, data: &'a [u8]) -> ValueWriteInput<'a> {
    ValueWriteInput {
        key_guid: KEY_GUID,
        name: "Setting",
        layer: "role",
        value_type,
        data,
        explicit_tombstone_operation: false,
        expected_sequence: None,
    }
}

#[test]
fn planned_value_write_dispatches_layered_value_entry_to_rsi_set_value() {
    let limits = limits();
    let mut counter = SequenceCounter::new(900);
    let planned = plan_value_write(&limits, &mut counter, &input(REG_BINARY, b"payload")).unwrap();

    let mut frame = [0u8; 160];
    let built = write_planned_rsi_set_value_request_frame(&mut frame, 1200, 77, &planned).unwrap();

    let header = parse_rsi_request_header(&frame[..built.len]).unwrap();
    assert_eq!(header.request_id, 1200);
    assert_eq!(header.op_code, RSI_SET_VALUE);
    assert_eq!(header.txn_id, 77);
    assert_eq!(built.retained.op_code, RSI_SET_VALUE);

    let payload =
        parse_rsi_set_value_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.value_name, field(b"Setting"));
    assert_eq!(payload.layer_name, field(b"role"));
    assert_eq!(payload.value_type, REG_BINARY);
    assert_eq!(payload.data, field(b"payload"));
    assert_eq!(payload.sequence, 900);
    assert_eq!(payload.expected_sequence, 0);
}

#[test]
fn planned_value_write_dispatch_preserves_conditional_expected_sequence() {
    let limits = limits();
    let mut counter = SequenceCounter::new(42);
    let dword = 7u32.to_le_bytes();
    let mut input = input(REG_DWORD, &dword);
    input.expected_sequence = Some(41);
    let planned = plan_value_write(&limits, &mut counter, &input).unwrap();

    let mut frame = [0u8; 160];
    let built = write_planned_rsi_set_value_request_frame(&mut frame, 1201, 0, &planned).unwrap();
    let payload =
        parse_rsi_set_value_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();

    assert_eq!(payload.value_type, REG_DWORD);
    assert_eq!(payload.data, field(&7u32.to_le_bytes()));
    assert_eq!(payload.sequence, 42);
    assert_eq!(payload.expected_sequence, 41);
}

#[test]
fn planned_value_write_dispatch_preserves_explicit_tombstone_entries() {
    let limits = limits();
    let mut counter = SequenceCounter::new(88);
    let mut input = input(REG_TOMBSTONE, b"");
    input.explicit_tombstone_operation = true;
    let planned = plan_value_write(&limits, &mut counter, &input).unwrap();

    let mut frame = [0u8; 160];
    let built = write_planned_rsi_set_value_request_frame(&mut frame, 1202, 0, &planned).unwrap();
    let payload =
        parse_rsi_set_value_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();

    assert_eq!(payload.value_type, REG_TOMBSTONE);
    assert_eq!(payload.data, field(b""));
    assert_eq!(payload.sequence, 88);
}

#[test]
fn planned_value_write_dispatch_fails_closed_on_short_output_buffer() {
    let limits = limits();
    let mut counter = SequenceCounter::new(5);
    let planned = plan_value_write(&limits, &mut counter, &input(REG_BINARY, b"payload")).unwrap();
    let mut frame = [0xaa; 10];

    assert_eq!(
        write_planned_rsi_set_value_request_frame(&mut frame, 1203, 0, &planned),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: 10,
            required: 88,
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
