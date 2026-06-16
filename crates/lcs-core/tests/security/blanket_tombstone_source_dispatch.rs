use lcs_core::{
    BlanketTombstoneInput, Guid, LcsError, LcsLimits, RSI_REQUEST_HEADER_LEN,
    RSI_SET_BLANKET_TOMBSTONE, RsiLengthPrefixedField, SequenceCounter, parse_rsi_request_header,
    parse_rsi_set_blanket_tombstone_request_payload, plan_blanket_tombstone,
    write_planned_rsi_set_blanket_tombstone_request_frame,
};

const KEY_GUID: Guid = [0x57; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn field(bytes: &[u8]) -> RsiLengthPrefixedField<'_> {
    RsiLengthPrefixedField {
        len: bytes.len() as u32,
        data: bytes,
    }
}

fn blanket_input(set: bool) -> BlanketTombstoneInput<'static> {
    BlanketTombstoneInput {
        key_guid: KEY_GUID,
        layer: "policy",
        set,
    }
}

#[test]
fn planned_blanket_tombstone_set_dispatches_sequence_to_source() {
    let limits = limits();
    let mut counter = SequenceCounter::new(700);
    let planned = plan_blanket_tombstone(&limits, &mut counter, &blanket_input(true))
        .expect("blanket set should plan");
    let mut frame = [0u8; 96];

    let built =
        write_planned_rsi_set_blanket_tombstone_request_frame(&mut frame, 300, 44, &planned)
            .expect("planned blanket set should write");
    let header = parse_rsi_request_header(&frame[..built.len]).expect("header should parse");
    let payload =
        parse_rsi_set_blanket_tombstone_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len])
            .expect("payload should parse");

    assert_eq!(header.request_id, 300);
    assert_eq!(header.op_code, RSI_SET_BLANKET_TOMBSTONE);
    assert_eq!(header.txn_id, 44);
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.layer_name, field(b"policy"));
    assert!(payload.set);
    assert_eq!(payload.sequence, 700);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn planned_blanket_tombstone_remove_dispatches_remove_without_allocated_sequence() {
    let limits = limits();
    let mut counter = SequenceCounter::new(700);
    let planned = plan_blanket_tombstone(&limits, &mut counter, &blanket_input(false))
        .expect("blanket remove should plan");
    let mut frame = [0u8; 96];

    let built =
        write_planned_rsi_set_blanket_tombstone_request_frame(&mut frame, 301, 45, &planned)
            .expect("planned blanket remove should write");
    let payload =
        parse_rsi_set_blanket_tombstone_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len])
            .expect("payload should parse");

    assert_eq!(counter.next_sequence(), 700);
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.layer_name, field(b"policy"));
    assert!(!payload.set);
    assert_eq!(payload.sequence, 0);
}

#[test]
fn planned_blanket_tombstone_dispatch_rejects_short_buffers_without_partial_write() {
    let limits = limits();
    let mut counter = SequenceCounter::new(700);
    let planned = plan_blanket_tombstone(&limits, &mut counter, &blanket_input(true))
        .expect("blanket set should plan");
    let required = RSI_REQUEST_HEADER_LEN + 16 + 4 + b"policy".len() + 1 + 8;
    let mut frame = [0xaa; RSI_REQUEST_HEADER_LEN + 16 + 4 + b"policy".len() + 1 + 7];

    assert_eq!(
        write_planned_rsi_set_blanket_tombstone_request_frame(&mut frame, 302, 46, &planned),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: required - 1,
            required,
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
