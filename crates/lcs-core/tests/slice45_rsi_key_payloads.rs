use lcs_core::{
    LcsError, RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME, RSI_WRITE_KEY_FIELD_SD, RsiLengthPrefixedField,
    RsiTrailingOptionalFieldsPlan, parse_rsi_create_key_request_payload,
    parse_rsi_drop_key_request_payload, parse_rsi_read_key_request_payload,
    parse_rsi_write_key_request_payload, validate_rsi_write_key_field_mask,
};

const KEY_GUID: [u8; 16] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
const PARENT_GUID: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];

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
fn create_key_request_payload_matches_key_wire_order_and_boolean_shape() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut payload, b"Child");
    payload.extend_from_slice(&PARENT_GUID);
    push_len_prefixed(&mut payload, b"self-relative-sd");
    payload.push(1);
    payload.push(0);
    payload.extend_from_slice(&[0xaa, 0xbb]);

    let parsed = parse_rsi_create_key_request_payload(&payload).unwrap();
    assert_eq!(parsed.guid, KEY_GUID);
    assert_eq!(parsed.name, field(b"Child"));
    assert_eq!(parsed.parent_guid, PARENT_GUID);
    assert_eq!(parsed.sd, field(b"self-relative-sd"));
    assert!(parsed.volatile);
    assert!(!parsed.symlink);
    assert_eq!(
        parsed.trailing,
        RsiTrailingOptionalFieldsPlan {
            ignored_trailing_len: 2,
        }
    );
}

#[test]
fn read_and_drop_key_request_payloads_are_guid_only() {
    let mut read = Vec::new();
    read.extend_from_slice(&KEY_GUID);
    read.extend_from_slice(&[0x99]);
    assert_eq!(
        parse_rsi_read_key_request_payload(&read).unwrap(),
        lcs_core::RsiReadKeyRequestPayload {
            guid: KEY_GUID,
            trailing: RsiTrailingOptionalFieldsPlan {
                ignored_trailing_len: 1,
            },
        }
    );

    let mut drop = Vec::new();
    drop.extend_from_slice(&KEY_GUID);
    assert_eq!(
        parse_rsi_drop_key_request_payload(&drop).unwrap(),
        lcs_core::RsiDropKeyRequestPayload {
            guid: KEY_GUID,
            trailing: RsiTrailingOptionalFieldsPlan {
                ignored_trailing_len: 0,
            },
        }
    );
}

#[test]
fn write_key_request_payload_reads_masked_fields_in_bit_order() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&KEY_GUID);
    payload.extend_from_slice(
        &(RSI_WRITE_KEY_FIELD_SD | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME).to_le_bytes(),
    );
    push_len_prefixed(&mut payload, b"new-sd");
    payload.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    payload.push(0xee);

    let parsed = parse_rsi_write_key_request_payload(&payload).unwrap();
    assert_eq!(parsed.guid, KEY_GUID);
    assert_eq!(
        parsed.field_mask,
        RSI_WRITE_KEY_FIELD_SD | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME
    );
    assert_eq!(parsed.sd, Some(field(b"new-sd")));
    assert_eq!(parsed.last_write_time, Some(0x1122_3344_5566_7788));
    assert_eq!(parsed.trailing.ignored_trailing_len, 1);
}

#[test]
fn write_key_request_payload_omits_unmasked_fields_without_reordering() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&KEY_GUID);
    payload.extend_from_slice(&RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME.to_le_bytes());
    payload.extend_from_slice(&1234u64.to_le_bytes());

    let parsed = parse_rsi_write_key_request_payload(&payload).unwrap();
    assert_eq!(parsed.sd, None);
    assert_eq!(parsed.last_write_time, Some(1234));
}

#[test]
fn key_request_payload_parsers_reject_invalid_booleans_masks_and_truncation() {
    let mut invalid_bool = Vec::new();
    invalid_bool.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut invalid_bool, b"Child");
    invalid_bool.extend_from_slice(&PARENT_GUID);
    push_len_prefixed(&mut invalid_bool, b"sd");
    invalid_bool.push(2);
    invalid_bool.push(0);
    assert_eq!(
        parse_rsi_create_key_request_payload(&invalid_bool),
        Err(LcsError::InvalidBooleanFlag {
            field: "rsi_create_key.volatile",
            value: 2,
        })
    );

    assert_eq!(
        validate_rsi_write_key_field_mask(0x8000_0000),
        Err(LcsError::UnknownRsiWriteKeyFieldMask {
            field_mask: 0x8000_0000,
            unknown: 0x8000_0000,
        })
    );

    let mut truncated_sd = Vec::new();
    truncated_sd.extend_from_slice(&KEY_GUID);
    truncated_sd.extend_from_slice(&RSI_WRITE_KEY_FIELD_SD.to_le_bytes());
    truncated_sd.extend_from_slice(&4u32.to_le_bytes());
    truncated_sd.extend_from_slice(b"abc");
    assert_eq!(
        parse_rsi_write_key_request_payload(&truncated_sd),
        Err(LcsError::RsiMessageTooShort {
            len: truncated_sd.len(),
            min: truncated_sd.len() + 1,
        })
    );
}
