use lcs_core::{
    LcsError, REG_DWORD, REG_SZ, RsiLengthPrefixedField, RsiTrailingOptionalFieldsPlan,
    parse_rsi_delete_value_entry_request_payload, parse_rsi_query_values_request_payload,
    parse_rsi_set_blanket_tombstone_request_payload, parse_rsi_set_value_request_payload,
};

const KEY_GUID: [u8; 16] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
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
fn query_values_request_payload_reads_value_name_and_query_all_flag() {
    let mut single = Vec::new();
    single.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut single, b"Enabled");
    single.push(0);

    let parsed_single = parse_rsi_query_values_request_payload(&single).unwrap();
    assert_eq!(parsed_single.guid, KEY_GUID);
    assert_eq!(parsed_single.value_name, field(b"Enabled"));
    assert!(!parsed_single.query_all);
    assert_eq!(parsed_single.trailing.ignored_trailing_len, 0);

    let mut all = Vec::new();
    all.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut all, b"");
    all.push(1);
    all.extend_from_slice(&[0x99]);

    let parsed_all = parse_rsi_query_values_request_payload(&all).unwrap();
    assert_eq!(parsed_all.value_name, field(b""));
    assert!(parsed_all.query_all);
    assert_eq!(
        parsed_all.trailing,
        RsiTrailingOptionalFieldsPlan {
            ignored_trailing_len: 1,
        }
    );
}

#[test]
fn set_value_request_payload_matches_value_wire_order() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut payload, b"Enabled");
    push_len_prefixed(&mut payload, b"base");
    payload.extend_from_slice(&REG_DWORD.to_le_bytes());
    push_len_prefixed(&mut payload, &1u32.to_le_bytes());
    payload.extend_from_slice(&100u64.to_le_bytes());
    payload.extend_from_slice(&99u64.to_le_bytes());

    let parsed = parse_rsi_set_value_request_payload(&payload).unwrap();
    assert_eq!(parsed.guid, KEY_GUID);
    assert_eq!(parsed.value_name, field(b"Enabled"));
    assert_eq!(parsed.layer_name, field(b"base"));
    assert_eq!(parsed.value_type, REG_DWORD);
    assert_eq!(parsed.data, field(&1u32.to_le_bytes()));
    assert_eq!(parsed.sequence, 100);
    assert_eq!(parsed.expected_sequence, 99);
    assert_eq!(parsed.trailing.ignored_trailing_len, 0);
}

#[test]
fn delete_value_entry_request_payload_reads_guid_value_and_layer() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut payload, b"Enabled");
    push_len_prefixed(&mut payload, b"user");
    payload.push(0xee);

    let parsed = parse_rsi_delete_value_entry_request_payload(&payload).unwrap();
    assert_eq!(parsed.guid, KEY_GUID);
    assert_eq!(parsed.value_name, field(b"Enabled"));
    assert_eq!(parsed.layer_name, field(b"user"));
    assert_eq!(parsed.trailing.ignored_trailing_len, 1);
}

#[test]
fn set_blanket_tombstone_request_payload_reads_layer_set_and_sequence() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut payload, b"MachinePolicy");
    payload.push(1);
    payload.extend_from_slice(&0xfeed_beef_u64.to_le_bytes());

    let parsed = parse_rsi_set_blanket_tombstone_request_payload(&payload).unwrap();
    assert_eq!(parsed.guid, KEY_GUID);
    assert_eq!(parsed.layer_name, field(b"MachinePolicy"));
    assert!(parsed.set);
    assert_eq!(parsed.sequence, 0xfeed_beef);
    assert_eq!(parsed.trailing.ignored_trailing_len, 0);
}

#[test]
fn value_request_payload_parsers_reject_invalid_booleans_and_truncation() {
    let mut invalid_query_all = Vec::new();
    invalid_query_all.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut invalid_query_all, b"Enabled");
    invalid_query_all.push(2);
    assert_eq!(
        parse_rsi_query_values_request_payload(&invalid_query_all),
        Err(LcsError::InvalidBooleanFlag {
            field: "rsi_query_values.query_all",
            value: 2,
        })
    );

    let mut invalid_set = Vec::new();
    invalid_set.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut invalid_set, b"base");
    invalid_set.push(3);
    invalid_set.extend_from_slice(&1u64.to_le_bytes());
    assert_eq!(
        parse_rsi_set_blanket_tombstone_request_payload(&invalid_set),
        Err(LcsError::InvalidBooleanFlag {
            field: "rsi_set_blanket_tombstone.set",
            value: 3,
        })
    );

    let mut truncated_sequence = Vec::new();
    truncated_sequence.extend_from_slice(&KEY_GUID);
    push_len_prefixed(&mut truncated_sequence, b"Name");
    push_len_prefixed(&mut truncated_sequence, b"base");
    truncated_sequence.extend_from_slice(&REG_SZ.to_le_bytes());
    push_len_prefixed(&mut truncated_sequence, b"value");
    truncated_sequence.extend_from_slice(&[0; 7]);
    assert_eq!(
        parse_rsi_set_value_request_payload(&truncated_sequence),
        Err(LcsError::RsiMessageTooShort {
            len: truncated_sequence.len(),
            min: truncated_sequence.len() + 1,
        })
    );
}
