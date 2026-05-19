use lcs_core::{
    LcsError, RsiLengthPrefixedField, RsiTrailingOptionalFieldsPlan,
    parse_rsi_create_entry_request_payload, parse_rsi_delete_entry_request_payload,
    parse_rsi_enum_children_request_payload, parse_rsi_hide_entry_request_payload,
    parse_rsi_lookup_request_payload,
};

const PARENT_GUID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const CHILD_GUID: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
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
fn lookup_request_payload_is_parent_guid_then_child_name_and_trailing_optional() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&PARENT_GUID);
    push_len_prefixed(&mut payload, b"Child");
    payload.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

    assert_eq!(
        parse_rsi_lookup_request_payload(&payload).unwrap(),
        lcs_core::RsiLookupRequestPayload {
            parent_guid: PARENT_GUID,
            child_name: field(b"Child"),
            trailing: RsiTrailingOptionalFieldsPlan {
                ignored_trailing_len: 3,
            },
        }
    );
}

#[test]
fn create_entry_request_payload_matches_path_entry_wire_order() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&PARENT_GUID);
    push_len_prefixed(&mut payload, b"Child");
    push_len_prefixed(&mut payload, b"base");
    payload.extend_from_slice(&CHILD_GUID);
    payload.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());

    let parsed = parse_rsi_create_entry_request_payload(&payload).unwrap();
    assert_eq!(parsed.parent_guid, PARENT_GUID);
    assert_eq!(parsed.child_name, field(b"Child"));
    assert_eq!(parsed.layer_name, field(b"base"));
    assert_eq!(parsed.child_guid, CHILD_GUID);
    assert_eq!(parsed.sequence, 0x0102_0304_0506_0708);
    assert_eq!(parsed.trailing.ignored_trailing_len, 0);
}

#[test]
fn hide_and_delete_entry_payloads_share_parent_child_layer_prefix() {
    let mut hide = Vec::new();
    hide.extend_from_slice(&PARENT_GUID);
    push_len_prefixed(&mut hide, b"Child");
    push_len_prefixed(&mut hide, b"MachinePolicy");
    hide.extend_from_slice(&77u64.to_le_bytes());

    let parsed_hide = parse_rsi_hide_entry_request_payload(&hide).unwrap();
    assert_eq!(parsed_hide.parent_guid, PARENT_GUID);
    assert_eq!(parsed_hide.child_name, field(b"Child"));
    assert_eq!(parsed_hide.layer_name, field(b"MachinePolicy"));
    assert_eq!(parsed_hide.sequence, 77);
    assert_eq!(parsed_hide.trailing.ignored_trailing_len, 0);

    let mut delete = Vec::new();
    delete.extend_from_slice(&PARENT_GUID);
    push_len_prefixed(&mut delete, b"Child");
    push_len_prefixed(&mut delete, b"MachinePolicy");
    delete.extend_from_slice(&[0xde, 0xad]);

    let parsed_delete = parse_rsi_delete_entry_request_payload(&delete).unwrap();
    assert_eq!(parsed_delete.parent_guid, PARENT_GUID);
    assert_eq!(parsed_delete.child_name, field(b"Child"));
    assert_eq!(parsed_delete.layer_name, field(b"MachinePolicy"));
    assert_eq!(parsed_delete.trailing.ignored_trailing_len, 2);
}

#[test]
fn enum_children_request_payload_is_parent_guid_only() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&PARENT_GUID);
    payload.extend_from_slice(&[0x99]);

    assert_eq!(
        parse_rsi_enum_children_request_payload(&payload).unwrap(),
        lcs_core::RsiEnumChildrenRequestPayload {
            parent_guid: PARENT_GUID,
            trailing: RsiTrailingOptionalFieldsPlan {
                ignored_trailing_len: 1,
            },
        }
    );
}

#[test]
fn path_request_payload_parsers_reject_truncated_mandatory_fields() {
    assert_eq!(
        parse_rsi_lookup_request_payload(&PARENT_GUID[..15]),
        Err(LcsError::RsiMessageTooShort { len: 15, min: 16 })
    );

    let mut truncated_child = Vec::new();
    truncated_child.extend_from_slice(&PARENT_GUID);
    truncated_child.extend_from_slice(&5u32.to_le_bytes());
    truncated_child.extend_from_slice(b"abc");
    assert_eq!(
        parse_rsi_lookup_request_payload(&truncated_child),
        Err(LcsError::RsiMessageTooShort { len: 23, min: 25 })
    );

    let mut missing_sequence = Vec::new();
    missing_sequence.extend_from_slice(&PARENT_GUID);
    push_len_prefixed(&mut missing_sequence, b"Child");
    push_len_prefixed(&mut missing_sequence, b"base");
    missing_sequence.extend_from_slice(&CHILD_GUID);
    missing_sequence.extend_from_slice(&[0; 7]);
    assert_eq!(
        parse_rsi_create_entry_request_payload(&missing_sequence),
        Err(LcsError::RsiMessageTooShort {
            len: missing_sequence.len(),
            min: missing_sequence.len() + 1,
        })
    );
}
