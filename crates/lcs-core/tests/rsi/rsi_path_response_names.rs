use crate::common::{finish_total_len, push_len_prefixed, response_frame};
use lcs_core::{
    LcsError, LcsLimits, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_PATH_TARGET_GUID,
    RsiRetainedRequest, parse_rsi_enum_children_success_response_payload,
    parse_rsi_lookup_success_response_payload, rsi_response_op_code,
    validate_rsi_enum_children_path_response_names, validate_rsi_lookup_path_response_names,
};



fn push_path_entry(frame: &mut Vec<u8>, layer_name: &[u8], target_guid: &[u8; 16]) {
    push_len_prefixed(frame, layer_name);
    frame.push(RSI_PATH_TARGET_GUID);
    frame.extend_from_slice(target_guid);
    frame.extend_from_slice(&1u64.to_le_bytes());
}


fn parse_lookup_frame(
    request_id: u64,
    frame: &[u8],
) -> lcs_core::RsiLookupSuccessResponsePayload<'_> {
    parse_rsi_lookup_success_response_payload(
        frame,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_LOOKUP,
        },
    )
    .unwrap()
}

fn parse_enum_frame(
    request_id: u64,
    frame: &[u8],
) -> lcs_core::RsiEnumChildrenSuccessResponsePayload<'_> {
    parse_rsi_enum_children_success_response_payload(
        frame,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .unwrap()
}

#[test]
fn lookup_path_response_names_validate_layer_names() {
    let guid = [0x40; 16];
    let limits = LcsLimits::DEFAULT;
    let mut frame = response_frame(401, rsi_response_op_code(RSI_LOOKUP).unwrap());
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", &guid);
    frame.extend_from_slice(&1u32.to_le_bytes());
    frame.extend_from_slice(&guid);
    push_len_prefixed(&mut frame, b"sd");
    frame.push(0);
    frame.push(0);
    frame.extend_from_slice(&1u64.to_le_bytes());
    finish_total_len(&mut frame);

    let parsed = parse_lookup_frame(401, &frame);
    validate_rsi_lookup_path_response_names(&parsed, &limits).unwrap();
}

#[test]
fn lookup_path_response_names_reject_invalid_layer_names() {
    let guid = [0x41; 16];
    let limits = LcsLimits::DEFAULT;

    let mut invalid_utf8 = response_frame(402, rsi_response_op_code(RSI_LOOKUP).unwrap());
    invalid_utf8.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut invalid_utf8, &[0xff], &guid);
    invalid_utf8.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut invalid_utf8);
    let parsed = parse_lookup_frame(402, &invalid_utf8);
    assert_eq!(
        validate_rsi_lookup_path_response_names(&parsed, &limits),
        Err(LcsError::InvalidUtf8 {
            field: "layer_name",
        })
    );

    let mut separator = response_frame(403, rsi_response_op_code(RSI_LOOKUP).unwrap());
    separator.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut separator, b"bad/layer", &guid);
    separator.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut separator);
    let parsed = parse_lookup_frame(403, &separator);
    assert_eq!(
        validate_rsi_lookup_path_response_names(&parsed, &limits),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}

#[test]
fn enum_children_path_response_names_validate_child_and_layer_names() {
    let guid = [0x42; 16];
    let limits = LcsLimits::DEFAULT;
    let mut frame = response_frame(404, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut frame, b"Child");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", &guid);
    frame.extend_from_slice(&1u32.to_le_bytes());
    frame.extend_from_slice(&guid);
    push_len_prefixed(&mut frame, b"sd");
    frame.push(0);
    frame.push(0);
    frame.extend_from_slice(&1u64.to_le_bytes());
    finish_total_len(&mut frame);

    let parsed = parse_enum_frame(404, &frame);
    validate_rsi_enum_children_path_response_names(&parsed, &limits).unwrap();
}

#[test]
fn enum_children_path_response_names_reject_invalid_child_and_layer_names() {
    let guid = [0x43; 16];
    let limits = LcsLimits::DEFAULT;

    let mut bad_child = response_frame(405, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    bad_child.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut bad_child, b"bad\\child");
    bad_child.extend_from_slice(&0u32.to_le_bytes());
    bad_child.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut bad_child);
    let parsed = parse_enum_frame(405, &bad_child);
    assert_eq!(
        validate_rsi_enum_children_path_response_names(&parsed, &limits),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );

    let mut empty_child = response_frame(406, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    empty_child.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut empty_child, b"");
    empty_child.extend_from_slice(&0u32.to_le_bytes());
    empty_child.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut empty_child);
    let parsed = parse_enum_frame(406, &empty_child);
    assert_eq!(
        validate_rsi_enum_children_path_response_names(&parsed, &limits),
        Err(LcsError::EmptyString {
            field: "key_component",
        })
    );

    let mut bad_layer = response_frame(407, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    bad_layer.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut bad_layer, b"Child");
    bad_layer.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut bad_layer, b"bad/layer", &guid);
    bad_layer.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut bad_layer);
    let parsed = parse_enum_frame(407, &bad_layer);
    assert_eq!(
        validate_rsi_enum_children_path_response_names(&parsed, &limits),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}
