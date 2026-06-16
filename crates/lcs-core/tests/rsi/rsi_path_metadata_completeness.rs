use crate::common::{finish_total_len, push_len_prefixed, response_frame};
use lcs_core::{
    LcsError, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_PATH_TARGET_GUID, RSI_PATH_TARGET_HIDDEN,
    RsiRetainedRequest, parse_rsi_enum_children_success_response_payload,
    parse_rsi_lookup_success_response_payload, rsi_response_op_code,
    validate_rsi_enum_children_metadata_completeness, validate_rsi_lookup_metadata_completeness,
};



fn push_path_entry(
    frame: &mut Vec<u8>,
    layer_name: &[u8],
    target_type: u8,
    target_guid: &[u8; 16],
    sequence: u64,
) {
    push_len_prefixed(frame, layer_name);
    frame.push(target_type);
    frame.extend_from_slice(target_guid);
    frame.extend_from_slice(&sequence.to_le_bytes());
}

fn push_metadata(frame: &mut Vec<u8>, guid: &[u8; 16]) {
    frame.extend_from_slice(guid);
    push_len_prefixed(frame, b"sd");
    frame.push(0);
    frame.push(0);
    frame.extend_from_slice(&1000u64.to_le_bytes());
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
fn lookup_metadata_completeness_accepts_duplicate_references_and_hidden_entries() {
    let guid = [0x10; 16];
    let mut frame = response_frame(301, rsi_response_op_code(RSI_LOOKUP).unwrap());
    frame.extend_from_slice(&3u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, &guid, 10);
    push_path_entry(&mut frame, b"override", RSI_PATH_TARGET_GUID, &guid, 11);
    push_path_entry(&mut frame, b"mask", RSI_PATH_TARGET_HIDDEN, &[0; 16], 12);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut frame, &guid);
    finish_total_len(&mut frame);

    let parsed = parse_lookup_frame(301, &frame);
    validate_rsi_lookup_metadata_completeness(&parsed).unwrap();
}

#[test]
fn lookup_metadata_completeness_rejects_missing_duplicate_unreferenced_and_nil_metadata() {
    let guid = [0x11; 16];

    let mut missing = response_frame(302, rsi_response_op_code(RSI_LOOKUP).unwrap());
    missing.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut missing, b"base", RSI_PATH_TARGET_GUID, &guid, 20);
    missing.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut missing);
    let parsed = parse_lookup_frame(302, &missing);
    assert_eq!(
        validate_rsi_lookup_metadata_completeness(&parsed),
        Err(LcsError::RsiPathMetadataMissing { guid })
    );

    let mut duplicate = response_frame(303, rsi_response_op_code(RSI_LOOKUP).unwrap());
    duplicate.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut duplicate, b"base", RSI_PATH_TARGET_GUID, &guid, 21);
    duplicate.extend_from_slice(&2u32.to_le_bytes());
    push_metadata(&mut duplicate, &guid);
    push_metadata(&mut duplicate, &guid);
    finish_total_len(&mut duplicate);
    let parsed = parse_lookup_frame(303, &duplicate);
    assert_eq!(
        validate_rsi_lookup_metadata_completeness(&parsed),
        Err(LcsError::RsiPathMetadataDuplicate { guid })
    );

    let mut unreferenced = response_frame(304, rsi_response_op_code(RSI_LOOKUP).unwrap());
    unreferenced.extend_from_slice(&0u32.to_le_bytes());
    unreferenced.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut unreferenced, &guid);
    finish_total_len(&mut unreferenced);
    let parsed = parse_lookup_frame(304, &unreferenced);
    assert_eq!(
        validate_rsi_lookup_metadata_completeness(&parsed),
        Err(LcsError::RsiPathMetadataUnreferenced { guid })
    );

    let mut nil = response_frame(305, rsi_response_op_code(RSI_LOOKUP).unwrap());
    nil.extend_from_slice(&0u32.to_le_bytes());
    nil.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut nil, &[0; 16]);
    finish_total_len(&mut nil);
    let parsed = parse_lookup_frame(305, &nil);
    assert_eq!(
        validate_rsi_lookup_metadata_completeness(&parsed),
        Err(LcsError::RsiPathMetadataNilGuid)
    );
}

#[test]
fn enum_children_metadata_completeness_walks_all_children() {
    let alpha_guid = [0x20; 16];
    let beta_guid = [0x21; 16];
    let mut frame = response_frame(306, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_len_prefixed(&mut frame, b"Alpha");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, &alpha_guid, 30);
    push_len_prefixed(&mut frame, b"Beta");
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, &beta_guid, 31);
    push_path_entry(&mut frame, b"mask", RSI_PATH_TARGET_HIDDEN, &[0; 16], 32);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_metadata(&mut frame, &alpha_guid);
    push_metadata(&mut frame, &beta_guid);
    finish_total_len(&mut frame);

    let parsed = parse_enum_frame(306, &frame);
    validate_rsi_enum_children_metadata_completeness(&parsed).unwrap();
}

#[test]
fn enum_children_metadata_completeness_rejects_missing_duplicate_unreferenced_and_nil_metadata() {
    let guid = [0x30; 16];

    let mut missing = response_frame(307, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    missing.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut missing, b"Missing");
    missing.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut missing, b"base", RSI_PATH_TARGET_GUID, &guid, 40);
    missing.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut missing);
    let parsed = parse_enum_frame(307, &missing);
    assert_eq!(
        validate_rsi_enum_children_metadata_completeness(&parsed),
        Err(LcsError::RsiPathMetadataMissing { guid })
    );

    let mut duplicate = response_frame(308, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    duplicate.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut duplicate, b"Duplicate");
    duplicate.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut duplicate, b"base", RSI_PATH_TARGET_GUID, &guid, 41);
    duplicate.extend_from_slice(&2u32.to_le_bytes());
    push_metadata(&mut duplicate, &guid);
    push_metadata(&mut duplicate, &guid);
    finish_total_len(&mut duplicate);
    let parsed = parse_enum_frame(308, &duplicate);
    assert_eq!(
        validate_rsi_enum_children_metadata_completeness(&parsed),
        Err(LcsError::RsiPathMetadataDuplicate { guid })
    );

    let mut unreferenced = response_frame(309, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    unreferenced.extend_from_slice(&0u32.to_le_bytes());
    unreferenced.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut unreferenced, &guid);
    finish_total_len(&mut unreferenced);
    let parsed = parse_enum_frame(309, &unreferenced);
    assert_eq!(
        validate_rsi_enum_children_metadata_completeness(&parsed),
        Err(LcsError::RsiPathMetadataUnreferenced { guid })
    );

    let mut nil = response_frame(310, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    nil.extend_from_slice(&0u32.to_le_bytes());
    nil.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut nil, &[0; 16]);
    finish_total_len(&mut nil);
    let parsed = parse_enum_frame(310, &nil);
    assert_eq!(
        validate_rsi_enum_children_metadata_completeness(&parsed),
        Err(LcsError::RsiPathMetadataNilGuid)
    );
}
