use crate::common::{finish_total_len, push_len_prefixed, system_sid};
use lcs_core::{
    LcsError, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_OK, RSI_READ_KEY, RsiRetainedRequest,
    parse_rsi_enum_children_success_response_payload, parse_rsi_lookup_success_response_payload,
    parse_rsi_read_key_success_response_payload, rsi_response_op_code,
    validate_rsi_enum_children_metadata_security_descriptors,
    validate_rsi_lookup_metadata_security_descriptors,
    validate_rsi_read_key_response_security_descriptor,
};

const SE_SELF_RELATIVE: u16 = 0x8000;

fn response_frame(request_id: u64, request_op_code: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&rsi_response_op_code(request_op_code).unwrap().to_le_bytes());
    frame.extend_from_slice(&RSI_OK.to_le_bytes());
    frame
}


fn push_metadata(frame: &mut Vec<u8>, guid: &[u8; 16], sd: &[u8]) {
    frame.extend_from_slice(guid);
    push_len_prefixed(frame, sd);
    frame.push(0);
    frame.push(0);
    frame.extend_from_slice(&1000u64.to_le_bytes());
}



fn owner_only_sd() -> Vec<u8> {
    let owner = system_sid();
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd
}

fn ownerless_sd() -> Vec<u8> {
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd
}

fn read_key_payload(request_id: u64, sd: &[u8]) -> Vec<u8> {
    let mut frame = response_frame(request_id, RSI_READ_KEY);
    push_len_prefixed(&mut frame, b"Key");
    frame.extend_from_slice(&[0x11; 16]);
    push_len_prefixed(&mut frame, sd);
    frame.push(0);
    frame.push(0);
    frame.extend_from_slice(&1000u64.to_le_bytes());
    finish_total_len(&mut frame);
    frame
}

fn lookup_payload(request_id: u64, sd: &[u8]) -> Vec<u8> {
    let mut frame = response_frame(request_id, RSI_LOOKUP);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut frame, &[0x22; 16], sd);
    finish_total_len(&mut frame);
    frame
}

fn enum_children_payload(request_id: u64, sd: &[u8]) -> Vec<u8> {
    let mut frame = response_frame(request_id, RSI_ENUM_CHILDREN);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut frame, &[0x33; 16], sd);
    finish_total_len(&mut frame);
    frame
}

#[test]
fn response_security_descriptor_validation_accepts_owner_bearing_sds() {
    let sd = owner_only_sd();

    let read_key = read_key_payload(701, &sd);
    let parsed_read_key = parse_rsi_read_key_success_response_payload(
        &read_key,
        RsiRetainedRequest {
            request_id: 701,
            op_code: RSI_READ_KEY,
        },
    )
    .unwrap();
    validate_rsi_read_key_response_security_descriptor(&parsed_read_key).unwrap();

    let lookup = lookup_payload(702, &sd);
    let parsed_lookup = parse_rsi_lookup_success_response_payload(
        &lookup,
        RsiRetainedRequest {
            request_id: 702,
            op_code: RSI_LOOKUP,
        },
    )
    .unwrap();
    validate_rsi_lookup_metadata_security_descriptors(&parsed_lookup).unwrap();

    let enum_children = enum_children_payload(703, &sd);
    let parsed_enum = parse_rsi_enum_children_success_response_payload(
        &enum_children,
        RsiRetainedRequest {
            request_id: 703,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .unwrap();
    validate_rsi_enum_children_metadata_security_descriptors(&parsed_enum).unwrap();
}

#[test]
fn response_security_descriptor_validation_rejects_malformed_sds() {
    let read_key = read_key_payload(704, b"bad");
    let parsed_read_key = parse_rsi_read_key_success_response_payload(
        &read_key,
        RsiRetainedRequest {
            request_id: 704,
            op_code: RSI_READ_KEY,
        },
    )
    .unwrap();
    assert_eq!(
        validate_rsi_read_key_response_security_descriptor(&parsed_read_key),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "rsi_read_key.sd"
        })
    );

    let lookup = lookup_payload(705, b"bad");
    let parsed_lookup = parse_rsi_lookup_success_response_payload(
        &lookup,
        RsiRetainedRequest {
            request_id: 705,
            op_code: RSI_LOOKUP,
        },
    )
    .unwrap();
    assert_eq!(
        validate_rsi_lookup_metadata_security_descriptors(&parsed_lookup),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "rsi_lookup.metadata.sd"
        })
    );
}

#[test]
fn response_security_descriptor_validation_rejects_ownerless_sds() {
    let sd = ownerless_sd();
    let enum_children = enum_children_payload(706, &sd);
    let parsed_enum = parse_rsi_enum_children_success_response_payload(
        &enum_children,
        RsiRetainedRequest {
            request_id: 706,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .unwrap();
    assert_eq!(
        validate_rsi_enum_children_metadata_security_descriptors(&parsed_enum),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "rsi_enum_children.metadata.sd"
        })
    );
}
