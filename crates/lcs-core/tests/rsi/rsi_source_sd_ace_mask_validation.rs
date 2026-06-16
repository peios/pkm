use crate::common::{finish_total_len, push_len_prefixed};
use kacs_core::{ACCESS_ALLOWED_ACE_TYPE, SE_DACL_PRESENT, SE_SELF_RELATIVE};
use lcs_core::{
    ACCESS_SYSTEM_SECURITY, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, LcsError,
    MAXIMUM_ALLOWED, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_OK, RSI_READ_KEY,
    RsiMalformedSourceDataPlan, RsiMappedErrno, RsiRetainedRequest, RsiSourceDataValidationFailure,
    SYNCHRONIZE, parse_rsi_enum_children_success_response_payload,
    parse_rsi_lookup_success_response_payload, parse_rsi_read_key_success_response_payload,
    plan_rsi_malformed_source_data, rsi_response_op_code,
    validate_rsi_enum_children_metadata_security_descriptors,
    validate_rsi_lookup_metadata_security_descriptors,
    validate_rsi_read_key_response_security_descriptor,
};

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


fn sid(authority: u8, subauths: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(1);
    bytes.push(subauths.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, authority]);
    for subauth in subauths {
        bytes.extend_from_slice(&subauth.to_le_bytes());
    }
    bytes
}

fn basic_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
    let ace_size = 8 + sid.len();
    let mut bytes = Vec::new();
    bytes.push(ACCESS_ALLOWED_ACE_TYPE);
    bytes.push(0);
    bytes.extend_from_slice(&(ace_size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::new();
    bytes.push(2);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    bytes
}

fn sd_with_dacl_mask(mask: u32) -> Vec<u8> {
    let owner = sid(5, &[18]);
    let user = sid(5, &[21, 1000]);
    let dacl = acl(&[basic_ace(mask, &user)]);
    let mut bytes = vec![0u8; 20];
    let owner_offset = bytes.len() as u32;
    bytes.extend_from_slice(&owner);
    let dacl_offset = bytes.len() as u32;
    bytes.extend_from_slice(&dacl);

    let control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes
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
fn rsi_source_sd_validation_accepts_raw_generic_ace_masks() {
    let sd =
        sd_with_dacl_mask(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | ACCESS_SYSTEM_SECURITY);
    let frame = read_key_payload(707, &sd);
    let parsed = parse_rsi_read_key_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 707,
            op_code: RSI_READ_KEY,
        },
    )
    .unwrap();

    validate_rsi_read_key_response_security_descriptor(&parsed).unwrap();
}

#[test]
fn rsi_read_key_source_sd_rejects_maximum_allowed_ace_masks() {
    let sd = sd_with_dacl_mask(MAXIMUM_ALLOWED);
    let frame = read_key_payload(708, &sd);
    let parsed = parse_rsi_read_key_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 708,
            op_code: RSI_READ_KEY,
        },
    )
    .unwrap();

    assert_eq!(
        validate_rsi_read_key_response_security_descriptor(&parsed),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "rsi_read_key.sd"
        })
    );
}

#[test]
fn rsi_lookup_source_sd_rejects_synchronize_ace_masks() {
    let sd = sd_with_dacl_mask(SYNCHRONIZE);
    let frame = lookup_payload(709, &sd);
    let parsed = parse_rsi_lookup_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 709,
            op_code: RSI_LOOKUP,
        },
    )
    .unwrap();

    assert_eq!(
        validate_rsi_lookup_metadata_security_descriptors(&parsed),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "rsi_lookup.metadata.sd"
        })
    );
}

#[test]
fn rsi_enum_children_source_sd_rejects_unknown_ace_mask_bits() {
    let sd = sd_with_dacl_mask(0x0400_0000);
    let frame = enum_children_payload(710, &sd);
    let parsed = parse_rsi_enum_children_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 710,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .unwrap();

    assert_eq!(
        validate_rsi_enum_children_metadata_security_descriptors(&parsed),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "rsi_enum_children.metadata.sd"
        })
    );
}

#[test]
fn malformed_source_sd_ace_masks_use_eio_audit_source_retention_policy() {
    assert_eq!(
        plan_rsi_malformed_source_data(RsiSourceDataValidationFailure::MalformedSecurityDescriptor),
        RsiMalformedSourceDataPlan {
            failure: RsiSourceDataValidationFailure::MalformedSecurityDescriptor,
            caller_errno: RsiMappedErrno::Eio,
            emit_audit: true,
            keep_source_alive: true,
            retain_previous_layer_metadata_sd: false,
        }
    );
}
