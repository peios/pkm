use crate::common::sid;
use kacs_core::TokenType;
use lcs_core::{
    LCS_SACL_MATCH_FAILURE, LCS_SACL_MATCH_SUCCESS, LcsAuditEventKind, LcsAuditPayloadWritePlan,
    LcsCallerTokenSummary, LcsError, LcsKeyOpenAuditDecision, key_open_audit_payload_len,
    plan_key_open_audit_record, write_key_open_audit_payload,
};

fn caller(user_sid: &[u8]) -> LcsCallerTokenSummary<'_> {
    LcsCallerTokenSummary {
        user_sid,
        integrity_level: 512,
        token_id: 99,
        authentication_id: 42,
        token_type: TokenType::Impersonation,
        impersonation_level: 3,
    }
}

fn append_str(dst: &mut Vec<u8>, value: &str) {
    assert!(value.len() <= 31);
    dst.push(0xa0 | value.len() as u8);
    dst.extend_from_slice(value.as_bytes());
}

fn append_bin(dst: &mut Vec<u8>, value: &[u8]) {
    assert!(value.len() <= u8::MAX as usize);
    dst.push(0xc4);
    dst.push(value.len() as u8);
    dst.extend_from_slice(value);
}

fn append_uint(dst: &mut Vec<u8>, value: u64) {
    if value <= 0x7f {
        dst.push(value as u8);
    } else if value <= u8::MAX as u64 {
        dst.extend_from_slice(&[0xcc, value as u8]);
    } else if value <= u16::MAX as u64 {
        dst.push(0xcd);
        dst.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        dst.push(0xce);
        dst.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        dst.push(0xcf);
        dst.extend_from_slice(&value.to_be_bytes());
    }
}

/// `lcs.audit.key.opened`: `subject.token.*` (the caller group), then
/// `object.kind`, `object.key.guid`, `access.{requested,granted}`,
/// `outcome.success` and `trigger.sacl-match`, each path as nested maps.
fn expected_key_open_payload(
    user_sid: &[u8],
    requested_access: u32,
    granted_access: u32,
    success: bool,
    sacl_match_flags: u32,
) -> Vec<u8> {
    let mut expected = Vec::new();
    expected.push(0x85);
    append_str(&mut expected, "subject");
    expected.push(0x81);
    append_str(&mut expected, "token");
    expected.push(0x86);
    append_str(&mut expected, "sid");
    append_bin(&mut expected, user_sid);
    append_str(&mut expected, "integrity");
    append_uint(&mut expected, 512);
    append_str(&mut expected, "id");
    append_uint(&mut expected, 99);
    append_str(&mut expected, "auth-id");
    append_uint(&mut expected, 42);
    append_str(&mut expected, "type");
    append_str(&mut expected, "impersonation");
    append_str(&mut expected, "impersonation");
    append_uint(&mut expected, 3);

    append_str(&mut expected, "object");
    expected.push(0x82);
    append_str(&mut expected, "kind");
    append_str(&mut expected, "key");
    append_str(&mut expected, "key");
    expected.push(0x81);
    append_str(&mut expected, "guid");
    append_bin(&mut expected, &[9; 16]);

    append_str(&mut expected, "access");
    expected.push(0x82);
    append_str(&mut expected, "requested");
    append_uint(&mut expected, requested_access as u64);
    append_str(&mut expected, "granted");
    append_uint(&mut expected, granted_access as u64);

    append_str(&mut expected, "outcome");
    expected.push(0x81);
    append_str(&mut expected, "success");
    expected.push(if success { 0xc3 } else { 0xc2 });

    append_str(&mut expected, "trigger");
    expected.push(0x81);
    append_str(&mut expected, "sacl-match");
    append_uint(&mut expected, sacl_match_flags as u64);
    expected
}

#[test]
fn key_open_audit_payload_serializes_single_msgpack_map_in_table_order() {
    let user = sid(5, &[18]);
    let record = plan_key_open_audit_record(
        caller(&user),
        [9; 16],
        0x0002_0001,
        0x0002_0001,
        LcsKeyOpenAuditDecision::Allowed,
        LCS_SACL_MATCH_SUCCESS | LCS_SACL_MATCH_FAILURE,
    )
    .expect("valid key-open audit record");
    let expected = expected_key_open_payload(
        &user,
        0x0002_0001,
        0x0002_0001,
        true,
        LCS_SACL_MATCH_SUCCESS | LCS_SACL_MATCH_FAILURE,
    );
    let mut output = vec![0xaa; expected.len() + 8];

    let plan = write_key_open_audit_payload(&record, &mut output).unwrap();

    assert_eq!(
        plan,
        LcsAuditPayloadWritePlan {
            bytes: expected.len()
        }
    );
    assert_eq!(key_open_audit_payload_len(&record), Ok(expected.len()));
    assert_eq!(&output[..plan.bytes], expected.as_slice());
    assert_eq!(&output[plan.bytes..], &[0xaa; 8]);
    assert_eq!(output[0], 0x85);
    assert_eq!(output[9], 0x81);
    assert_eq!(output[16], 0x86);
}

#[test]
fn key_open_audit_payload_serializes_denied_decision_with_zero_grant() {
    let user = sid(5, &[21, 1000]);
    let record = plan_key_open_audit_record(
        caller(&user),
        [9; 16],
        0x0002_0001,
        0,
        LcsKeyOpenAuditDecision::Denied,
        LCS_SACL_MATCH_FAILURE,
    )
    .expect("valid denied key-open audit record");
    let expected = expected_key_open_payload(&user, 0x0002_0001, 0, false, LCS_SACL_MATCH_FAILURE);
    let mut output = vec![0; expected.len()];

    let plan = write_key_open_audit_payload(&record, &mut output).unwrap();

    assert_eq!(plan.bytes, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn denied_key_open_audit_record_requires_zero_granted_access() {
    let user = sid(5, &[18]);

    assert_eq!(
        plan_key_open_audit_record(
            caller(&user),
            [9; 16],
            0x0002_0001,
            1,
            LcsKeyOpenAuditDecision::Denied,
            LCS_SACL_MATCH_FAILURE,
        ),
        Err(LcsError::DeniedKeyOpenAuditWithGrantedAccess { granted_access: 1 })
    );
}

#[test]
fn key_open_audit_payload_refuses_short_buffer_without_partial_write() {
    let user = sid(5, &[18]);
    let record = plan_key_open_audit_record(
        caller(&user),
        [9; 16],
        0x0002_0001,
        0x0002_0001,
        LcsKeyOpenAuditDecision::Allowed,
        LCS_SACL_MATCH_SUCCESS,
    )
    .expect("valid key-open audit record");
    let required_len = key_open_audit_payload_len(&record).unwrap();
    let mut output = vec![0xaa; required_len - 1];

    assert_eq!(
        write_key_open_audit_payload(&record, &mut output),
        Err(LcsError::AuditPayloadOutputBufferTooSmall {
            buffer_len: required_len - 1,
            required_len,
        })
    );
    assert_eq!(output, vec![0xaa; required_len - 1]);
}

#[test]
fn key_open_audit_payload_rejects_wrong_typed_event_kind() {
    let user = sid(5, &[18]);
    let mut record = plan_key_open_audit_record(
        caller(&user),
        [9; 16],
        0x0002_0001,
        0x0002_0001,
        LcsKeyOpenAuditDecision::Allowed,
        LCS_SACL_MATCH_SUCCESS,
    )
    .expect("valid key-open audit record");
    record.event_kind = LcsAuditEventKind::BackupStart;

    assert_eq!(
        key_open_audit_payload_len(&record),
        Err(LcsError::AuditEventKindMismatch {
            expected: LcsAuditEventKind::KeyOpenAudit,
            actual: LcsAuditEventKind::BackupStart,
        })
    );
}
