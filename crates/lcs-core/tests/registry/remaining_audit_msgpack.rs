use crate::common::sid;
use kacs_core::TokenType;
use lcs_core::{
    LCS_CONFIG_ROOT_PATH, LcsAuditEventKind, LcsAuditPayloadWritePlan, LcsCallerTokenSummary,
    LcsError, LcsLimits, REG_SZ, REQUEST_TIMEOUT_MS, RsiSourceDataValidationFailure,
    SelfConfigValue, backup_restore_complete_audit_payload_len,
    backup_restore_start_audit_payload_len, plan_backup_complete_audit_record,
    plan_backup_start_audit_record, plan_restore_complete_audit_record,
    plan_restore_start_audit_record, plan_self_config_invalid_audit_record,
    plan_source_validation_failure_audit_record, self_config_invalid_audit_payload_len,
    source_validation_failure_audit_payload_len, write_backup_restore_complete_audit_payload,
    write_backup_restore_start_audit_payload, write_self_config_invalid_audit_payload,
    write_source_validation_failure_audit_payload,
};

fn caller(user_sid: &[u8]) -> LcsCallerTokenSummary<'_> {
    LcsCallerTokenSummary {
        user_sid,
        integrity_level: 512,
        token_id: 99,
        authentication_id: 42,
        token_type: TokenType::Primary,
        impersonation_level: 0,
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

fn append_i32(dst: &mut Vec<u8>, value: i32) {
    dst.push(0xd2);
    dst.extend_from_slice(&value.to_be_bytes());
}

/// The `caller` group: `subject.token.{sid,integrity,id,auth-id,type,
/// impersonation}`, written as the `subject` entry of the top-level map.
fn append_caller(dst: &mut Vec<u8>, user_sid: &[u8]) {
    append_str(dst, "subject");
    dst.push(0x81);
    append_str(dst, "token");
    dst.push(0x86);
    append_str(dst, "sid");
    append_bin(dst, user_sid);
    append_str(dst, "integrity");
    append_uint(dst, 512);
    append_str(dst, "id");
    append_uint(dst, 99);
    append_str(dst, "auth-id");
    append_uint(dst, 42);
    append_str(dst, "type");
    append_str(dst, "primary");
    append_str(dst, "impersonation");
    append_uint(dst, 0);
}

/// `object: {key: {guid: ...}}`.
fn append_object_key(dst: &mut Vec<u8>, key_guid: &[u8; 16]) {
    append_str(dst, "object");
    dst.push(0x81);
    append_str(dst, "key");
    dst.push(0x81);
    append_str(dst, "guid");
    append_bin(dst, key_guid);
}

fn expected_start_payload(user_sid: &[u8], fd: u64) -> Vec<u8> {
    let mut expected = Vec::new();
    expected.push(0x83);
    append_caller(&mut expected, user_sid);
    append_object_key(&mut expected, &[7; 16]);
    append_str(&mut expected, "operation");
    expected.push(0x81);
    append_str(&mut expected, "fd");
    append_uint(&mut expected, fd);
    expected
}

/// `outcome.errno` is the negated errno, and is absent on success.
fn expected_complete_payload(user_sid: &[u8], errno: Option<i32>) -> Vec<u8> {
    let mut expected = Vec::new();
    expected.push(0x83);
    append_caller(&mut expected, user_sid);
    append_object_key(&mut expected, &[7; 16]);
    append_str(&mut expected, "outcome");
    match errno {
        None => {
            expected.push(0x81);
            append_str(&mut expected, "success");
            expected.push(0xc3);
        }
        Some(errno) => {
            expected.push(0x82);
            append_str(&mut expected, "success");
            expected.push(0xc2);
            append_str(&mut expected, "errno");
            append_i32(&mut expected, errno);
        }
    }
    expected
}

/// `lcs.config.value.rejected`: one `config` map, the same shape as
/// `kmes.config.value.rejected`.
fn expected_self_config_payload(
    received_kind: &str,
    received_type: Option<u32>,
    received_value: Option<u32>,
) -> Vec<u8> {
    let mut expected = Vec::new();
    expected.push(0x81);
    append_str(&mut expected, "config");
    expected.push(0x85);
    append_str(&mut expected, "key");
    expected.push(0x81);
    append_str(&mut expected, "path");
    append_str(&mut expected, LCS_CONFIG_ROOT_PATH);
    append_str(&mut expected, "name");
    append_str(&mut expected, REQUEST_TIMEOUT_MS.name);
    append_str(&mut expected, "expected");
    expected.push(0x83);
    append_str(&mut expected, "type");
    append_uint(&mut expected, lcs_core::REG_DWORD as u64);
    append_str(&mut expected, "min");
    append_uint(&mut expected, REQUEST_TIMEOUT_MS.min as u64);
    append_str(&mut expected, "max");
    append_uint(&mut expected, REQUEST_TIMEOUT_MS.max as u64);
    append_str(&mut expected, "received");
    expected.push(0x81 + u8::from(received_type.is_some()) + u8::from(received_value.is_some()));
    append_str(&mut expected, "kind");
    append_str(&mut expected, received_kind);
    if let Some(value) = received_type {
        append_str(&mut expected, "type");
        append_uint(&mut expected, value as u64);
    }
    if let Some(value) = received_value {
        append_str(&mut expected, "value");
        append_uint(&mut expected, value as u64);
    }
    append_str(&mut expected, "value");
    append_uint(&mut expected, 45_000);
    expected
}

#[test]
fn backup_and_restore_start_payloads_serialize_caller_key_and_fd() {
    let user = sid(5, &[18]);
    // operation.fd is a uint, not the int32 the old `fd` key carried.
    let expected = expected_start_payload(&user, 11);

    let backup = plan_backup_start_audit_record(caller(&user), [7; 16], 11).unwrap();
    let restore = plan_restore_start_audit_record(caller(&user), [7; 16], 11).unwrap();
    let mut backup_output = vec![0xaa; expected.len() + 4];
    let mut restore_output = vec![0xbb; expected.len()];

    let backup_plan = write_backup_restore_start_audit_payload(&backup, &mut backup_output)
        .expect("backup start payload");
    let restore_plan = write_backup_restore_start_audit_payload(&restore, &mut restore_output)
        .expect("restore start payload");

    assert_eq!(
        backup_plan,
        LcsAuditPayloadWritePlan {
            bytes: expected.len()
        }
    );
    assert_eq!(restore_plan.bytes, expected.len());
    assert_eq!(
        backup_restore_start_audit_payload_len(&backup),
        Ok(expected.len())
    );
    assert_eq!(&backup_output[..backup_plan.bytes], expected.as_slice());
    assert_eq!(&backup_output[backup_plan.bytes..], &[0xaa; 4]);
    assert_eq!(restore_output, expected);
}

#[test]
fn backup_and_restore_complete_payloads_serialize_outcome() {
    let user = sid(5, &[18]);
    let expected_success = expected_complete_payload(&user, None);
    let expected_failure = expected_complete_payload(&user, Some(-5));
    let backup = plan_backup_complete_audit_record(caller(&user), [7; 16], 0).unwrap();
    let restore = plan_restore_complete_audit_record(caller(&user), [7; 16], 5).unwrap();
    let mut backup_output = vec![0; expected_success.len()];
    let mut restore_output = vec![0; expected_failure.len()];

    let backup_plan =
        write_backup_restore_complete_audit_payload(&backup, &mut backup_output).unwrap();
    let restore_plan =
        write_backup_restore_complete_audit_payload(&restore, &mut restore_output).unwrap();

    assert_eq!(backup_plan.bytes, expected_success.len());
    assert_eq!(restore_plan.bytes, expected_failure.len());
    assert_eq!(
        backup_restore_complete_audit_payload_len(&backup),
        Ok(expected_success.len())
    );
    assert_eq!(backup_output, expected_success);
    assert_eq!(restore_output, expected_failure);
}

#[test]
fn source_validation_failure_payload_serializes_optional_context() {
    let key_guid = [8; 16];
    let record = plan_source_validation_failure_audit_record(
        &LcsLimits::default(),
        3,
        Some("Machine"),
        Some(44),
        Some(0x1234),
        Some(key_guid),
        RsiSourceDataValidationFailure::MalformedLayerName,
    )
    .expect("valid source-validation audit record");
    let mut expected = Vec::new();
    expected.push(0x84);
    append_str(&mut expected, "source");
    expected.push(0x81);
    append_str(&mut expected, "rsi");
    expected.push(0x82);
    append_str(&mut expected, "slot");
    append_uint(&mut expected, 3);
    append_str(&mut expected, "hive");
    append_str(&mut expected, "Machine");
    append_str(&mut expected, "request");
    expected.push(0x82);
    append_str(&mut expected, "id");
    append_uint(&mut expected, 44);
    append_str(&mut expected, "op-code");
    append_uint(&mut expected, 0x1234);
    append_object_key(&mut expected, &key_guid);
    append_str(&mut expected, "outcome");
    expected.push(0x81);
    append_str(&mut expected, "reason");
    append_str(&mut expected, "malformed-layer-name");
    let mut output = vec![0; expected.len()];

    let plan = write_source_validation_failure_audit_payload(&record, &mut output).unwrap();

    assert_eq!(plan.bytes, expected.len());
    assert_eq!(
        source_validation_failure_audit_payload_len(&record),
        Ok(expected.len())
    );
    assert_eq!(output, expected);
}

#[test]
fn source_validation_failure_payload_leaves_absent_context_out() {
    let record = plan_source_validation_failure_audit_record(
        &LcsLimits::default(),
        9,
        None,
        None,
        None,
        None,
        RsiSourceDataValidationFailure::FutureSequenceNumber,
    )
    .expect("valid source-validation audit record");
    // No hive, request or key: those maps are absent, not nil, and the
    // top-level map counts only `source` and `outcome`.
    let mut expected = Vec::new();
    expected.push(0x82);
    append_str(&mut expected, "source");
    expected.push(0x81);
    append_str(&mut expected, "rsi");
    expected.push(0x81);
    append_str(&mut expected, "slot");
    append_uint(&mut expected, 9);
    append_str(&mut expected, "outcome");
    expected.push(0x81);
    append_str(&mut expected, "reason");
    append_str(&mut expected, "future-sequence-number");
    let mut output = vec![0; expected.len()];

    let plan = write_source_validation_failure_audit_payload(&record, &mut output).unwrap();

    assert_eq!(plan.bytes, expected.len());
    assert_eq!(output, expected);
}

#[test]
fn source_validation_failure_payload_writes_request_with_only_the_op_code() {
    let record = plan_source_validation_failure_audit_record(
        &LcsLimits::default(),
        2,
        None,
        None,
        Some(0x0021),
        None,
        RsiSourceDataValidationFailure::MalformedResponsePayload,
    )
    .expect("valid source-validation audit record");
    let mut expected = Vec::new();
    expected.push(0x83);
    append_str(&mut expected, "source");
    expected.push(0x81);
    append_str(&mut expected, "rsi");
    expected.push(0x81);
    append_str(&mut expected, "slot");
    append_uint(&mut expected, 2);
    append_str(&mut expected, "request");
    expected.push(0x81);
    append_str(&mut expected, "op-code");
    append_uint(&mut expected, 0x0021);
    append_str(&mut expected, "outcome");
    expected.push(0x81);
    append_str(&mut expected, "reason");
    append_str(&mut expected, "malformed-response-payload");
    let mut output = vec![0; expected.len()];

    let plan = write_source_validation_failure_audit_payload(&record, &mut output).unwrap();

    assert_eq!(plan.bytes, expected.len());
    assert_eq!(
        source_validation_failure_audit_payload_len(&record),
        Ok(expected.len())
    );
    assert_eq!(output, expected);
}

#[test]
fn self_config_invalid_payload_serializes_received_value_shapes() {
    let current = LcsLimits {
        request_timeout_ms: 45_000,
        ..LcsLimits::default()
    };
    let missing =
        plan_self_config_invalid_audit_record(&current, REQUEST_TIMEOUT_MS, None).unwrap();
    let wrong_type = plan_self_config_invalid_audit_record(
        &current,
        REQUEST_TIMEOUT_MS,
        Some(SelfConfigValue::WrongType {
            actual_type: REG_SZ,
        }),
    )
    .unwrap();
    let out_of_range = plan_self_config_invalid_audit_record(
        &current,
        REQUEST_TIMEOUT_MS,
        Some(SelfConfigValue::Dword(999_999)),
    )
    .unwrap();

    let expected = expected_self_config_payload("missing", None, None);
    let expected_wrong_type = expected_self_config_payload("wrong-type", Some(REG_SZ), None);
    let expected_out_of_range = expected_self_config_payload("out-of-range", None, Some(999_999));
    let mut output = vec![0; expected.len()];
    let mut wrong_type_output = vec![0; expected_wrong_type.len()];
    let mut out_of_range_output = vec![0; expected_out_of_range.len()];

    let plan = write_self_config_invalid_audit_payload(&missing, &mut output).unwrap();
    let wrong_type_plan =
        write_self_config_invalid_audit_payload(&wrong_type, &mut wrong_type_output).unwrap();
    let out_of_range_plan =
        write_self_config_invalid_audit_payload(&out_of_range, &mut out_of_range_output).unwrap();

    assert_eq!(plan.bytes, expected.len());
    assert_eq!(wrong_type_plan.bytes, expected_wrong_type.len());
    assert_eq!(out_of_range_plan.bytes, expected_out_of_range.len());
    assert_eq!(
        self_config_invalid_audit_payload_len(&missing),
        Ok(expected.len())
    );
    assert_eq!(output, expected);
    assert_eq!(wrong_type_output, expected_wrong_type);
    assert_eq!(out_of_range_output, expected_out_of_range);
    assert_eq!(wrong_type.received_kind(), "wrong-type");
    assert_eq!(wrong_type.received_type(), Some(REG_SZ));
    assert_eq!(wrong_type.received_u32(), None);
    assert_eq!(out_of_range.received_kind(), "out-of-range");
    assert_eq!(out_of_range.received_type(), None);
    assert_eq!(out_of_range.received_u32(), Some(999_999));
}

#[test]
fn remaining_audit_serializers_fail_closed_without_partial_writes() {
    let user = sid(5, &[18]);
    let mut start = plan_backup_start_audit_record(caller(&user), [7; 16], 11).unwrap();
    start.event_kind = LcsAuditEventKind::KeyOpenAudit;
    assert_eq!(
        backup_restore_start_audit_payload_len(&start),
        Err(LcsError::AuditEventKindMismatch {
            expected: LcsAuditEventKind::BackupStart,
            actual: LcsAuditEventKind::KeyOpenAudit,
        })
    );

    let record = plan_source_validation_failure_audit_record(
        &LcsLimits::default(),
        3,
        None,
        None,
        None,
        None,
        RsiSourceDataValidationFailure::MalformedSecurityDescriptor,
    )
    .unwrap();
    let required_len = source_validation_failure_audit_payload_len(&record).unwrap();
    let mut output = vec![0xaa; required_len - 1];

    assert_eq!(
        write_source_validation_failure_audit_payload(&record, &mut output),
        Err(LcsError::AuditPayloadOutputBufferTooSmall {
            buffer_len: required_len - 1,
            required_len,
        })
    );
    assert_eq!(output, vec![0xaa; required_len - 1]);
}
