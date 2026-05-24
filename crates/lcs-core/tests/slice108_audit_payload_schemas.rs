use lcs_core::{
    LCS_CONFIG_ROOT_PATH, LCS_SACL_MATCH_FAILURE, LCS_SACL_MATCH_SUCCESS, LcsAuditEventKind,
    LcsCallerTokenSummary, LcsError, LcsKeyOpenAuditDecision, LcsSelfConfigReceivedValue,
    LcsSourceValidationClass, REG_DWORD, REG_SZ, REQUEST_TIMEOUT_MS,
    RsiSourceDataValidationFailure, plan_backup_complete_audit_record,
    plan_backup_start_audit_record, plan_key_open_audit_record, plan_restore_complete_audit_record,
    plan_restore_start_audit_record, plan_self_config_invalid_audit_record,
    plan_source_validation_failure_audit_record, validate_sacl_match_flags,
};

fn sid(authority: u8, subauths: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + subauths.len() * 4);
    bytes.push(1);
    bytes.push(subauths.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, authority]);
    for subauth in subauths {
        bytes.extend_from_slice(&subauth.to_le_bytes());
    }
    bytes
}

fn caller(user_sid: &[u8]) -> LcsCallerTokenSummary<'_> {
    LcsCallerTokenSummary {
        effective_token_guid: [1; 16],
        true_token_guid: [2; 16],
        process_guid: [3; 16],
        user_sid,
        authentication_id: 42,
        token_id: 99,
        token_type: 1,
        impersonation_level: 3,
        integrity_level: 512,
    }
}

#[test]
fn key_open_audit_record_matches_explicit_schema_and_rejects_bad_flags() {
    let user = sid(5, &[21, 1000]);
    let key_guid = [9; 16];
    let record = plan_key_open_audit_record(
        caller(&user),
        key_guid,
        0x0002_0001,
        0x0002_0001,
        LcsKeyOpenAuditDecision::Allowed,
        LCS_SACL_MATCH_SUCCESS | LCS_SACL_MATCH_FAILURE,
    )
    .expect("valid key-open audit record");

    assert_eq!(record.event_kind, LcsAuditEventKind::KeyOpenAudit);
    assert_eq!(record.caller.user_sid, user.as_slice());
    assert_eq!(record.key_guid, key_guid);
    assert_eq!(record.decision.as_str(), "allowed");
    assert_eq!(
        record.sacl_match_flags,
        LCS_SACL_MATCH_SUCCESS | LCS_SACL_MATCH_FAILURE
    );

    assert_eq!(
        validate_sacl_match_flags(0),
        Err(LcsError::ZeroSaclMatchFlags)
    );
    assert_eq!(
        validate_sacl_match_flags(0x4),
        Err(LcsError::UnknownSaclMatchFlags {
            flags: 0x4,
            unknown: 0x4,
        })
    );
}

#[test]
fn audit_caller_summary_is_bounded_and_validates_user_sid() {
    let malformed_sid = [1, 5, 0, 0];

    assert_eq!(
        caller(&malformed_sid).validate(),
        Err(LcsError::MalformedAuditCallerSid {
            field: "caller.user_sid"
        })
    );
}

#[test]
fn backup_and_restore_audit_records_use_start_complete_payload_shapes() {
    let user = sid(5, &[18]);
    let key_guid = [7; 16];

    let backup_start = plan_backup_start_audit_record(caller(&user), key_guid, 11).unwrap();
    assert_eq!(backup_start.event_kind, LcsAuditEventKind::BackupStart);
    assert_eq!(backup_start.fd, 11);

    let restore_start = plan_restore_start_audit_record(caller(&user), key_guid, 12).unwrap();
    assert_eq!(restore_start.event_kind, LcsAuditEventKind::RestoreStart);
    assert_eq!(restore_start.fd, 12);

    let backup_complete = plan_backup_complete_audit_record(caller(&user), key_guid, 0).unwrap();
    assert_eq!(
        backup_complete.event_kind,
        LcsAuditEventKind::BackupComplete
    );
    assert_eq!(backup_complete.result_errno, 0);

    let restore_complete = plan_restore_complete_audit_record(caller(&user), key_guid, 5).unwrap();
    assert_eq!(
        restore_complete.event_kind,
        LcsAuditEventKind::RestoreComplete
    );
    assert_eq!(restore_complete.result_errno, 5);

    assert_eq!(
        plan_backup_start_audit_record(caller(&user), key_guid, -1),
        Err(LcsError::InvalidAuditFd { fd: -1 })
    );
}

#[test]
fn source_validation_failure_audit_record_maps_validation_classes() {
    let key_guid = [6; 16];
    let record = plan_source_validation_failure_audit_record(
        &lcs_core::LcsLimits::default(),
        3,
        Some("Machine"),
        Some(44),
        Some(0x11),
        Some(key_guid),
        RsiSourceDataValidationFailure::MalformedLayerMetadataSecurityDescriptor,
    )
    .expect("valid source-validation audit");

    assert_eq!(
        record.event_kind,
        LcsAuditEventKind::SourceValidationFailure
    );
    assert_eq!(record.source_slot, 3);
    assert_eq!(record.hive_name, Some("Machine"));
    assert_eq!(record.request_id, Some(44));
    assert_eq!(record.op_code, Some(0x11));
    assert_eq!(record.key_guid, Some(key_guid));
    assert_eq!(
        record.validation_class,
        LcsSourceValidationClass::MalformedLayerMetadataSecurityDescriptor
    );
    assert_eq!(
        record.validation_class.as_str(),
        "malformed_layer_metadata_security_descriptor"
    );
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::FutureSequenceNumber)
            .as_str(),
        "future_sequence_number"
    );
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedKeyName).as_str(),
        "malformed_key_name"
    );
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedValueName).as_str(),
        "malformed_value_name"
    );
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedResponsePayload)
            .as_str(),
        "malformed_response_payload"
    );
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedKeyMetadata)
            .as_str(),
        "malformed_key_metadata"
    );
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedValuePayload)
            .as_str(),
        "malformed_value_payload"
    );
    assert_eq!(
        LcsSourceValidationClass::from(
            RsiSourceDataValidationFailure::MalformedDeleteLayerOrphanList,
        )
        .as_str(),
        "malformed_delete_layer_orphan_list"
    );
}

#[test]
fn source_validation_failure_rejects_malformed_optional_hive_name() {
    assert_eq!(
        plan_source_validation_failure_audit_record(
            &lcs_core::LcsLimits::default(),
            3,
            Some("Bad\\Hive"),
            None,
            None,
            None,
            RsiSourceDataValidationFailure::MalformedSecurityDescriptor,
        ),
        Err(LcsError::NameContainsSeparator { field: "hive_name" })
    );
}

#[test]
fn self_config_invalid_record_projects_explicit_received_fields() {
    let current = lcs_core::LcsLimits {
        request_timeout_ms: 45_000,
        ..lcs_core::LcsLimits::default()
    };

    let out_of_range = plan_self_config_invalid_audit_record(
        &current,
        REQUEST_TIMEOUT_MS,
        Some(lcs_core::SelfConfigValue::Dword(999_999)),
    )
    .unwrap();
    assert_eq!(
        out_of_range.event_kind,
        LcsAuditEventKind::SelfConfigInvalid
    );
    assert_eq!(out_of_range.configuration_parent_path, LCS_CONFIG_ROOT_PATH);
    assert_eq!(out_of_range.expected_type, REG_DWORD);
    assert_eq!(out_of_range.received_kind(), "dword_out_of_range");
    assert_eq!(out_of_range.received_type(), None);
    assert_eq!(out_of_range.received_u32(), Some(999_999));
    assert_eq!(out_of_range.retained_value, 45_000);

    let wrong_type = LcsSelfConfigReceivedValue::WrongType {
        actual_type: REG_SZ,
    };
    assert_eq!(wrong_type.received_kind(), "wrong_type");
    assert_eq!(wrong_type.received_type(), Some(REG_SZ));
    assert_eq!(wrong_type.received_u32(), None);

    assert_eq!(
        LcsSelfConfigReceivedValue::Missing.received_kind(),
        "missing"
    );
}
