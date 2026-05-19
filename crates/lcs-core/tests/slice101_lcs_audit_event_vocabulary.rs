use lcs_core::{
    LCS_CONFIG_ROOT_PATH, LcsAuditEmissionFailurePolicy, LcsAuditEventKind, LcsLimits,
    LcsSelfConfigInvalidAuditRecord, LcsSelfConfigReceivedValue, REG_DWORD, REG_SZ,
    REQUEST_TIMEOUT_MS, lcs_audit_emission_failure_policy, plan_self_config_invalid_audit_record,
};

#[test]
fn lcs_audit_event_names_match_psd_005() {
    assert_eq!(
        LcsAuditEventKind::KeyOpenAudit.event_type(),
        "LCS_KEY_OPEN_AUDIT"
    );
    assert_eq!(
        LcsAuditEventKind::BackupStart.event_type(),
        "LCS_BACKUP_START"
    );
    assert_eq!(
        LcsAuditEventKind::BackupComplete.event_type(),
        "LCS_BACKUP_COMPLETE"
    );
    assert_eq!(
        LcsAuditEventKind::RestoreStart.event_type(),
        "LCS_RESTORE_START"
    );
    assert_eq!(
        LcsAuditEventKind::RestoreComplete.event_type(),
        "LCS_RESTORE_COMPLETE"
    );
    assert_eq!(
        LcsAuditEventKind::SourceValidationFailure.event_type(),
        "LCS_SOURCE_VALIDATION_FAILURE"
    );
    assert_eq!(
        LcsAuditEventKind::SelfConfigInvalid.event_type(),
        "LCS_SELF_CONFIG_INVALID"
    );
}

#[test]
fn lcs_audit_failure_policy_matches_psd_005() {
    assert_eq!(
        lcs_audit_emission_failure_policy(LcsAuditEventKind::KeyOpenAudit),
        LcsAuditEmissionFailurePolicy::FailOperationWithEio
    );
    assert_eq!(
        lcs_audit_emission_failure_policy(LcsAuditEventKind::BackupStart),
        LcsAuditEmissionFailurePolicy::FailOperationWithEio
    );
    assert_eq!(
        lcs_audit_emission_failure_policy(LcsAuditEventKind::RestoreStart),
        LcsAuditEmissionFailurePolicy::FailOperationWithEio
    );
    assert_eq!(
        lcs_audit_emission_failure_policy(LcsAuditEventKind::BackupComplete),
        LcsAuditEmissionFailurePolicy::PreserveAlreadyDeterminedResult
    );
    assert_eq!(
        lcs_audit_emission_failure_policy(LcsAuditEventKind::RestoreComplete),
        LcsAuditEmissionFailurePolicy::PreserveAlreadyDeterminedResult
    );
    assert_eq!(
        lcs_audit_emission_failure_policy(LcsAuditEventKind::SourceValidationFailure),
        LcsAuditEmissionFailurePolicy::PreserveAlreadyDeterminedResult
    );
    assert_eq!(
        lcs_audit_emission_failure_policy(LcsAuditEventKind::SelfConfigInvalid),
        LcsAuditEmissionFailurePolicy::PreserveRetainedConfiguration
    );
}

#[test]
fn self_config_invalid_audit_record_carries_required_fields() {
    let current = LcsLimits {
        request_timeout_ms: 45_000,
        ..LcsLimits::default()
    };

    assert_eq!(
        plan_self_config_invalid_audit_record(
            &current,
            REQUEST_TIMEOUT_MS,
            Some(lcs_core::SelfConfigValue::Dword(999_999))
        ),
        Some(LcsSelfConfigInvalidAuditRecord {
            event_kind: LcsAuditEventKind::SelfConfigInvalid,
            configuration_parent_path: LCS_CONFIG_ROOT_PATH,
            configuration_name: "RequestTimeoutMs",
            expected_type: REG_DWORD,
            expected_min: 1_000,
            expected_max: 600_000,
            received: LcsSelfConfigReceivedValue::DwordOutOfRange { value: 999_999 },
            retained_value: 45_000,
        })
    );

    assert_eq!(
        plan_self_config_invalid_audit_record(
            &current,
            REQUEST_TIMEOUT_MS,
            Some(lcs_core::SelfConfigValue::WrongType {
                actual_type: REG_SZ,
            })
        )
        .unwrap()
        .received,
        LcsSelfConfigReceivedValue::WrongType {
            actual_type: REG_SZ
        }
    );

    assert_eq!(
        plan_self_config_invalid_audit_record(&current, REQUEST_TIMEOUT_MS, None)
            .unwrap()
            .received,
        LcsSelfConfigReceivedValue::Missing
    );
}

#[test]
fn self_config_audit_record_is_absent_for_valid_value() {
    assert_eq!(
        plan_self_config_invalid_audit_record(
            &LcsLimits::default(),
            REQUEST_TIMEOUT_MS,
            Some(lcs_core::SelfConfigValue::Dword(60_000))
        ),
        None
    );
}
