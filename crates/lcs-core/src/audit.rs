//! Pure LCS audit-event vocabulary and payload planning.

use crate::config::{
    ConfigRange, LcsLimits, SelfConfigRetentionReason, SelfConfigValue, retained_config_value,
    self_config_audit_intent,
};
use crate::constants::REG_DWORD;

pub const LCS_CONFIG_ROOT_PATH: &str = "Machine\\System\\Registry";

/// PSD-005 LCS KMES audit event names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsAuditEventKind {
    KeyOpenAudit,
    BackupStart,
    BackupComplete,
    RestoreStart,
    RestoreComplete,
    SourceValidationFailure,
    SelfConfigInvalid,
}

impl LcsAuditEventKind {
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::KeyOpenAudit => "LCS_KEY_OPEN_AUDIT",
            Self::BackupStart => "LCS_BACKUP_START",
            Self::BackupComplete => "LCS_BACKUP_COMPLETE",
            Self::RestoreStart => "LCS_RESTORE_START",
            Self::RestoreComplete => "LCS_RESTORE_COMPLETE",
            Self::SourceValidationFailure => "LCS_SOURCE_VALIDATION_FAILURE",
            Self::SelfConfigInvalid => "LCS_SELF_CONFIG_INVALID",
        }
    }
}

/// Policy to apply if synchronous KMES emission fails at the audit point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsAuditEmissionFailurePolicy {
    FailOperationWithEio,
    PreserveAlreadyDeterminedResult,
    PreserveRetainedConfiguration,
}

pub const fn lcs_audit_emission_failure_policy(
    kind: LcsAuditEventKind,
) -> LcsAuditEmissionFailurePolicy {
    match kind {
        LcsAuditEventKind::KeyOpenAudit
        | LcsAuditEventKind::BackupStart
        | LcsAuditEventKind::RestoreStart => LcsAuditEmissionFailurePolicy::FailOperationWithEio,
        LcsAuditEventKind::BackupComplete
        | LcsAuditEventKind::RestoreComplete
        | LcsAuditEventKind::SourceValidationFailure => {
            LcsAuditEmissionFailurePolicy::PreserveAlreadyDeterminedResult
        }
        LcsAuditEventKind::SelfConfigInvalid => {
            LcsAuditEmissionFailurePolicy::PreserveRetainedConfiguration
        }
    }
}

/// Received-value summary for `LCS_SELF_CONFIG_INVALID`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsSelfConfigReceivedValue {
    Missing,
    WrongType { actual_type: u32 },
    DwordOutOfRange { value: u32 },
}

/// Pure payload plan for the `LCS_SELF_CONFIG_INVALID` audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsSelfConfigInvalidAuditRecord {
    pub event_kind: LcsAuditEventKind,
    pub configuration_parent_path: &'static str,
    pub configuration_name: &'static str,
    pub expected_type: u32,
    pub expected_min: u32,
    pub expected_max: u32,
    pub received: LcsSelfConfigReceivedValue,
    pub retained_value: u32,
}

pub fn plan_self_config_invalid_audit_record(
    current: &LcsLimits,
    range: ConfigRange,
    value: Option<SelfConfigValue>,
) -> Option<LcsSelfConfigInvalidAuditRecord> {
    let intent = self_config_audit_intent(current, range, value)?;
    let received = match intent.reason {
        SelfConfigRetentionReason::Missing => LcsSelfConfigReceivedValue::Missing,
        SelfConfigRetentionReason::WrongType { actual_type } => {
            LcsSelfConfigReceivedValue::WrongType { actual_type }
        }
        SelfConfigRetentionReason::OutOfRange { value, .. } => {
            LcsSelfConfigReceivedValue::DwordOutOfRange { value }
        }
    };

    Some(LcsSelfConfigInvalidAuditRecord {
        event_kind: LcsAuditEventKind::SelfConfigInvalid,
        configuration_parent_path: LCS_CONFIG_ROOT_PATH,
        configuration_name: range.name,
        expected_type: REG_DWORD,
        expected_min: range.min,
        expected_max: range.max,
        received,
        retained_value: retained_config_value(current, range),
    })
}
