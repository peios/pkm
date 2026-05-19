//! Pure LCS audit-event vocabulary and payload planning.

use crate::config::{
    ConfigRange, LcsLimits, SelfConfigRetentionReason, SelfConfigValue, retained_config_value,
    self_config_audit_intent,
};
use crate::constants::REG_DWORD;
use crate::error::{LcsError, LcsResult};
use crate::path::validate_hive_name_bytes;
use crate::rsi::RsiSourceDataValidationFailure;
use kacs_core::Sid;

pub const LCS_CONFIG_ROOT_PATH: &str = "Machine\\System\\Registry";
pub const LCS_SACL_MATCH_SUCCESS: u32 = 0x1;
pub const LCS_SACL_MATCH_FAILURE: u32 = 0x2;
pub const LCS_SACL_MATCH_VALID_MASK: u32 = LCS_SACL_MATCH_SUCCESS | LCS_SACL_MATCH_FAILURE;

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

/// Bounded caller token summary embedded in LCS audit payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsCallerTokenSummary<'a> {
    pub effective_token_guid: [u8; 16],
    pub true_token_guid: [u8; 16],
    pub process_guid: [u8; 16],
    pub user_sid: &'a [u8],
    pub authentication_id: u64,
    pub token_id: u64,
    pub token_type: u32,
    pub impersonation_level: u32,
    pub integrity_level: u32,
}

impl LcsCallerTokenSummary<'_> {
    pub fn validate(&self) -> LcsResult<()> {
        Sid::parse(self.user_sid).map_err(|_| LcsError::MalformedAuditCallerSid {
            field: "caller.user_sid",
        })?;
        Ok(())
    }
}

/// AccessCheck decision vocabulary in `LCS_KEY_OPEN_AUDIT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsKeyOpenAuditDecision {
    Allowed,
    Denied,
}

impl LcsKeyOpenAuditDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
        }
    }
}

/// Pure payload plan for `LCS_KEY_OPEN_AUDIT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsKeyOpenAuditRecord<'a> {
    pub event_kind: LcsAuditEventKind,
    pub caller: LcsCallerTokenSummary<'a>,
    pub key_guid: [u8; 16],
    pub requested_access: u32,
    pub granted_access: u32,
    pub decision: LcsKeyOpenAuditDecision,
    pub sacl_match_flags: u32,
}

/// Pure payload plan for backup/restore start events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsBackupRestoreStartAuditRecord<'a> {
    pub event_kind: LcsAuditEventKind,
    pub caller: LcsCallerTokenSummary<'a>,
    pub key_guid: [u8; 16],
    pub fd: i32,
}

/// Pure payload plan for backup/restore complete events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsBackupRestoreCompleteAuditRecord<'a> {
    pub event_kind: LcsAuditEventKind,
    pub caller: LcsCallerTokenSummary<'a>,
    pub key_guid: [u8; 16],
    pub result_errno: u32,
}

/// Stable source-validation failure vocabulary in `LCS_SOURCE_VALIDATION_FAILURE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsSourceValidationClass {
    MalformedSecurityDescriptor,
    FutureSequenceNumber,
    DuplicateWinningSequenceTie,
    MalformedLayerMetadataSecurityDescriptor,
}

impl LcsSourceValidationClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedSecurityDescriptor => "malformed_security_descriptor",
            Self::FutureSequenceNumber => "future_sequence_number",
            Self::DuplicateWinningSequenceTie => "duplicate_winning_sequence_tie",
            Self::MalformedLayerMetadataSecurityDescriptor => {
                "malformed_layer_metadata_security_descriptor"
            }
        }
    }
}

impl From<RsiSourceDataValidationFailure> for LcsSourceValidationClass {
    fn from(value: RsiSourceDataValidationFailure) -> Self {
        match value {
            RsiSourceDataValidationFailure::MalformedSecurityDescriptor => {
                Self::MalformedSecurityDescriptor
            }
            RsiSourceDataValidationFailure::FutureSequenceNumber => Self::FutureSequenceNumber,
            RsiSourceDataValidationFailure::DuplicateWinningSequenceTie => {
                Self::DuplicateWinningSequenceTie
            }
            RsiSourceDataValidationFailure::MalformedLayerMetadataSecurityDescriptor => {
                Self::MalformedLayerMetadataSecurityDescriptor
            }
        }
    }
}

/// Pure payload plan for `LCS_SOURCE_VALIDATION_FAILURE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsSourceValidationFailureAuditRecord<'a> {
    pub event_kind: LcsAuditEventKind,
    pub source_slot: u32,
    pub hive_name: Option<&'a str>,
    pub request_id: Option<u64>,
    pub op_code: Option<u16>,
    pub key_guid: Option<[u8; 16]>,
    pub validation_class: LcsSourceValidationClass,
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

impl LcsSelfConfigReceivedValue {
    pub const fn received_kind(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::WrongType { .. } => "wrong_type",
            Self::DwordOutOfRange { .. } => "dword_out_of_range",
        }
    }

    pub const fn received_type(self) -> Option<u32> {
        match self {
            Self::WrongType { actual_type } => Some(actual_type),
            Self::Missing | Self::DwordOutOfRange { .. } => None,
        }
    }

    pub const fn received_u32(self) -> Option<u32> {
        match self {
            Self::DwordOutOfRange { value } => Some(value),
            Self::Missing | Self::WrongType { .. } => None,
        }
    }
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

impl LcsSelfConfigInvalidAuditRecord {
    pub const fn received_kind(&self) -> &'static str {
        self.received.received_kind()
    }

    pub const fn received_type(&self) -> Option<u32> {
        self.received.received_type()
    }

    pub const fn received_u32(&self) -> Option<u32> {
        self.received.received_u32()
    }
}

pub fn validate_sacl_match_flags(flags: u32) -> LcsResult<u32> {
    if flags == 0 {
        return Err(LcsError::ZeroSaclMatchFlags);
    }
    let unknown = flags & !LCS_SACL_MATCH_VALID_MASK;
    if unknown != 0 {
        return Err(LcsError::UnknownSaclMatchFlags { flags, unknown });
    }
    Ok(flags)
}

pub fn plan_key_open_audit_record<'a>(
    caller: LcsCallerTokenSummary<'a>,
    key_guid: [u8; 16],
    requested_access: u32,
    granted_access: u32,
    decision: LcsKeyOpenAuditDecision,
    sacl_match_flags: u32,
) -> LcsResult<LcsKeyOpenAuditRecord<'a>> {
    caller.validate()?;
    let sacl_match_flags = validate_sacl_match_flags(sacl_match_flags)?;
    Ok(LcsKeyOpenAuditRecord {
        event_kind: LcsAuditEventKind::KeyOpenAudit,
        caller,
        key_guid,
        requested_access,
        granted_access,
        decision,
        sacl_match_flags,
    })
}

pub fn plan_backup_start_audit_record<'a>(
    caller: LcsCallerTokenSummary<'a>,
    key_guid: [u8; 16],
    output_fd: i32,
) -> LcsResult<LcsBackupRestoreStartAuditRecord<'a>> {
    plan_backup_restore_start_audit_record(
        LcsAuditEventKind::BackupStart,
        caller,
        key_guid,
        output_fd,
    )
}

pub fn plan_restore_start_audit_record<'a>(
    caller: LcsCallerTokenSummary<'a>,
    key_guid: [u8; 16],
    input_fd: i32,
) -> LcsResult<LcsBackupRestoreStartAuditRecord<'a>> {
    plan_backup_restore_start_audit_record(
        LcsAuditEventKind::RestoreStart,
        caller,
        key_guid,
        input_fd,
    )
}

pub fn plan_backup_complete_audit_record(
    caller: LcsCallerTokenSummary<'_>,
    key_guid: [u8; 16],
    result_errno: u32,
) -> LcsResult<LcsBackupRestoreCompleteAuditRecord<'_>> {
    plan_backup_restore_complete_audit_record(
        LcsAuditEventKind::BackupComplete,
        caller,
        key_guid,
        result_errno,
    )
}

pub fn plan_restore_complete_audit_record(
    caller: LcsCallerTokenSummary<'_>,
    key_guid: [u8; 16],
    result_errno: u32,
) -> LcsResult<LcsBackupRestoreCompleteAuditRecord<'_>> {
    plan_backup_restore_complete_audit_record(
        LcsAuditEventKind::RestoreComplete,
        caller,
        key_guid,
        result_errno,
    )
}

pub fn plan_source_validation_failure_audit_record<'a>(
    limits: &LcsLimits,
    source_slot: u32,
    hive_name: Option<&'a str>,
    request_id: Option<u64>,
    op_code: Option<u16>,
    key_guid: Option<[u8; 16]>,
    validation_failure: RsiSourceDataValidationFailure,
) -> LcsResult<LcsSourceValidationFailureAuditRecord<'a>> {
    if let Some(hive_name) = hive_name {
        validate_hive_name_bytes(hive_name.as_bytes(), limits)?;
    }
    Ok(LcsSourceValidationFailureAuditRecord {
        event_kind: LcsAuditEventKind::SourceValidationFailure,
        source_slot,
        hive_name,
        request_id,
        op_code,
        key_guid,
        validation_class: validation_failure.into(),
    })
}

fn plan_backup_restore_start_audit_record<'a>(
    event_kind: LcsAuditEventKind,
    caller: LcsCallerTokenSummary<'a>,
    key_guid: [u8; 16],
    fd: i32,
) -> LcsResult<LcsBackupRestoreStartAuditRecord<'a>> {
    caller.validate()?;
    if fd < 0 {
        return Err(LcsError::InvalidAuditFd { fd });
    }
    Ok(LcsBackupRestoreStartAuditRecord {
        event_kind,
        caller,
        key_guid,
        fd,
    })
}

fn plan_backup_restore_complete_audit_record(
    event_kind: LcsAuditEventKind,
    caller: LcsCallerTokenSummary<'_>,
    key_guid: [u8; 16],
    result_errno: u32,
) -> LcsResult<LcsBackupRestoreCompleteAuditRecord<'_>> {
    caller.validate()?;
    Ok(LcsBackupRestoreCompleteAuditRecord {
        event_kind,
        caller,
        key_guid,
        result_errno,
    })
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
