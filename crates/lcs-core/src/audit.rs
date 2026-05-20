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

const FIELD_CALLER: &str = "caller";
const FIELD_KEY_GUID: &str = "key_guid";
const FIELD_REQUESTED_ACCESS: &str = "requested_access";
const FIELD_GRANTED_ACCESS: &str = "granted_access";
const FIELD_DECISION: &str = "decision";
const FIELD_SACL_MATCH_FLAGS: &str = "sacl_match_flags";
const FIELD_FD: &str = "fd";
const FIELD_RESULT_ERRNO: &str = "result_errno";
const FIELD_SOURCE_SLOT: &str = "source_slot";
const FIELD_HIVE_NAME: &str = "hive_name";
const FIELD_REQUEST_ID: &str = "request_id";
const FIELD_OP_CODE: &str = "op_code";
const FIELD_VALIDATION_CLASS: &str = "validation_class";
const FIELD_CONFIGURATION_PARENT_PATH: &str = "configuration_parent_path";
const FIELD_CONFIGURATION_NAME: &str = "configuration_name";
const FIELD_EXPECTED_TYPE: &str = "expected_type";
const FIELD_EXPECTED_MIN: &str = "expected_min";
const FIELD_EXPECTED_MAX: &str = "expected_max";
const FIELD_RECEIVED_KIND: &str = "received_kind";
const FIELD_RECEIVED_TYPE: &str = "received_type";
const FIELD_RECEIVED_U32: &str = "received_u32";
const FIELD_RETAINED_VALUE: &str = "retained_value";

const CALLER_FIELD_EFFECTIVE_TOKEN_GUID: &str = "effective_token_guid";
const CALLER_FIELD_TRUE_TOKEN_GUID: &str = "true_token_guid";
const CALLER_FIELD_PROCESS_GUID: &str = "process_guid";
const CALLER_FIELD_USER_SID: &str = "user_sid";
const CALLER_FIELD_AUTHENTICATION_ID: &str = "authentication_id";
const CALLER_FIELD_TOKEN_ID: &str = "token_id";
const CALLER_FIELD_TOKEN_TYPE: &str = "token_type";
const CALLER_FIELD_IMPERSONATION_LEVEL: &str = "impersonation_level";
const CALLER_FIELD_INTEGRITY_LEVEL: &str = "integrity_level";

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

/// Pure msgpack serialization result for an LCS audit payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsAuditPayloadWritePlan {
    pub bytes: usize,
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
    MalformedLayerName,
    UnknownRsiStatusCode,
    FutureSequenceNumber,
    DuplicateWinningSequenceTie,
    MalformedLayerMetadataSecurityDescriptor,
}

impl LcsSourceValidationClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedSecurityDescriptor => "malformed_security_descriptor",
            Self::MalformedLayerName => "malformed_layer_name",
            Self::UnknownRsiStatusCode => "unknown_rsi_status_code",
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
            RsiSourceDataValidationFailure::MalformedLayerName => Self::MalformedLayerName,
            RsiSourceDataValidationFailure::UnknownRsiStatusCode => Self::UnknownRsiStatusCode,
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

pub fn key_open_audit_payload_len(record: &LcsKeyOpenAuditRecord<'_>) -> LcsResult<usize> {
    validate_key_open_audit_record(record)?;

    let mut len = msgpack_map_len(6);
    add_len(&mut len, msgpack_str_len(FIELD_CALLER.len()))?;
    add_len(&mut len, caller_summary_payload_len(&record.caller)?)?;
    add_len(&mut len, msgpack_str_len(FIELD_KEY_GUID.len()))?;
    add_len(&mut len, msgpack_bin_len(record.key_guid.len()))?;
    add_len(&mut len, msgpack_str_len(FIELD_REQUESTED_ACCESS.len()))?;
    add_len(&mut len, msgpack_uint_len(record.requested_access as u64))?;
    add_len(&mut len, msgpack_str_len(FIELD_GRANTED_ACCESS.len()))?;
    add_len(&mut len, msgpack_uint_len(record.granted_access as u64))?;
    add_len(&mut len, msgpack_str_len(FIELD_DECISION.len()))?;
    add_len(&mut len, msgpack_str_len(record.decision.as_str().len()))?;
    add_len(&mut len, msgpack_str_len(FIELD_SACL_MATCH_FLAGS.len()))?;
    add_len(&mut len, msgpack_uint_len(record.sacl_match_flags as u64))?;
    Ok(len)
}

pub fn write_key_open_audit_payload(
    record: &LcsKeyOpenAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = key_open_audit_payload_len(record)?;
    if output.len() < required_len {
        return Err(LcsError::AuditPayloadOutputBufferTooSmall {
            buffer_len: output.len(),
            required_len,
        });
    }

    let mut writer = MsgpackWriter::new(&mut output[..required_len]);
    writer.write_map_len(6)?;
    writer.write_str(FIELD_CALLER)?;
    write_caller_summary_payload(&mut writer, &record.caller)?;
    writer.write_str(FIELD_KEY_GUID)?;
    writer.write_bin(&record.key_guid)?;
    writer.write_str(FIELD_REQUESTED_ACCESS)?;
    writer.write_uint(record.requested_access as u64)?;
    writer.write_str(FIELD_GRANTED_ACCESS)?;
    writer.write_uint(record.granted_access as u64)?;
    writer.write_str(FIELD_DECISION)?;
    writer.write_str(record.decision.as_str())?;
    writer.write_str(FIELD_SACL_MATCH_FLAGS)?;
    writer.write_uint(record.sacl_match_flags as u64)?;

    Ok(LcsAuditPayloadWritePlan {
        bytes: writer.bytes_written(),
    })
}

pub fn backup_restore_start_audit_payload_len(
    record: &LcsBackupRestoreStartAuditRecord<'_>,
) -> LcsResult<usize> {
    validate_backup_restore_start_audit_record(record)?;
    let mut len = msgpack_map_len(3);
    add_len(&mut len, msgpack_str_len(FIELD_CALLER.len()))?;
    add_len(&mut len, caller_summary_payload_len(&record.caller)?)?;
    add_len(&mut len, msgpack_str_len(FIELD_KEY_GUID.len()))?;
    add_len(&mut len, msgpack_bin_len(record.key_guid.len()))?;
    add_len(&mut len, msgpack_str_len(FIELD_FD.len()))?;
    add_len(&mut len, msgpack_i32_len())?;
    Ok(len)
}

pub fn write_backup_restore_start_audit_payload(
    record: &LcsBackupRestoreStartAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = backup_restore_start_audit_payload_len(record)?;
    if output.len() < required_len {
        return Err(LcsError::AuditPayloadOutputBufferTooSmall {
            buffer_len: output.len(),
            required_len,
        });
    }

    let mut writer = MsgpackWriter::new(&mut output[..required_len]);
    writer.write_map_len(3)?;
    writer.write_str(FIELD_CALLER)?;
    write_caller_summary_payload(&mut writer, &record.caller)?;
    writer.write_str(FIELD_KEY_GUID)?;
    writer.write_bin(&record.key_guid)?;
    writer.write_str(FIELD_FD)?;
    writer.write_i32(record.fd)?;

    Ok(LcsAuditPayloadWritePlan {
        bytes: writer.bytes_written(),
    })
}

pub fn backup_restore_complete_audit_payload_len(
    record: &LcsBackupRestoreCompleteAuditRecord<'_>,
) -> LcsResult<usize> {
    validate_backup_restore_complete_audit_record(record)?;
    let mut len = msgpack_map_len(3);
    add_len(&mut len, msgpack_str_len(FIELD_CALLER.len()))?;
    add_len(&mut len, caller_summary_payload_len(&record.caller)?)?;
    add_len(&mut len, msgpack_str_len(FIELD_KEY_GUID.len()))?;
    add_len(&mut len, msgpack_bin_len(record.key_guid.len()))?;
    add_len(&mut len, msgpack_str_len(FIELD_RESULT_ERRNO.len()))?;
    add_len(&mut len, msgpack_uint_len(record.result_errno as u64))?;
    Ok(len)
}

pub fn write_backup_restore_complete_audit_payload(
    record: &LcsBackupRestoreCompleteAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = backup_restore_complete_audit_payload_len(record)?;
    if output.len() < required_len {
        return Err(LcsError::AuditPayloadOutputBufferTooSmall {
            buffer_len: output.len(),
            required_len,
        });
    }

    let mut writer = MsgpackWriter::new(&mut output[..required_len]);
    writer.write_map_len(3)?;
    writer.write_str(FIELD_CALLER)?;
    write_caller_summary_payload(&mut writer, &record.caller)?;
    writer.write_str(FIELD_KEY_GUID)?;
    writer.write_bin(&record.key_guid)?;
    writer.write_str(FIELD_RESULT_ERRNO)?;
    writer.write_uint(record.result_errno as u64)?;

    Ok(LcsAuditPayloadWritePlan {
        bytes: writer.bytes_written(),
    })
}

pub fn source_validation_failure_audit_payload_len(
    record: &LcsSourceValidationFailureAuditRecord<'_>,
) -> LcsResult<usize> {
    validate_source_validation_failure_audit_record(record)?;
    let mut len = msgpack_map_len(6);
    add_len(&mut len, msgpack_str_len(FIELD_SOURCE_SLOT.len()))?;
    add_len(&mut len, msgpack_uint_len(record.source_slot as u64))?;
    add_len(&mut len, msgpack_str_len(FIELD_HIVE_NAME.len()))?;
    add_len(
        &mut len,
        record
            .hive_name
            .map_or(msgpack_nil_len(), |value| msgpack_str_len(value.len())),
    )?;
    add_len(&mut len, msgpack_str_len(FIELD_REQUEST_ID.len()))?;
    add_len(
        &mut len,
        record
            .request_id
            .map_or(msgpack_nil_len(), msgpack_uint_len),
    )?;
    add_len(&mut len, msgpack_str_len(FIELD_OP_CODE.len()))?;
    add_len(
        &mut len,
        record
            .op_code
            .map_or(msgpack_nil_len(), |value| msgpack_uint_len(value as u64)),
    )?;
    add_len(&mut len, msgpack_str_len(FIELD_KEY_GUID.len()))?;
    add_len(
        &mut len,
        record
            .key_guid
            .map_or(msgpack_nil_len(), |guid| msgpack_bin_len(guid.len())),
    )?;
    add_len(&mut len, msgpack_str_len(FIELD_VALIDATION_CLASS.len()))?;
    add_len(
        &mut len,
        msgpack_str_len(record.validation_class.as_str().len()),
    )?;
    Ok(len)
}

pub fn write_source_validation_failure_audit_payload(
    record: &LcsSourceValidationFailureAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = source_validation_failure_audit_payload_len(record)?;
    if output.len() < required_len {
        return Err(LcsError::AuditPayloadOutputBufferTooSmall {
            buffer_len: output.len(),
            required_len,
        });
    }

    let mut writer = MsgpackWriter::new(&mut output[..required_len]);
    writer.write_map_len(6)?;
    writer.write_str(FIELD_SOURCE_SLOT)?;
    writer.write_uint(record.source_slot as u64)?;
    writer.write_str(FIELD_HIVE_NAME)?;
    match record.hive_name {
        Some(value) => writer.write_str(value)?,
        None => writer.write_nil()?,
    }
    writer.write_str(FIELD_REQUEST_ID)?;
    match record.request_id {
        Some(value) => writer.write_uint(value)?,
        None => writer.write_nil()?,
    }
    writer.write_str(FIELD_OP_CODE)?;
    match record.op_code {
        Some(value) => writer.write_uint(value as u64)?,
        None => writer.write_nil()?,
    }
    writer.write_str(FIELD_KEY_GUID)?;
    match record.key_guid {
        Some(guid) => writer.write_bin(&guid)?,
        None => writer.write_nil()?,
    }
    writer.write_str(FIELD_VALIDATION_CLASS)?;
    writer.write_str(record.validation_class.as_str())?;

    Ok(LcsAuditPayloadWritePlan {
        bytes: writer.bytes_written(),
    })
}

pub fn self_config_invalid_audit_payload_len(
    record: &LcsSelfConfigInvalidAuditRecord,
) -> LcsResult<usize> {
    validate_self_config_invalid_audit_record(record)?;
    let mut len = msgpack_map_len(9);
    add_len(
        &mut len,
        msgpack_str_len(FIELD_CONFIGURATION_PARENT_PATH.len()),
    )?;
    add_len(
        &mut len,
        msgpack_str_len(record.configuration_parent_path.len()),
    )?;
    add_len(&mut len, msgpack_str_len(FIELD_CONFIGURATION_NAME.len()))?;
    add_len(&mut len, msgpack_str_len(record.configuration_name.len()))?;
    add_len(&mut len, msgpack_str_len(FIELD_EXPECTED_TYPE.len()))?;
    add_len(&mut len, msgpack_uint_len(record.expected_type as u64))?;
    add_len(&mut len, msgpack_str_len(FIELD_EXPECTED_MIN.len()))?;
    add_len(&mut len, msgpack_uint_len(record.expected_min as u64))?;
    add_len(&mut len, msgpack_str_len(FIELD_EXPECTED_MAX.len()))?;
    add_len(&mut len, msgpack_uint_len(record.expected_max as u64))?;
    add_len(&mut len, msgpack_str_len(FIELD_RECEIVED_KIND.len()))?;
    add_len(&mut len, msgpack_str_len(record.received_kind().len()))?;
    add_len(&mut len, msgpack_str_len(FIELD_RECEIVED_TYPE.len()))?;
    add_len(
        &mut len,
        record
            .received_type()
            .map_or(msgpack_nil_len(), |value| msgpack_uint_len(value as u64)),
    )?;
    add_len(&mut len, msgpack_str_len(FIELD_RECEIVED_U32.len()))?;
    add_len(
        &mut len,
        record
            .received_u32()
            .map_or(msgpack_nil_len(), |value| msgpack_uint_len(value as u64)),
    )?;
    add_len(&mut len, msgpack_str_len(FIELD_RETAINED_VALUE.len()))?;
    add_len(&mut len, msgpack_uint_len(record.retained_value as u64))?;
    Ok(len)
}

pub fn write_self_config_invalid_audit_payload(
    record: &LcsSelfConfigInvalidAuditRecord,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = self_config_invalid_audit_payload_len(record)?;
    if output.len() < required_len {
        return Err(LcsError::AuditPayloadOutputBufferTooSmall {
            buffer_len: output.len(),
            required_len,
        });
    }

    let mut writer = MsgpackWriter::new(&mut output[..required_len]);
    writer.write_map_len(9)?;
    writer.write_str(FIELD_CONFIGURATION_PARENT_PATH)?;
    writer.write_str(record.configuration_parent_path)?;
    writer.write_str(FIELD_CONFIGURATION_NAME)?;
    writer.write_str(record.configuration_name)?;
    writer.write_str(FIELD_EXPECTED_TYPE)?;
    writer.write_uint(record.expected_type as u64)?;
    writer.write_str(FIELD_EXPECTED_MIN)?;
    writer.write_uint(record.expected_min as u64)?;
    writer.write_str(FIELD_EXPECTED_MAX)?;
    writer.write_uint(record.expected_max as u64)?;
    writer.write_str(FIELD_RECEIVED_KIND)?;
    writer.write_str(record.received_kind())?;
    writer.write_str(FIELD_RECEIVED_TYPE)?;
    match record.received_type() {
        Some(value) => writer.write_uint(value as u64)?,
        None => writer.write_nil()?,
    }
    writer.write_str(FIELD_RECEIVED_U32)?;
    match record.received_u32() {
        Some(value) => writer.write_uint(value as u64)?,
        None => writer.write_nil()?,
    }
    writer.write_str(FIELD_RETAINED_VALUE)?;
    writer.write_uint(record.retained_value as u64)?;

    Ok(LcsAuditPayloadWritePlan {
        bytes: writer.bytes_written(),
    })
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
    validate_key_open_audit_decision_grant(decision, granted_access)?;
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

fn validate_key_open_audit_record(record: &LcsKeyOpenAuditRecord<'_>) -> LcsResult<()> {
    if record.event_kind != LcsAuditEventKind::KeyOpenAudit {
        return Err(LcsError::AuditEventKindMismatch {
            expected: LcsAuditEventKind::KeyOpenAudit,
            actual: record.event_kind,
        });
    }
    record.caller.validate()?;
    validate_sacl_match_flags(record.sacl_match_flags)?;
    validate_key_open_audit_decision_grant(record.decision, record.granted_access)
}

fn validate_key_open_audit_decision_grant(
    decision: LcsKeyOpenAuditDecision,
    granted_access: u32,
) -> LcsResult<()> {
    if decision == LcsKeyOpenAuditDecision::Denied && granted_access != 0 {
        return Err(LcsError::DeniedKeyOpenAuditWithGrantedAccess { granted_access });
    }
    Ok(())
}

fn validate_backup_restore_start_audit_record(
    record: &LcsBackupRestoreStartAuditRecord<'_>,
) -> LcsResult<()> {
    match record.event_kind {
        LcsAuditEventKind::BackupStart | LcsAuditEventKind::RestoreStart => {}
        actual => {
            return Err(LcsError::AuditEventKindMismatch {
                expected: LcsAuditEventKind::BackupStart,
                actual,
            });
        }
    }
    record.caller.validate()?;
    if record.fd < 0 {
        return Err(LcsError::InvalidAuditFd { fd: record.fd });
    }
    Ok(())
}

fn validate_backup_restore_complete_audit_record(
    record: &LcsBackupRestoreCompleteAuditRecord<'_>,
) -> LcsResult<()> {
    match record.event_kind {
        LcsAuditEventKind::BackupComplete | LcsAuditEventKind::RestoreComplete => {}
        actual => {
            return Err(LcsError::AuditEventKindMismatch {
                expected: LcsAuditEventKind::BackupComplete,
                actual,
            });
        }
    }
    record.caller.validate()
}

fn validate_source_validation_failure_audit_record(
    record: &LcsSourceValidationFailureAuditRecord<'_>,
) -> LcsResult<()> {
    if record.event_kind != LcsAuditEventKind::SourceValidationFailure {
        return Err(LcsError::AuditEventKindMismatch {
            expected: LcsAuditEventKind::SourceValidationFailure,
            actual: record.event_kind,
        });
    }
    Ok(())
}

fn validate_self_config_invalid_audit_record(
    record: &LcsSelfConfigInvalidAuditRecord,
) -> LcsResult<()> {
    if record.event_kind != LcsAuditEventKind::SelfConfigInvalid {
        return Err(LcsError::AuditEventKindMismatch {
            expected: LcsAuditEventKind::SelfConfigInvalid,
            actual: record.event_kind,
        });
    }
    Ok(())
}

fn caller_summary_payload_len(caller: &LcsCallerTokenSummary<'_>) -> LcsResult<usize> {
    let mut len = msgpack_map_len(9);
    add_len(
        &mut len,
        msgpack_str_len(CALLER_FIELD_EFFECTIVE_TOKEN_GUID.len()),
    )?;
    add_len(&mut len, msgpack_bin_len(caller.effective_token_guid.len()))?;
    add_len(
        &mut len,
        msgpack_str_len(CALLER_FIELD_TRUE_TOKEN_GUID.len()),
    )?;
    add_len(&mut len, msgpack_bin_len(caller.true_token_guid.len()))?;
    add_len(&mut len, msgpack_str_len(CALLER_FIELD_PROCESS_GUID.len()))?;
    add_len(&mut len, msgpack_bin_len(caller.process_guid.len()))?;
    add_len(&mut len, msgpack_str_len(CALLER_FIELD_USER_SID.len()))?;
    add_len(&mut len, msgpack_bin_len(caller.user_sid.len()))?;
    add_len(
        &mut len,
        msgpack_str_len(CALLER_FIELD_AUTHENTICATION_ID.len()),
    )?;
    add_len(&mut len, msgpack_uint_len(caller.authentication_id))?;
    add_len(&mut len, msgpack_str_len(CALLER_FIELD_TOKEN_ID.len()))?;
    add_len(&mut len, msgpack_uint_len(caller.token_id))?;
    add_len(&mut len, msgpack_str_len(CALLER_FIELD_TOKEN_TYPE.len()))?;
    add_len(&mut len, msgpack_uint_len(caller.token_type as u64))?;
    add_len(
        &mut len,
        msgpack_str_len(CALLER_FIELD_IMPERSONATION_LEVEL.len()),
    )?;
    add_len(
        &mut len,
        msgpack_uint_len(caller.impersonation_level as u64),
    )?;
    add_len(
        &mut len,
        msgpack_str_len(CALLER_FIELD_INTEGRITY_LEVEL.len()),
    )?;
    add_len(&mut len, msgpack_uint_len(caller.integrity_level as u64))?;
    Ok(len)
}

fn write_caller_summary_payload(
    writer: &mut MsgpackWriter<'_>,
    caller: &LcsCallerTokenSummary<'_>,
) -> LcsResult<()> {
    writer.write_map_len(9)?;
    writer.write_str(CALLER_FIELD_EFFECTIVE_TOKEN_GUID)?;
    writer.write_bin(&caller.effective_token_guid)?;
    writer.write_str(CALLER_FIELD_TRUE_TOKEN_GUID)?;
    writer.write_bin(&caller.true_token_guid)?;
    writer.write_str(CALLER_FIELD_PROCESS_GUID)?;
    writer.write_bin(&caller.process_guid)?;
    writer.write_str(CALLER_FIELD_USER_SID)?;
    writer.write_bin(caller.user_sid)?;
    writer.write_str(CALLER_FIELD_AUTHENTICATION_ID)?;
    writer.write_uint(caller.authentication_id)?;
    writer.write_str(CALLER_FIELD_TOKEN_ID)?;
    writer.write_uint(caller.token_id)?;
    writer.write_str(CALLER_FIELD_TOKEN_TYPE)?;
    writer.write_uint(caller.token_type as u64)?;
    writer.write_str(CALLER_FIELD_IMPERSONATION_LEVEL)?;
    writer.write_uint(caller.impersonation_level as u64)?;
    writer.write_str(CALLER_FIELD_INTEGRITY_LEVEL)?;
    writer.write_uint(caller.integrity_level as u64)?;
    Ok(())
}

fn add_len(total: &mut usize, value: usize) -> LcsResult<()> {
    *total = total
        .checked_add(value)
        .ok_or(LcsError::OutputSizeOverflow)?;
    Ok(())
}

fn msgpack_map_len(count: usize) -> usize {
    if count <= 15 {
        1
    } else if count <= u16::MAX as usize {
        3
    } else {
        5
    }
}

fn msgpack_nil_len() -> usize {
    1
}

fn msgpack_str_len(len: usize) -> usize {
    if len <= 31 {
        1 + len
    } else if len <= u8::MAX as usize {
        2 + len
    } else if len <= u16::MAX as usize {
        3 + len
    } else {
        5 + len
    }
}

fn msgpack_bin_len(len: usize) -> usize {
    if len <= u8::MAX as usize {
        2 + len
    } else if len <= u16::MAX as usize {
        3 + len
    } else {
        5 + len
    }
}

fn msgpack_uint_len(value: u64) -> usize {
    if value <= 0x7f {
        1
    } else if value <= u8::MAX as u64 {
        2
    } else if value <= u16::MAX as u64 {
        3
    } else if value <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

fn msgpack_i32_len() -> usize {
    5
}

struct MsgpackWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> MsgpackWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn bytes_written(&self) -> usize {
        self.pos
    }

    fn write_map_len(&mut self, count: usize) -> LcsResult<()> {
        if count <= 15 {
            self.write_byte(0x80 | count as u8)
        } else if count <= u16::MAX as usize {
            self.write_byte(0xde)?;
            self.write_u16_be(count as u16)
        } else {
            self.write_byte(0xdf)?;
            self.write_u32_be(count as u32)
        }
    }

    fn write_nil(&mut self) -> LcsResult<()> {
        self.write_byte(0xc0)
    }

    fn write_str(&mut self, value: &str) -> LcsResult<()> {
        let len = value.len();
        if len <= 31 {
            self.write_byte(0xa0 | len as u8)?;
        } else if len <= u8::MAX as usize {
            self.write_byte(0xd9)?;
            self.write_byte(len as u8)?;
        } else if len <= u16::MAX as usize {
            self.write_byte(0xda)?;
            self.write_u16_be(len as u16)?;
        } else {
            self.write_byte(0xdb)?;
            self.write_u32_be(len as u32)?;
        }
        self.write_bytes(value.as_bytes())
    }

    fn write_bin(&mut self, value: &[u8]) -> LcsResult<()> {
        let len = value.len();
        if len <= u8::MAX as usize {
            self.write_byte(0xc4)?;
            self.write_byte(len as u8)?;
        } else if len <= u16::MAX as usize {
            self.write_byte(0xc5)?;
            self.write_u16_be(len as u16)?;
        } else {
            self.write_byte(0xc6)?;
            self.write_u32_be(len as u32)?;
        }
        self.write_bytes(value)
    }

    fn write_uint(&mut self, value: u64) -> LcsResult<()> {
        if value <= 0x7f {
            self.write_byte(value as u8)
        } else if value <= u8::MAX as u64 {
            self.write_byte(0xcc)?;
            self.write_byte(value as u8)
        } else if value <= u16::MAX as u64 {
            self.write_byte(0xcd)?;
            self.write_u16_be(value as u16)
        } else if value <= u32::MAX as u64 {
            self.write_byte(0xce)?;
            self.write_u32_be(value as u32)
        } else {
            self.write_byte(0xcf)?;
            self.write_bytes(&value.to_be_bytes())
        }
    }

    fn write_i32(&mut self, value: i32) -> LcsResult<()> {
        self.write_byte(0xd2)?;
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_byte(&mut self, value: u8) -> LcsResult<()> {
        self.write_bytes(&[value])
    }

    fn write_u16_be(&mut self, value: u16) -> LcsResult<()> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_u32_be(&mut self, value: u32) -> LcsResult<()> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_bytes(&mut self, value: &[u8]) -> LcsResult<()> {
        let end = self
            .pos
            .checked_add(value.len())
            .ok_or(LcsError::OutputSizeOverflow)?;
        if end > self.buf.len() {
            return Err(LcsError::AuditPayloadOutputBufferTooSmall {
                buffer_len: self.buf.len(),
                required_len: end,
            });
        }
        self.buf[self.pos..end].copy_from_slice(value);
        self.pos = end;
        Ok(())
    }
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
