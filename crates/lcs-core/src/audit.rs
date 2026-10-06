//! Pure LCS audit-event vocabulary and payload planning.
//!
//! Every payload follows the event catalogue's wire rules (PGSS §6.4–§6.6):
//! a dotted field path is written as nested maps, one per segment, and a
//! value the emitter does not have is left out rather than written as nil.

use crate::config::{
    ConfigRange, LcsLimits, SelfConfigRetentionReason, SelfConfigValue, retained_config_value,
    self_config_audit_intent,
};
use crate::constants::REG_DWORD;
use crate::error::{LcsError, LcsResult};
use crate::path::validate_hive_name_bytes;
use crate::rsi::RsiSourceDataValidationFailure;
use kacs_core::{Sid, TokenType};

pub const LCS_CONFIG_ROOT_PATH: &str = "Machine\\System\\Registry";
pub const LCS_SACL_MATCH_SUCCESS: u32 = 0x1;
pub const LCS_SACL_MATCH_FAILURE: u32 = 0x2;
pub const LCS_SACL_MATCH_VALID_MASK: u32 = LCS_SACL_MATCH_SUCCESS | LCS_SACL_MATCH_FAILURE;

// Map keys, one per field-path segment. `subject.token.sid` is written as
// `{subject: {token: {sid: ...}}}`, so a key never contains a dot.
const FIELD_SUBJECT: &str = "subject";
const FIELD_TOKEN: &str = "token";
const FIELD_OBJECT: &str = "object";
const FIELD_KIND: &str = "kind";
const FIELD_KEY: &str = "key";
const FIELD_GUID: &str = "guid";
const FIELD_ACCESS: &str = "access";
const FIELD_REQUESTED: &str = "requested";
const FIELD_GRANTED: &str = "granted";
const FIELD_OUTCOME: &str = "outcome";
const FIELD_SUCCESS: &str = "success";
const FIELD_ERRNO: &str = "errno";
const FIELD_REASON: &str = "reason";
const FIELD_TRIGGER: &str = "trigger";
const FIELD_SACL_MATCH: &str = "sacl-match";
const FIELD_OPERATION: &str = "operation";
const FIELD_FD: &str = "fd";
const FIELD_SOURCE: &str = "source";
const FIELD_RSI: &str = "rsi";
const FIELD_SLOT: &str = "slot";
const FIELD_HIVE: &str = "hive";
const FIELD_REQUEST: &str = "request";
const FIELD_ID: &str = "id";
const FIELD_OP_CODE: &str = "op-code";
const FIELD_CONFIG: &str = "config";
const FIELD_PATH: &str = "path";
const FIELD_NAME: &str = "name";
const FIELD_EXPECTED: &str = "expected";
const FIELD_TYPE: &str = "type";
const FIELD_MIN: &str = "min";
const FIELD_MAX: &str = "max";
const FIELD_RECEIVED: &str = "received";
const FIELD_VALUE: &str = "value";
const FIELD_LAYER: &str = "layer";
const FIELD_MATCHED: &str = "matched";
const FIELD_AUDIT_MASK: &str = "audit-mask";
const FIELD_TRANSACTION: &str = "transaction";
const FIELD_STATE: &str = "state";
const FIELD_COMMIT_OUTSTANDING: &str = "commit-outstanding";
const FIELD_MUTATION: &str = "mutation";
const FIELD_SEQUENCE: &str = "sequence";
const FIELD_SEQUENCE_EXPECTED: &str = "sequence-expected";
const FIELD_TIMED_OUT: &str = "timed-out";
const FIELD_LENGTH: &str = "length";
const FIELD_DIGEST: &str = "digest";
const FIELD_TYPE_PREVIOUS: &str = "type-previous";
const FIELD_LENGTH_PREVIOUS: &str = "length-previous";
const FIELD_DIGEST_PREVIOUS: &str = "digest-previous";
const FIELD_CREATED: &str = "created";
const FIELD_VOLATILE: &str = "volatile";
const FIELD_VOLATILE_REQUESTED: &str = "volatile-requested";
const FIELD_SYMLINK: &str = "symlink";
const FIELD_SD: &str = "sd";
const FIELD_COMPONENTS: &str = "components";
const FIELD_OWNER: &str = "owner";
const FIELD_OWNER_PREVIOUS: &str = "owner-previous";

// The `caller` group: `subject.token.{sid,integrity,id,auth-id,type,
// impersonation}`, in the group's order.
const TOKEN_FIELD_SID: &str = "sid";
const TOKEN_FIELD_INTEGRITY: &str = "integrity";
const TOKEN_FIELD_ID: &str = "id";
const TOKEN_FIELD_AUTH_ID: &str = "auth-id";
const TOKEN_FIELD_TYPE: &str = "type";
const TOKEN_FIELD_IMPERSONATION: &str = "impersonation";
const CALLER_TOKEN_FIELD_COUNT: usize = 6;

const OBJECT_KIND_KEY: &str = "key";

/// LCS KMES audit event types, as named in the event catalogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsAuditEventKind {
    KeyOpenAudit,
    BackupStart,
    BackupComplete,
    RestoreStart,
    RestoreComplete,
    SourceValidationFailure,
    SelfConfigInvalid,
    ValueSet,
    ValueDeleted,
    KeyTombstoned,
    KeyDeleted,
    KeyHidden,
    KeyCreated,
    TransactionCommitted,
    KeyDescriptorChanged,
}

impl LcsAuditEventKind {
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::KeyOpenAudit => "lcs.audit.key.opened",
            Self::BackupStart => "lcs.audit.backup.started",
            Self::BackupComplete => "lcs.audit.backup.ended",
            Self::RestoreStart => "lcs.audit.restore.started",
            Self::RestoreComplete => "lcs.audit.restore.ended",
            Self::SourceValidationFailure => "lcs.source.response.rejected",
            Self::SelfConfigInvalid => "lcs.config.value.rejected",
            Self::ValueSet => "lcs.audit.value.set",
            Self::ValueDeleted => "lcs.audit.value.deleted",
            Self::KeyTombstoned => "lcs.audit.key.tombstoned",
            Self::KeyDeleted => "lcs.audit.key.deleted",
            Self::KeyHidden => "lcs.audit.key.hidden",
            Self::KeyCreated => "lcs.audit.key.created",
            Self::TransactionCommitted => "lcs.audit.transaction.committed",
            Self::KeyDescriptorChanged => "lcs.audit.key.descriptor.changed",
        }
    }
}

/// Map a uapi `KACS_TOKEN_TYPE_*` value onto the token type an audit
/// record names. Anything else is not a token LCS can describe.
pub const fn audit_token_type_from_raw(raw: u32) -> Option<TokenType> {
    match raw {
        peios_uapi::KACS_TOKEN_TYPE_PRIMARY => Some(TokenType::Primary),
        peios_uapi::KACS_TOKEN_TYPE_IMPERSONATION => Some(TokenType::Impersonation),
        _ => None,
    }
}

const fn token_type_name(token_type: TokenType) -> &'static str {
    match token_type {
        TokenType::Primary => "primary",
        TokenType::Impersonation => "impersonation",
    }
}

/// Bounded caller token summary written as the `caller` group. The token
/// and process GUIDs are not here: they ride in the KMES event header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsCallerTokenSummary<'a> {
    pub user_sid: &'a [u8],
    pub integrity_level: u32,
    pub token_id: u64,
    pub authentication_id: u64,
    pub token_type: TokenType,
    pub impersonation_level: u32,
}

impl LcsCallerTokenSummary<'_> {
    pub fn validate(&self) -> LcsResult<()> {
        Sid::parse(self.user_sid).map_err(|_| LcsError::MalformedAuditCallerSid {
            field: "subject.token.sid",
        })?;
        Ok(())
    }
}

/// AccessCheck decision recorded by `lcs.audit.key.opened`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsKeyOpenAuditDecision {
    Allowed,
    Denied,
}

impl LcsKeyOpenAuditDecision {
    /// The decision as `outcome.success`.
    pub const fn success(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Pure payload plan for `lcs.audit.key.opened`.
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

/// Pure payload plan for `lcs.audit.backup.started` and
/// `lcs.audit.restore.started`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsBackupRestoreStartAuditRecord<'a> {
    pub event_kind: LcsAuditEventKind,
    pub caller: LcsCallerTokenSummary<'a>,
    pub key_guid: [u8; 16],
    pub fd: i32,
}

/// Pure payload plan for `lcs.audit.backup.ended` and
/// `lcs.audit.restore.ended`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsBackupRestoreCompleteAuditRecord<'a> {
    pub event_kind: LcsAuditEventKind,
    pub caller: LcsCallerTokenSummary<'a>,
    pub key_guid: [u8; 16],
    /// The operation's result as a positive errno, 0 on success. The wire
    /// carries `outcome.success` and, on failure, the negated errno.
    pub result_errno: u32,
}

/// Source-validation failure class, carried as `outcome.reason` on
/// `lcs.source.response.rejected`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsSourceValidationClass {
    MalformedSecurityDescriptor,
    MalformedLayerName,
    UnknownRsiStatusCode,
    FutureSequenceNumber,
    DuplicateWinningSequenceTie,
    MalformedLayerMetadataSecurityDescriptor,
    MalformedKeyName,
    MalformedValueName,
    MalformedResponsePayload,
    MalformedKeyMetadata,
    MalformedValuePayload,
    MalformedDeleteLayerOrphanList,
}

impl LcsSourceValidationClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedSecurityDescriptor => "malformed-security-descriptor",
            Self::MalformedLayerName => "malformed-layer-name",
            Self::UnknownRsiStatusCode => "unknown-rsi-status-code",
            Self::FutureSequenceNumber => "future-sequence-number",
            Self::DuplicateWinningSequenceTie => "duplicate-winning-sequence-tie",
            Self::MalformedLayerMetadataSecurityDescriptor => {
                "malformed-layer-metadata-security-descriptor"
            }
            Self::MalformedKeyName => "malformed-key-name",
            Self::MalformedValueName => "malformed-value-name",
            Self::MalformedResponsePayload => "malformed-response-payload",
            Self::MalformedKeyMetadata => "malformed-key-metadata",
            Self::MalformedValuePayload => "malformed-value-payload",
            Self::MalformedDeleteLayerOrphanList => "malformed-delete-layer-orphan-list",
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
            RsiSourceDataValidationFailure::MalformedKeyName => Self::MalformedKeyName,
            RsiSourceDataValidationFailure::MalformedValueName => Self::MalformedValueName,
            RsiSourceDataValidationFailure::MalformedResponsePayload => {
                Self::MalformedResponsePayload
            }
            RsiSourceDataValidationFailure::MalformedKeyMetadata => Self::MalformedKeyMetadata,
            RsiSourceDataValidationFailure::MalformedValuePayload => Self::MalformedValuePayload,
            RsiSourceDataValidationFailure::MalformedDeleteLayerOrphanList => {
                Self::MalformedDeleteLayerOrphanList
            }
        }
    }
}

/// Pure payload plan for `lcs.source.response.rejected`.
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

/// Policy to apply after a valid audit payload exists but KMES transport
/// enqueue, retention, or consumption fails at the audit point.
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
        LcsAuditEventKind::KeyOpenAudit => {
            LcsAuditEmissionFailurePolicy::PreserveAlreadyDeterminedResult
        }
        LcsAuditEventKind::BackupStart | LcsAuditEventKind::RestoreStart => {
            LcsAuditEmissionFailurePolicy::FailOperationWithEio
        }
        LcsAuditEventKind::BackupComplete
        | LcsAuditEventKind::RestoreComplete
        | LcsAuditEventKind::SourceValidationFailure => {
            LcsAuditEmissionFailurePolicy::PreserveAlreadyDeterminedResult
        }
        LcsAuditEventKind::SelfConfigInvalid => {
            LcsAuditEmissionFailurePolicy::PreserveRetainedConfiguration
        }
        // Every registry write record is written after the source has
        // answered, so the write has landed (or failed) by then: a record
        // that cannot be built or retained does not change the result the
        // caller is given. A transaction's terminal record likewise follows
        // a state that is already final.
        LcsAuditEventKind::ValueSet
        | LcsAuditEventKind::ValueDeleted
        | LcsAuditEventKind::KeyTombstoned
        | LcsAuditEventKind::KeyDeleted
        | LcsAuditEventKind::KeyHidden
        | LcsAuditEventKind::KeyCreated
        | LcsAuditEventKind::TransactionCommitted
        | LcsAuditEventKind::KeyDescriptorChanged => {
            LcsAuditEmissionFailurePolicy::PreserveAlreadyDeterminedResult
        }
    }
}

/// Bytes in every digest an LCS record carries: SHA-256.
pub const LCS_AUDIT_DIGEST_LEN: usize = 32;

/// A registry value's type, length and SHA-256 digest, recorded in place of
/// its data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsValueAuditSummary {
    pub value_type: u32,
    pub length: u32,
    pub digest: [u8; LCS_AUDIT_DIGEST_LEN],
}

/// One security descriptor as a record describes it: its length, its
/// SHA-256 digest and its owner SID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsSdAuditSummary<'a> {
    pub length: u32,
    pub digest: [u8; LCS_AUDIT_DIGEST_LEN],
    /// Absent only for a descriptor with no owner.
    pub owner: Option<&'a [u8]>,
}

/// The masks a registry write record carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsKeyAuditAccess {
    /// The right the operation needed (`access.requested`).
    pub requested: u32,
    /// What the handle was opened with, or what a parent check granted
    /// (`access.granted`).
    pub granted: u32,
    /// The continuous-audit mask cached on the handle (`access.audit-mask`).
    /// When present, `access.matched` is written as `requested & mask`.
    /// Absent for `lcs.audit.key.created`, which no handle governs.
    pub audit_mask: Option<u32>,
}

/// The event-specific part of a registry write record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsKeyAuditDetail<'a> {
    /// `lcs.audit.value.set`.
    ValueSet {
        value_name: Option<&'a str>,
        value: Option<LcsValueAuditSummary>,
        previous: Option<LcsValueAuditSummary>,
        sequence: Option<u64>,
        expected_sequence: Option<u64>,
    },
    /// `lcs.audit.value.deleted`.
    ValueDeleted {
        value_name: Option<&'a str>,
        previous: Option<LcsValueAuditSummary>,
    },
    /// `lcs.audit.key.tombstoned`. `set` is `None` when the request failed
    /// before its direction was read.
    KeyTombstoned {
        set: Option<bool>,
        sequence: Option<u64>,
    },
    /// `lcs.audit.key.deleted`. `layer_name` names the layer whose metadata
    /// key this was, when the delete removed a layer.
    KeyDeleted { layer_name: Option<&'a str> },
    /// `lcs.audit.key.hidden`.
    KeyHidden { sequence: Option<u64> },
    /// `lcs.audit.key.created`, written only for a key that was created.
    KeyCreated {
        volatile: bool,
        volatile_requested: bool,
        symlink: bool,
        sd_owner: Option<&'a [u8]>,
        sd_length: u32,
    },
    /// `lcs.audit.key.descriptor.changed`. `sd` and `previous` are absent
    /// when the request failed before the descriptors were read and merged.
    KeyDescriptorChanged {
        components: u32,
        sd: Option<LcsSdAuditSummary<'a>>,
        previous: Option<LcsSdAuditSummary<'a>>,
    },
}

impl LcsKeyAuditDetail<'_> {
    pub const fn event_kind(&self) -> LcsAuditEventKind {
        match self {
            Self::ValueSet { .. } => LcsAuditEventKind::ValueSet,
            Self::ValueDeleted { .. } => LcsAuditEventKind::ValueDeleted,
            Self::KeyTombstoned { .. } => LcsAuditEventKind::KeyTombstoned,
            Self::KeyDeleted { .. } => LcsAuditEventKind::KeyDeleted,
            Self::KeyHidden { .. } => LcsAuditEventKind::KeyHidden,
            Self::KeyCreated { .. } => LcsAuditEventKind::KeyCreated,
            Self::KeyDescriptorChanged { .. } => LcsAuditEventKind::KeyDescriptorChanged,
        }
    }
}

/// Pure payload plan for the registry write records: the five mutation
/// events, `lcs.audit.key.created` and `lcs.audit.key.descriptor.changed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsKeyAuditRecord<'a> {
    pub caller: LcsCallerTokenSummary<'a>,
    /// The key acted on. For a delete or hide, the key removed; for a
    /// create, the new key.
    pub key_guid: [u8; 16],
    /// That key's resolved absolute path, components joined by `\`.
    pub key_path: &'a str,
    /// The layer the operation wrote (`object.key.layer.name`).
    pub key_layer_name: Option<&'a str>,
    pub access: LcsKeyAuditAccess,
    /// Present when the operation was staged in a transaction.
    pub transaction_id: Option<u64>,
    /// The operation's result as a positive errno, 0 on success.
    pub result_errno: u32,
    /// The source did not answer before the request timeout. Only on a
    /// failure, and written there as `request.timed-out`.
    pub timed_out: bool,
    pub detail: LcsKeyAuditDetail<'a>,
}

impl LcsKeyAuditRecord<'_> {
    pub const fn event_kind(&self) -> LcsAuditEventKind {
        self.detail.event_kind()
    }

    pub const fn success(&self) -> bool {
        self.result_errno == 0
    }
}

/// A registry transaction's state, as `transaction.state` names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsTransactionAuditState {
    ActiveUnbound,
    ActiveBound,
    Committed,
    Aborted,
    TimedOut,
    SourceDown,
}

impl LcsTransactionAuditState {
    /// From a uapi `REG_TXN_*` state.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::ActiveUnbound),
            1 => Some(Self::ActiveBound),
            2 => Some(Self::Committed),
            3 => Some(Self::Aborted),
            4 => Some(Self::TimedOut),
            5 => Some(Self::SourceDown),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActiveUnbound => "active-unbound",
            Self::ActiveBound => "active-bound",
            Self::Committed => "committed",
            Self::Aborted => "aborted",
            Self::TimedOut => "timed-out",
            Self::SourceDown => "source-down",
        }
    }
}

/// Why a transaction ended without its changes taking effect
/// (`outcome.reason` on `lcs.audit.transaction.committed`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsTransactionAuditReason {
    Aborted,
    TimedOut,
    SourceError,
}

impl LcsTransactionAuditReason {
    /// From the C emitter's code: 1 aborted, 2 timed out, 3 source error.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Aborted),
            2 => Some(Self::TimedOut),
            3 => Some(Self::SourceError),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aborted => "aborted",
            Self::TimedOut => "timed-out",
            Self::SourceError => "source-error",
        }
    }
}

/// Pure payload plan for `lcs.audit.transaction.committed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LcsTransactionCommittedAuditRecord<'a> {
    /// The committer on `REG_IOC_COMMIT`; the subject that began the
    /// transaction when it ended by close or timeout.
    pub caller: LcsCallerTokenSummary<'a>,
    pub transaction_id: u64,
    /// The state the transaction ended in. Success is `Committed`.
    pub state: LcsTransactionAuditState,
    /// Present only on a failure, and only when a commit call failed.
    pub errno: Option<u32>,
    /// Required on a failure, absent on success.
    pub reason: Option<LcsTransactionAuditReason>,
    /// Whether the commit had been sent and not answered. Only on a failure.
    pub commit_outstanding: Option<bool>,
}

impl LcsTransactionCommittedAuditRecord<'_> {
    pub const fn success(&self) -> bool {
        matches!(self.state, LcsTransactionAuditState::Committed)
    }
}

pub fn key_audit_payload_len(record: &LcsKeyAuditRecord<'_>) -> LcsResult<usize> {
    validate_key_audit_record(record)?;
    payload_len(|writer| serialize_key_audit(writer, record))
}

pub fn write_key_audit_payload(
    record: &LcsKeyAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = key_audit_payload_len(record)?;
    write_payload(output, required_len, |writer| {
        serialize_key_audit(writer, record)
    })
}

pub fn transaction_committed_audit_payload_len(
    record: &LcsTransactionCommittedAuditRecord<'_>,
) -> LcsResult<usize> {
    validate_transaction_committed_audit_record(record)?;
    payload_len(|writer| serialize_transaction_committed_audit(writer, record))
}

pub fn write_transaction_committed_audit_payload(
    record: &LcsTransactionCommittedAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = transaction_committed_audit_payload_len(record)?;
    write_payload(output, required_len, |writer| {
        serialize_transaction_committed_audit(writer, record)
    })
}

/// `KACS_SECINFO_*` bits `object.sd.components` may carry.
const SD_COMPONENTS_VALID_MASK: u32 = 0x1f;

fn malformed_key_audit(field: &'static str) -> LcsError {
    LcsError::MalformedKeyAuditRecord { field }
}

fn validate_audit_sid(sid: &[u8], field: &'static str) -> LcsResult<()> {
    Sid::parse(sid).map_err(|_| malformed_key_audit(field))?;
    Ok(())
}

fn validate_key_audit_record(record: &LcsKeyAuditRecord<'_>) -> LcsResult<()> {
    record.caller.validate()?;
    if record.key_path.is_empty() {
        return Err(malformed_key_audit("object.key.path"));
    }
    if record.timed_out && record.success() {
        return Err(malformed_key_audit("request.timed-out"));
    }
    if let Some(mask) = record.access.audit_mask {
        // A record gated on the handle's mask exists because the right
        // overlapped it; only a descriptor change that touched the SACL is
        // recorded without an overlap.
        let forced = matches!(
            record.detail,
            LcsKeyAuditDetail::KeyDescriptorChanged { components, .. } if components & 0x8 != 0
        );
        if record.access.requested & mask == 0 && !forced {
            return Err(malformed_key_audit("access.matched"));
        }
    }
    match record.detail {
        LcsKeyAuditDetail::KeyCreated { sd_owner, .. } => {
            if !record.success() {
                return Err(malformed_key_audit("outcome.success"));
            }
            if record.access.audit_mask.is_some() {
                return Err(malformed_key_audit("access.audit-mask"));
            }
            if let Some(owner) = sd_owner {
                validate_audit_sid(owner, "object.sd.owner")?;
            }
        }
        LcsKeyAuditDetail::KeyDescriptorChanged {
            components,
            sd,
            previous,
        } => {
            if components == 0 || components & !SD_COMPONENTS_VALID_MASK != 0 {
                return Err(malformed_key_audit("object.sd.components"));
            }
            if record.access.audit_mask.is_none() {
                return Err(malformed_key_audit("access.audit-mask"));
            }
            if let Some(owner) = sd.and_then(|sd| sd.owner) {
                validate_audit_sid(owner, "object.sd.owner")?;
            }
            if let Some(owner) = previous.and_then(|sd| sd.owner) {
                validate_audit_sid(owner, "object.sd.owner-previous")?;
            }
        }
        _ => {
            if record.access.audit_mask.is_none() {
                return Err(malformed_key_audit("access.audit-mask"));
            }
        }
    }
    Ok(())
}

fn validate_transaction_committed_audit_record(
    record: &LcsTransactionCommittedAuditRecord<'_>,
) -> LcsResult<()> {
    record.caller.validate()?;
    if record.success() {
        if record.errno.is_some() || record.reason.is_some() || record.commit_outstanding.is_some()
        {
            return Err(malformed_key_audit("outcome.success"));
        }
    } else if record.reason.is_none() {
        return Err(malformed_key_audit("outcome.reason"));
    }
    if record.errno == Some(0) {
        return Err(malformed_key_audit("outcome.errno"));
    }
    Ok(())
}

fn write_value_summary(
    writer: &mut MsgpackWriter<'_>,
    summary: &LcsValueAuditSummary,
    previous: bool,
) -> LcsResult<()> {
    let (type_key, length_key, digest_key) = if previous {
        (
            FIELD_TYPE_PREVIOUS,
            FIELD_LENGTH_PREVIOUS,
            FIELD_DIGEST_PREVIOUS,
        )
    } else {
        (FIELD_TYPE, FIELD_LENGTH, FIELD_DIGEST)
    };
    writer.write_str(type_key)?;
    writer.write_uint(summary.value_type as u64)?;
    writer.write_str(length_key)?;
    writer.write_uint(summary.length as u64)?;
    writer.write_str(digest_key)?;
    writer.write_bin(&summary.digest)
}

/// Writes `value: {...}` inside the open `object.key` map.
fn write_key_value_map(
    writer: &mut MsgpackWriter<'_>,
    value_name: Option<&str>,
    value: Option<&LcsValueAuditSummary>,
    previous: Option<&LcsValueAuditSummary>,
) -> LcsResult<()> {
    writer.write_str(FIELD_VALUE)?;
    writer.write_map_len(
        usize::from(value_name.is_some())
            + 3 * usize::from(value.is_some())
            + 3 * usize::from(previous.is_some()),
    )?;
    if let Some(name) = value_name {
        writer.write_str(FIELD_NAME)?;
        writer.write_str(name)?;
    }
    if let Some(value) = value {
        write_value_summary(writer, value, false)?;
    }
    if let Some(previous) = previous {
        write_value_summary(writer, previous, true)?;
    }
    Ok(())
}

fn key_value_map_present(
    value_name: Option<&str>,
    value: Option<&LcsValueAuditSummary>,
    previous: Option<&LcsValueAuditSummary>,
) -> bool {
    value_name.is_some() || value.is_some() || previous.is_some()
}

fn serialize_key_audit(
    writer: &mut MsgpackWriter<'_>,
    record: &LcsKeyAuditRecord<'_>,
) -> LcsResult<()> {
    let success = record.success();
    let (value_name, value, previous) = match &record.detail {
        LcsKeyAuditDetail::ValueSet {
            value_name,
            value,
            previous,
            ..
        } => (*value_name, value.as_ref(), previous.as_ref()),
        LcsKeyAuditDetail::ValueDeleted {
            value_name,
            previous,
        } => (*value_name, None, previous.as_ref()),
        _ => (None, None, None),
    };
    let value_map = key_value_map_present(value_name, value, previous);
    let (sequence, expected_sequence) = match record.detail {
        LcsKeyAuditDetail::ValueSet {
            sequence,
            expected_sequence,
            ..
        } => (sequence, expected_sequence),
        LcsKeyAuditDetail::KeyTombstoned { sequence, .. }
        | LcsKeyAuditDetail::KeyHidden { sequence } => (sequence, None),
        _ => (None, None),
    };
    let mutation_len = usize::from(sequence.is_some()) + usize::from(expected_sequence.is_some());
    let operation_name = match record.detail {
        LcsKeyAuditDetail::KeyTombstoned { set: Some(set), .. } => {
            Some(if set { "set" } else { "clear" })
        }
        _ => None,
    };
    let created = matches!(record.detail, LcsKeyAuditDetail::KeyCreated { .. });
    // request.timed-out rides every failure except a create, which is
    // recorded only when it succeeded.
    let request = !success && !created;
    let metadata_layer = match record.detail {
        LcsKeyAuditDetail::KeyDeleted { layer_name } => layer_name,
        _ => None,
    };
    let sd_map = matches!(
        record.detail,
        LcsKeyAuditDetail::KeyCreated { .. } | LcsKeyAuditDetail::KeyDescriptorChanged { .. }
    );

    writer.write_map_len(
        4 + usize::from(operation_name.is_some())
            + usize::from(mutation_len != 0)
            + usize::from(record.transaction_id.is_some())
            + usize::from(request),
    )?;
    write_caller(writer, &record.caller)?;

    // object: kind, key, [layer], [sd]
    writer.write_str(FIELD_OBJECT)?;
    writer.write_map_len(2 + usize::from(metadata_layer.is_some()) + usize::from(sd_map))?;
    writer.write_str(FIELD_KIND)?;
    writer.write_str(OBJECT_KIND_KEY)?;

    writer.write_str(FIELD_KEY)?;
    writer.write_map_len(
        2 + usize::from(record.key_layer_name.is_some())
            + usize::from(value_map)
            + 4 * usize::from(created),
    )?;
    writer.write_str(FIELD_GUID)?;
    writer.write_bin(&record.key_guid)?;
    writer.write_str(FIELD_PATH)?;
    writer.write_str(record.key_path)?;
    if let Some(layer) = record.key_layer_name {
        write_layer_name(writer, layer)?;
    }
    if value_map {
        write_key_value_map(writer, value_name, value, previous)?;
    }
    if let LcsKeyAuditDetail::KeyCreated {
        volatile,
        volatile_requested,
        symlink,
        ..
    } = record.detail
    {
        writer.write_str(FIELD_CREATED)?;
        writer.write_bool(true)?;
        writer.write_str(FIELD_VOLATILE)?;
        writer.write_bool(volatile)?;
        writer.write_str(FIELD_VOLATILE_REQUESTED)?;
        writer.write_bool(volatile_requested)?;
        writer.write_str(FIELD_SYMLINK)?;
        writer.write_bool(symlink)?;
    }
    if let Some(layer) = metadata_layer {
        write_layer_name(writer, layer)?;
    }
    match record.detail {
        LcsKeyAuditDetail::KeyCreated {
            sd_owner,
            sd_length,
            ..
        } => {
            writer.write_str(FIELD_SD)?;
            writer.write_map_len(1 + usize::from(sd_owner.is_some()))?;
            writer.write_str(FIELD_LENGTH)?;
            writer.write_uint(sd_length as u64)?;
            if let Some(owner) = sd_owner {
                writer.write_str(FIELD_OWNER)?;
                writer.write_bin(owner)?;
            }
        }
        LcsKeyAuditDetail::KeyDescriptorChanged {
            components,
            sd,
            previous,
        } => write_descriptor_change_sd_map(writer, components, sd.as_ref(), previous.as_ref())?,
        _ => {}
    }

    // access: requested, granted, [matched, audit-mask]
    writer.write_str(FIELD_ACCESS)?;
    writer.write_map_len(2 + 2 * usize::from(record.access.audit_mask.is_some()))?;
    writer.write_str(FIELD_REQUESTED)?;
    writer.write_uint(record.access.requested as u64)?;
    writer.write_str(FIELD_GRANTED)?;
    writer.write_uint(record.access.granted as u64)?;
    if let Some(mask) = record.access.audit_mask {
        writer.write_str(FIELD_MATCHED)?;
        writer.write_uint((record.access.requested & mask) as u64)?;
        writer.write_str(FIELD_AUDIT_MASK)?;
        writer.write_uint(mask as u64)?;
    }

    if let Some(name) = operation_name {
        writer.write_str(FIELD_OPERATION)?;
        writer.write_map_len(1)?;
        writer.write_str(FIELD_NAME)?;
        writer.write_str(name)?;
    }

    if mutation_len != 0 {
        writer.write_str(FIELD_MUTATION)?;
        writer.write_map_len(mutation_len)?;
        if let Some(sequence) = sequence {
            writer.write_str(FIELD_SEQUENCE)?;
            writer.write_uint(sequence)?;
        }
        if let Some(expected) = expected_sequence {
            writer.write_str(FIELD_SEQUENCE_EXPECTED)?;
            writer.write_uint(expected)?;
        }
    }

    if let Some(transaction_id) = record.transaction_id {
        writer.write_str(FIELD_TRANSACTION)?;
        writer.write_map_len(1)?;
        writer.write_str(FIELD_ID)?;
        writer.write_uint(transaction_id)?;
    }

    if request {
        writer.write_str(FIELD_REQUEST)?;
        writer.write_map_len(1)?;
        writer.write_str(FIELD_TIMED_OUT)?;
        writer.write_bool(record.timed_out)?;
    }

    write_outcome(writer, success, record.result_errno)
}

/// `layer: {name: ...}` inside an already-open map.
fn write_layer_name(writer: &mut MsgpackWriter<'_>, layer: &str) -> LcsResult<()> {
    writer.write_str(FIELD_LAYER)?;
    writer.write_map_len(1)?;
    writer.write_str(FIELD_NAME)?;
    writer.write_str(layer)
}

/// `sd: {components, length, length-previous, digest, digest-previous,
/// owner, owner-previous}`, each descriptor's fields present when it was
/// read.
fn write_descriptor_change_sd_map(
    writer: &mut MsgpackWriter<'_>,
    components: u32,
    sd: Option<&LcsSdAuditSummary<'_>>,
    previous: Option<&LcsSdAuditSummary<'_>>,
) -> LcsResult<()> {
    let sd_owner = sd.and_then(|sd| sd.owner);
    let previous_owner = previous.and_then(|sd| sd.owner);
    writer.write_str(FIELD_SD)?;
    writer.write_map_len(
        1 + 2 * usize::from(sd.is_some())
            + 2 * usize::from(previous.is_some())
            + usize::from(sd_owner.is_some())
            + usize::from(previous_owner.is_some()),
    )?;
    writer.write_str(FIELD_COMPONENTS)?;
    writer.write_uint(components as u64)?;
    if let Some(sd) = sd {
        writer.write_str(FIELD_LENGTH)?;
        writer.write_uint(sd.length as u64)?;
    }
    if let Some(previous) = previous {
        writer.write_str(FIELD_LENGTH_PREVIOUS)?;
        writer.write_uint(previous.length as u64)?;
    }
    if let Some(sd) = sd {
        writer.write_str(FIELD_DIGEST)?;
        writer.write_bin(&sd.digest)?;
    }
    if let Some(previous) = previous {
        writer.write_str(FIELD_DIGEST_PREVIOUS)?;
        writer.write_bin(&previous.digest)?;
    }
    if let Some(owner) = sd_owner {
        writer.write_str(FIELD_OWNER)?;
        writer.write_bin(owner)?;
    }
    if let Some(owner) = previous_owner {
        writer.write_str(FIELD_OWNER_PREVIOUS)?;
        writer.write_bin(owner)?;
    }
    Ok(())
}

/// `outcome: {success, [errno]}`; the errno only on a failure.
fn write_outcome(writer: &mut MsgpackWriter<'_>, success: bool, errno: u32) -> LcsResult<()> {
    writer.write_str(FIELD_OUTCOME)?;
    writer.write_map_len(if success { 1 } else { 2 })?;
    writer.write_str(FIELD_SUCCESS)?;
    writer.write_bool(success)?;
    if !success {
        writer.write_str(FIELD_ERRNO)?;
        writer.write_int(-(errno as i64))?;
    }
    Ok(())
}

fn serialize_transaction_committed_audit(
    writer: &mut MsgpackWriter<'_>,
    record: &LcsTransactionCommittedAuditRecord<'_>,
) -> LcsResult<()> {
    let success = record.success();

    writer.write_map_len(3)?;
    write_caller(writer, &record.caller)?;

    writer.write_str(FIELD_TRANSACTION)?;
    writer.write_map_len(2 + usize::from(record.commit_outstanding.is_some()))?;
    writer.write_str(FIELD_ID)?;
    writer.write_uint(record.transaction_id)?;
    writer.write_str(FIELD_STATE)?;
    writer.write_str(record.state.as_str())?;
    if let Some(outstanding) = record.commit_outstanding {
        writer.write_str(FIELD_COMMIT_OUTSTANDING)?;
        writer.write_bool(outstanding)?;
    }

    writer.write_str(FIELD_OUTCOME)?;
    writer.write_map_len(
        1 + usize::from(record.errno.is_some()) + usize::from(record.reason.is_some()),
    )?;
    writer.write_str(FIELD_SUCCESS)?;
    writer.write_bool(success)?;
    if let Some(errno) = record.errno {
        writer.write_str(FIELD_ERRNO)?;
        writer.write_int(-(errno as i64))?;
    }
    if let Some(reason) = record.reason {
        writer.write_str(FIELD_REASON)?;
        writer.write_str(reason.as_str())?;
    }
    Ok(())
}

/// Received-value summary for `lcs.config.value.rejected`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LcsSelfConfigReceivedValue {
    Missing,
    WrongType { actual_type: u32 },
    DwordOutOfRange { value: u32 },
}

impl LcsSelfConfigReceivedValue {
    /// `config.received.kind`. The width of an out-of-range value is not
    /// part of the kind; `config.expected.type` already carries it.
    pub const fn received_kind(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::WrongType { .. } => "wrong-type",
            Self::DwordOutOfRange { .. } => "out-of-range",
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

/// Pure payload plan for the `lcs.config.value.rejected` audit event.
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
    payload_len(|writer| serialize_key_open_audit(writer, record))
}

pub fn write_key_open_audit_payload(
    record: &LcsKeyOpenAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = key_open_audit_payload_len(record)?;
    write_payload(output, required_len, |writer| {
        serialize_key_open_audit(writer, record)
    })
}

pub fn backup_restore_start_audit_payload_len(
    record: &LcsBackupRestoreStartAuditRecord<'_>,
) -> LcsResult<usize> {
    validate_backup_restore_start_audit_record(record)?;
    payload_len(|writer| serialize_backup_restore_start_audit(writer, record))
}

pub fn write_backup_restore_start_audit_payload(
    record: &LcsBackupRestoreStartAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = backup_restore_start_audit_payload_len(record)?;
    write_payload(output, required_len, |writer| {
        serialize_backup_restore_start_audit(writer, record)
    })
}

pub fn backup_restore_complete_audit_payload_len(
    record: &LcsBackupRestoreCompleteAuditRecord<'_>,
) -> LcsResult<usize> {
    validate_backup_restore_complete_audit_record(record)?;
    payload_len(|writer| serialize_backup_restore_complete_audit(writer, record))
}

pub fn write_backup_restore_complete_audit_payload(
    record: &LcsBackupRestoreCompleteAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = backup_restore_complete_audit_payload_len(record)?;
    write_payload(output, required_len, |writer| {
        serialize_backup_restore_complete_audit(writer, record)
    })
}

pub fn source_validation_failure_audit_payload_len(
    record: &LcsSourceValidationFailureAuditRecord<'_>,
) -> LcsResult<usize> {
    validate_source_validation_failure_audit_record(record)?;
    payload_len(|writer| serialize_source_validation_failure_audit(writer, record))
}

pub fn write_source_validation_failure_audit_payload(
    record: &LcsSourceValidationFailureAuditRecord<'_>,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = source_validation_failure_audit_payload_len(record)?;
    write_payload(output, required_len, |writer| {
        serialize_source_validation_failure_audit(writer, record)
    })
}

pub fn self_config_invalid_audit_payload_len(
    record: &LcsSelfConfigInvalidAuditRecord,
) -> LcsResult<usize> {
    validate_self_config_invalid_audit_record(record)?;
    payload_len(|writer| serialize_self_config_invalid_audit(writer, record))
}

pub fn write_self_config_invalid_audit_payload(
    record: &LcsSelfConfigInvalidAuditRecord,
    output: &mut [u8],
) -> LcsResult<LcsAuditPayloadWritePlan> {
    let required_len = self_config_invalid_audit_payload_len(record)?;
    write_payload(output, required_len, |writer| {
        serialize_self_config_invalid_audit(writer, record)
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

// Each payload has one serializer. It runs once against a counting writer
// to size the payload and once against the caller's buffer, so the length
// and the bytes cannot drift apart.

fn serialize_key_open_audit(
    writer: &mut MsgpackWriter<'_>,
    record: &LcsKeyOpenAuditRecord<'_>,
) -> LcsResult<()> {
    writer.write_map_len(5)?;
    write_caller(writer, &record.caller)?;

    writer.write_str(FIELD_OBJECT)?;
    writer.write_map_len(2)?;
    writer.write_str(FIELD_KIND)?;
    writer.write_str(OBJECT_KIND_KEY)?;
    write_key_guid(writer, &record.key_guid)?;

    writer.write_str(FIELD_ACCESS)?;
    writer.write_map_len(2)?;
    writer.write_str(FIELD_REQUESTED)?;
    writer.write_uint(record.requested_access as u64)?;
    writer.write_str(FIELD_GRANTED)?;
    writer.write_uint(record.granted_access as u64)?;

    writer.write_str(FIELD_OUTCOME)?;
    writer.write_map_len(1)?;
    writer.write_str(FIELD_SUCCESS)?;
    writer.write_bool(record.decision.success())?;

    writer.write_str(FIELD_TRIGGER)?;
    writer.write_map_len(1)?;
    writer.write_str(FIELD_SACL_MATCH)?;
    writer.write_uint(record.sacl_match_flags as u64)
}

fn serialize_backup_restore_start_audit(
    writer: &mut MsgpackWriter<'_>,
    record: &LcsBackupRestoreStartAuditRecord<'_>,
) -> LcsResult<()> {
    writer.write_map_len(3)?;
    write_caller(writer, &record.caller)?;

    writer.write_str(FIELD_OBJECT)?;
    writer.write_map_len(1)?;
    write_key_guid(writer, &record.key_guid)?;

    // Validation has already refused a negative fd, so the cast is exact.
    writer.write_str(FIELD_OPERATION)?;
    writer.write_map_len(1)?;
    writer.write_str(FIELD_FD)?;
    writer.write_uint(record.fd as u64)
}

fn serialize_backup_restore_complete_audit(
    writer: &mut MsgpackWriter<'_>,
    record: &LcsBackupRestoreCompleteAuditRecord<'_>,
) -> LcsResult<()> {
    let success = record.result_errno == 0;

    writer.write_map_len(3)?;
    write_caller(writer, &record.caller)?;

    writer.write_str(FIELD_OBJECT)?;
    writer.write_map_len(1)?;
    write_key_guid(writer, &record.key_guid)?;

    // outcome.errno is present exactly when outcome.success is false.
    writer.write_str(FIELD_OUTCOME)?;
    writer.write_map_len(if success { 1 } else { 2 })?;
    writer.write_str(FIELD_SUCCESS)?;
    writer.write_bool(success)?;
    if !success {
        writer.write_str(FIELD_ERRNO)?;
        writer.write_int(-(record.result_errno as i64))?;
    }
    Ok(())
}

fn serialize_source_validation_failure_audit(
    writer: &mut MsgpackWriter<'_>,
    record: &LcsSourceValidationFailureAuditRecord<'_>,
) -> LcsResult<()> {
    let request_len =
        usize::from(record.request_id.is_some()) + usize::from(record.op_code.is_some());
    let top_len = 2 + usize::from(request_len != 0) + usize::from(record.key_guid.is_some());

    writer.write_map_len(top_len)?;

    writer.write_str(FIELD_SOURCE)?;
    writer.write_map_len(1)?;
    writer.write_str(FIELD_RSI)?;
    writer.write_map_len(1 + usize::from(record.hive_name.is_some()))?;
    writer.write_str(FIELD_SLOT)?;
    writer.write_uint(record.source_slot as u64)?;
    if let Some(hive_name) = record.hive_name {
        writer.write_str(FIELD_HIVE)?;
        writer.write_str(hive_name)?;
    }

    if request_len != 0 {
        writer.write_str(FIELD_REQUEST)?;
        writer.write_map_len(request_len)?;
        if let Some(request_id) = record.request_id {
            writer.write_str(FIELD_ID)?;
            writer.write_uint(request_id)?;
        }
        if let Some(op_code) = record.op_code {
            writer.write_str(FIELD_OP_CODE)?;
            writer.write_uint(op_code as u64)?;
        }
    }

    if let Some(key_guid) = record.key_guid {
        writer.write_str(FIELD_OBJECT)?;
        writer.write_map_len(1)?;
        write_key_guid(writer, &key_guid)?;
    }

    writer.write_str(FIELD_OUTCOME)?;
    writer.write_map_len(1)?;
    writer.write_str(FIELD_REASON)?;
    writer.write_str(record.validation_class.as_str())
}

/// The shape is shared with `kmes.config.value.rejected`: one `config` map
/// holding `key.path`, `name`, `expected.{type,min,max}`,
/// `received.{kind,type|value}` and `value`, in that order.
fn serialize_self_config_invalid_audit(
    writer: &mut MsgpackWriter<'_>,
    record: &LcsSelfConfigInvalidAuditRecord,
) -> LcsResult<()> {
    writer.write_map_len(1)?;
    writer.write_str(FIELD_CONFIG)?;
    writer.write_map_len(5)?;

    writer.write_str(FIELD_KEY)?;
    writer.write_map_len(1)?;
    writer.write_str(FIELD_PATH)?;
    writer.write_str(record.configuration_parent_path)?;

    writer.write_str(FIELD_NAME)?;
    writer.write_str(record.configuration_name)?;

    writer.write_str(FIELD_EXPECTED)?;
    writer.write_map_len(3)?;
    writer.write_str(FIELD_TYPE)?;
    writer.write_uint(record.expected_type as u64)?;
    writer.write_str(FIELD_MIN)?;
    writer.write_uint(record.expected_min as u64)?;
    writer.write_str(FIELD_MAX)?;
    writer.write_uint(record.expected_max as u64)?;

    // config.received.type only for wrong-type, config.received.value
    // only for out-of-range; a missing value carries the kind alone.
    let received_type = record.received_type();
    let received_value = record.received_u32();
    writer.write_str(FIELD_RECEIVED)?;
    writer.write_map_len(
        1 + usize::from(received_type.is_some()) + usize::from(received_value.is_some()),
    )?;
    writer.write_str(FIELD_KIND)?;
    writer.write_str(record.received_kind())?;
    if let Some(received_type) = received_type {
        writer.write_str(FIELD_TYPE)?;
        writer.write_uint(received_type as u64)?;
    }
    if let Some(received_value) = received_value {
        writer.write_str(FIELD_VALUE)?;
        writer.write_uint(received_value as u64)?;
    }

    writer.write_str(FIELD_VALUE)?;
    writer.write_uint(record.retained_value as u64)
}

/// Writes the `caller` group as the top-level `subject` entry.
fn write_caller(
    writer: &mut MsgpackWriter<'_>,
    caller: &LcsCallerTokenSummary<'_>,
) -> LcsResult<()> {
    writer.write_str(FIELD_SUBJECT)?;
    writer.write_map_len(1)?;
    writer.write_str(FIELD_TOKEN)?;
    writer.write_map_len(CALLER_TOKEN_FIELD_COUNT)?;
    writer.write_str(TOKEN_FIELD_SID)?;
    writer.write_bin(caller.user_sid)?;
    writer.write_str(TOKEN_FIELD_INTEGRITY)?;
    writer.write_uint(caller.integrity_level as u64)?;
    writer.write_str(TOKEN_FIELD_ID)?;
    writer.write_uint(caller.token_id)?;
    writer.write_str(TOKEN_FIELD_AUTH_ID)?;
    writer.write_uint(caller.authentication_id)?;
    writer.write_str(TOKEN_FIELD_TYPE)?;
    writer.write_str(token_type_name(caller.token_type))?;
    writer.write_str(TOKEN_FIELD_IMPERSONATION)?;
    writer.write_uint(caller.impersonation_level as u64)
}

/// Writes `key: {guid: ...}` inside an already-open `object` map.
fn write_key_guid(writer: &mut MsgpackWriter<'_>, key_guid: &[u8; 16]) -> LcsResult<()> {
    writer.write_str(FIELD_KEY)?;
    writer.write_map_len(1)?;
    writer.write_str(FIELD_GUID)?;
    writer.write_bin(key_guid)
}

fn payload_len(
    serialize: impl FnOnce(&mut MsgpackWriter<'_>) -> LcsResult<()>,
) -> LcsResult<usize> {
    let mut writer = MsgpackWriter::counting();
    serialize(&mut writer)?;
    Ok(writer.bytes_written())
}

fn write_payload(
    output: &mut [u8],
    required_len: usize,
    serialize: impl FnOnce(&mut MsgpackWriter<'_>) -> LcsResult<()>,
) -> LcsResult<LcsAuditPayloadWritePlan> {
    if output.len() < required_len {
        return Err(LcsError::AuditPayloadOutputBufferTooSmall {
            buffer_len: output.len(),
            required_len,
        });
    }

    let mut writer = MsgpackWriter::new(&mut output[..required_len]);
    serialize(&mut writer)?;
    Ok(LcsAuditPayloadWritePlan {
        bytes: writer.bytes_written(),
    })
}

/// A msgpack writer over a buffer, or over nothing when it only counts.
struct MsgpackWriter<'a> {
    buf: Option<&'a mut [u8]>,
    pos: usize,
}

impl<'a> MsgpackWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf: Some(buf),
            pos: 0,
        }
    }

    fn counting() -> Self {
        Self { buf: None, pos: 0 }
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

    fn write_bool(&mut self, value: bool) -> LcsResult<()> {
        self.write_byte(if value { 0xc3 } else { 0xc2 })
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

    /// A signed integer as int32, or int64 when it does not fit. Only
    /// errnos are written this way, and every real errno fits int32.
    fn write_int(&mut self, value: i64) -> LcsResult<()> {
        if let Ok(value) = i32::try_from(value) {
            self.write_byte(0xd2)?;
            self.write_bytes(&value.to_be_bytes())
        } else {
            self.write_byte(0xd3)?;
            self.write_bytes(&value.to_be_bytes())
        }
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
        if let Some(buf) = self.buf.as_deref_mut() {
            if end > buf.len() {
                return Err(LcsError::AuditPayloadOutputBufferTooSmall {
                    buffer_len: buf.len(),
                    required_len: end,
                });
            }
            buf[self.pos..end].copy_from_slice(value);
        }
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
