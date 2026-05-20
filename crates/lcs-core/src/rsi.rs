use crate::access::validate_registry_source_security_descriptor;
use crate::config::LcsLimits;
use crate::constants::{
    REG_TOMBSTONE, RSI_ABORT_TRANSACTION, RSI_ALREADY_EXISTS, RSI_BEGIN_TRANSACTION,
    RSI_CAS_FAILED, RSI_COMMIT_TRANSACTION, RSI_CREATE_ENTRY, RSI_CREATE_KEY, RSI_DELETE_ENTRY,
    RSI_DELETE_LAYER, RSI_DELETE_VALUE_ENTRY, RSI_DROP_KEY, RSI_ENUM_CHILDREN, RSI_FLUSH,
    RSI_HIDE_ENTRY, RSI_INVALID, RSI_LOOKUP, RSI_MIN_RESPONSE_LEN, RSI_NOT_EMPTY, RSI_NOT_FOUND,
    RSI_OK, RSI_QUERY_VALUES, RSI_READ_KEY, RSI_REQUEST_HEADER_LEN, RSI_RESPONSE_BIT,
    RSI_RESPONSE_HEADER_LEN, RSI_SET_BLANKET_TOMBSTONE, RSI_SET_VALUE, RSI_STORAGE_ERROR,
    RSI_TOO_LARGE, RSI_TXN_BUSY, RSI_TXN_NOT_SUPPORTED, RSI_TXN_READ_ONLY, RSI_TXN_READ_WRITE,
    RSI_WRITE_KEY,
};
use crate::error::{LcsError, LcsResult};
use crate::path::{
    validate_key_component_bytes, validate_layer_name_bytes, validate_value_name_bytes,
};
use crate::resolution::{
    BlanketTombstoneEntry, EnumeratedSubkey, EnumeratedValue, Guid, LayerResolutionContext,
    NamedPathEntry, NamedPathResolution, NamedValueEntry, PathEntry, PathTarget, ResolvedPathEntry,
    ValidatedPathEntryWrite, ValueEntry, for_each_effective_value, for_each_visible_subkey,
    resolve_named_path_entry,
};
use crate::security::RegistrySetSecurityPlan;
use crate::transaction::TransactionKernelEffectsPlan;
use crate::transaction_log::{
    TransactionReplaySnapshotQuery, TransactionReplaySnapshotQueryKind,
    TransactionReplaySnapshotResult, TransactionReplaySnapshotResultKind,
    TransactionReplaySnapshotResultTableSummary, TransactionReplayValueWatchScope,
    insert_transaction_replay_snapshot_result,
};
use crate::value::{
    BlanketTombstoneAction, PlannedBlanketTombstone, PlannedValueWrite, ValidatedValueType,
    validate_value_data_len, validate_value_write_type,
};

pub type RsiRequestId = u64;

pub const RSI_WRITE_KEY_FIELD_SD: u32 = 0x01;
pub const RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME: u32 = 0x02;
pub const RSI_WRITE_KEY_FIELD_KNOWN_MASK: u32 =
    RSI_WRITE_KEY_FIELD_SD | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME;
pub const RSI_PATH_TARGET_GUID: u8 = 0;
pub const RSI_PATH_TARGET_HIDDEN: u8 = 1;

/// Parsed common RSI request header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiRequestHeader {
    pub total_len: u32,
    pub request_id: RsiRequestId,
    pub op_code: u16,
    pub txn_id: u64,
}

/// Parsed common RSI response header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiResponseHeader {
    pub total_len: u32,
    pub request_id: RsiRequestId,
    pub op_code: u16,
}

/// Retained request metadata needed to validate one response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiRetainedRequest {
    pub request_id: RsiRequestId,
    pub op_code: u16,
}

/// Validated response header and status field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiValidatedResponse {
    pub header: RsiResponseHeader,
    pub status: RsiStatus,
}

/// Result of writing an RSI request frame into a caller-provided buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiBuiltRequest {
    pub len: usize,
    pub retained: RsiRetainedRequest,
}

/// Retained RSI request metadata for one transaction replay snapshot query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiTransactionReplaySnapshotRequestRecord<'a> {
    pub request_id: RsiRequestId,
    pub query: TransactionReplaySnapshotQuery<'a>,
    pub retained: RsiRetainedRequest,
}

/// Summary of fixed-capacity transaction replay snapshot request records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiTransactionReplaySnapshotRequestTableSummary {
    pub entries: usize,
    pub capacity: usize,
    pub full: bool,
}

/// Result of writing and retaining one replay snapshot query request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiTransactionReplaySnapshotScheduledRequest<'a> {
    pub built: RsiBuiltRequest,
    pub record: RsiTransactionReplaySnapshotRequestRecord<'a>,
    pub request_summary: RsiTransactionReplaySnapshotRequestTableSummary,
}

/// Result of reserving a source slot for one replay snapshot query request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiTransactionReplaySnapshotReservationPlan<'a> {
    DispatchNow {
        scheduled: RsiTransactionReplaySnapshotScheduledRequest<'a>,
        remaining_timeout_ms: u32,
        in_flight_after_dispatch: usize,
    },
    WaitForSlot {
        remaining_timeout_ms: u32,
    },
    TimeoutBeforeDispatchNoRequest,
}

/// Reason a replay snapshot request batch stopped scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiTransactionReplaySnapshotBatchScheduleStop {
    AllScheduled,
    WaitForSlot { remaining_timeout_ms: u32 },
    TimeoutBeforeDispatchNoRequest,
}

/// Summary of scheduling a bounded replay snapshot request batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiTransactionReplaySnapshotBatchScheduleSummary {
    pub planned_queries: usize,
    pub scheduled_requests: usize,
    pub request_summary: RsiTransactionReplaySnapshotRequestTableSummary,
    pub in_flight_after_schedule: usize,
    pub stop: RsiTransactionReplaySnapshotBatchScheduleStop,
}

/// Validated response match for one retained transaction replay snapshot request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiTransactionReplaySnapshotResponseMatch<'a> {
    pub record: RsiTransactionReplaySnapshotRequestRecord<'a>,
    pub response: RsiValidatedResponse,
}

/// Parsed successful response payload for one replay snapshot query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiTransactionReplaySnapshotParsedResponse<'q, 'f> {
    EffectiveValue {
        record: RsiTransactionReplaySnapshotRequestRecord<'q>,
        payload: RsiQueryValuesSuccessResponsePayload<'f>,
    },
    EffectiveSubkeys {
        record: RsiTransactionReplaySnapshotRequestRecord<'q>,
        payload: RsiEnumChildrenSuccessResponsePayload<'f>,
    },
    ChildVisibility {
        record: RsiTransactionReplaySnapshotRequestRecord<'q>,
        payload: RsiLookupSuccessResponsePayload<'f>,
    },
}

/// Materialized retained replay snapshot result plus projection summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiTransactionReplaySnapshotMaterializedResponse<'a> {
    EffectiveValue {
        result: TransactionReplaySnapshotResult<'a>,
        summary: RsiEffectiveValueSnapshotProjectionSummary,
    },
    EffectiveSubkeys {
        result: TransactionReplaySnapshotResult<'a>,
        summary: RsiEffectiveSubkeySnapshotProjectionSummary,
    },
    ChildVisibility {
        result: TransactionReplaySnapshotResult<'a>,
        summary: RsiChildVisibilitySnapshotProjection<'a>,
    },
}

/// Result of processing one successful replay snapshot response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiTransactionReplaySnapshotStoredResponse<'q, 'out> {
    pub response: RsiValidatedResponse,
    pub released_record: RsiTransactionReplaySnapshotRequestRecord<'q>,
    pub materialized: RsiTransactionReplaySnapshotMaterializedResponse<'out>,
    pub result_summary: TransactionReplaySnapshotResultTableSummary,
}

/// Result of processing one replay snapshot source-error response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiTransactionReplaySnapshotSourceErrorResponse<'a> {
    pub response: RsiValidatedResponse,
    pub released_record: RsiTransactionReplaySnapshotRequestRecord<'a>,
    pub source_errno: RsiMappedErrno,
}

/// Failure class for post-commit transaction replay snapshot acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReplaySnapshotFailureKind {
    SourceError {
        source_errno: RsiMappedErrno,
    },
    TimeoutBeforeDispatch,
    TimeoutAfterDispatch {
        request_id: RsiRequestId,
    },
    MalformedData {
        failure: RsiSourceDataValidationFailure,
    },
    MalformedProtocol,
    SourceConnectionTornDown,
}

/// Source-level policy selected for failed post-commit replay snapshot recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReplaySnapshotRecoverySourcePolicy {
    KeepSourceAlive,
    TearDownAndMarkSourceDown,
    SourceAlreadyTornDown,
}

/// Request-record disposition selected by failed replay snapshot recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReplaySnapshotRecoveryRequestDisposition {
    NoRequestSent,
    ReleaseFailedRequestRecord,
    RetainTimedOutInFlightRequest { request_id: RsiRequestId },
    ReleaseInFlightTableOnSourceTeardown,
}

/// Recovery policy when exact post-commit replay snapshots are unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplaySnapshotFailureRecoveryPlan {
    pub commit_remains_successful: bool,
    pub caller_errno: Option<RsiMappedErrno>,
    pub emit_normal_watch_events: bool,
    pub queue_overflow_for_affected_watches: bool,
    pub release_transaction_replay_state: bool,
    pub late_response_must_not_resurrect_normal_events: bool,
    pub source_errno: Option<RsiMappedErrno>,
    pub malformed_data_plan: Option<RsiMalformedSourceDataPlan>,
    pub source_policy: TransactionReplaySnapshotRecoverySourcePolicy,
    pub request_disposition: TransactionReplaySnapshotRecoveryRequestDisposition,
}

/// One length-prefixed RSI string or byte-array field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiLengthPrefixedField<'a> {
    pub len: u32,
    pub data: &'a [u8],
}

/// Explicit plan for ignored forward-compatible trailing request fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiTrailingOptionalFieldsPlan {
    pub ignored_trailing_len: usize,
}

/// Cursor for parsing fixed-order RSI payload fields from a framed message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiPayloadCursor<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> RsiPayloadCursor<'a> {
    pub const fn new(payload: &'a [u8]) -> Self {
        Self { payload, offset: 0 }
    }

    pub const fn position(&self) -> usize {
        self.offset
    }

    pub const fn remaining_len(&self) -> usize {
        self.payload.len() - self.offset
    }

    pub fn read_fixed(&mut self, len: usize) -> LcsResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(LcsError::RsiPayloadLengthOverflow)?;
        if end > self.payload.len() {
            return Err(LcsError::RsiMessageTooShort {
                len: self.payload.len(),
                min: end,
            });
        }
        let data = &self.payload[self.offset..end];
        self.offset = end;
        Ok(data)
    }

    pub fn read_u8(&mut self) -> LcsResult<u8> {
        Ok(self.read_fixed(1)?[0])
    }

    pub fn read_bool(&mut self, field: &'static str) -> LcsResult<bool> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(LcsError::InvalidBooleanFlag { field, value }),
        }
    }

    pub fn read_u32_le(&mut self) -> LcsResult<u32> {
        let bytes = self.read_fixed(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u64_le(&mut self) -> LcsResult<u64> {
        let bytes = self.read_fixed(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn read_guid(&mut self) -> LcsResult<Guid> {
        let bytes = self.read_fixed(16)?;
        let mut guid = [0u8; 16];
        guid.copy_from_slice(bytes);
        Ok(guid)
    }

    pub fn read_length_prefixed(&mut self) -> LcsResult<RsiLengthPrefixedField<'a>> {
        let len = self.read_u32_le()?;
        let data = self.read_fixed(len as usize)?;
        Ok(RsiLengthPrefixedField { len, data })
    }

    pub fn finish_allowing_trailing_optional_fields(&self) -> RsiTrailingOptionalFieldsPlan {
        RsiTrailingOptionalFieldsPlan {
            ignored_trailing_len: self.remaining_len(),
        }
    }
}

/// Parsed RSI_LOOKUP request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiLookupRequestPayload<'a> {
    pub parent_guid: Guid,
    pub child_name: RsiLengthPrefixedField<'a>,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Defined RSI path-entry target type vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RsiPathTargetType {
    Guid = RSI_PATH_TARGET_GUID,
    Hidden = RSI_PATH_TARGET_HIDDEN,
}

impl RsiPathTargetType {
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            RSI_PATH_TARGET_GUID => Some(Self::Guid),
            RSI_PATH_TARGET_HIDDEN => Some(Self::Hidden),
            _ => None,
        }
    }

    pub fn code(self) -> u8 {
        self as u8
    }
}

/// One parsed path entry from an RSI_LOOKUP-style response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiLookupPathEntry<'a> {
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub target_type: RsiPathTargetType,
    pub target_guid: Guid,
    pub sequence: u64,
}

/// One parsed key metadata entry from an RSI_LOOKUP-style response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiKeyMetadataResponseEntry<'a> {
    pub guid: Guid,
    pub sd: RsiLengthPrefixedField<'a>,
    pub volatile: bool,
    pub symlink: bool,
    pub last_write_time: u64,
}

/// Parsed successful RSI_LOOKUP response payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiLookupSuccessResponsePayload<'a> {
    pub response: RsiValidatedResponse,
    pub entry_count: u32,
    pub entries_bytes: &'a [u8],
    pub metadata_count: u32,
    pub metadata_bytes: &'a [u8],
}

impl<'a> RsiLookupSuccessResponsePayload<'a> {
    pub fn for_each_path_entry<F>(&self, visitor: F) -> LcsResult<()>
    where
        F: FnMut(RsiLookupPathEntry<'a>) -> LcsResult<()>,
    {
        parse_rsi_lookup_path_entries(self.entry_count, self.entries_bytes, visitor)
    }

    pub fn for_each_key_metadata<F>(&self, visitor: F) -> LcsResult<()>
    where
        F: FnMut(RsiKeyMetadataResponseEntry<'a>) -> LcsResult<()>,
    {
        parse_rsi_key_metadata_entries(self.metadata_count, self.metadata_bytes, visitor)
    }
}

/// One parsed child record from an RSI_ENUM_CHILDREN response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiEnumChildResponseEntry<'a> {
    pub child_name: RsiLengthPrefixedField<'a>,
    pub path_entry_count: u32,
    pub path_entries_bytes: &'a [u8],
}

impl<'a> RsiEnumChildResponseEntry<'a> {
    pub fn for_each_path_entry<F>(&self, visitor: F) -> LcsResult<()>
    where
        F: FnMut(RsiLookupPathEntry<'a>) -> LcsResult<()>,
    {
        parse_rsi_lookup_path_entries(self.path_entry_count, self.path_entries_bytes, visitor)
    }
}

/// Parsed successful RSI_ENUM_CHILDREN response payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiEnumChildrenSuccessResponsePayload<'a> {
    pub response: RsiValidatedResponse,
    pub child_count: u32,
    pub children_bytes: &'a [u8],
    pub metadata_count: u32,
    pub metadata_bytes: &'a [u8],
}

impl<'a> RsiEnumChildrenSuccessResponsePayload<'a> {
    pub fn for_each_child<F>(&self, visitor: F) -> LcsResult<()>
    where
        F: FnMut(RsiEnumChildResponseEntry<'a>) -> LcsResult<()>,
    {
        parse_rsi_enum_children_entries(self.child_count, self.children_bytes, visitor)
    }

    pub fn for_each_key_metadata<F>(&self, visitor: F) -> LcsResult<()>
    where
        F: FnMut(RsiKeyMetadataResponseEntry<'a>) -> LcsResult<()>,
    {
        parse_rsi_key_metadata_entries(self.metadata_count, self.metadata_bytes, visitor)
    }
}

/// Parsed RSI_CREATE_ENTRY request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiCreateEntryRequestPayload<'a> {
    pub parent_guid: Guid,
    pub child_name: RsiLengthPrefixedField<'a>,
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub child_guid: Guid,
    pub sequence: u64,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_HIDE_ENTRY request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiHideEntryRequestPayload<'a> {
    pub parent_guid: Guid,
    pub child_name: RsiLengthPrefixedField<'a>,
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub sequence: u64,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_DELETE_ENTRY request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiDeleteEntryRequestPayload<'a> {
    pub parent_guid: Guid,
    pub child_name: RsiLengthPrefixedField<'a>,
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_ENUM_CHILDREN request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiEnumChildrenRequestPayload {
    pub parent_guid: Guid,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_CREATE_KEY request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiCreateKeyRequestPayload<'a> {
    pub guid: Guid,
    pub name: RsiLengthPrefixedField<'a>,
    pub parent_guid: Guid,
    pub sd: RsiLengthPrefixedField<'a>,
    pub volatile: bool,
    pub symlink: bool,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_READ_KEY request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiReadKeyRequestPayload {
    pub guid: Guid,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_WRITE_KEY request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiWriteKeyRequestPayload<'a> {
    pub guid: Guid,
    pub field_mask: u32,
    pub sd: Option<RsiLengthPrefixedField<'a>>,
    pub last_write_time: Option<u64>,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_DROP_KEY request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiDropKeyRequestPayload {
    pub guid: Guid,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed successful RSI_READ_KEY response payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiReadKeySuccessResponsePayload<'a> {
    pub response: RsiValidatedResponse,
    pub name: RsiLengthPrefixedField<'a>,
    pub parent_guid: Guid,
    pub sd: RsiLengthPrefixedField<'a>,
    pub volatile: bool,
    pub symlink: bool,
    pub last_write_time: u64,
}

/// Parsed RSI_QUERY_VALUES request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiQueryValuesRequestPayload<'a> {
    pub guid: Guid,
    pub value_name: RsiLengthPrefixedField<'a>,
    pub query_all: bool,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// One parsed value entry from a successful RSI_QUERY_VALUES response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiQueryValueResponseEntry<'a> {
    pub value_name: RsiLengthPrefixedField<'a>,
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub value_type: u32,
    pub data: RsiLengthPrefixedField<'a>,
    pub sequence: u64,
}

/// One parsed blanket tombstone entry from a successful RSI_QUERY_VALUES response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiQueryValuesBlanketResponseEntry<'a> {
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub sequence: u64,
}

/// Parsed successful RSI_QUERY_VALUES response payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiQueryValuesSuccessResponsePayload<'a> {
    pub response: RsiValidatedResponse,
    pub entry_count: u32,
    pub entries_bytes: &'a [u8],
    pub blanket_count: u32,
    pub blanket_bytes: &'a [u8],
}

impl<'a> RsiQueryValuesSuccessResponsePayload<'a> {
    pub fn for_each_value_entry<F>(&self, visitor: F) -> LcsResult<()>
    where
        F: FnMut(RsiQueryValueResponseEntry<'a>) -> LcsResult<()>,
    {
        parse_rsi_query_value_entries(self.entry_count, self.entries_bytes, visitor)
    }

    pub fn for_each_blanket_entry<F>(&self, visitor: F) -> LcsResult<()>
    where
        F: FnMut(RsiQueryValuesBlanketResponseEntry<'a>) -> LcsResult<()>,
    {
        parse_rsi_query_values_blankets(self.blanket_count, self.blanket_bytes, visitor)
    }
}

/// Summary of effective-value snapshot materialization from RSI_QUERY_VALUES.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiEffectiveValueSnapshotProjectionSummary {
    pub source_value_entries: usize,
    pub source_blanket_entries: usize,
    pub emitted_values: usize,
    pub value_capacity: usize,
    pub blanket_capacity: usize,
}

/// Summary of effective-subkey snapshot materialization from RSI_ENUM_CHILDREN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiEffectiveSubkeySnapshotProjectionSummary {
    pub source_path_entries: usize,
    pub emitted_subkeys: usize,
    pub path_capacity: usize,
}

/// Child-visibility snapshot materialized from RSI_LOOKUP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiChildVisibilitySnapshotProjection<'a> {
    pub source_path_entries: usize,
    pub path_capacity: usize,
    pub resolved: Option<ResolvedPathEntry<'a>>,
}

/// Parsed RSI_SET_VALUE request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiSetValueRequestPayload<'a> {
    pub guid: Guid,
    pub value_name: RsiLengthPrefixedField<'a>,
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub value_type: u32,
    pub data: RsiLengthPrefixedField<'a>,
    pub sequence: u64,
    pub expected_sequence: u64,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_DELETE_VALUE_ENTRY request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiDeleteValueEntryRequestPayload<'a> {
    pub guid: Guid,
    pub value_name: RsiLengthPrefixedField<'a>,
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_SET_BLANKET_TOMBSTONE request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiSetBlanketTombstoneRequestPayload<'a> {
    pub guid: Guid,
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub set: bool,
    pub sequence: u64,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Defined RSI transaction mode vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RsiTransactionMode {
    ReadWrite = RSI_TXN_READ_WRITE,
    ReadOnly = RSI_TXN_READ_ONLY,
}

impl RsiTransactionMode {
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            RSI_TXN_READ_WRITE => Some(Self::ReadWrite),
            RSI_TXN_READ_ONLY => Some(Self::ReadOnly),
            _ => None,
        }
    }

    pub fn code(self) -> u32 {
        self as u32
    }
}

/// Parsed RSI_BEGIN_TRANSACTION request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiBeginTransactionRequestPayload {
    pub transaction_id: u64,
    pub mode: RsiTransactionMode,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_COMMIT_TRANSACTION request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiCommitTransactionRequestPayload {
    pub transaction_id: u64,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_ABORT_TRANSACTION request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiAbortTransactionRequestPayload {
    pub transaction_id: u64,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Parsed RSI_DELETE_LAYER request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiDeleteLayerRequestPayload<'a> {
    pub layer_name: RsiLengthPrefixedField<'a>,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Borrowed count-prefixed GUID array in an RSI response payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiGuidArray<'a> {
    pub count: u32,
    pub bytes: &'a [u8],
}

impl<'a> RsiGuidArray<'a> {
    pub fn guid_at(&self, index: u32) -> Option<Guid> {
        if index >= self.count {
            return None;
        }
        let start = (index as usize).checked_mul(16)?;
        let end = start.checked_add(16)?;
        if end > self.bytes.len() {
            return None;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&self.bytes[start..end]);
        Some(guid)
    }
}

/// Parsed successful RSI_DELETE_LAYER response payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiDeleteLayerSuccessResponsePayload<'a> {
    pub response: RsiValidatedResponse,
    pub orphaned_guids: RsiGuidArray<'a>,
}

/// Parsed RSI_FLUSH request payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiFlushRequestPayload<'a> {
    pub hive_name: RsiLengthPrefixedField<'a>,
    pub trailing: RsiTrailingOptionalFieldsPlan,
}

/// Retained-record lookup result for a late response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiLateResponseRecordState {
    Retained(RsiRetainedRequest),
    UnknownRequestId,
    DuplicateResponse,
    ReleasedRequestRecord,
}

/// Malformed protocol reason selected for unsafe late-response records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiMalformedProtocolReason {
    UnknownRequestId,
    DuplicateResponse,
    ReleasedRequestRecord,
}

/// Late-response handling selected from retained-record state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiLateResponseRecordPlan {
    ValidateNormally(RsiRetainedRequest),
    MalformedProtocolTearDown {
        reason: RsiMalformedProtocolReason,
        tear_down_source: bool,
        mark_source_down: bool,
    },
}

/// Kernel-side effects for a successful late mutating response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiLateMutatingKernelEffects {
    pub update_hive_generation: bool,
    pub dispatch_watch_events: bool,
    pub refresh_layer_cache: bool,
    pub track_orphans: bool,
    pub transaction_commit_effects: Option<TransactionKernelEffectsPlan>,
}

/// Post-validation outcome for a retained late response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiLateResponseValidationOutcome {
    SourceError(RsiMappedErrno),
    SuccessReadOnly,
    SuccessMutating(RsiLateMutatingKernelEffects),
    MalformedData(RsiSourceDataValidationFailure),
    MalformedProtocol,
    MissingOrInvalidKernelMetadata,
}

/// Fail-closed reason for a late response that cannot safely be applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiLateResponseTearDownReason {
    MalformedProtocol,
    MissingOrInvalidKernelMetadata,
}

/// Kernel-side effect plan for a retained late response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiLateResponseEffectPlan {
    ReleaseRecordNoNormalEffects {
        source_errno: Option<RsiMappedErrno>,
        release_request_record: bool,
    },
    DiscardValidatedReadOnlyResponse {
        release_request_record: bool,
    },
    ApplyMutatingKernelEffects {
        effects: RsiLateMutatingKernelEffects,
        release_request_record: bool,
    },
    MalformedData {
        plan: RsiMalformedSourceDataPlan,
        release_request_record: bool,
    },
    MalformedProtocolTearDown {
        reason: RsiLateResponseTearDownReason,
        tear_down_source: bool,
        mark_source_down: bool,
        release_in_flight_table: bool,
    },
}

/// Cleanup needed after a late source-state success creates source-side state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiLateCleanupPlan {
    pub abort_transaction_id: u64,
    pub enqueue_abort_transaction: bool,
}

/// Retained metadata for a successful late response whose op code has been validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiLateSuccessMetadata {
    pub txn_id: u64,
    pub mutation_effects: Option<RsiLateMutatingKernelEffects>,
}

/// Op-code-specific effect plan for a retained late success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiLateSuccessEffectPlan {
    Effect(RsiLateResponseEffectPlan),
    EnqueueCleanup {
        cleanup: RsiLateCleanupPlan,
        release_request_record: bool,
    },
}

/// Source fd read behavior selected from queue state and caller flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiReadPlan {
    ReturnOneCompleteRequest {
        request_len: usize,
        consume_request: bool,
    },
    WaitForRequestOrClose,
    ReturnEagain,
    ReturnEmsgsize {
        required_len: usize,
        consume_request: bool,
    },
    WakeForClose,
}

/// Complete queued request frame visible to a source fd read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiQueuedRequest<'a> {
    pub frame: &'a [u8],
    pub retained: RsiRetainedRequest,
}

/// Summary of fixed-capacity source request queue storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiRequestQueueSummary {
    pub entries: usize,
    pub capacity: usize,
    pub full: bool,
}

/// Applied source-fd read-drain outcome over fixed request queue storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiRequestQueueReadDrain<'a> {
    Copied {
        request: RsiQueuedRequest<'a>,
        bytes: usize,
        summary: RsiRequestQueueSummary,
    },
    WaitForRequestOrClose,
    ReturnEagain,
    ReturnEmsgsize {
        required_len: usize,
        consume_request: bool,
    },
    WakeForClose,
}

/// Source fd poll readiness bits expressed without platform poll constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiPollPlan {
    pub readable: bool,
    pub writable: bool,
    pub hangup: bool,
    pub error: bool,
}

/// Slot reservation result for a caller attempting to dispatch an RSI request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiSlotReservationPlan {
    DispatchNow {
        request_id: RsiRequestId,
        remaining_timeout_ms: u32,
        in_flight_after_dispatch: usize,
    },
    WaitForSlot {
        remaining_timeout_ms: u32,
    },
    TimeoutBeforeDispatchNoRequest,
}

/// Caller-visible errno class for RSI request timeout outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiRequestTimeoutErrno {
    Etimedout,
}

/// Wait result for a request that has already been dispatched to a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiDispatchedWaitPlan {
    ContinueWaiting {
        remaining_timeout_ms: u32,
    },
    CallerTimedOutRetainRecord {
        request_id: RsiRequestId,
        retain_request_record: bool,
        remains_in_flight: bool,
        completion_may_still_occur: bool,
    },
}

/// Per-source monotonic RSI request-id allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiRequestIdCounter {
    next_request_id: RsiRequestId,
}

impl RsiRequestIdCounter {
    pub const fn new() -> Self {
        Self { next_request_id: 0 }
    }

    pub const fn from_next_request_id(next_request_id: RsiRequestId) -> Self {
        Self { next_request_id }
    }

    pub const fn next_request_id(&self) -> RsiRequestId {
        self.next_request_id
    }

    pub fn allocate(&mut self) -> LcsResult<RsiRequestId> {
        let allocated = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(LcsError::RsiRequestIdOverflow)?;
        Ok(allocated)
    }
}

impl Default for RsiRequestIdCounter {
    fn default() -> Self {
        Self::new()
    }
}

struct RsiFrameWriter<'a> {
    dst: &'a mut [u8],
    offset: usize,
}

impl<'a> RsiFrameWriter<'a> {
    fn new(dst: &'a mut [u8]) -> Self {
        Self { dst, offset: 0 }
    }

    fn write_fixed(&mut self, bytes: &[u8]) -> LcsResult<()> {
        let end = self
            .offset
            .checked_add(bytes.len())
            .ok_or(LcsError::RsiPayloadLengthOverflow)?;
        if end > self.dst.len() {
            return Err(LcsError::RsiFrameBufferTooSmall {
                len: self.dst.len(),
                required: end,
            });
        }
        self.dst[self.offset..end].copy_from_slice(bytes);
        self.offset = end;
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> LcsResult<()> {
        self.write_fixed(&[value])
    }

    fn write_u16_le(&mut self, value: u16) -> LcsResult<()> {
        self.write_fixed(&value.to_le_bytes())
    }

    fn write_u32_le(&mut self, value: u32) -> LcsResult<()> {
        self.write_fixed(&value.to_le_bytes())
    }

    fn write_u64_le(&mut self, value: u64) -> LcsResult<()> {
        self.write_fixed(&value.to_le_bytes())
    }

    fn write_guid(&mut self, value: Guid) -> LcsResult<()> {
        self.write_fixed(&value)
    }

    fn write_length_prefixed(&mut self, bytes: &[u8]) -> LcsResult<()> {
        let len = checked_rsi_field_len_u32(bytes)?;
        self.write_u32_le(len)?;
        self.write_fixed(bytes)
    }

    fn finish(self) -> usize {
        self.offset
    }
}

/// Writes a complete RSI_LOOKUP request frame.
pub fn write_rsi_lookup_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    parent_guid: Guid,
    child_name: &[u8],
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_add_len(16, checked_rsi_length_prefixed_len(child_name)?)?;
    write_rsi_request_frame(dst, request_id, RSI_LOOKUP, txn_id, payload_len, |writer| {
        writer.write_guid(parent_guid)?;
        writer.write_length_prefixed(child_name)
    })
}

/// Writes a complete RSI_CREATE_ENTRY request frame.
pub fn write_rsi_create_entry_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    parent_guid: Guid,
    child_name: &[u8],
    layer_name: &[u8],
    child_guid: Guid,
    sequence: u64,
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_add_len(
        checked_add_len(
            checked_add_len(16, checked_rsi_length_prefixed_len(child_name)?)?,
            checked_rsi_length_prefixed_len(layer_name)?,
        )?,
        24,
    )?;
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_CREATE_ENTRY,
        txn_id,
        payload_len,
        |writer| {
            writer.write_guid(parent_guid)?;
            writer.write_length_prefixed(child_name)?;
            writer.write_length_prefixed(layer_name)?;
            writer.write_guid(child_guid)?;
            writer.write_u64_le(sequence)
        },
    )
}

/// Writes a complete RSI_HIDE_ENTRY request frame.
pub fn write_rsi_hide_entry_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    parent_guid: Guid,
    child_name: &[u8],
    layer_name: &[u8],
    sequence: u64,
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_add_len(
        checked_add_len(
            checked_add_len(16, checked_rsi_length_prefixed_len(child_name)?)?,
            checked_rsi_length_prefixed_len(layer_name)?,
        )?,
        8,
    )?;
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_HIDE_ENTRY,
        txn_id,
        payload_len,
        |writer| {
            writer.write_guid(parent_guid)?;
            writer.write_length_prefixed(child_name)?;
            writer.write_length_prefixed(layer_name)?;
            writer.write_u64_le(sequence)
        },
    )
}

/// Writes the source request corresponding to a validated path-entry write.
pub fn write_rsi_path_entry_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    path_entry: ValidatedPathEntryWrite<'_>,
) -> LcsResult<RsiBuiltRequest> {
    match path_entry.target {
        PathTarget::Guid(child_guid) => write_rsi_create_entry_request_frame(
            dst,
            request_id,
            txn_id,
            path_entry.parent_guid,
            path_entry.child_name.as_bytes(),
            path_entry.layer.as_bytes(),
            child_guid,
            path_entry.sequence,
        ),
        PathTarget::Hidden => write_rsi_hide_entry_request_frame(
            dst,
            request_id,
            txn_id,
            path_entry.parent_guid,
            path_entry.child_name.as_bytes(),
            path_entry.layer.as_bytes(),
            path_entry.sequence,
        ),
    }
}

/// Writes a complete RSI_DELETE_ENTRY request frame.
pub fn write_rsi_delete_entry_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    parent_guid: Guid,
    child_name: &[u8],
    layer_name: &[u8],
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_add_len(
        checked_add_len(16, checked_rsi_length_prefixed_len(child_name)?)?,
        checked_rsi_length_prefixed_len(layer_name)?,
    )?;
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_DELETE_ENTRY,
        txn_id,
        payload_len,
        |writer| {
            writer.write_guid(parent_guid)?;
            writer.write_length_prefixed(child_name)?;
            writer.write_length_prefixed(layer_name)
        },
    )
}

/// Writes a complete RSI_ENUM_CHILDREN request frame.
pub fn write_rsi_enum_children_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    parent_guid: Guid,
) -> LcsResult<RsiBuiltRequest> {
    write_rsi_request_frame(dst, request_id, RSI_ENUM_CHILDREN, txn_id, 16, |writer| {
        writer.write_guid(parent_guid)
    })
}

/// Writes a complete RSI_CREATE_KEY request frame.
pub fn write_rsi_create_key_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    guid: Guid,
    name: &[u8],
    parent_guid: Guid,
    sd: &[u8],
    volatile: bool,
    symlink: bool,
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_add_len(
        checked_add_len(
            checked_add_len(
                checked_add_len(16, checked_rsi_length_prefixed_len(name)?)?,
                16,
            )?,
            checked_rsi_length_prefixed_len(sd)?,
        )?,
        2,
    )?;
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_CREATE_KEY,
        txn_id,
        payload_len,
        |writer| {
            writer.write_guid(guid)?;
            writer.write_length_prefixed(name)?;
            writer.write_guid(parent_guid)?;
            writer.write_length_prefixed(sd)?;
            writer.write_u8(u8::from(volatile))?;
            writer.write_u8(u8::from(symlink))
        },
    )
}

/// Writes a complete RSI_READ_KEY request frame.
pub fn write_rsi_read_key_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    guid: Guid,
) -> LcsResult<RsiBuiltRequest> {
    write_rsi_request_frame(dst, request_id, RSI_READ_KEY, txn_id, 16, |writer| {
        writer.write_guid(guid)
    })
}

/// Writes a complete RSI_WRITE_KEY request frame.
pub fn write_rsi_write_key_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    guid: Guid,
    sd: Option<&[u8]>,
    last_write_time: Option<u64>,
) -> LcsResult<RsiBuiltRequest> {
    let mut field_mask = 0u32;
    let mut payload_len = checked_add_len(16, 4)?;
    if let Some(sd) = sd {
        field_mask |= RSI_WRITE_KEY_FIELD_SD;
        payload_len = checked_add_len(payload_len, checked_rsi_length_prefixed_len(sd)?)?;
    }
    if last_write_time.is_some() {
        field_mask |= RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME;
        payload_len = checked_add_len(payload_len, 8)?;
    }

    write_rsi_request_frame(
        dst,
        request_id,
        RSI_WRITE_KEY,
        txn_id,
        payload_len,
        |writer| {
            writer.write_guid(guid)?;
            writer.write_u32_le(field_mask)?;
            if let Some(sd) = sd {
                writer.write_length_prefixed(sd)?;
            }
            if let Some(last_write_time) = last_write_time {
                writer.write_u64_le(last_write_time)?;
            }
            Ok(())
        },
    )
}

/// Writes the `RSI_WRITE_KEY` request for a validated `REG_IOC_SET_SECURITY`.
pub fn write_registry_set_security_rsi_write_key_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    guid: Guid,
    last_write_time: u64,
    plan: &RegistrySetSecurityPlan,
) -> LcsResult<RsiBuiltRequest> {
    write_rsi_write_key_request_frame(
        dst,
        request_id,
        txn_id,
        guid,
        Some(plan.merged_sd.as_slice()),
        Some(last_write_time),
    )
}

/// Writes a complete RSI_DROP_KEY request frame.
pub fn write_rsi_drop_key_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    guid: Guid,
) -> LcsResult<RsiBuiltRequest> {
    write_rsi_request_frame(dst, request_id, RSI_DROP_KEY, txn_id, 16, |writer| {
        writer.write_guid(guid)
    })
}

/// Writes a complete RSI_QUERY_VALUES request frame.
pub fn write_rsi_query_values_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    guid: Guid,
    value_name: &[u8],
    query_all: bool,
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_add_len(
        checked_add_len(16, checked_rsi_length_prefixed_len(value_name)?)?,
        1,
    )?;
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_QUERY_VALUES,
        txn_id,
        payload_len,
        |writer| {
            writer.write_guid(guid)?;
            writer.write_length_prefixed(value_name)?;
            writer.write_u8(u8::from(query_all))
        },
    )
}

/// Writes a complete RSI_SET_VALUE request frame.
pub fn write_rsi_set_value_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    guid: Guid,
    value_name: &[u8],
    layer_name: &[u8],
    value_type: u32,
    data: &[u8],
    sequence: u64,
    expected_sequence: u64,
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_add_len(
        checked_add_len(
            checked_add_len(
                checked_add_len(
                    checked_add_len(16, checked_rsi_length_prefixed_len(value_name)?)?,
                    checked_rsi_length_prefixed_len(layer_name)?,
                )?,
                4,
            )?,
            checked_rsi_length_prefixed_len(data)?,
        )?,
        16,
    )?;
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_SET_VALUE,
        txn_id,
        payload_len,
        |writer| {
            writer.write_guid(guid)?;
            writer.write_length_prefixed(value_name)?;
            writer.write_length_prefixed(layer_name)?;
            writer.write_u32_le(value_type)?;
            writer.write_length_prefixed(data)?;
            writer.write_u64_le(sequence)?;
            writer.write_u64_le(expected_sequence)
        },
    )
}

/// Writes a complete RSI_SET_VALUE request frame from a planned value write.
pub fn write_planned_rsi_set_value_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    planned: &PlannedValueWrite<'_>,
) -> LcsResult<RsiBuiltRequest> {
    let value_type = match planned.write.value_type {
        ValidatedValueType::Normal(value_type) => value_type.code(),
        ValidatedValueType::Tombstone => REG_TOMBSTONE,
    };

    write_rsi_set_value_request_frame(
        dst,
        request_id,
        txn_id,
        planned.write.key_guid,
        planned.write.name.as_bytes(),
        planned.write.layer.as_bytes(),
        value_type,
        planned.write.data,
        planned.write.sequence,
        planned.write.expected_sequence.unwrap_or(0),
    )
}

/// Retains response-matching metadata for one transaction replay snapshot query.
pub fn retain_transaction_replay_snapshot_request<'a>(
    request_id: RsiRequestId,
    query: TransactionReplaySnapshotQuery<'a>,
) -> RsiTransactionReplaySnapshotRequestRecord<'a> {
    RsiTransactionReplaySnapshotRequestRecord {
        request_id,
        query,
        retained: RsiRetainedRequest {
            request_id,
            op_code: transaction_replay_snapshot_query_op_code(query.kind),
        },
    }
}

/// Summarizes replay snapshot request-table occupancy.
pub fn summarize_transaction_replay_snapshot_request_table(
    storage: &[Option<RsiTransactionReplaySnapshotRequestRecord<'_>>],
) -> LcsResult<RsiTransactionReplaySnapshotRequestTableSummary> {
    summarize_transaction_replay_snapshot_request_table_internal(storage)
}

/// Inserts one retained replay snapshot request record into fixed storage.
pub fn insert_transaction_replay_snapshot_request_record<'a>(
    storage: &mut [Option<RsiTransactionReplaySnapshotRequestRecord<'a>>],
    record: RsiTransactionReplaySnapshotRequestRecord<'a>,
) -> LcsResult<RsiTransactionReplaySnapshotRequestTableSummary> {
    let summary = summarize_transaction_replay_snapshot_request_table_internal(storage)?;
    if storage
        .iter()
        .flatten()
        .any(|existing| existing.request_id == record.request_id)
    {
        return Err(LcsError::DuplicateTransactionReplaySnapshotRequest {
            request_id: record.request_id,
        });
    }

    if summary.full {
        return Err(LcsError::TransactionReplaySnapshotRequestTableFull {
            capacity: summary.capacity,
        });
    }
    let Some(slot) = storage.iter_mut().find(|slot| slot.is_none()) else {
        return Err(LcsError::TransactionReplaySnapshotRequestTableFull {
            capacity: storage.len(),
        });
    };
    *slot = Some(record);
    summarize_transaction_replay_snapshot_request_table(storage)
}

/// Writes one replay snapshot query request frame and retains its match record.
pub fn schedule_transaction_replay_snapshot_query_request<'a>(
    storage: &mut [Option<RsiTransactionReplaySnapshotRequestRecord<'a>>],
    dst: &mut [u8],
    request_id: RsiRequestId,
    query: TransactionReplaySnapshotQuery<'a>,
) -> LcsResult<RsiTransactionReplaySnapshotScheduledRequest<'a>> {
    let summary = summarize_transaction_replay_snapshot_request_table_internal(storage)?;
    if storage
        .iter()
        .flatten()
        .any(|existing| existing.request_id == request_id)
    {
        return Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id });
    }
    if summary.full {
        return Err(LcsError::TransactionReplaySnapshotRequestTableFull {
            capacity: summary.capacity,
        });
    }

    let built = write_transaction_replay_snapshot_query_request_frame(dst, request_id, query)?;
    let record = retain_transaction_replay_snapshot_request(request_id, query);
    let request_summary = insert_transaction_replay_snapshot_request_record(storage, record)?;

    Ok(RsiTransactionReplaySnapshotScheduledRequest {
        built,
        record,
        request_summary,
    })
}

/// Reserves a source slot, writes one replay snapshot request, and retains it.
pub fn reserve_and_schedule_transaction_replay_snapshot_query_request<'a>(
    limits: &LcsLimits,
    counter: &mut RsiRequestIdCounter,
    in_flight_count: usize,
    elapsed_ms_since_reservation_attempt: u32,
    storage: &mut [Option<RsiTransactionReplaySnapshotRequestRecord<'a>>],
    dst: &mut [u8],
    query: TransactionReplaySnapshotQuery<'a>,
) -> LcsResult<RsiTransactionReplaySnapshotReservationPlan<'a>> {
    let summary = summarize_transaction_replay_snapshot_request_table_internal(storage)?;
    if summary.full {
        return Err(LcsError::TransactionReplaySnapshotRequestTableFull {
            capacity: summary.capacity,
        });
    }

    let required_frame_len = transaction_replay_snapshot_query_request_frame_len(query)?;
    if dst.len() < required_frame_len {
        return Err(LcsError::RsiFrameBufferTooSmall {
            len: dst.len(),
            required: required_frame_len,
        });
    }

    match plan_rsi_slot_reservation(
        limits,
        counter,
        in_flight_count,
        elapsed_ms_since_reservation_attempt,
    )? {
        RsiSlotReservationPlan::DispatchNow {
            request_id,
            remaining_timeout_ms,
            in_flight_after_dispatch,
        } => {
            let scheduled = schedule_transaction_replay_snapshot_query_request(
                storage, dst, request_id, query,
            )?;
            Ok(RsiTransactionReplaySnapshotReservationPlan::DispatchNow {
                scheduled,
                remaining_timeout_ms,
                in_flight_after_dispatch,
            })
        }
        RsiSlotReservationPlan::WaitForSlot {
            remaining_timeout_ms,
        } => Ok(RsiTransactionReplaySnapshotReservationPlan::WaitForSlot {
            remaining_timeout_ms,
        }),
        RsiSlotReservationPlan::TimeoutBeforeDispatchNoRequest => {
            Ok(RsiTransactionReplaySnapshotReservationPlan::TimeoutBeforeDispatchNoRequest)
        }
    }
}

/// Schedules a bounded prefix of replay snapshot query requests.
pub fn reserve_and_schedule_transaction_replay_snapshot_query_batch<'a>(
    limits: &LcsLimits,
    counter: &mut RsiRequestIdCounter,
    in_flight_count: usize,
    elapsed_ms_since_reservation_attempt: u32,
    storage: &mut [Option<RsiTransactionReplaySnapshotRequestRecord<'a>>],
    frames: &mut [&mut [u8]],
    queries: &[TransactionReplaySnapshotQuery<'a>],
) -> LcsResult<RsiTransactionReplaySnapshotBatchScheduleSummary> {
    let request_summary = summarize_transaction_replay_snapshot_request_table_internal(storage)?;
    if queries.is_empty() {
        return Ok(RsiTransactionReplaySnapshotBatchScheduleSummary {
            planned_queries: 0,
            scheduled_requests: 0,
            request_summary,
            in_flight_after_schedule: in_flight_count,
            stop: RsiTransactionReplaySnapshotBatchScheduleStop::AllScheduled,
        });
    }

    if elapsed_ms_since_reservation_attempt >= limits.request_timeout_ms {
        return Ok(RsiTransactionReplaySnapshotBatchScheduleSummary {
            planned_queries: queries.len(),
            scheduled_requests: 0,
            request_summary,
            in_flight_after_schedule: in_flight_count,
            stop: RsiTransactionReplaySnapshotBatchScheduleStop::TimeoutBeforeDispatchNoRequest,
        });
    }

    let remaining_timeout_ms = limits.request_timeout_ms - elapsed_ms_since_reservation_attempt;
    if in_flight_count >= limits.max_concurrent_rsi_requests {
        return Ok(RsiTransactionReplaySnapshotBatchScheduleSummary {
            planned_queries: queries.len(),
            scheduled_requests: 0,
            request_summary,
            in_flight_after_schedule: in_flight_count,
            stop: RsiTransactionReplaySnapshotBatchScheduleStop::WaitForSlot {
                remaining_timeout_ms,
            },
        });
    }

    let available_slots = limits.max_concurrent_rsi_requests - in_flight_count;
    let schedule_count = queries.len().min(available_slots);
    prevalidate_transaction_replay_snapshot_batch_schedule(
        counter.next_request_id(),
        storage,
        frames,
        queries,
        schedule_count,
        request_summary,
    )?;

    let mut in_flight_after_schedule = in_flight_count;
    for (index, query) in queries[..schedule_count].iter().copied().enumerate() {
        let plan = reserve_and_schedule_transaction_replay_snapshot_query_request(
            limits,
            counter,
            in_flight_after_schedule,
            elapsed_ms_since_reservation_attempt,
            storage,
            &mut *frames[index],
            query,
        )?;
        let RsiTransactionReplaySnapshotReservationPlan::DispatchNow {
            in_flight_after_dispatch,
            ..
        } = plan
        else {
            return Err(LcsError::InvalidTransactionRuntimeState);
        };
        in_flight_after_schedule = in_flight_after_dispatch;
    }

    let request_summary = summarize_transaction_replay_snapshot_request_table_internal(storage)?;
    let stop = if schedule_count == queries.len() {
        RsiTransactionReplaySnapshotBatchScheduleStop::AllScheduled
    } else {
        RsiTransactionReplaySnapshotBatchScheduleStop::WaitForSlot {
            remaining_timeout_ms,
        }
    };

    Ok(RsiTransactionReplaySnapshotBatchScheduleSummary {
        planned_queries: queries.len(),
        scheduled_requests: schedule_count,
        request_summary,
        in_flight_after_schedule,
        stop,
    })
}

/// Finds one retained replay snapshot request record by request ID.
pub fn find_transaction_replay_snapshot_request_record<'a>(
    storage: &[Option<RsiTransactionReplaySnapshotRequestRecord<'a>>],
    request_id: RsiRequestId,
) -> LcsResult<RsiTransactionReplaySnapshotRequestRecord<'a>> {
    storage
        .iter()
        .flatten()
        .find(|record| record.request_id == request_id)
        .copied()
        .ok_or(LcsError::TransactionReplaySnapshotRequestNotFound { request_id })
}

/// Removes one retained replay snapshot request record by request ID.
pub fn release_transaction_replay_snapshot_request_record<'a>(
    storage: &mut [Option<RsiTransactionReplaySnapshotRequestRecord<'a>>],
    request_id: RsiRequestId,
) -> LcsResult<RsiTransactionReplaySnapshotRequestRecord<'a>> {
    for slot in storage {
        if slot
            .as_ref()
            .is_some_and(|record| record.request_id == request_id)
        {
            return slot
                .take()
                .ok_or(LcsError::TransactionReplaySnapshotRequestNotFound { request_id });
        }
    }
    Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id })
}

/// Matches a response frame to a retained replay snapshot request without releasing it.
pub fn match_transaction_replay_snapshot_response_record<'a>(
    storage: &[Option<RsiTransactionReplaySnapshotRequestRecord<'a>>],
    frame: &[u8],
) -> LcsResult<RsiTransactionReplaySnapshotResponseMatch<'a>> {
    summarize_transaction_replay_snapshot_request_table_internal(storage)?;
    validate_frame_len(frame, RSI_MIN_RESPONSE_LEN)?;
    let header = parse_rsi_response_header(frame)?;
    let record = find_transaction_replay_snapshot_request_record(storage, header.request_id)?;
    let response = validate_rsi_response_for_request(frame, record.retained)?;
    Ok(RsiTransactionReplaySnapshotResponseMatch { record, response })
}

/// Parses a matched successful replay snapshot response into its query-specific payload.
pub fn parse_transaction_replay_snapshot_response_payload<'q, 'f>(
    matched: RsiTransactionReplaySnapshotResponseMatch<'q>,
    frame: &'f [u8],
) -> LcsResult<RsiTransactionReplaySnapshotParsedResponse<'q, 'f>> {
    match matched.record.query.kind {
        TransactionReplaySnapshotQueryKind::EffectiveValue { .. } => {
            let payload =
                parse_rsi_query_values_success_response_payload(frame, matched.record.retained)?;
            Ok(RsiTransactionReplaySnapshotParsedResponse::EffectiveValue {
                record: matched.record,
                payload,
            })
        }
        TransactionReplaySnapshotQueryKind::EffectiveSubkeys { .. } => {
            let payload =
                parse_rsi_enum_children_success_response_payload(frame, matched.record.retained)?;
            Ok(
                RsiTransactionReplaySnapshotParsedResponse::EffectiveSubkeys {
                    record: matched.record,
                    payload,
                },
            )
        }
        TransactionReplaySnapshotQueryKind::ChildVisibility { .. } => {
            let payload =
                parse_rsi_lookup_success_response_payload(frame, matched.record.retained)?;
            Ok(
                RsiTransactionReplaySnapshotParsedResponse::ChildVisibility {
                    record: matched.record,
                    payload,
                },
            )
        }
    }
}

/// Materializes a parsed replay snapshot response into a retained snapshot result.
pub fn materialize_transaction_replay_snapshot_response<'q, 'f, 'out>(
    context: &LayerResolutionContext<'out>,
    parsed: RsiTransactionReplaySnapshotParsedResponse<'q, 'f>,
    value_entry_storage: &'out mut [NamedValueEntry<'out>],
    blanket_storage: &'out mut [BlanketTombstoneEntry<'out>],
    path_storage: &'out mut [NamedPathEntry<'out>],
    value_result_storage: &'out mut [EnumeratedValue<'out>],
    subkey_result_storage: &'out mut [EnumeratedSubkey<'out>],
) -> LcsResult<RsiTransactionReplaySnapshotMaterializedResponse<'out>>
where
    'q: 'out,
    'f: 'out,
{
    match parsed {
        RsiTransactionReplaySnapshotParsedResponse::EffectiveValue { record, payload } => {
            let TransactionReplaySnapshotQueryKind::EffectiveValue { key_guid, scope } =
                record.query.kind
            else {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "replay_snapshot.query_kind",
                });
            };
            let max_effective_values = checked_snapshot_count(payload.entry_count)?;
            require_replay_snapshot_storage(
                "query_values.effective_values",
                max_effective_values,
                value_result_storage.len(),
            )?;
            let mut emitted = 0usize;
            let summary = for_each_rsi_query_values_effective_snapshot_entry(
                context,
                &payload,
                value_entry_storage,
                blanket_storage,
                |entry| {
                    value_result_storage[emitted] = entry;
                    emitted += 1;
                    Ok(())
                },
            )?;
            let result = TransactionReplaySnapshotResult {
                phase: record.query.phase,
                operation_index: record.query.operation_index,
                kind: TransactionReplaySnapshotResultKind::EffectiveValue {
                    key_guid,
                    scope,
                    values: &value_result_storage[..emitted],
                },
            };
            Ok(
                RsiTransactionReplaySnapshotMaterializedResponse::EffectiveValue {
                    result,
                    summary,
                },
            )
        }
        RsiTransactionReplaySnapshotParsedResponse::EffectiveSubkeys { record, payload } => {
            let TransactionReplaySnapshotQueryKind::EffectiveSubkeys { parent_guid } =
                record.query.kind
            else {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "replay_snapshot.query_kind",
                });
            };
            let max_effective_subkeys = checked_snapshot_count(payload.child_count)?;
            require_replay_snapshot_storage(
                "enum_children.effective_subkeys",
                max_effective_subkeys,
                subkey_result_storage.len(),
            )?;
            let mut emitted = 0usize;
            let summary = for_each_rsi_enum_children_effective_subkey_snapshot_entry(
                context,
                &payload,
                path_storage,
                |entry| {
                    subkey_result_storage[emitted] = entry;
                    emitted += 1;
                    Ok(())
                },
            )?;
            let result = TransactionReplaySnapshotResult {
                phase: record.query.phase,
                operation_index: record.query.operation_index,
                kind: TransactionReplaySnapshotResultKind::EffectiveSubkeys {
                    parent_guid,
                    children: &subkey_result_storage[..emitted],
                },
            };
            Ok(
                RsiTransactionReplaySnapshotMaterializedResponse::EffectiveSubkeys {
                    result,
                    summary,
                },
            )
        }
        RsiTransactionReplaySnapshotParsedResponse::ChildVisibility { record, payload } => {
            let TransactionReplaySnapshotQueryKind::ChildVisibility {
                parent_guid,
                child_name,
            } = record.query.kind
            else {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "replay_snapshot.query_kind",
                });
            };
            let summary = resolve_rsi_lookup_child_visibility_snapshot(
                context,
                &payload,
                child_name,
                path_storage,
            )?;
            let result = TransactionReplaySnapshotResult {
                phase: record.query.phase,
                operation_index: record.query.operation_index,
                kind: TransactionReplaySnapshotResultKind::ChildVisibility {
                    parent_guid,
                    child_name,
                    child: summary.resolved,
                },
            };
            Ok(
                RsiTransactionReplaySnapshotMaterializedResponse::ChildVisibility {
                    result,
                    summary,
                },
            )
        }
    }
}

/// Processes one matched successful replay snapshot response and releases it.
pub fn process_transaction_replay_snapshot_success_response<'q, 'f, 'out>(
    request_storage: &mut [Option<RsiTransactionReplaySnapshotRequestRecord<'q>>],
    result_storage: &mut [Option<TransactionReplaySnapshotResult<'out>>],
    frame: &'f [u8],
    context: &LayerResolutionContext<'out>,
    value_entry_storage: &'out mut [NamedValueEntry<'out>],
    blanket_storage: &'out mut [BlanketTombstoneEntry<'out>],
    path_storage: &'out mut [NamedPathEntry<'out>],
    value_result_storage: &'out mut [EnumeratedValue<'out>],
    subkey_result_storage: &'out mut [EnumeratedSubkey<'out>],
) -> LcsResult<RsiTransactionReplaySnapshotStoredResponse<'q, 'out>>
where
    'q: 'out,
    'f: 'out,
{
    let matched = match_transaction_replay_snapshot_response_record(request_storage, frame)?;
    let request_id = matched.record.request_id;
    let response = matched.response;
    let parsed = parse_transaction_replay_snapshot_response_payload(matched, frame)?;
    let materialized = materialize_transaction_replay_snapshot_response(
        context,
        parsed,
        value_entry_storage,
        blanket_storage,
        path_storage,
        value_result_storage,
        subkey_result_storage,
    )?;
    let result = match materialized {
        RsiTransactionReplaySnapshotMaterializedResponse::EffectiveValue { result, .. }
        | RsiTransactionReplaySnapshotMaterializedResponse::EffectiveSubkeys { result, .. }
        | RsiTransactionReplaySnapshotMaterializedResponse::ChildVisibility { result, .. } => {
            result
        }
    };
    let result_summary = insert_transaction_replay_snapshot_result(result_storage, result)?;
    let released_record =
        release_transaction_replay_snapshot_request_record(request_storage, request_id)?;

    Ok(RsiTransactionReplaySnapshotStoredResponse {
        response,
        released_record,
        materialized,
        result_summary,
    })
}

/// Processes one matched replay snapshot source-error response and releases it.
pub fn process_transaction_replay_snapshot_source_error_response<'a>(
    request_storage: &mut [Option<RsiTransactionReplaySnapshotRequestRecord<'a>>],
    frame: &[u8],
) -> LcsResult<RsiTransactionReplaySnapshotSourceErrorResponse<'a>> {
    let matched = match_transaction_replay_snapshot_response_record(request_storage, frame)?;
    let request_id = matched.record.request_id;
    let response = matched.response;
    if frame.len() != RSI_MIN_RESPONSE_LEN {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: matched.record.retained.op_code,
            extra_len: frame.len() - RSI_MIN_RESPONSE_LEN,
        });
    }
    let source_errno = match map_rsi_status(response.status) {
        RsiStatusOutcome::Success => {
            return Err(LcsError::RsiResponseRequiresPayloadParser(
                matched.record.retained.op_code,
            ));
        }
        RsiStatusOutcome::Failure(source_errno) => source_errno,
    };
    let released_record =
        release_transaction_replay_snapshot_request_record(request_storage, request_id)?;

    Ok(RsiTransactionReplaySnapshotSourceErrorResponse {
        response,
        released_record,
        source_errno,
    })
}

/// Writes an RSI request frame for a transaction replay snapshot query.
pub fn write_transaction_replay_snapshot_query_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    query: TransactionReplaySnapshotQuery<'_>,
) -> LcsResult<RsiBuiltRequest> {
    const COMMITTED_STATE_TXN_ID: u64 = 0;

    match query.kind {
        TransactionReplaySnapshotQueryKind::EffectiveValue { key_guid, scope } => match scope {
            TransactionReplayValueWatchScope::NamedValue { name } => {
                write_rsi_query_values_request_frame(
                    dst,
                    request_id,
                    COMMITTED_STATE_TXN_ID,
                    key_guid,
                    name.as_bytes(),
                    false,
                )
            }
            TransactionReplayValueWatchScope::AllValues => write_rsi_query_values_request_frame(
                dst,
                request_id,
                COMMITTED_STATE_TXN_ID,
                key_guid,
                b"",
                true,
            ),
        },
        TransactionReplaySnapshotQueryKind::EffectiveSubkeys { parent_guid } => {
            write_rsi_enum_children_request_frame(
                dst,
                request_id,
                COMMITTED_STATE_TXN_ID,
                parent_guid,
            )
        }
        TransactionReplaySnapshotQueryKind::ChildVisibility {
            parent_guid,
            child_name,
        } => write_rsi_lookup_request_frame(
            dst,
            request_id,
            COMMITTED_STATE_TXN_ID,
            parent_guid,
            child_name.as_bytes(),
        ),
    }
}

/// Computes the complete request-frame length for one replay snapshot query.
pub fn transaction_replay_snapshot_query_request_frame_len(
    query: TransactionReplaySnapshotQuery<'_>,
) -> LcsResult<usize> {
    let payload_len = match query.kind {
        TransactionReplaySnapshotQueryKind::EffectiveValue { scope, .. } => {
            let value_name = match scope {
                TransactionReplayValueWatchScope::NamedValue { name } => name.as_bytes(),
                TransactionReplayValueWatchScope::AllValues => b"",
            };
            checked_add_len(
                checked_add_len(16, checked_rsi_length_prefixed_len(value_name)?)?,
                1,
            )?
        }
        TransactionReplaySnapshotQueryKind::EffectiveSubkeys { .. } => 16,
        TransactionReplaySnapshotQueryKind::ChildVisibility { child_name, .. } => {
            checked_add_len(16, checked_rsi_length_prefixed_len(child_name.as_bytes())?)?
        }
    };

    checked_rsi_request_frame_len(payload_len)
}

fn prevalidate_transaction_replay_snapshot_batch_schedule(
    next_request_id: RsiRequestId,
    storage: &[Option<RsiTransactionReplaySnapshotRequestRecord<'_>>],
    frames: &[&mut [u8]],
    queries: &[TransactionReplaySnapshotQuery<'_>],
    schedule_count: usize,
    request_summary: RsiTransactionReplaySnapshotRequestTableSummary,
) -> LcsResult<()> {
    let free_request_slots = request_summary.capacity - request_summary.entries;
    if schedule_count > free_request_slots {
        return Err(LcsError::TransactionReplaySnapshotRequestTableFull {
            capacity: request_summary.capacity,
        });
    }
    if frames.len() < schedule_count {
        return Err(LcsError::TransactionReplaySnapshotStorageFull {
            field: "transaction_replay_snapshot_request_frames",
            required: schedule_count,
            capacity: frames.len(),
        });
    }

    let mut request_id = next_request_id;
    for (index, query) in queries[..schedule_count].iter().copied().enumerate() {
        if request_id == u64::MAX {
            return Err(LcsError::RsiRequestIdOverflow);
        }
        if storage
            .iter()
            .flatten()
            .any(|existing| existing.request_id == request_id)
        {
            return Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id });
        }

        let required_frame_len = transaction_replay_snapshot_query_request_frame_len(query)?;
        if frames[index].len() < required_frame_len {
            return Err(LcsError::RsiFrameBufferTooSmall {
                len: frames[index].len(),
                required: required_frame_len,
            });
        }

        request_id = request_id
            .checked_add(1)
            .ok_or(LcsError::RsiRequestIdOverflow)?;
    }

    Ok(())
}

fn transaction_replay_snapshot_query_op_code(query: TransactionReplaySnapshotQueryKind<'_>) -> u16 {
    match query {
        TransactionReplaySnapshotQueryKind::EffectiveValue { .. } => RSI_QUERY_VALUES,
        TransactionReplaySnapshotQueryKind::EffectiveSubkeys { .. } => RSI_ENUM_CHILDREN,
        TransactionReplaySnapshotQueryKind::ChildVisibility { .. } => RSI_LOOKUP,
    }
}

fn summarize_transaction_replay_snapshot_request_table_internal(
    storage: &[Option<RsiTransactionReplaySnapshotRequestRecord<'_>>],
) -> LcsResult<RsiTransactionReplaySnapshotRequestTableSummary> {
    let mut entries = 0usize;
    for (index, record) in storage.iter().enumerate() {
        if let Some(record) = record {
            entries += 1;
            if storage[..index]
                .iter()
                .flatten()
                .any(|previous| previous.request_id == record.request_id)
            {
                return Err(LcsError::DuplicateTransactionReplaySnapshotRequest {
                    request_id: record.request_id,
                });
            }
        }
    }
    Ok(RsiTransactionReplaySnapshotRequestTableSummary {
        entries,
        capacity: storage.len(),
        full: entries == storage.len(),
    })
}

/// Writes a complete RSI_DELETE_VALUE_ENTRY request frame.
pub fn write_rsi_delete_value_entry_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    guid: Guid,
    value_name: &[u8],
    layer_name: &[u8],
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_add_len(
        checked_add_len(16, checked_rsi_length_prefixed_len(value_name)?)?,
        checked_rsi_length_prefixed_len(layer_name)?,
    )?;
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_DELETE_VALUE_ENTRY,
        txn_id,
        payload_len,
        |writer| {
            writer.write_guid(guid)?;
            writer.write_length_prefixed(value_name)?;
            writer.write_length_prefixed(layer_name)
        },
    )
}

/// Writes a complete RSI_SET_BLANKET_TOMBSTONE request frame.
pub fn write_rsi_set_blanket_tombstone_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    guid: Guid,
    layer_name: &[u8],
    set: bool,
    sequence: u64,
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_add_len(
        checked_add_len(16, checked_rsi_length_prefixed_len(layer_name)?)?,
        9,
    )?;
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_SET_BLANKET_TOMBSTONE,
        txn_id,
        payload_len,
        |writer| {
            writer.write_guid(guid)?;
            writer.write_length_prefixed(layer_name)?;
            writer.write_u8(u8::from(set))?;
            writer.write_u64_le(sequence)
        },
    )
}

/// Writes a planned blanket tombstone mutation to a complete RSI request frame.
pub fn write_planned_rsi_set_blanket_tombstone_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    planned: &PlannedBlanketTombstone<'_>,
) -> LcsResult<RsiBuiltRequest> {
    let (set, sequence) = match planned.blanket.action {
        BlanketTombstoneAction::Set { sequence } => (true, sequence),
        BlanketTombstoneAction::Remove => (false, 0),
    };

    write_rsi_set_blanket_tombstone_request_frame(
        dst,
        request_id,
        txn_id,
        planned.blanket.key_guid,
        planned.blanket.layer.as_bytes(),
        set,
        sequence,
    )
}

/// Writes a complete RSI_BEGIN_TRANSACTION request frame.
pub fn write_rsi_begin_transaction_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    transaction_id: u64,
    mode: RsiTransactionMode,
) -> LcsResult<RsiBuiltRequest> {
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_BEGIN_TRANSACTION,
        txn_id,
        12,
        |writer| {
            writer.write_u64_le(transaction_id)?;
            writer.write_u32_le(mode.code())
        },
    )
}

/// Writes a complete RSI_COMMIT_TRANSACTION request frame.
pub fn write_rsi_commit_transaction_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    transaction_id: u64,
) -> LcsResult<RsiBuiltRequest> {
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_COMMIT_TRANSACTION,
        txn_id,
        8,
        |writer| writer.write_u64_le(transaction_id),
    )
}

/// Writes a complete RSI_ABORT_TRANSACTION request frame.
pub fn write_rsi_abort_transaction_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    transaction_id: u64,
) -> LcsResult<RsiBuiltRequest> {
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_ABORT_TRANSACTION,
        txn_id,
        8,
        |writer| writer.write_u64_le(transaction_id),
    )
}

/// Writes a complete RSI_DELETE_LAYER request frame.
pub fn write_rsi_delete_layer_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    layer_name: &[u8],
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_rsi_length_prefixed_len(layer_name)?;
    write_rsi_request_frame(
        dst,
        request_id,
        RSI_DELETE_LAYER,
        txn_id,
        payload_len,
        |writer| writer.write_length_prefixed(layer_name),
    )
}

/// Writes a complete RSI_FLUSH request frame.
pub fn write_rsi_flush_request_frame(
    dst: &mut [u8],
    request_id: RsiRequestId,
    txn_id: u64,
    hive_name: &[u8],
) -> LcsResult<RsiBuiltRequest> {
    let payload_len = checked_rsi_length_prefixed_len(hive_name)?;
    write_rsi_request_frame(dst, request_id, RSI_FLUSH, txn_id, payload_len, |writer| {
        writer.write_length_prefixed(hive_name)
    })
}

fn write_rsi_request_frame<F>(
    dst: &mut [u8],
    request_id: RsiRequestId,
    op_code: u16,
    txn_id: u64,
    payload_len: usize,
    write_payload: F,
) -> LcsResult<RsiBuiltRequest>
where
    F: FnOnce(&mut RsiFrameWriter<'_>) -> LcsResult<()>,
{
    let total_len = checked_rsi_request_frame_len(payload_len)?;
    if dst.len() < total_len {
        return Err(LcsError::RsiFrameBufferTooSmall {
            len: dst.len(),
            required: total_len,
        });
    }

    let mut writer = RsiFrameWriter::new(dst);
    writer.write_u32_le(total_len as u32)?;
    writer.write_u64_le(request_id)?;
    writer.write_u16_le(op_code)?;
    writer.write_u64_le(txn_id)?;
    write_payload(&mut writer)?;
    let len = writer.finish();
    if len != total_len {
        return Err(LcsError::RsiMessageLengthMismatch {
            total_len: total_len as u32,
            actual_len: len,
        });
    }

    Ok(RsiBuiltRequest {
        len,
        retained: RsiRetainedRequest {
            request_id,
            op_code,
        },
    })
}

fn checked_rsi_request_frame_len(payload_len: usize) -> LcsResult<usize> {
    let total_len = checked_add_len(RSI_REQUEST_HEADER_LEN, payload_len)?;
    if total_len > u32::MAX as usize {
        return Err(LcsError::RsiPayloadLengthOverflow);
    }
    Ok(total_len)
}

fn checked_rsi_length_prefixed_len(bytes: &[u8]) -> LcsResult<usize> {
    checked_rsi_field_len_u32(bytes)?;
    checked_add_len(4, bytes.len())
}

fn checked_rsi_field_len_u32(bytes: &[u8]) -> LcsResult<u32> {
    if bytes.len() > u32::MAX as usize {
        return Err(LcsError::RsiPayloadLengthOverflow);
    }
    Ok(bytes.len() as u32)
}

fn checked_add_len(left: usize, right: usize) -> LcsResult<usize> {
    left.checked_add(right)
        .ok_or(LcsError::RsiPayloadLengthOverflow)
}

/// Defined RSI source response status vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RsiStatus {
    Ok = RSI_OK,
    NotFound = RSI_NOT_FOUND,
    AlreadyExists = RSI_ALREADY_EXISTS,
    StorageError = RSI_STORAGE_ERROR,
    NotEmpty = RSI_NOT_EMPTY,
    TooLarge = RSI_TOO_LARGE,
    TxnBusy = RSI_TXN_BUSY,
    Invalid = RSI_INVALID,
    CasFailed = RSI_CAS_FAILED,
    TxnNotSupported = RSI_TXN_NOT_SUPPORTED,
}

impl RsiStatus {
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            RSI_OK => Some(Self::Ok),
            RSI_NOT_FOUND => Some(Self::NotFound),
            RSI_ALREADY_EXISTS => Some(Self::AlreadyExists),
            RSI_STORAGE_ERROR => Some(Self::StorageError),
            RSI_NOT_EMPTY => Some(Self::NotEmpty),
            RSI_TOO_LARGE => Some(Self::TooLarge),
            RSI_TXN_BUSY => Some(Self::TxnBusy),
            RSI_INVALID => Some(Self::Invalid),
            RSI_CAS_FAILED => Some(Self::CasFailed),
            RSI_TXN_NOT_SUPPORTED => Some(Self::TxnNotSupported),
            _ => None,
        }
    }

    pub fn code(self) -> u32 {
        self as u32
    }
}

/// Kernel-facing errno category selected for a source status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiMappedErrno {
    Enoent,
    Eexist,
    Eio,
    Enotempty,
    Enospc,
    Ebusy,
    Einval,
    Eagain,
    Enotsup,
    Etimedout,
    Exdev,
}

/// Result of classifying a source status code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiStatusOutcome {
    Success,
    Failure(RsiMappedErrno),
}

/// Caller-visible operation that attempted to bind an explicit source transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiTransactionBeginUse {
    ReadWriteFirstBind,
    ReadOnlyBackupSnapshot,
    ReadWriteRestore,
}

/// Source transaction-begin status handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiTransactionBeginStatusPlan {
    Begun,
    NotSupported {
        use_case: RsiTransactionBeginUse,
        mapped_errno: RsiMappedErrno,
    },
    Failed(RsiMappedErrno),
}

/// Source response content validation failure after protocol framing succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsiSourceDataValidationFailure {
    MalformedSecurityDescriptor,
    MalformedLayerName,
    FutureSequenceNumber,
    DuplicateWinningSequenceTie,
    MalformedLayerMetadataSecurityDescriptor,
}

/// Failure policy for malformed but structurally parsed source response data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsiMalformedSourceDataPlan {
    pub failure: RsiSourceDataValidationFailure,
    pub caller_errno: RsiMappedErrno,
    pub emit_audit: bool,
    pub keep_source_alive: bool,
    pub retain_previous_layer_metadata_sd: bool,
}

/// Parses an RSI status code from a source response.
pub fn parse_rsi_status(code: u32) -> LcsResult<RsiStatus> {
    RsiStatus::from_code(code).ok_or(LcsError::UnknownRsiStatus(code))
}

/// Maps a parsed RSI status to the PSD-005 errno category.
pub fn map_rsi_status(status: RsiStatus) -> RsiStatusOutcome {
    match status {
        RsiStatus::Ok => RsiStatusOutcome::Success,
        RsiStatus::NotFound => RsiStatusOutcome::Failure(RsiMappedErrno::Enoent),
        RsiStatus::AlreadyExists => RsiStatusOutcome::Failure(RsiMappedErrno::Eexist),
        RsiStatus::StorageError => RsiStatusOutcome::Failure(RsiMappedErrno::Eio),
        RsiStatus::NotEmpty => RsiStatusOutcome::Failure(RsiMappedErrno::Enotempty),
        RsiStatus::TooLarge => RsiStatusOutcome::Failure(RsiMappedErrno::Enospc),
        RsiStatus::TxnBusy => RsiStatusOutcome::Failure(RsiMappedErrno::Ebusy),
        RsiStatus::Invalid => RsiStatusOutcome::Failure(RsiMappedErrno::Einval),
        RsiStatus::CasFailed => RsiStatusOutcome::Failure(RsiMappedErrno::Eagain),
        RsiStatus::TxnNotSupported => RsiStatusOutcome::Failure(RsiMappedErrno::Enotsup),
    }
}

/// Parses and maps an RSI status code in one step.
pub fn classify_rsi_status_code(code: u32) -> LcsResult<RsiStatusOutcome> {
    Ok(map_rsi_status(parse_rsi_status(code)?))
}

/// Maps RSI_BEGIN_TRANSACTION source status at the user-visible binding point.
pub fn plan_rsi_transaction_begin_status(
    use_case: RsiTransactionBeginUse,
    status: RsiStatus,
) -> RsiTransactionBeginStatusPlan {
    match status {
        RsiStatus::Ok => RsiTransactionBeginStatusPlan::Begun,
        RsiStatus::TxnNotSupported => RsiTransactionBeginStatusPlan::NotSupported {
            use_case,
            mapped_errno: RsiMappedErrno::Enotsup,
        },
        other => match map_rsi_status(other) {
            RsiStatusOutcome::Success => RsiTransactionBeginStatusPlan::Begun,
            RsiStatusOutcome::Failure(errno) => RsiTransactionBeginStatusPlan::Failed(errno),
        },
    }
}

/// Plans the mandatory policy for malformed source data.
pub fn plan_rsi_malformed_source_data(
    failure: RsiSourceDataValidationFailure,
) -> RsiMalformedSourceDataPlan {
    RsiMalformedSourceDataPlan {
        failure,
        caller_errno: RsiMappedErrno::Eio,
        emit_audit: true,
        keep_source_alive: true,
        retain_previous_layer_metadata_sd: matches!(
            failure,
            RsiSourceDataValidationFailure::MalformedLayerMetadataSecurityDescriptor
        ),
    }
}

/// Plans fail-closed watch recovery after committed replay snapshots fail.
pub fn plan_transaction_replay_snapshot_failure_recovery(
    failure: TransactionReplaySnapshotFailureKind,
) -> TransactionReplaySnapshotFailureRecoveryPlan {
    let (source_policy, request_disposition, source_errno, malformed_data_plan) = match failure {
        TransactionReplaySnapshotFailureKind::SourceError { source_errno } => (
            TransactionReplaySnapshotRecoverySourcePolicy::KeepSourceAlive,
            TransactionReplaySnapshotRecoveryRequestDisposition::ReleaseFailedRequestRecord,
            Some(source_errno),
            None,
        ),
        TransactionReplaySnapshotFailureKind::TimeoutBeforeDispatch => (
            TransactionReplaySnapshotRecoverySourcePolicy::KeepSourceAlive,
            TransactionReplaySnapshotRecoveryRequestDisposition::NoRequestSent,
            None,
            None,
        ),
        TransactionReplaySnapshotFailureKind::TimeoutAfterDispatch { request_id } => (
            TransactionReplaySnapshotRecoverySourcePolicy::KeepSourceAlive,
            TransactionReplaySnapshotRecoveryRequestDisposition::RetainTimedOutInFlightRequest {
                request_id,
            },
            None,
            None,
        ),
        TransactionReplaySnapshotFailureKind::MalformedData { failure } => (
            TransactionReplaySnapshotRecoverySourcePolicy::KeepSourceAlive,
            TransactionReplaySnapshotRecoveryRequestDisposition::ReleaseFailedRequestRecord,
            None,
            Some(plan_rsi_malformed_source_data(failure)),
        ),
        TransactionReplaySnapshotFailureKind::MalformedProtocol => (
            TransactionReplaySnapshotRecoverySourcePolicy::TearDownAndMarkSourceDown,
            TransactionReplaySnapshotRecoveryRequestDisposition::ReleaseInFlightTableOnSourceTeardown,
            None,
            None,
        ),
        TransactionReplaySnapshotFailureKind::SourceConnectionTornDown => (
            TransactionReplaySnapshotRecoverySourcePolicy::SourceAlreadyTornDown,
            TransactionReplaySnapshotRecoveryRequestDisposition::ReleaseInFlightTableOnSourceTeardown,
            None,
            None,
        ),
    };

    TransactionReplaySnapshotFailureRecoveryPlan {
        commit_remains_successful: true,
        caller_errno: None,
        emit_normal_watch_events: false,
        queue_overflow_for_affected_watches: true,
        release_transaction_replay_state: true,
        late_response_must_not_resurrect_normal_events: true,
        source_errno,
        malformed_data_plan,
        source_policy,
        request_disposition,
    }
}

/// Parses the RSI_LOOKUP request payload layout.
pub fn parse_rsi_lookup_request_payload(payload: &[u8]) -> LcsResult<RsiLookupRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let parent_guid = cursor.read_guid()?;
    let child_name = cursor.read_length_prefixed()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiLookupRequestPayload {
        parent_guid,
        child_name,
        trailing,
    })
}

/// Parses the RSI_CREATE_ENTRY request payload layout.
pub fn parse_rsi_create_entry_request_payload(
    payload: &[u8],
) -> LcsResult<RsiCreateEntryRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let parent_guid = cursor.read_guid()?;
    let child_name = cursor.read_length_prefixed()?;
    let layer_name = cursor.read_length_prefixed()?;
    let child_guid = cursor.read_guid()?;
    let sequence = cursor.read_u64_le()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiCreateEntryRequestPayload {
        parent_guid,
        child_name,
        layer_name,
        child_guid,
        sequence,
        trailing,
    })
}

/// Parses the RSI_HIDE_ENTRY request payload layout.
pub fn parse_rsi_hide_entry_request_payload(
    payload: &[u8],
) -> LcsResult<RsiHideEntryRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let parent_guid = cursor.read_guid()?;
    let child_name = cursor.read_length_prefixed()?;
    let layer_name = cursor.read_length_prefixed()?;
    let sequence = cursor.read_u64_le()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiHideEntryRequestPayload {
        parent_guid,
        child_name,
        layer_name,
        sequence,
        trailing,
    })
}

/// Parses the RSI_DELETE_ENTRY request payload layout.
pub fn parse_rsi_delete_entry_request_payload(
    payload: &[u8],
) -> LcsResult<RsiDeleteEntryRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let parent_guid = cursor.read_guid()?;
    let child_name = cursor.read_length_prefixed()?;
    let layer_name = cursor.read_length_prefixed()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiDeleteEntryRequestPayload {
        parent_guid,
        child_name,
        layer_name,
        trailing,
    })
}

/// Parses the RSI_ENUM_CHILDREN request payload layout.
pub fn parse_rsi_enum_children_request_payload(
    payload: &[u8],
) -> LcsResult<RsiEnumChildrenRequestPayload> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let parent_guid = cursor.read_guid()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiEnumChildrenRequestPayload {
        parent_guid,
        trailing,
    })
}

/// Parses the RSI_CREATE_KEY request payload layout.
pub fn parse_rsi_create_key_request_payload(
    payload: &[u8],
) -> LcsResult<RsiCreateKeyRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let guid = cursor.read_guid()?;
    let name = cursor.read_length_prefixed()?;
    let parent_guid = cursor.read_guid()?;
    let sd = cursor.read_length_prefixed()?;
    let volatile = cursor.read_bool("rsi_create_key.volatile")?;
    let symlink = cursor.read_bool("rsi_create_key.symlink")?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiCreateKeyRequestPayload {
        guid,
        name,
        parent_guid,
        sd,
        volatile,
        symlink,
        trailing,
    })
}

/// Parses the RSI_READ_KEY request payload layout.
pub fn parse_rsi_read_key_request_payload(payload: &[u8]) -> LcsResult<RsiReadKeyRequestPayload> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let guid = cursor.read_guid()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiReadKeyRequestPayload { guid, trailing })
}

/// Parses the RSI_WRITE_KEY request payload layout.
pub fn parse_rsi_write_key_request_payload(
    payload: &[u8],
) -> LcsResult<RsiWriteKeyRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let guid = cursor.read_guid()?;
    let field_mask = cursor.read_u32_le()?;
    validate_rsi_write_key_field_mask(field_mask)?;

    let sd = if (field_mask & RSI_WRITE_KEY_FIELD_SD) != 0 {
        Some(cursor.read_length_prefixed()?)
    } else {
        None
    };
    let last_write_time = if (field_mask & RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME) != 0 {
        Some(cursor.read_u64_le()?)
    } else {
        None
    };
    let trailing = cursor.finish_allowing_trailing_optional_fields();

    Ok(RsiWriteKeyRequestPayload {
        guid,
        field_mask,
        sd,
        last_write_time,
        trailing,
    })
}

/// Parses the RSI_DROP_KEY request payload layout.
pub fn parse_rsi_drop_key_request_payload(payload: &[u8]) -> LcsResult<RsiDropKeyRequestPayload> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let guid = cursor.read_guid()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiDropKeyRequestPayload { guid, trailing })
}

/// Validates the defined RSI_WRITE_KEY mutable-field bitmask vocabulary.
pub fn validate_rsi_write_key_field_mask(field_mask: u32) -> LcsResult<u32> {
    let unknown = field_mask & !RSI_WRITE_KEY_FIELD_KNOWN_MASK;
    if unknown != 0 {
        return Err(LcsError::UnknownRsiWriteKeyFieldMask {
            field_mask,
            unknown,
        });
    }
    Ok(field_mask)
}

/// Parses the RSI_QUERY_VALUES request payload layout.
pub fn parse_rsi_query_values_request_payload(
    payload: &[u8],
) -> LcsResult<RsiQueryValuesRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let guid = cursor.read_guid()?;
    let value_name = cursor.read_length_prefixed()?;
    let query_all = cursor.read_bool("rsi_query_values.query_all")?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiQueryValuesRequestPayload {
        guid,
        value_name,
        query_all,
        trailing,
    })
}

/// Parses the RSI_SET_VALUE request payload layout.
pub fn parse_rsi_set_value_request_payload(
    payload: &[u8],
) -> LcsResult<RsiSetValueRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let guid = cursor.read_guid()?;
    let value_name = cursor.read_length_prefixed()?;
    let layer_name = cursor.read_length_prefixed()?;
    let value_type = cursor.read_u32_le()?;
    let data = cursor.read_length_prefixed()?;
    let sequence = cursor.read_u64_le()?;
    let expected_sequence = cursor.read_u64_le()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiSetValueRequestPayload {
        guid,
        value_name,
        layer_name,
        value_type,
        data,
        sequence,
        expected_sequence,
        trailing,
    })
}

/// Parses the RSI_DELETE_VALUE_ENTRY request payload layout.
pub fn parse_rsi_delete_value_entry_request_payload(
    payload: &[u8],
) -> LcsResult<RsiDeleteValueEntryRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let guid = cursor.read_guid()?;
    let value_name = cursor.read_length_prefixed()?;
    let layer_name = cursor.read_length_prefixed()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiDeleteValueEntryRequestPayload {
        guid,
        value_name,
        layer_name,
        trailing,
    })
}

/// Parses the RSI_SET_BLANKET_TOMBSTONE request payload layout.
pub fn parse_rsi_set_blanket_tombstone_request_payload(
    payload: &[u8],
) -> LcsResult<RsiSetBlanketTombstoneRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let guid = cursor.read_guid()?;
    let layer_name = cursor.read_length_prefixed()?;
    let set = cursor.read_bool("rsi_set_blanket_tombstone.set")?;
    let sequence = cursor.read_u64_le()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiSetBlanketTombstoneRequestPayload {
        guid,
        layer_name,
        set,
        sequence,
        trailing,
    })
}

/// Parses the RSI_BEGIN_TRANSACTION request payload layout.
pub fn parse_rsi_begin_transaction_request_payload(
    payload: &[u8],
) -> LcsResult<RsiBeginTransactionRequestPayload> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let transaction_id = cursor.read_u64_le()?;
    let mode_code = cursor.read_u32_le()?;
    let mode = RsiTransactionMode::from_code(mode_code)
        .ok_or(LcsError::UnknownRsiTransactionMode(mode_code))?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiBeginTransactionRequestPayload {
        transaction_id,
        mode,
        trailing,
    })
}

/// Parses the RSI_COMMIT_TRANSACTION request payload layout.
pub fn parse_rsi_commit_transaction_request_payload(
    payload: &[u8],
) -> LcsResult<RsiCommitTransactionRequestPayload> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let transaction_id = cursor.read_u64_le()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiCommitTransactionRequestPayload {
        transaction_id,
        trailing,
    })
}

/// Parses the RSI_ABORT_TRANSACTION request payload layout.
pub fn parse_rsi_abort_transaction_request_payload(
    payload: &[u8],
) -> LcsResult<RsiAbortTransactionRequestPayload> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let transaction_id = cursor.read_u64_le()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiAbortTransactionRequestPayload {
        transaction_id,
        trailing,
    })
}

/// Parses the RSI_DELETE_LAYER request payload layout.
pub fn parse_rsi_delete_layer_request_payload(
    payload: &[u8],
) -> LcsResult<RsiDeleteLayerRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let layer_name = cursor.read_length_prefixed()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiDeleteLayerRequestPayload {
        layer_name,
        trailing,
    })
}

/// Parses the RSI_FLUSH request payload layout.
pub fn parse_rsi_flush_request_payload(payload: &[u8]) -> LcsResult<RsiFlushRequestPayload<'_>> {
    let mut cursor = RsiPayloadCursor::new(payload);
    let hive_name = cursor.read_length_prefixed()?;
    let trailing = cursor.finish_allowing_trailing_optional_fields();
    Ok(RsiFlushRequestPayload {
        hive_name,
        trailing,
    })
}

/// Validates that an op code is one of PSD-005's request op codes.
pub fn validate_rsi_request_op_code(op_code: u16) -> LcsResult<u16> {
    match op_code {
        RSI_LOOKUP
        | RSI_CREATE_ENTRY
        | RSI_HIDE_ENTRY
        | RSI_DELETE_ENTRY
        | RSI_ENUM_CHILDREN
        | RSI_CREATE_KEY
        | RSI_READ_KEY
        | RSI_WRITE_KEY
        | RSI_DROP_KEY
        | RSI_QUERY_VALUES
        | RSI_SET_VALUE
        | RSI_DELETE_VALUE_ENTRY
        | RSI_SET_BLANKET_TOMBSTONE
        | RSI_BEGIN_TRANSACTION
        | RSI_COMMIT_TRANSACTION
        | RSI_ABORT_TRANSACTION
        | RSI_FLUSH
        | RSI_DELETE_LAYER => Ok(op_code),
        _ => Err(LcsError::UnknownRsiOpcode(op_code)),
    }
}

/// Computes the response op code for a validated request op code.
pub fn rsi_response_op_code(request_op_code: u16) -> LcsResult<u16> {
    Ok(validate_rsi_request_op_code(request_op_code)? | RSI_RESPONSE_BIT)
}

/// Parses and validates the fixed request header from a complete RSI frame.
pub fn parse_rsi_request_header(frame: &[u8]) -> LcsResult<RsiRequestHeader> {
    validate_frame_len(frame, RSI_REQUEST_HEADER_LEN)?;
    let header = RsiRequestHeader {
        total_len: read_u32_le(frame, 0),
        request_id: read_u64_le(frame, 4),
        op_code: read_u16_le(frame, 12),
        txn_id: read_u64_le(frame, 14),
    };
    validate_rsi_request_op_code(header.op_code)?;
    Ok(header)
}

/// Parses the fixed response header from a complete RSI frame.
pub fn parse_rsi_response_header(frame: &[u8]) -> LcsResult<RsiResponseHeader> {
    validate_frame_len(frame, RSI_RESPONSE_HEADER_LEN)?;
    Ok(RsiResponseHeader {
        total_len: read_u32_le(frame, 0),
        request_id: read_u64_le(frame, 4),
        op_code: read_u16_le(frame, 12),
    })
}

/// Validates a response against the retained request record it claims to answer.
pub fn validate_rsi_response_for_request(
    frame: &[u8],
    retained: RsiRetainedRequest,
) -> LcsResult<RsiValidatedResponse> {
    validate_frame_len(frame, RSI_MIN_RESPONSE_LEN)?;
    let header = parse_rsi_response_header(frame)?;
    if header.request_id != retained.request_id {
        return Err(LcsError::RsiRequestIdMismatch {
            expected: retained.request_id,
            actual: header.request_id,
        });
    }

    let expected_op = rsi_response_op_code(retained.op_code)?;
    if header.op_code != expected_op {
        return Err(LcsError::RsiResponseOpcodeMismatch {
            expected: expected_op,
            actual: header.op_code,
        });
    }

    let status = parse_rsi_status(read_u32_le(frame, RSI_RESPONSE_HEADER_LEN))?;
    Ok(RsiValidatedResponse { header, status })
}

/// Reports whether a request op's successful response has only a status field.
pub fn rsi_request_has_status_only_response(op_code: u16) -> LcsResult<bool> {
    match validate_rsi_request_op_code(op_code)? {
        RSI_CREATE_ENTRY
        | RSI_HIDE_ENTRY
        | RSI_DELETE_ENTRY
        | RSI_CREATE_KEY
        | RSI_WRITE_KEY
        | RSI_DROP_KEY
        | RSI_SET_VALUE
        | RSI_DELETE_VALUE_ENTRY
        | RSI_SET_BLANKET_TOMBSTONE
        | RSI_BEGIN_TRANSACTION
        | RSI_COMMIT_TRANSACTION
        | RSI_ABORT_TRANSACTION
        | RSI_FLUSH => Ok(true),
        RSI_LOOKUP | RSI_ENUM_CHILDREN | RSI_READ_KEY | RSI_QUERY_VALUES | RSI_DELETE_LAYER => {
            Ok(false)
        }
        _ => unreachable!("validate_rsi_request_op_code accepted an unknown RSI opcode"),
    }
}

/// Validates a response for operations whose response payload is exactly status.
pub fn validate_rsi_status_only_response_for_request(
    frame: &[u8],
    retained: RsiRetainedRequest,
) -> LcsResult<RsiValidatedResponse> {
    if !rsi_request_has_status_only_response(retained.op_code)? {
        return Err(LcsError::RsiResponseRequiresPayloadParser(retained.op_code));
    }

    let response = validate_rsi_response_for_request(frame, retained)?;
    if frame.len() != RSI_MIN_RESPONSE_LEN {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: retained.op_code,
            extra_len: frame.len() - RSI_MIN_RESPONSE_LEN,
        });
    }
    Ok(response)
}

/// Parses the successful RSI_READ_KEY response payload.
pub fn parse_rsi_read_key_success_response_payload<'a>(
    frame: &'a [u8],
    retained: RsiRetainedRequest,
) -> LcsResult<RsiReadKeySuccessResponsePayload<'a>> {
    let response = validate_rsi_success_response_for_request(frame, retained, RSI_READ_KEY)?;
    let mut cursor = RsiPayloadCursor::new(&frame[RSI_MIN_RESPONSE_LEN..]);
    let name = cursor.read_length_prefixed()?;
    let parent_guid = cursor.read_guid()?;
    let sd = cursor.read_length_prefixed()?;
    let volatile = cursor.read_bool("read_key.volatile")?;
    let symlink = cursor.read_bool("read_key.symlink")?;
    let last_write_time = cursor.read_u64_le()?;
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: retained.op_code,
            extra_len: cursor.remaining_len(),
        });
    }

    Ok(RsiReadKeySuccessResponsePayload {
        response,
        name,
        parent_guid,
        sd,
        volatile,
        symlink,
        last_write_time,
    })
}

/// Parses the successful RSI_DELETE_LAYER response payload.
pub fn parse_rsi_delete_layer_success_response_payload<'a>(
    frame: &'a [u8],
    retained: RsiRetainedRequest,
) -> LcsResult<RsiDeleteLayerSuccessResponsePayload<'a>> {
    let response = validate_rsi_success_response_for_request(frame, retained, RSI_DELETE_LAYER)?;
    let mut cursor = RsiPayloadCursor::new(&frame[RSI_MIN_RESPONSE_LEN..]);
    let count = cursor.read_u32_le()?;
    let guid_bytes_len = (count as usize)
        .checked_mul(16)
        .ok_or(LcsError::RsiPayloadLengthOverflow)?;
    let bytes = cursor.read_fixed(guid_bytes_len)?;
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: retained.op_code,
            extra_len: cursor.remaining_len(),
        });
    }

    Ok(RsiDeleteLayerSuccessResponsePayload {
        response,
        orphaned_guids: RsiGuidArray { count, bytes },
    })
}

/// Parses the successful RSI_QUERY_VALUES response payload.
pub fn parse_rsi_query_values_success_response_payload<'a>(
    frame: &'a [u8],
    retained: RsiRetainedRequest,
) -> LcsResult<RsiQueryValuesSuccessResponsePayload<'a>> {
    let response = validate_rsi_success_response_for_request(frame, retained, RSI_QUERY_VALUES)?;
    let mut cursor = RsiPayloadCursor::new(&frame[RSI_MIN_RESPONSE_LEN..]);
    let entry_count = cursor.read_u32_le()?;
    let entries_start = cursor.position();
    skip_rsi_query_value_entries(&mut cursor, entry_count)?;
    let entries_end = cursor.position();
    let blanket_count = cursor.read_u32_le()?;
    let blanket_start = cursor.position();
    skip_rsi_query_values_blankets(&mut cursor, blanket_count)?;
    let blanket_end = cursor.position();
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: retained.op_code,
            extra_len: cursor.remaining_len(),
        });
    }

    let payload = &frame[RSI_MIN_RESPONSE_LEN..];
    Ok(RsiQueryValuesSuccessResponsePayload {
        response,
        entry_count,
        entries_bytes: &payload[entries_start..entries_end],
        blanket_count,
        blanket_bytes: &payload[blanket_start..blanket_end],
    })
}

/// Parses the successful RSI_LOOKUP response payload.
pub fn parse_rsi_lookup_success_response_payload<'a>(
    frame: &'a [u8],
    retained: RsiRetainedRequest,
) -> LcsResult<RsiLookupSuccessResponsePayload<'a>> {
    let response = validate_rsi_success_response_for_request(frame, retained, RSI_LOOKUP)?;
    let mut cursor = RsiPayloadCursor::new(&frame[RSI_MIN_RESPONSE_LEN..]);
    let entry_count = cursor.read_u32_le()?;
    let entries_start = cursor.position();
    skip_rsi_lookup_path_entries(&mut cursor, entry_count)?;
    let entries_end = cursor.position();
    let metadata_count = cursor.read_u32_le()?;
    let metadata_start = cursor.position();
    skip_rsi_key_metadata_entries(&mut cursor, metadata_count)?;
    let metadata_end = cursor.position();
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: retained.op_code,
            extra_len: cursor.remaining_len(),
        });
    }

    let payload = &frame[RSI_MIN_RESPONSE_LEN..];
    Ok(RsiLookupSuccessResponsePayload {
        response,
        entry_count,
        entries_bytes: &payload[entries_start..entries_end],
        metadata_count,
        metadata_bytes: &payload[metadata_start..metadata_end],
    })
}

/// Parses the successful RSI_ENUM_CHILDREN response payload.
pub fn parse_rsi_enum_children_success_response_payload<'a>(
    frame: &'a [u8],
    retained: RsiRetainedRequest,
) -> LcsResult<RsiEnumChildrenSuccessResponsePayload<'a>> {
    let response = validate_rsi_success_response_for_request(frame, retained, RSI_ENUM_CHILDREN)?;
    let mut cursor = RsiPayloadCursor::new(&frame[RSI_MIN_RESPONSE_LEN..]);
    let child_count = cursor.read_u32_le()?;
    let children_start = cursor.position();
    skip_rsi_enum_children_entries(&mut cursor, child_count)?;
    let children_end = cursor.position();
    let metadata_count = cursor.read_u32_le()?;
    let metadata_start = cursor.position();
    skip_rsi_key_metadata_entries(&mut cursor, metadata_count)?;
    let metadata_end = cursor.position();
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: retained.op_code,
            extra_len: cursor.remaining_len(),
        });
    }

    let payload = &frame[RSI_MIN_RESPONSE_LEN..];
    Ok(RsiEnumChildrenSuccessResponsePayload {
        response,
        child_count,
        children_bytes: &payload[children_start..children_end],
        metadata_count,
        metadata_bytes: &payload[metadata_start..metadata_end],
    })
}

/// Validates lookup response metadata against returned GUID path targets.
pub fn validate_rsi_lookup_metadata_completeness(
    payload: &RsiLookupSuccessResponsePayload<'_>,
) -> LcsResult<()> {
    payload.for_each_path_entry(|entry| {
        if entry.target_type == RsiPathTargetType::Guid
            && !lookup_metadata_contains_guid(payload, entry.target_guid)?
        {
            return Err(LcsError::RsiPathMetadataMissing {
                guid: entry.target_guid,
            });
        }
        Ok(())
    })?;

    payload.for_each_key_metadata(|metadata| {
        validate_rsi_path_metadata_guid(metadata.guid)?;
        if lookup_metadata_guid_count(payload, metadata.guid)? > 1 {
            return Err(LcsError::RsiPathMetadataDuplicate {
                guid: metadata.guid,
            });
        }
        if !lookup_path_references_guid(payload, metadata.guid)? {
            return Err(LcsError::RsiPathMetadataUnreferenced {
                guid: metadata.guid,
            });
        }
        Ok(())
    })
}

/// Validates enum-children response metadata against returned GUID path targets.
pub fn validate_rsi_enum_children_metadata_completeness(
    payload: &RsiEnumChildrenSuccessResponsePayload<'_>,
) -> LcsResult<()> {
    payload.for_each_child(|child| {
        child.for_each_path_entry(|entry| {
            if entry.target_type == RsiPathTargetType::Guid
                && !enum_children_metadata_contains_guid(payload, entry.target_guid)?
            {
                return Err(LcsError::RsiPathMetadataMissing {
                    guid: entry.target_guid,
                });
            }
            Ok(())
        })
    })?;

    payload.for_each_key_metadata(|metadata| {
        validate_rsi_path_metadata_guid(metadata.guid)?;
        if enum_children_metadata_guid_count(payload, metadata.guid)? > 1 {
            return Err(LcsError::RsiPathMetadataDuplicate {
                guid: metadata.guid,
            });
        }
        if !enum_children_path_references_guid(payload, metadata.guid)? {
            return Err(LcsError::RsiPathMetadataUnreferenced {
                guid: metadata.guid,
            });
        }
        Ok(())
    })
}

/// Validates lookup response string fields before path resolution.
pub fn validate_rsi_lookup_path_response_names(
    payload: &RsiLookupSuccessResponsePayload<'_>,
    limits: &LcsLimits,
) -> LcsResult<()> {
    payload.for_each_path_entry(|entry| {
        validate_layer_name_bytes(entry.layer_name.data, limits)?;
        Ok(())
    })
}

/// Validates enum-children response string fields before enumeration resolution.
pub fn validate_rsi_enum_children_path_response_names(
    payload: &RsiEnumChildrenSuccessResponsePayload<'_>,
    limits: &LcsLimits,
) -> LcsResult<()> {
    payload.for_each_child(|child| {
        validate_key_component_bytes(child.child_name.data, limits)?;
        child.for_each_path_entry(|entry| {
            validate_layer_name_bytes(entry.layer_name.data, limits)?;
            Ok(())
        })
    })
}

/// Validates read-key response string fields before key metadata use.
pub fn validate_rsi_read_key_response_names(
    payload: &RsiReadKeySuccessResponsePayload<'_>,
    limits: &LcsLimits,
) -> LcsResult<()> {
    validate_key_component_bytes(payload.name.data, limits)?;
    Ok(())
}

/// Validates the read-key response SD before AccessCheck use.
pub fn validate_rsi_read_key_response_security_descriptor(
    payload: &RsiReadKeySuccessResponsePayload<'_>,
) -> LcsResult<()> {
    validate_rsi_source_security_descriptor(payload.sd.data, "rsi_read_key.sd")
}

/// Validates lookup metadata SDs before path resolution uses them.
pub fn validate_rsi_lookup_metadata_security_descriptors(
    payload: &RsiLookupSuccessResponsePayload<'_>,
) -> LcsResult<()> {
    payload.for_each_key_metadata(|metadata| {
        validate_rsi_source_security_descriptor(metadata.sd.data, "rsi_lookup.metadata.sd")
    })
}

/// Validates enum-children metadata SDs before enumeration uses them.
pub fn validate_rsi_enum_children_metadata_security_descriptors(
    payload: &RsiEnumChildrenSuccessResponsePayload<'_>,
) -> LcsResult<()> {
    payload.for_each_key_metadata(|metadata| {
        validate_rsi_source_security_descriptor(metadata.sd.data, "rsi_enum_children.metadata.sd")
    })
}

/// Validates delete-layer orphan GUIDs before orphan tracking consumes them.
pub fn validate_rsi_delete_layer_orphaned_guids(
    payload: &RsiDeleteLayerSuccessResponsePayload<'_>,
) -> LcsResult<()> {
    for index in 0..payload.orphaned_guids.count {
        let guid = payload
            .orphaned_guids
            .guid_at(index)
            .ok_or(LcsError::RsiPayloadLengthOverflow)?;
        if guid == [0; 16] {
            return Err(LcsError::RsiDeleteLayerOrphanedGuidNil);
        }

        for previous_index in 0..index {
            if payload.orphaned_guids.guid_at(previous_index) == Some(guid) {
                return Err(LcsError::RsiDeleteLayerOrphanedGuidDuplicate { guid });
            }
        }
    }
    Ok(())
}

/// Validates lookup response path-entry sequence numbers before resolution.
pub fn validate_rsi_lookup_path_response_sequences(
    payload: &RsiLookupSuccessResponsePayload<'_>,
    next_sequence: u64,
) -> LcsResult<()> {
    payload.for_each_path_entry(|entry| validate_rsi_source_sequence(entry.sequence, next_sequence))
}

/// Validates enum-children response path-entry sequence numbers before enumeration resolution.
pub fn validate_rsi_enum_children_path_response_sequences(
    payload: &RsiEnumChildrenSuccessResponsePayload<'_>,
    next_sequence: u64,
) -> LcsResult<()> {
    payload.for_each_child(|child| {
        child.for_each_path_entry(|entry| {
            validate_rsi_source_sequence(entry.sequence, next_sequence)
        })
    })
}

/// Validates query-values response value and blanket sequence numbers before resolution.
pub fn validate_rsi_query_values_response_sequences(
    payload: &RsiQueryValuesSuccessResponsePayload<'_>,
    next_sequence: u64,
) -> LcsResult<()> {
    payload.for_each_value_entry(|entry| {
        validate_rsi_source_sequence(entry.sequence, next_sequence)
    })?;
    payload
        .for_each_blanket_entry(|entry| validate_rsi_source_sequence(entry.sequence, next_sequence))
}

/// Validates query-values response string fields before value resolution.
pub fn validate_rsi_query_values_response_names(
    payload: &RsiQueryValuesSuccessResponsePayload<'_>,
    limits: &LcsLimits,
) -> LcsResult<()> {
    payload.for_each_value_entry(|entry| {
        validate_value_name_bytes(entry.value_name.data, limits)?;
        validate_layer_name_bytes(entry.layer_name.data, limits)?;
        Ok(())
    })?;

    payload.for_each_blanket_entry(|entry| {
        validate_layer_name_bytes(entry.layer_name.data, limits)?;
        Ok(())
    })
}

/// Validates query-values response value type/data fields before resolution.
pub fn validate_rsi_query_values_response_value_payloads(
    payload: &RsiQueryValuesSuccessResponsePayload<'_>,
    limits: &LcsLimits,
) -> LcsResult<()> {
    payload.for_each_value_entry(|entry| {
        validate_value_data_len(entry.data.data.len(), limits)?;
        validate_value_write_type(
            entry.value_type,
            entry.data.data.len(),
            entry.value_type == REG_TOMBSTONE,
        )?;
        Ok(())
    })
}

/// Projects successful RSI_QUERY_VALUES value entries into resolution inputs.
pub fn for_each_rsi_query_values_source_value_entry<'a, F>(
    payload: &RsiQueryValuesSuccessResponsePayload<'a>,
    limits: &LcsLimits,
    mut visitor: F,
) -> LcsResult<usize>
where
    F: FnMut(NamedValueEntry<'a>) -> LcsResult<()>,
{
    let mut emitted = 0usize;
    payload.for_each_value_entry(|entry| {
        let name = validate_value_name_bytes(entry.value_name.data, limits)?;
        let layer = validate_layer_name_bytes(entry.layer_name.data, limits)?;
        validate_value_data_len(entry.data.data.len(), limits)?;
        validate_value_write_type(
            entry.value_type,
            entry.data.data.len(),
            entry.value_type == REG_TOMBSTONE,
        )?;
        visitor(NamedValueEntry {
            name,
            entry: ValueEntry {
                layer,
                sequence: entry.sequence,
                value_type: entry.value_type,
                data: entry.data.data,
            },
        })?;
        emitted += 1;
        Ok(())
    })?;
    Ok(emitted)
}

/// Projects successful RSI_QUERY_VALUES blanket tombstones into resolution inputs.
pub fn for_each_rsi_query_values_source_blanket_entry<'a, F>(
    payload: &RsiQueryValuesSuccessResponsePayload<'a>,
    limits: &LcsLimits,
    mut visitor: F,
) -> LcsResult<usize>
where
    F: FnMut(BlanketTombstoneEntry<'a>) -> LcsResult<()>,
{
    let mut emitted = 0usize;
    payload.for_each_blanket_entry(|entry| {
        let layer = validate_layer_name_bytes(entry.layer_name.data, limits)?;
        visitor(BlanketTombstoneEntry {
            layer,
            sequence: entry.sequence,
        })?;
        emitted += 1;
        Ok(())
    })?;
    Ok(emitted)
}

/// Projects successful RSI_LOOKUP path entries into resolution inputs.
pub fn for_each_rsi_lookup_source_path_entry<'a, F>(
    payload: &RsiLookupSuccessResponsePayload<'a>,
    limits: &LcsLimits,
    child_name: &'a str,
    mut visitor: F,
) -> LcsResult<usize>
where
    F: FnMut(NamedPathEntry<'a>) -> LcsResult<()>,
{
    let child_name = validate_key_component_bytes(child_name.as_bytes(), limits)?;
    let mut emitted = 0usize;
    payload.for_each_path_entry(|entry| {
        let layer = validate_layer_name_bytes(entry.layer_name.data, limits)?;
        visitor(NamedPathEntry {
            child_name,
            entry: PathEntry {
                layer,
                sequence: entry.sequence,
                target: rsi_path_target_to_resolution(entry),
            },
        })?;
        emitted += 1;
        Ok(())
    })?;
    Ok(emitted)
}

/// Projects successful RSI_ENUM_CHILDREN path entries into resolution inputs.
pub fn for_each_rsi_enum_children_source_path_entry<'a, F>(
    payload: &RsiEnumChildrenSuccessResponsePayload<'a>,
    limits: &LcsLimits,
    mut visitor: F,
) -> LcsResult<usize>
where
    F: FnMut(NamedPathEntry<'a>) -> LcsResult<()>,
{
    let mut emitted = 0usize;
    payload.for_each_child(|child| {
        let child_name = validate_key_component_bytes(child.child_name.data, limits)?;
        child.for_each_path_entry(|entry| {
            let layer = validate_layer_name_bytes(entry.layer_name.data, limits)?;
            visitor(NamedPathEntry {
                child_name,
                entry: PathEntry {
                    layer,
                    sequence: entry.sequence,
                    target: rsi_path_target_to_resolution(entry),
                },
            })?;
            emitted += 1;
            Ok(())
        })
    })?;
    Ok(emitted)
}

/// Resolves an RSI_QUERY_VALUES response into effective value snapshot entries.
pub fn for_each_rsi_query_values_effective_snapshot_entry<'a, F>(
    context: &LayerResolutionContext<'a>,
    payload: &RsiQueryValuesSuccessResponsePayload<'a>,
    value_storage: &'a mut [NamedValueEntry<'a>],
    blanket_storage: &'a mut [BlanketTombstoneEntry<'a>],
    emit: F,
) -> LcsResult<RsiEffectiveValueSnapshotProjectionSummary>
where
    F: FnMut(EnumeratedValue<'a>) -> LcsResult<()>,
{
    let required_values = checked_snapshot_count(payload.entry_count)?;
    require_replay_snapshot_storage(
        "query_values.value_entries",
        required_values,
        value_storage.len(),
    )?;
    let required_blankets = checked_snapshot_count(payload.blanket_count)?;
    require_replay_snapshot_storage(
        "query_values.blanket_entries",
        required_blankets,
        blanket_storage.len(),
    )?;

    let mut value_count = 0usize;
    for_each_rsi_query_values_source_value_entry(payload, context.limits, |entry| {
        value_storage[value_count] = entry;
        value_count += 1;
        Ok(())
    })?;

    let mut blanket_count = 0usize;
    for_each_rsi_query_values_source_blanket_entry(payload, context.limits, |entry| {
        blanket_storage[blanket_count] = entry;
        blanket_count += 1;
        Ok(())
    })?;

    let emitted_values = for_each_effective_value(
        context,
        &value_storage[..value_count],
        &blanket_storage[..blanket_count],
        emit,
    )?;
    Ok(RsiEffectiveValueSnapshotProjectionSummary {
        source_value_entries: value_count,
        source_blanket_entries: blanket_count,
        emitted_values,
        value_capacity: value_storage.len(),
        blanket_capacity: blanket_storage.len(),
    })
}

/// Resolves an RSI_ENUM_CHILDREN response into effective subkey snapshot entries.
pub fn for_each_rsi_enum_children_effective_subkey_snapshot_entry<'a, F>(
    context: &LayerResolutionContext<'a>,
    payload: &RsiEnumChildrenSuccessResponsePayload<'a>,
    path_storage: &'a mut [NamedPathEntry<'a>],
    emit: F,
) -> LcsResult<RsiEffectiveSubkeySnapshotProjectionSummary>
where
    F: FnMut(EnumeratedSubkey<'a>) -> LcsResult<()>,
{
    let required_paths = rsi_enum_children_path_entry_count(payload)?;
    require_replay_snapshot_storage(
        "enum_children.path_entries",
        required_paths,
        path_storage.len(),
    )?;

    let mut path_count = 0usize;
    for_each_rsi_enum_children_source_path_entry(payload, context.limits, |entry| {
        path_storage[path_count] = entry;
        path_count += 1;
        Ok(())
    })?;

    let emitted_subkeys = for_each_visible_subkey(context, &path_storage[..path_count], emit)?;
    Ok(RsiEffectiveSubkeySnapshotProjectionSummary {
        source_path_entries: path_count,
        emitted_subkeys,
        path_capacity: path_storage.len(),
    })
}

/// Resolves an RSI_LOOKUP response into an optional child-visibility snapshot.
pub fn resolve_rsi_lookup_child_visibility_snapshot<'a>(
    context: &LayerResolutionContext<'a>,
    payload: &RsiLookupSuccessResponsePayload<'a>,
    child_name: &'a str,
    path_storage: &'a mut [NamedPathEntry<'a>],
) -> LcsResult<RsiChildVisibilitySnapshotProjection<'a>> {
    let required_paths = checked_snapshot_count(payload.entry_count)?;
    require_replay_snapshot_storage("lookup.path_entries", required_paths, path_storage.len())?;

    let mut path_count = 0usize;
    for_each_rsi_lookup_source_path_entry(payload, context.limits, child_name, |entry| {
        path_storage[path_count] = entry;
        path_count += 1;
        Ok(())
    })?;

    let resolved = match resolve_named_path_entry(context, child_name, &path_storage[..path_count])?
    {
        NamedPathResolution::Found(entry) => Some(entry.path),
        NamedPathResolution::NotFound => None,
    };
    Ok(RsiChildVisibilitySnapshotProjection {
        source_path_entries: path_count,
        path_capacity: path_storage.len(),
        resolved,
    })
}

fn rsi_path_target_to_resolution(entry: RsiLookupPathEntry<'_>) -> PathTarget {
    match entry.target_type {
        RsiPathTargetType::Guid => PathTarget::Guid(entry.target_guid),
        RsiPathTargetType::Hidden => PathTarget::Hidden,
    }
}

fn checked_snapshot_count(count: u32) -> LcsResult<usize> {
    usize::try_from(count).map_err(|_| LcsError::RsiPayloadLengthOverflow)
}

fn require_replay_snapshot_storage(
    field: &'static str,
    required: usize,
    capacity: usize,
) -> LcsResult<()> {
    if required > capacity {
        return Err(LcsError::TransactionReplaySnapshotStorageFull {
            field,
            required,
            capacity,
        });
    }
    Ok(())
}

fn rsi_enum_children_path_entry_count(
    payload: &RsiEnumChildrenSuccessResponsePayload<'_>,
) -> LcsResult<usize> {
    let mut total = 0usize;
    payload.for_each_child(|child| {
        total = total
            .checked_add(checked_snapshot_count(child.path_entry_count)?)
            .ok_or(LcsError::RsiPayloadLengthOverflow)?;
        Ok(())
    })?;
    Ok(total)
}

/// Validates a complete request frame as a source-visible queued request.
pub fn rsi_queued_request_from_frame(frame: &[u8]) -> LcsResult<RsiQueuedRequest<'_>> {
    let header = parse_rsi_request_header(frame)?;
    Ok(RsiQueuedRequest {
        frame,
        retained: RsiRetainedRequest {
            request_id: header.request_id,
            op_code: header.op_code,
        },
    })
}

/// Validates and summarizes fixed-capacity source request queue storage.
pub fn summarize_rsi_request_queue(
    storage: &[Option<RsiQueuedRequest<'_>>],
) -> LcsResult<RsiRequestQueueSummary> {
    let mut entries = 0usize;
    let mut seen_empty = false;

    for (index, slot) in storage.iter().enumerate() {
        match (seen_empty, slot) {
            (false, Some(request)) => {
                validate_rsi_queued_request(*request)?;
                entries += 1;
            }
            (false, None) => seen_empty = true,
            (true, Some(_)) => return Err(LcsError::InvalidRsiRequestQueue { index }),
            (true, None) => {}
        }
    }

    Ok(RsiRequestQueueSummary {
        entries,
        capacity: storage.len(),
        full: entries == storage.len(),
    })
}

/// Appends one complete request frame to a fixed-capacity FIFO source queue.
pub fn insert_rsi_queued_request<'a>(
    storage: &mut [Option<RsiQueuedRequest<'a>>],
    frame: &'a [u8],
) -> LcsResult<RsiRequestQueueSummary> {
    let request = rsi_queued_request_from_frame(frame)?;
    let summary = summarize_rsi_request_queue(storage)?;
    if summary.full {
        return Err(LcsError::RsiRequestQueueFull {
            capacity: storage.len(),
        });
    }

    storage[summary.entries] = Some(request);
    Ok(RsiRequestQueueSummary {
        entries: summary.entries + 1,
        capacity: summary.capacity,
        full: summary.entries + 1 == summary.capacity,
    })
}

/// Copies and consumes one queued request when source read semantics allow it.
pub fn drain_rsi_request_queue_read<'a>(
    storage: &mut [Option<RsiQueuedRequest<'a>>],
    dst: &mut [u8],
    nonblocking: bool,
    fd_closing: bool,
) -> LcsResult<RsiRequestQueueReadDrain<'a>> {
    let summary = summarize_rsi_request_queue(storage)?;
    let next_request = if summary.entries == 0 {
        None
    } else {
        storage[0]
    };
    let read_plan = plan_rsi_source_read(
        next_request.map(|request| request.frame.len()),
        dst.len(),
        nonblocking,
        fd_closing,
    )?;

    match read_plan {
        RsiReadPlan::ReturnOneCompleteRequest { request_len, .. } => {
            let request = next_request.ok_or(LcsError::InvalidRsiRequestQueue { index: 0 })?;
            dst[..request_len].copy_from_slice(request.frame);
            for index in 1..summary.entries {
                storage[index - 1] = storage[index];
            }
            storage[summary.entries - 1] = None;
            Ok(RsiRequestQueueReadDrain::Copied {
                request,
                bytes: request_len,
                summary: RsiRequestQueueSummary {
                    entries: summary.entries - 1,
                    capacity: summary.capacity,
                    full: false,
                },
            })
        }
        RsiReadPlan::WaitForRequestOrClose => Ok(RsiRequestQueueReadDrain::WaitForRequestOrClose),
        RsiReadPlan::ReturnEagain => Ok(RsiRequestQueueReadDrain::ReturnEagain),
        RsiReadPlan::ReturnEmsgsize {
            required_len,
            consume_request,
        } => Ok(RsiRequestQueueReadDrain::ReturnEmsgsize {
            required_len,
            consume_request,
        }),
        RsiReadPlan::WakeForClose => Ok(RsiRequestQueueReadDrain::WakeForClose),
    }
}

/// Plans one message-oriented source-fd read without splitting queued requests.
pub fn plan_rsi_source_read(
    next_queued_request_len: Option<usize>,
    caller_buffer_len: usize,
    nonblocking: bool,
    fd_closing: bool,
) -> LcsResult<RsiReadPlan> {
    let Some(request_len) = next_queued_request_len else {
        if fd_closing {
            return Ok(RsiReadPlan::WakeForClose);
        }
        if nonblocking {
            return Ok(RsiReadPlan::ReturnEagain);
        }
        return Ok(RsiReadPlan::WaitForRequestOrClose);
    };

    if request_len < RSI_REQUEST_HEADER_LEN {
        return Err(LcsError::RsiMessageTooShort {
            len: request_len,
            min: RSI_REQUEST_HEADER_LEN,
        });
    }
    if caller_buffer_len < request_len {
        return Ok(RsiReadPlan::ReturnEmsgsize {
            required_len: request_len,
            consume_request: false,
        });
    }
    Ok(RsiReadPlan::ReturnOneCompleteRequest {
        request_len,
        consume_request: true,
    })
}

/// Plans source-fd poll readiness from live slot and queue state.
pub fn plan_rsi_source_poll(
    queued_request_count: usize,
    source_slot_active: bool,
    fd_closing: bool,
) -> RsiPollPlan {
    if !source_slot_active || fd_closing {
        return RsiPollPlan {
            readable: false,
            writable: false,
            hangup: true,
            error: true,
        };
    }
    RsiPollPlan {
        readable: queued_request_count > 0,
        writable: true,
        hangup: false,
        error: false,
    }
}

/// Plans request dispatch against the per-source in-flight slot limit.
pub fn plan_rsi_slot_reservation(
    limits: &LcsLimits,
    counter: &mut RsiRequestIdCounter,
    in_flight_count: usize,
    elapsed_ms_since_reservation_attempt: u32,
) -> LcsResult<RsiSlotReservationPlan> {
    if elapsed_ms_since_reservation_attempt >= limits.request_timeout_ms {
        return Ok(RsiSlotReservationPlan::TimeoutBeforeDispatchNoRequest);
    }

    let remaining_timeout_ms = limits.request_timeout_ms - elapsed_ms_since_reservation_attempt;
    if in_flight_count >= limits.max_concurrent_rsi_requests {
        return Ok(RsiSlotReservationPlan::WaitForSlot {
            remaining_timeout_ms,
        });
    }

    let request_id = counter.allocate()?;
    Ok(RsiSlotReservationPlan::DispatchNow {
        request_id,
        remaining_timeout_ms,
        in_flight_after_dispatch: in_flight_count + 1,
    })
}

/// Maps pre-dispatch slot reservation timeout outcomes to caller errno.
pub fn rsi_slot_reservation_timeout_errno(
    plan: &RsiSlotReservationPlan,
) -> Option<RsiRequestTimeoutErrno> {
    match plan {
        RsiSlotReservationPlan::TimeoutBeforeDispatchNoRequest => {
            Some(RsiRequestTimeoutErrno::Etimedout)
        }
        RsiSlotReservationPlan::DispatchNow { .. } | RsiSlotReservationPlan::WaitForSlot { .. } => {
            None
        }
    }
}

/// Plans caller wait behavior for a request already dispatched to a source.
pub fn plan_rsi_dispatched_wait(
    request_id: RsiRequestId,
    request_timeout_ms: u32,
    elapsed_ms_since_reservation_attempt: u32,
) -> RsiDispatchedWaitPlan {
    if elapsed_ms_since_reservation_attempt < request_timeout_ms {
        return RsiDispatchedWaitPlan::ContinueWaiting {
            remaining_timeout_ms: request_timeout_ms - elapsed_ms_since_reservation_attempt,
        };
    }
    RsiDispatchedWaitPlan::CallerTimedOutRetainRecord {
        request_id,
        retain_request_record: true,
        remains_in_flight: true,
        completion_may_still_occur: true,
    }
}

/// Maps post-dispatch wait timeout outcomes to caller errno.
pub fn rsi_dispatched_wait_timeout_errno(
    plan: &RsiDispatchedWaitPlan,
) -> Option<RsiRequestTimeoutErrno> {
    match plan {
        RsiDispatchedWaitPlan::CallerTimedOutRetainRecord { .. } => {
            Some(RsiRequestTimeoutErrno::Etimedout)
        }
        RsiDispatchedWaitPlan::ContinueWaiting { .. } => None,
    }
}

/// Plans late-response retained-record disposition before payload validation.
pub fn plan_rsi_late_response_record(
    state: RsiLateResponseRecordState,
) -> RsiLateResponseRecordPlan {
    match state {
        RsiLateResponseRecordState::Retained(request) => {
            RsiLateResponseRecordPlan::ValidateNormally(request)
        }
        RsiLateResponseRecordState::UnknownRequestId => {
            malformed_late_response_plan(RsiMalformedProtocolReason::UnknownRequestId)
        }
        RsiLateResponseRecordState::DuplicateResponse => {
            malformed_late_response_plan(RsiMalformedProtocolReason::DuplicateResponse)
        }
        RsiLateResponseRecordState::ReleasedRequestRecord => {
            malformed_late_response_plan(RsiMalformedProtocolReason::ReleasedRequestRecord)
        }
    }
}

/// Plans side effects for a retained late response after normal response validation.
pub fn plan_rsi_late_response_effects(
    outcome: RsiLateResponseValidationOutcome,
) -> RsiLateResponseEffectPlan {
    match outcome {
        RsiLateResponseValidationOutcome::SourceError(source_errno) => {
            RsiLateResponseEffectPlan::ReleaseRecordNoNormalEffects {
                source_errno: Some(source_errno),
                release_request_record: true,
            }
        }
        RsiLateResponseValidationOutcome::SuccessReadOnly => {
            RsiLateResponseEffectPlan::DiscardValidatedReadOnlyResponse {
                release_request_record: true,
            }
        }
        RsiLateResponseValidationOutcome::SuccessMutating(effects) => {
            RsiLateResponseEffectPlan::ApplyMutatingKernelEffects {
                effects,
                release_request_record: true,
            }
        }
        RsiLateResponseValidationOutcome::MalformedData(failure) => {
            RsiLateResponseEffectPlan::MalformedData {
                plan: plan_rsi_malformed_source_data(failure),
                release_request_record: true,
            }
        }
        RsiLateResponseValidationOutcome::MalformedProtocol => {
            malformed_late_response_effect_plan(RsiLateResponseTearDownReason::MalformedProtocol)
        }
        RsiLateResponseValidationOutcome::MissingOrInvalidKernelMetadata => {
            malformed_late_response_effect_plan(
                RsiLateResponseTearDownReason::MissingOrInvalidKernelMetadata,
            )
        }
    }
}

/// Plans a successful retained late response from the validated request op code.
pub fn plan_rsi_late_success_by_op_code(
    op_code: u16,
    metadata: RsiLateSuccessMetadata,
) -> RsiLateSuccessEffectPlan {
    match op_code {
        RSI_LOOKUP | RSI_ENUM_CHILDREN | RSI_READ_KEY | RSI_QUERY_VALUES => {
            RsiLateSuccessEffectPlan::Effect(plan_rsi_late_response_effects(
                RsiLateResponseValidationOutcome::SuccessReadOnly,
            ))
        }
        RSI_CREATE_ENTRY
        | RSI_HIDE_ENTRY
        | RSI_DELETE_ENTRY
        | RSI_CREATE_KEY
        | RSI_WRITE_KEY
        | RSI_DROP_KEY
        | RSI_SET_VALUE
        | RSI_DELETE_VALUE_ENTRY
        | RSI_SET_BLANKET_TOMBSTONE
        | RSI_DELETE_LAYER => match metadata.mutation_effects {
            Some(effects) => RsiLateSuccessEffectPlan::Effect(plan_rsi_late_response_effects(
                RsiLateResponseValidationOutcome::SuccessMutating(effects),
            )),
            None => RsiLateSuccessEffectPlan::Effect(plan_rsi_late_response_effects(
                RsiLateResponseValidationOutcome::MissingOrInvalidKernelMetadata,
            )),
        },
        RSI_COMMIT_TRANSACTION => match metadata.mutation_effects {
            Some(effects) if effects.transaction_commit_effects.is_some() => {
                RsiLateSuccessEffectPlan::Effect(plan_rsi_late_response_effects(
                    RsiLateResponseValidationOutcome::SuccessMutating(effects),
                ))
            }
            _ => RsiLateSuccessEffectPlan::Effect(plan_rsi_late_response_effects(
                RsiLateResponseValidationOutcome::MissingOrInvalidKernelMetadata,
            )),
        },
        RSI_BEGIN_TRANSACTION => {
            if metadata.txn_id == 0 {
                RsiLateSuccessEffectPlan::Effect(plan_rsi_late_response_effects(
                    RsiLateResponseValidationOutcome::MissingOrInvalidKernelMetadata,
                ))
            } else {
                RsiLateSuccessEffectPlan::EnqueueCleanup {
                    cleanup: RsiLateCleanupPlan {
                        abort_transaction_id: metadata.txn_id,
                        enqueue_abort_transaction: true,
                    },
                    release_request_record: true,
                }
            }
        }
        RSI_ABORT_TRANSACTION | RSI_FLUSH => RsiLateSuccessEffectPlan::Effect(
            RsiLateResponseEffectPlan::ReleaseRecordNoNormalEffects {
                source_errno: None,
                release_request_record: true,
            },
        ),
        _ => RsiLateSuccessEffectPlan::Effect(plan_rsi_late_response_effects(
            RsiLateResponseValidationOutcome::MissingOrInvalidKernelMetadata,
        )),
    }
}

fn malformed_late_response_plan(reason: RsiMalformedProtocolReason) -> RsiLateResponseRecordPlan {
    RsiLateResponseRecordPlan::MalformedProtocolTearDown {
        reason,
        tear_down_source: true,
        mark_source_down: true,
    }
}

fn malformed_late_response_effect_plan(
    reason: RsiLateResponseTearDownReason,
) -> RsiLateResponseEffectPlan {
    RsiLateResponseEffectPlan::MalformedProtocolTearDown {
        reason,
        tear_down_source: true,
        mark_source_down: true,
        release_in_flight_table: true,
    }
}

fn validate_frame_len(frame: &[u8], min_len: usize) -> LcsResult<()> {
    if frame.len() < min_len {
        return Err(LcsError::RsiMessageTooShort {
            len: frame.len(),
            min: min_len,
        });
    }
    let total_len = read_u32_le(frame, 0);
    if total_len as usize != frame.len() {
        return Err(LcsError::RsiMessageLengthMismatch {
            total_len,
            actual_len: frame.len(),
        });
    }
    Ok(())
}

fn validate_rsi_queued_request(request: RsiQueuedRequest<'_>) -> LcsResult<()> {
    let header = parse_rsi_request_header(request.frame)?;
    if header.request_id != request.retained.request_id
        || header.op_code != request.retained.op_code
    {
        return Err(LcsError::RsiQueuedRequestMetadataMismatch {
            header_request_id: header.request_id,
            retained_request_id: request.retained.request_id,
            header_op_code: header.op_code,
            retained_op_code: request.retained.op_code,
        });
    }
    Ok(())
}

fn validate_rsi_success_response_for_request(
    frame: &[u8],
    retained: RsiRetainedRequest,
    expected_op_code: u16,
) -> LcsResult<RsiValidatedResponse> {
    if retained.op_code != expected_op_code {
        return Err(LcsError::RsiResponsePayloadParserMismatch {
            expected: expected_op_code,
            actual: retained.op_code,
        });
    }

    let response = validate_rsi_response_for_request(frame, retained)?;
    if response.status != RsiStatus::Ok {
        return Err(LcsError::RsiResponseStatusNotOk(response.status.code()));
    }
    Ok(response)
}

fn skip_rsi_query_value_entries(cursor: &mut RsiPayloadCursor<'_>, count: u32) -> LcsResult<()> {
    for _ in 0..count {
        cursor.read_length_prefixed()?;
        cursor.read_length_prefixed()?;
        cursor.read_u32_le()?;
        cursor.read_length_prefixed()?;
        cursor.read_u64_le()?;
    }
    Ok(())
}

fn skip_rsi_query_values_blankets(cursor: &mut RsiPayloadCursor<'_>, count: u32) -> LcsResult<()> {
    for _ in 0..count {
        cursor.read_length_prefixed()?;
        cursor.read_u64_le()?;
    }
    Ok(())
}

fn parse_rsi_query_value_entries<'a, F>(
    count: u32,
    bytes: &'a [u8],
    mut visitor: F,
) -> LcsResult<()>
where
    F: FnMut(RsiQueryValueResponseEntry<'a>) -> LcsResult<()>,
{
    let mut cursor = RsiPayloadCursor::new(bytes);
    for _ in 0..count {
        let value_name = cursor.read_length_prefixed()?;
        let layer_name = cursor.read_length_prefixed()?;
        let value_type = cursor.read_u32_le()?;
        let data = cursor.read_length_prefixed()?;
        let sequence = cursor.read_u64_le()?;
        visitor(RsiQueryValueResponseEntry {
            value_name,
            layer_name,
            value_type,
            data,
            sequence,
        })?;
    }
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_QUERY_VALUES,
            extra_len: cursor.remaining_len(),
        });
    }
    Ok(())
}

fn parse_rsi_query_values_blankets<'a, F>(
    count: u32,
    bytes: &'a [u8],
    mut visitor: F,
) -> LcsResult<()>
where
    F: FnMut(RsiQueryValuesBlanketResponseEntry<'a>) -> LcsResult<()>,
{
    let mut cursor = RsiPayloadCursor::new(bytes);
    for _ in 0..count {
        let layer_name = cursor.read_length_prefixed()?;
        let sequence = cursor.read_u64_le()?;
        visitor(RsiQueryValuesBlanketResponseEntry {
            layer_name,
            sequence,
        })?;
    }
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_QUERY_VALUES,
            extra_len: cursor.remaining_len(),
        });
    }
    Ok(())
}

fn skip_rsi_lookup_path_entries(cursor: &mut RsiPayloadCursor<'_>, count: u32) -> LcsResult<()> {
    for _ in 0..count {
        cursor.read_length_prefixed()?;
        let target_type = parse_rsi_path_target_type(cursor.read_u8()?)?;
        let target_guid = cursor.read_guid()?;
        validate_rsi_path_target_guid(target_type, target_guid)?;
        cursor.read_u64_le()?;
    }
    Ok(())
}

fn skip_rsi_key_metadata_entries(cursor: &mut RsiPayloadCursor<'_>, count: u32) -> LcsResult<()> {
    for _ in 0..count {
        cursor.read_guid()?;
        cursor.read_length_prefixed()?;
        cursor.read_bool("key_metadata.volatile")?;
        cursor.read_bool("key_metadata.symlink")?;
        cursor.read_u64_le()?;
    }
    Ok(())
}

fn skip_rsi_enum_children_entries(cursor: &mut RsiPayloadCursor<'_>, count: u32) -> LcsResult<()> {
    for _ in 0..count {
        cursor.read_length_prefixed()?;
        let path_entry_count = cursor.read_u32_le()?;
        skip_rsi_lookup_path_entries(cursor, path_entry_count)?;
    }
    Ok(())
}

fn parse_rsi_lookup_path_entries<'a, F>(
    count: u32,
    bytes: &'a [u8],
    mut visitor: F,
) -> LcsResult<()>
where
    F: FnMut(RsiLookupPathEntry<'a>) -> LcsResult<()>,
{
    let mut cursor = RsiPayloadCursor::new(bytes);
    for _ in 0..count {
        let layer_name = cursor.read_length_prefixed()?;
        let target_type = parse_rsi_path_target_type(cursor.read_u8()?)?;
        let target_guid = cursor.read_guid()?;
        validate_rsi_path_target_guid(target_type, target_guid)?;
        let sequence = cursor.read_u64_le()?;
        visitor(RsiLookupPathEntry {
            layer_name,
            target_type,
            target_guid,
            sequence,
        })?;
    }
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_LOOKUP,
            extra_len: cursor.remaining_len(),
        });
    }
    Ok(())
}

fn parse_rsi_enum_children_entries<'a, F>(
    count: u32,
    bytes: &'a [u8],
    mut visitor: F,
) -> LcsResult<()>
where
    F: FnMut(RsiEnumChildResponseEntry<'a>) -> LcsResult<()>,
{
    let mut cursor = RsiPayloadCursor::new(bytes);
    for _ in 0..count {
        let child_name = cursor.read_length_prefixed()?;
        let path_entry_count = cursor.read_u32_le()?;
        let entries_start = cursor.position();
        skip_rsi_lookup_path_entries(&mut cursor, path_entry_count)?;
        let entries_end = cursor.position();
        visitor(RsiEnumChildResponseEntry {
            child_name,
            path_entry_count,
            path_entries_bytes: &bytes[entries_start..entries_end],
        })?;
    }
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_ENUM_CHILDREN,
            extra_len: cursor.remaining_len(),
        });
    }
    Ok(())
}

fn parse_rsi_key_metadata_entries<'a, F>(
    count: u32,
    bytes: &'a [u8],
    mut visitor: F,
) -> LcsResult<()>
where
    F: FnMut(RsiKeyMetadataResponseEntry<'a>) -> LcsResult<()>,
{
    let mut cursor = RsiPayloadCursor::new(bytes);
    for _ in 0..count {
        let guid = cursor.read_guid()?;
        let sd = cursor.read_length_prefixed()?;
        let volatile = cursor.read_bool("key_metadata.volatile")?;
        let symlink = cursor.read_bool("key_metadata.symlink")?;
        let last_write_time = cursor.read_u64_le()?;
        visitor(RsiKeyMetadataResponseEntry {
            guid,
            sd,
            volatile,
            symlink,
            last_write_time,
        })?;
    }
    if cursor.remaining_len() != 0 {
        return Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_LOOKUP,
            extra_len: cursor.remaining_len(),
        });
    }
    Ok(())
}

fn validate_rsi_path_metadata_guid(guid: Guid) -> LcsResult<()> {
    if guid == [0; 16] {
        return Err(LcsError::RsiPathMetadataNilGuid);
    }
    Ok(())
}

fn validate_rsi_source_security_descriptor(bytes: &[u8], field: &'static str) -> LcsResult<()> {
    let sd = kacs_core::SecurityDescriptor::parse(bytes)
        .map_err(|_| LcsError::MalformedSecurityDescriptor { field })?;
    validate_registry_source_security_descriptor(&sd, field)
}

fn validate_rsi_source_sequence(sequence: u64, next_sequence: u64) -> LcsResult<()> {
    if sequence >= next_sequence {
        return Err(LcsError::FutureSequence {
            sequence,
            next_sequence,
        });
    }
    Ok(())
}

fn lookup_metadata_contains_guid(
    payload: &RsiLookupSuccessResponsePayload<'_>,
    guid: Guid,
) -> LcsResult<bool> {
    let mut found = false;
    payload.for_each_key_metadata(|metadata| {
        if metadata.guid == guid {
            found = true;
        }
        Ok(())
    })?;
    Ok(found)
}

fn lookup_metadata_guid_count(
    payload: &RsiLookupSuccessResponsePayload<'_>,
    guid: Guid,
) -> LcsResult<u32> {
    let mut count = 0u32;
    payload.for_each_key_metadata(|metadata| {
        if metadata.guid == guid {
            count = count.saturating_add(1);
        }
        Ok(())
    })?;
    Ok(count)
}

fn lookup_path_references_guid(
    payload: &RsiLookupSuccessResponsePayload<'_>,
    guid: Guid,
) -> LcsResult<bool> {
    let mut found = false;
    payload.for_each_path_entry(|entry| {
        if entry.target_type == RsiPathTargetType::Guid && entry.target_guid == guid {
            found = true;
        }
        Ok(())
    })?;
    Ok(found)
}

fn enum_children_metadata_contains_guid(
    payload: &RsiEnumChildrenSuccessResponsePayload<'_>,
    guid: Guid,
) -> LcsResult<bool> {
    let mut found = false;
    payload.for_each_key_metadata(|metadata| {
        if metadata.guid == guid {
            found = true;
        }
        Ok(())
    })?;
    Ok(found)
}

fn enum_children_metadata_guid_count(
    payload: &RsiEnumChildrenSuccessResponsePayload<'_>,
    guid: Guid,
) -> LcsResult<u32> {
    let mut count = 0u32;
    payload.for_each_key_metadata(|metadata| {
        if metadata.guid == guid {
            count = count.saturating_add(1);
        }
        Ok(())
    })?;
    Ok(count)
}

fn enum_children_path_references_guid(
    payload: &RsiEnumChildrenSuccessResponsePayload<'_>,
    guid: Guid,
) -> LcsResult<bool> {
    let mut found = false;
    payload.for_each_child(|child| {
        child.for_each_path_entry(|entry| {
            if entry.target_type == RsiPathTargetType::Guid && entry.target_guid == guid {
                found = true;
            }
            Ok(())
        })
    })?;
    Ok(found)
}

fn parse_rsi_path_target_type(code: u8) -> LcsResult<RsiPathTargetType> {
    RsiPathTargetType::from_code(code).ok_or(LcsError::InvalidRsiPathTargetType(code))
}

fn validate_rsi_path_target_guid(target_type: RsiPathTargetType, guid: Guid) -> LcsResult<()> {
    if target_type == RsiPathTargetType::Hidden && guid != [0; 16] {
        return Err(LcsError::RsiHiddenPathTargetGuidNotZero);
    }
    Ok(())
}

fn read_u16_le(frame: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([frame[offset], frame[offset + 1]])
}

fn read_u32_le(frame: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        frame[offset],
        frame[offset + 1],
        frame[offset + 2],
        frame[offset + 3],
    ])
}

fn read_u64_le(frame: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        frame[offset],
        frame[offset + 1],
        frame[offset + 2],
        frame[offset + 3],
        frame[offset + 4],
        frame[offset + 5],
        frame[offset + 6],
        frame[offset + 7],
    ])
}
