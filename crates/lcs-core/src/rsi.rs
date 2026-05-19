use crate::config::LcsLimits;
use crate::constants::{
    RSI_ABORT_TRANSACTION, RSI_ALREADY_EXISTS, RSI_BEGIN_TRANSACTION, RSI_CAS_FAILED,
    RSI_COMMIT_TRANSACTION, RSI_CREATE_ENTRY, RSI_CREATE_KEY, RSI_DELETE_ENTRY, RSI_DELETE_LAYER,
    RSI_DELETE_VALUE_ENTRY, RSI_DROP_KEY, RSI_ENUM_CHILDREN, RSI_FLUSH, RSI_HIDE_ENTRY,
    RSI_INVALID, RSI_LOOKUP, RSI_MIN_RESPONSE_LEN, RSI_NOT_EMPTY, RSI_NOT_FOUND, RSI_OK,
    RSI_QUERY_VALUES, RSI_READ_KEY, RSI_REQUEST_HEADER_LEN, RSI_RESPONSE_BIT,
    RSI_RESPONSE_HEADER_LEN, RSI_SET_BLANKET_TOMBSTONE, RSI_SET_VALUE, RSI_STORAGE_ERROR,
    RSI_TOO_LARGE, RSI_TXN_BUSY, RSI_TXN_NOT_SUPPORTED, RSI_TXN_READ_ONLY, RSI_TXN_READ_WRITE,
    RSI_WRITE_KEY,
};
use crate::error::{LcsError, LcsResult};
use crate::resolution::Guid;

pub type RsiRequestId = u64;

pub const RSI_WRITE_KEY_FIELD_SD: u32 = 0x01;
pub const RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME: u32 = 0x02;
pub const RSI_WRITE_KEY_FIELD_KNOWN_MASK: u32 =
    RSI_WRITE_KEY_FIELD_SD | RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME;

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

fn malformed_late_response_plan(reason: RsiMalformedProtocolReason) -> RsiLateResponseRecordPlan {
    RsiLateResponseRecordPlan::MalformedProtocolTearDown {
        reason,
        tear_down_source: true,
        mark_source_down: true,
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
