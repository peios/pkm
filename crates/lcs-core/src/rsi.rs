use crate::config::LcsLimits;
use crate::constants::{
    RSI_ABORT_TRANSACTION, RSI_ALREADY_EXISTS, RSI_BEGIN_TRANSACTION, RSI_CAS_FAILED,
    RSI_COMMIT_TRANSACTION, RSI_CREATE_ENTRY, RSI_CREATE_KEY, RSI_DELETE_ENTRY, RSI_DELETE_LAYER,
    RSI_DELETE_VALUE_ENTRY, RSI_DROP_KEY, RSI_ENUM_CHILDREN, RSI_FLUSH, RSI_HIDE_ENTRY,
    RSI_INVALID, RSI_LOOKUP, RSI_MIN_RESPONSE_LEN, RSI_NOT_EMPTY, RSI_NOT_FOUND, RSI_OK,
    RSI_QUERY_VALUES, RSI_READ_KEY, RSI_REQUEST_HEADER_LEN, RSI_RESPONSE_BIT,
    RSI_RESPONSE_HEADER_LEN, RSI_SET_BLANKET_TOMBSTONE, RSI_SET_VALUE, RSI_STORAGE_ERROR,
    RSI_TOO_LARGE, RSI_TXN_BUSY, RSI_TXN_NOT_SUPPORTED, RSI_WRITE_KEY,
};
use crate::error::{LcsError, LcsResult};

pub type RsiRequestId = u64;

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
