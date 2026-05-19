use crate::constants::{
    RSI_ALREADY_EXISTS, RSI_CAS_FAILED, RSI_INVALID, RSI_NOT_EMPTY, RSI_NOT_FOUND, RSI_OK,
    RSI_STORAGE_ERROR, RSI_TOO_LARGE, RSI_TXN_BUSY, RSI_TXN_NOT_SUPPORTED,
};
use crate::error::{LcsError, LcsResult};

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
