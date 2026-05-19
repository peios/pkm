use lcs_core::{
    LcsError, RSI_ALREADY_EXISTS, RSI_CAS_FAILED, RSI_INVALID, RSI_NOT_EMPTY, RSI_NOT_FOUND,
    RSI_OK, RSI_STORAGE_ERROR, RSI_TOO_LARGE, RSI_TXN_BUSY, RSI_TXN_NOT_SUPPORTED, RsiMappedErrno,
    RsiStatus, RsiStatusOutcome, classify_rsi_status_code, map_rsi_status, parse_rsi_status,
};

#[test]
fn rsi_status_parser_accepts_defined_vocabulary() {
    let cases = [
        (RSI_OK, RsiStatus::Ok),
        (RSI_NOT_FOUND, RsiStatus::NotFound),
        (RSI_ALREADY_EXISTS, RsiStatus::AlreadyExists),
        (RSI_STORAGE_ERROR, RsiStatus::StorageError),
        (RSI_NOT_EMPTY, RsiStatus::NotEmpty),
        (RSI_TOO_LARGE, RsiStatus::TooLarge),
        (RSI_TXN_BUSY, RsiStatus::TxnBusy),
        (RSI_INVALID, RsiStatus::Invalid),
        (RSI_CAS_FAILED, RsiStatus::CasFailed),
        (RSI_TXN_NOT_SUPPORTED, RsiStatus::TxnNotSupported),
    ];

    for (code, status) in cases {
        assert_eq!(parse_rsi_status(code), Ok(status));
        assert_eq!(status.code(), code);
    }
}

#[test]
fn rsi_status_parser_rejects_unknown_codes() {
    assert_eq!(parse_rsi_status(10), Err(LcsError::UnknownRsiStatus(10)));
    assert_eq!(
        classify_rsi_status_code(u32::MAX),
        Err(LcsError::UnknownRsiStatus(u32::MAX))
    );
}

#[test]
fn rsi_status_mapping_matches_psd_005_errno_table() {
    let cases = [
        (RsiStatus::Ok, RsiStatusOutcome::Success),
        (
            RsiStatus::NotFound,
            RsiStatusOutcome::Failure(RsiMappedErrno::Enoent),
        ),
        (
            RsiStatus::AlreadyExists,
            RsiStatusOutcome::Failure(RsiMappedErrno::Eexist),
        ),
        (
            RsiStatus::StorageError,
            RsiStatusOutcome::Failure(RsiMappedErrno::Eio),
        ),
        (
            RsiStatus::NotEmpty,
            RsiStatusOutcome::Failure(RsiMappedErrno::Enotempty),
        ),
        (
            RsiStatus::TooLarge,
            RsiStatusOutcome::Failure(RsiMappedErrno::Enospc),
        ),
        (
            RsiStatus::TxnBusy,
            RsiStatusOutcome::Failure(RsiMappedErrno::Ebusy),
        ),
        (
            RsiStatus::Invalid,
            RsiStatusOutcome::Failure(RsiMappedErrno::Einval),
        ),
        (
            RsiStatus::CasFailed,
            RsiStatusOutcome::Failure(RsiMappedErrno::Eagain),
        ),
        (
            RsiStatus::TxnNotSupported,
            RsiStatusOutcome::Failure(RsiMappedErrno::Enotsup),
        ),
    ];

    for (status, outcome) in cases {
        assert_eq!(map_rsi_status(status), outcome);
        assert_eq!(classify_rsi_status_code(status.code()), Ok(outcome));
    }
}
