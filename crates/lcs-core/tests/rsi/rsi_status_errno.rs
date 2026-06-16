use lcs_core::{
    LcsError, LinuxErrno, RSI_ALREADY_EXISTS, RSI_CAS_FAILED, RSI_INVALID, RSI_NOT_EMPTY,
    RSI_NOT_FOUND, RSI_OK, RSI_STORAGE_ERROR, RSI_TOO_LARGE, RSI_TXN_BUSY, RSI_TXN_NOT_SUPPORTED,
    RsiMappedErrno, RsiStatusOutcome, rsi_status_code_errno, rsi_status_outcome_errno,
};

#[test]
fn rsi_ok_status_projects_to_success_without_errno() {
    assert_eq!(rsi_status_code_errno(RSI_OK), Ok(None));
    assert_eq!(rsi_status_outcome_errno(RsiStatusOutcome::Success), None);
}

#[test]
fn rsi_source_error_statuses_project_to_linux_errnos() {
    let cases = [
        (RSI_NOT_FOUND, LinuxErrno::Enoent),
        (RSI_ALREADY_EXISTS, LinuxErrno::Eexist),
        (RSI_STORAGE_ERROR, LinuxErrno::Eio),
        (RSI_NOT_EMPTY, LinuxErrno::Enotempty),
        (RSI_TOO_LARGE, LinuxErrno::Enospc),
        (RSI_TXN_BUSY, LinuxErrno::Ebusy),
        (RSI_INVALID, LinuxErrno::Einval),
        (RSI_CAS_FAILED, LinuxErrno::Eagain),
        (RSI_TXN_NOT_SUPPORTED, LinuxErrno::Enotsup),
    ];

    for (status, errno) in cases {
        assert_eq!(rsi_status_code_errno(status), Ok(Some(errno)));
    }
}

#[test]
fn rsi_status_outcome_projects_symbolic_failure_to_linux_errno() {
    assert_eq!(
        rsi_status_outcome_errno(RsiStatusOutcome::Failure(RsiMappedErrno::Eio)),
        Some(LinuxErrno::Eio)
    );
    assert_eq!(
        rsi_status_outcome_errno(RsiStatusOutcome::Failure(RsiMappedErrno::Enotsup)),
        Some(LinuxErrno::Enotsup)
    );
}

#[test]
fn unknown_status_code_remains_malformed_source_data() {
    assert_eq!(
        rsi_status_code_errno(10),
        Err(LcsError::UnknownRsiStatus(10))
    );
}
