use lcs_core::{LinuxErrno, TransactionUseFailure, transaction_use_failure_linux_errno};

#[test]
fn transaction_use_failures_project_to_linux_errnos() {
    let cases = [
        (TransactionUseFailure::Invalid, LinuxErrno::Einval),
        (TransactionUseFailure::TimedOut, LinuxErrno::Etimedout),
        (TransactionUseFailure::SourceDown, LinuxErrno::Eio),
        (TransactionUseFailure::CrossHive, LinuxErrno::Exdev),
        (TransactionUseFailure::Busy, LinuxErrno::Ebusy),
        (TransactionUseFailure::NotSupported, LinuxErrno::Enotsup),
    ];

    for (failure, errno) in cases {
        assert_eq!(transaction_use_failure_linux_errno(failure), errno);
    }
}
