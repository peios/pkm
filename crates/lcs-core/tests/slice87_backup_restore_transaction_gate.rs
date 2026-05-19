use lcs_core::{
    RsiMappedErrno, RsiStatus, RsiTransactionBeginStatusPlan, RsiTransactionBeginUse,
    plan_rsi_transaction_begin_status,
};

#[test]
fn restore_requires_read_write_transaction_begin_success() {
    assert_eq!(
        plan_rsi_transaction_begin_status(RsiTransactionBeginUse::ReadWriteRestore, RsiStatus::Ok),
        RsiTransactionBeginStatusPlan::Begun
    );
}

#[test]
fn restore_rejects_sources_without_read_write_transaction_support() {
    assert_eq!(
        plan_rsi_transaction_begin_status(
            RsiTransactionBeginUse::ReadWriteRestore,
            RsiStatus::TxnNotSupported,
        ),
        RsiTransactionBeginStatusPlan::NotSupported {
            use_case: RsiTransactionBeginUse::ReadWriteRestore,
            mapped_errno: RsiMappedErrno::Enotsup,
        }
    );
}

#[test]
fn restore_transaction_begin_preserves_other_source_error_mappings() {
    assert_eq!(
        plan_rsi_transaction_begin_status(
            RsiTransactionBeginUse::ReadWriteRestore,
            RsiStatus::TxnBusy,
        ),
        RsiTransactionBeginStatusPlan::Failed(RsiMappedErrno::Ebusy)
    );
    assert_eq!(
        plan_rsi_transaction_begin_status(
            RsiTransactionBeginUse::ReadWriteRestore,
            RsiStatus::StorageError,
        ),
        RsiTransactionBeginStatusPlan::Failed(RsiMappedErrno::Eio)
    );
}
