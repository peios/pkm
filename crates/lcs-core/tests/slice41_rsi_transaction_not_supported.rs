use lcs_core::{
    RsiMappedErrno, RsiStatus, RsiTransactionBeginStatusPlan, RsiTransactionBeginUse,
    plan_rsi_transaction_begin_status,
};

#[test]
fn source_transaction_begin_ok_allows_binding_or_backup_to_continue() {
    assert_eq!(
        plan_rsi_transaction_begin_status(
            RsiTransactionBeginUse::ReadWriteFirstBind,
            RsiStatus::Ok
        ),
        RsiTransactionBeginStatusPlan::Begun
    );
    assert_eq!(
        plan_rsi_transaction_begin_status(
            RsiTransactionBeginUse::ReadOnlyBackupSnapshot,
            RsiStatus::Ok
        ),
        RsiTransactionBeginStatusPlan::Begun
    );
}

#[test]
fn read_write_transaction_not_supported_maps_to_enotsup_at_first_bind() {
    assert_eq!(
        plan_rsi_transaction_begin_status(
            RsiTransactionBeginUse::ReadWriteFirstBind,
            RsiStatus::TxnNotSupported
        ),
        RsiTransactionBeginStatusPlan::NotSupported {
            use_case: RsiTransactionBeginUse::ReadWriteFirstBind,
            mapped_errno: RsiMappedErrno::Enotsup,
        }
    );
}

#[test]
fn read_only_transaction_not_supported_maps_to_enotsup_for_backup() {
    assert_eq!(
        plan_rsi_transaction_begin_status(
            RsiTransactionBeginUse::ReadOnlyBackupSnapshot,
            RsiStatus::TxnNotSupported
        ),
        RsiTransactionBeginStatusPlan::NotSupported {
            use_case: RsiTransactionBeginUse::ReadOnlyBackupSnapshot,
            mapped_errno: RsiMappedErrno::Enotsup,
        }
    );
}

#[test]
fn other_transaction_begin_source_errors_keep_their_errno_mapping() {
    assert_eq!(
        plan_rsi_transaction_begin_status(
            RsiTransactionBeginUse::ReadWriteFirstBind,
            RsiStatus::TxnBusy
        ),
        RsiTransactionBeginStatusPlan::Failed(RsiMappedErrno::Ebusy)
    );
    assert_eq!(
        plan_rsi_transaction_begin_status(
            RsiTransactionBeginUse::ReadOnlyBackupSnapshot,
            RsiStatus::StorageError
        ),
        RsiTransactionBeginStatusPlan::Failed(RsiMappedErrno::Eio)
    );
}
