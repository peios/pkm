use lcs_core::{
    HiveRouteErrno, KeyFdOrphanOperationErrno, KeyPathMutationErrno, LayerCreationAdmissionErrno,
    LayerTargetAdmissionErrno, LinuxErrno, OutputBufferAggregate, RegistryIoctlFdAccessErrno,
    RegistryOpenPreResolutionErrno, RsiMappedErrno, RsiRequestTimeoutErrno, SymlinkResolutionErrno,
    TransactionTerminalErrno, TransactionTimeoutErrno, ValueLayerAdmissionErrno,
    ValueTypeValidationErrno, output_buffer_aggregate_errno, transaction_terminal_errno_raw,
};

#[test]
fn linux_errno_table_matches_psd_005_registry_error_vocabulary() {
    assert_eq!(LinuxErrno::Eperm.raw(), 1);
    assert_eq!(LinuxErrno::Enoent.raw(), 2);
    assert_eq!(LinuxErrno::Eio.raw(), 5);
    assert_eq!(LinuxErrno::Ebadf.raw(), 9);
    assert_eq!(LinuxErrno::Eagain.raw(), 11);
    assert_eq!(LinuxErrno::Enomem.raw(), 12);
    assert_eq!(LinuxErrno::Eacces.raw(), 13);
    assert_eq!(LinuxErrno::Efault.raw(), 14);
    assert_eq!(LinuxErrno::Ebusy.raw(), 16);
    assert_eq!(LinuxErrno::Eexist.raw(), 17);
    assert_eq!(LinuxErrno::Exdev.raw(), 18);
    assert_eq!(LinuxErrno::Einval.raw(), 22);
    assert_eq!(LinuxErrno::Enospc.raw(), 28);
    assert_eq!(LinuxErrno::Erange.raw(), 34);
    assert_eq!(LinuxErrno::Enametoolong.raw(), 36);
    assert_eq!(LinuxErrno::Enotempty.raw(), 39);
    assert_eq!(LinuxErrno::Eloop.raw(), 40);
    assert_eq!(LinuxErrno::Emsgsize.raw(), 90);
    assert_eq!(LinuxErrno::Eoverflow.raw(), 75);
    assert_eq!(LinuxErrno::Enotsup.raw(), 95);
    assert_eq!(LinuxErrno::Etimedout.raw(), 110);
    assert_eq!(LinuxErrno::Estale.raw(), 116);
    assert_eq!(LinuxErrno::Eacces.negated_return(), -13);
}

#[test]
fn symbolic_errno_classes_project_to_linux_errno_numbers() {
    assert_eq!(LinuxErrno::from(RsiMappedErrno::Enoent), LinuxErrno::Enoent);
    assert_eq!(LinuxErrno::from(RsiMappedErrno::Eexist), LinuxErrno::Eexist);
    assert_eq!(LinuxErrno::from(RsiMappedErrno::Eio), LinuxErrno::Eio);
    assert_eq!(
        LinuxErrno::from(RsiMappedErrno::Enotempty),
        LinuxErrno::Enotempty
    );
    assert_eq!(LinuxErrno::from(RsiMappedErrno::Enospc), LinuxErrno::Enospc);
    assert_eq!(LinuxErrno::from(RsiMappedErrno::Ebusy), LinuxErrno::Ebusy);
    assert_eq!(LinuxErrno::from(RsiMappedErrno::Einval), LinuxErrno::Einval);
    assert_eq!(LinuxErrno::from(RsiMappedErrno::Eagain), LinuxErrno::Eagain);
    assert_eq!(
        LinuxErrno::from(RsiMappedErrno::Enotsup),
        LinuxErrno::Enotsup
    );
    assert_eq!(
        LinuxErrno::from(RsiMappedErrno::Etimedout),
        LinuxErrno::Etimedout
    );
    assert_eq!(LinuxErrno::from(RsiMappedErrno::Exdev), LinuxErrno::Exdev);
    assert_eq!(
        LinuxErrno::from(RsiRequestTimeoutErrno::Etimedout),
        LinuxErrno::Etimedout
    );
    assert_eq!(
        LinuxErrno::from(TransactionTimeoutErrno::Etimedout),
        LinuxErrno::Etimedout
    );
}

#[test]
fn non_rsi_symbolic_errno_classes_project_to_linux_errno_numbers() {
    assert_eq!(LinuxErrno::from(HiveRouteErrno::Enoent), LinuxErrno::Enoent);
    assert_eq!(LinuxErrno::from(HiveRouteErrno::Eio), LinuxErrno::Eio);
    assert_eq!(
        LinuxErrno::from(SymlinkResolutionErrno::Einval),
        LinuxErrno::Einval
    );
    assert_eq!(
        LinuxErrno::from(SymlinkResolutionErrno::Eloop),
        LinuxErrno::Eloop
    );
    assert_eq!(
        LinuxErrno::from(ValueTypeValidationErrno::Einval),
        LinuxErrno::Einval
    );
    assert_eq!(
        LinuxErrno::from(ValueLayerAdmissionErrno::Enospc),
        LinuxErrno::Enospc
    );
    assert_eq!(
        LinuxErrno::from(LayerCreationAdmissionErrno::Enospc),
        LinuxErrno::Enospc
    );
    assert_eq!(
        LinuxErrno::from(LayerTargetAdmissionErrno::Enoent),
        LinuxErrno::Enoent
    );
    assert_eq!(
        LinuxErrno::from(KeyPathMutationErrno::Enotempty),
        LinuxErrno::Enotempty
    );
    assert_eq!(
        LinuxErrno::from(KeyFdOrphanOperationErrno::Enoent),
        LinuxErrno::Enoent
    );
    assert_eq!(
        LinuxErrno::from(RegistryIoctlFdAccessErrno::Eacces),
        LinuxErrno::Eacces
    );
    assert_eq!(
        LinuxErrno::from(RegistryOpenPreResolutionErrno::Einval),
        LinuxErrno::Einval
    );
}

#[test]
fn txn_status_terminal_errno_uses_linux_numbers_or_zero() {
    assert_eq!(
        transaction_terminal_errno_raw(TransactionTerminalErrno::None),
        0
    );
    assert_eq!(
        transaction_terminal_errno_raw(TransactionTerminalErrno::Invalid),
        LinuxErrno::Einval.raw()
    );
    assert_eq!(
        transaction_terminal_errno_raw(TransactionTerminalErrno::TimedOut),
        LinuxErrno::Etimedout.raw()
    );
    assert_eq!(
        transaction_terminal_errno_raw(TransactionTerminalErrno::Io),
        LinuxErrno::Eio.raw()
    );
}

#[test]
fn output_buffer_aggregate_projects_only_too_small_to_erange() {
    assert_eq!(
        output_buffer_aggregate_errno(OutputBufferAggregate::AllFit),
        None
    );
    assert_eq!(
        output_buffer_aggregate_errno(OutputBufferAggregate::TooSmall),
        Some(LinuxErrno::Erange)
    );
}
