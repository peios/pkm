use lcs_core::{
    Guid, KEY_READ, KeyFdClosePlan, KeyFdOpenView, KeyWatchState, LcsError, LcsLimits,
    TransactionBinding, TransactionFdClosePlan, TransactionState, plan_key_fd_close,
    plan_transaction_fd_close,
};

const ROOT_GUID: Guid = [0x10; 16];
const CHILD_GUID: Guid = [0x20; 16];

fn key_fd(watch_state: KeyWatchState) -> KeyFdOpenView<'static> {
    static PATH: [&str; 2] = ["Machine", "Child"];
    static ANCESTORS: [Guid; 2] = [ROOT_GUID, CHILD_GUID];

    KeyFdOpenView {
        key_guid: CHILD_GUID,
        granted_access: KEY_READ,
        resolved_path: &PATH,
        ancestor_guids: &ANCESTORS,
        watch_state,
    }
}

fn binding() -> TransactionBinding<'static> {
    TransactionBinding {
        source_id: 7,
        hive_name: "Machine",
        hive_root_guid: ROOT_GUID,
    }
}

#[test]
fn key_fd_close_releases_key_without_watch_cleanup_when_unarmed() {
    assert_eq!(
        plan_key_fd_close(
            &LcsLimits::default(),
            &key_fd(KeyWatchState {
                armed: false,
                orphaned: false,
            }),
        ),
        Ok(KeyFdClosePlan {
            release_key_reference: true,
            remove_watch: false,
            discard_pending_watch_events: false,
        })
    );
}

#[test]
fn key_fd_close_removes_armed_watch_and_pending_events() {
    assert_eq!(
        plan_key_fd_close(
            &LcsLimits::default(),
            &key_fd(KeyWatchState {
                armed: true,
                orphaned: true,
            }),
        ),
        Ok(KeyFdClosePlan {
            release_key_reference: true,
            remove_watch: true,
            discard_pending_watch_events: true,
        })
    );
}

#[test]
fn key_fd_close_revalidates_fd_snapshot_before_release_planning() {
    static PATH: [&str; 2] = ["Machine", "Child"];
    static BAD_ANCESTORS: [Guid; 1] = [ROOT_GUID];
    let bad_fd = KeyFdOpenView {
        key_guid: CHILD_GUID,
        granted_access: KEY_READ,
        resolved_path: &PATH,
        ancestor_guids: &BAD_ANCESTORS,
        watch_state: KeyWatchState {
            armed: false,
            orphaned: false,
        },
    };

    assert_eq!(
        plan_key_fd_close(&LcsLimits::default(), &bad_fd),
        Err(LcsError::InvalidFdAncestry)
    );
}

#[test]
fn transaction_fd_close_aborts_active_unbound_without_source_abort() {
    assert_eq!(
        plan_transaction_fd_close(&LcsLimits::default(), TransactionState::ActiveUnbound),
        Ok(TransactionFdClosePlan {
            final_state: TransactionState::Aborted,
            binding: None,
            dispatch_source_abort: false,
            discard_mutation_log: true,
            wake_poll_waiters: true,
            release_fd_object: true,
        })
    );
}

#[test]
fn transaction_fd_close_aborts_active_bound_and_dispatches_source_abort() {
    let binding = binding();

    assert_eq!(
        plan_transaction_fd_close(
            &LcsLimits::default(),
            TransactionState::ActiveBound(binding)
        ),
        Ok(TransactionFdClosePlan {
            final_state: TransactionState::Aborted,
            binding: Some(binding),
            dispatch_source_abort: true,
            discard_mutation_log: true,
            wake_poll_waiters: true,
            release_fd_object: true,
        })
    );
}

#[test]
fn transaction_fd_close_releases_terminal_transactions_without_new_effects() {
    let cases = [
        TransactionState::Committed,
        TransactionState::Aborted,
        TransactionState::TimedOut,
        TransactionState::SourceDown,
    ];

    for state in cases {
        assert_eq!(
            plan_transaction_fd_close(&LcsLimits::default(), state),
            Ok(TransactionFdClosePlan {
                final_state: state,
                binding: None,
                dispatch_source_abort: false,
                discard_mutation_log: false,
                wake_poll_waiters: false,
                release_fd_object: true,
            })
        );
    }
}

#[test]
fn transaction_fd_close_rejects_corrupt_active_binding() {
    let corrupt = TransactionBinding {
        source_id: 7,
        hive_name: "Machine",
        hive_root_guid: [0; 16],
    };

    assert_eq!(
        plan_transaction_fd_close(
            &LcsLimits::default(),
            TransactionState::ActiveBound(corrupt)
        ),
        Err(LcsError::NilHiveRootGuid)
    );
}
