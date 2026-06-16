use lcs_core::{
    LINUX_POLLERR, LINUX_POLLHUP, LINUX_POLLIN, LINUX_POLLOUT, TransactionBinding,
    TransactionPollPlan, TransactionState, plan_transaction_poll_mask, transaction_poll_plan_mask,
};

const HIVE_ROOT: [u8; 16] = [0x55; 16];

fn active_bound_state() -> TransactionState<'static> {
    TransactionState::ActiveBound(TransactionBinding {
        source_id: 9,
        hive_name: "Machine",
        hive_root_guid: HIVE_ROOT,
    })
}

#[test]
fn linux_poll_constants_match_local_kernel_uapi_values() {
    assert_eq!(LINUX_POLLIN, 0x0001);
    assert_eq!(LINUX_POLLOUT, 0x0004);
    assert_eq!(LINUX_POLLERR, 0x0008);
    assert_eq!(LINUX_POLLHUP, 0x0010);
}

#[test]
fn transaction_poll_plan_projects_symbolic_bits_to_linux_mask() {
    assert_eq!(
        transaction_poll_plan_mask(TransactionPollPlan {
            readable: true,
            writable: true,
            hangup: true,
            error: true,
        }),
        LINUX_POLLIN | LINUX_POLLOUT | LINUX_POLLERR | LINUX_POLLHUP
    );

    assert_eq!(
        transaction_poll_plan_mask(TransactionPollPlan {
            readable: false,
            writable: false,
            hangup: true,
            error: true,
        }),
        LINUX_POLLERR | LINUX_POLLHUP
    );
}

#[test]
fn active_transaction_poll_mask_is_empty() {
    assert_eq!(
        plan_transaction_poll_mask(TransactionState::ActiveUnbound),
        0
    );
    assert_eq!(plan_transaction_poll_mask(active_bound_state()), 0);
}

#[test]
fn terminal_transaction_poll_mask_is_pollerr_pollhup() {
    for state in [
        TransactionState::Committed,
        TransactionState::Aborted,
        TransactionState::TimedOut,
        TransactionState::SourceDown,
    ] {
        assert_eq!(
            plan_transaction_poll_mask(state),
            LINUX_POLLERR | LINUX_POLLHUP
        );
    }
}
