use lcs_core::{TransactionBinding, TransactionPollPlan, TransactionState, plan_transaction_poll};

const HIVE_ROOT: [u8; 16] = [0x55; 16];

fn active_bound_state() -> TransactionState<'static> {
    TransactionState::ActiveBound(TransactionBinding {
        source_id: 9,
        hive_name: "Machine",
        hive_root_guid: HIVE_ROOT,
    })
}

#[test]
fn active_transaction_fds_report_no_poll_readiness() {
    let not_ready = TransactionPollPlan {
        readable: false,
        writable: false,
        hangup: false,
        error: false,
    };

    assert_eq!(
        plan_transaction_poll(TransactionState::ActiveUnbound),
        not_ready
    );
    assert_eq!(plan_transaction_poll(active_bound_state()), not_ready);
}

#[test]
fn terminal_transaction_fds_report_error_and_hangup() {
    let terminal_ready = TransactionPollPlan {
        readable: false,
        writable: false,
        hangup: true,
        error: true,
    };

    for state in [
        TransactionState::Committed,
        TransactionState::Aborted,
        TransactionState::TimedOut,
        TransactionState::SourceDown,
    ] {
        assert_eq!(plan_transaction_poll(state), terminal_ready);
    }
}

#[test]
fn transaction_poll_readiness_matches_terminal_failure_classification() {
    for state in [
        TransactionState::Committed,
        TransactionState::Aborted,
        TransactionState::TimedOut,
        TransactionState::SourceDown,
    ] {
        let poll = plan_transaction_poll(state);
        assert!(poll.error);
        assert!(poll.hangup);
    }
}
