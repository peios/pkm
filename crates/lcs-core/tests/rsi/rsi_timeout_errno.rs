use lcs_core::{
    LcsLimits, RsiDispatchedWaitPlan, RsiRequestIdCounter, RsiRequestTimeoutErrno,
    RsiSlotReservationPlan, plan_rsi_dispatched_wait, plan_rsi_slot_reservation,
    rsi_dispatched_wait_timeout_errno, rsi_slot_reservation_timeout_errno,
};

fn limits() -> LcsLimits {
    LcsLimits {
        request_timeout_ms: 1_000,
        max_concurrent_rsi_requests: 2,
        ..LcsLimits::default()
    }
}

#[test]
fn pre_dispatch_timeout_reports_etimedout_without_allocating_request_id() {
    let limits = limits();
    let mut counter = RsiRequestIdCounter::from_next_request_id(77);
    let plan = plan_rsi_slot_reservation(&limits, &mut counter, 2, 1_000).unwrap();

    assert_eq!(plan, RsiSlotReservationPlan::TimeoutBeforeDispatchNoRequest);
    assert_eq!(
        rsi_slot_reservation_timeout_errno(&plan),
        Some(RsiRequestTimeoutErrno::Etimedout)
    );
    assert_eq!(counter.next_request_id(), 77);
}

#[test]
fn non_timeout_slot_reservation_states_do_not_report_timeout_errno() {
    let limits = limits();
    let mut counter = RsiRequestIdCounter::from_next_request_id(77);

    let dispatch = plan_rsi_slot_reservation(&limits, &mut counter, 1, 250).unwrap();
    assert_eq!(
        dispatch,
        RsiSlotReservationPlan::DispatchNow {
            request_id: 77,
            remaining_timeout_ms: 750,
            in_flight_after_dispatch: 2,
        }
    );
    assert_eq!(rsi_slot_reservation_timeout_errno(&dispatch), None);

    let wait = plan_rsi_slot_reservation(&limits, &mut counter, 2, 250).unwrap();
    assert_eq!(
        wait,
        RsiSlotReservationPlan::WaitForSlot {
            remaining_timeout_ms: 750,
        }
    );
    assert_eq!(rsi_slot_reservation_timeout_errno(&wait), None);
}

#[test]
fn post_dispatch_timeout_reports_etimedout_and_preserves_uncertainty() {
    let plan = plan_rsi_dispatched_wait(12, 1_000, 1_250);

    assert_eq!(
        plan,
        RsiDispatchedWaitPlan::CallerTimedOutRetainRecord {
            request_id: 12,
            retain_request_record: true,
            remains_in_flight: true,
            completion_may_still_occur: true,
        }
    );
    assert_eq!(
        rsi_dispatched_wait_timeout_errno(&plan),
        Some(RsiRequestTimeoutErrno::Etimedout)
    );
}

#[test]
fn continuing_dispatched_wait_does_not_report_timeout_errno() {
    let plan = plan_rsi_dispatched_wait(12, 1_000, 999);

    assert_eq!(
        plan,
        RsiDispatchedWaitPlan::ContinueWaiting {
            remaining_timeout_ms: 1,
        }
    );
    assert_eq!(rsi_dispatched_wait_timeout_errno(&plan), None);
}
