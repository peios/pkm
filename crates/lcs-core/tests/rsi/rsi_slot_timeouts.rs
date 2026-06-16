use lcs_core::{
    LcsLimits, RsiDispatchedWaitPlan, RsiRequestIdCounter, RsiSlotReservationPlan,
    plan_rsi_dispatched_wait, plan_rsi_slot_reservation,
};

fn limits() -> LcsLimits {
    LcsLimits {
        request_timeout_ms: 1_000,
        max_concurrent_rsi_requests: 2,
        ..LcsLimits::default()
    }
}

#[test]
fn slot_reservation_dispatches_only_when_below_in_flight_limit() {
    let limits = limits();
    let mut counter = RsiRequestIdCounter::from_next_request_id(77);

    assert_eq!(
        plan_rsi_slot_reservation(&limits, &mut counter, 1, 250),
        Ok(RsiSlotReservationPlan::DispatchNow {
            request_id: 77,
            remaining_timeout_ms: 750,
            in_flight_after_dispatch: 2,
        })
    );
    assert_eq!(counter.next_request_id(), 78);
}

#[test]
fn slot_reservation_waits_without_allocating_when_limit_is_reached() {
    let limits = limits();
    let mut counter = RsiRequestIdCounter::from_next_request_id(77);

    assert_eq!(
        plan_rsi_slot_reservation(&limits, &mut counter, 2, 250),
        Ok(RsiSlotReservationPlan::WaitForSlot {
            remaining_timeout_ms: 750,
        })
    );
    assert_eq!(counter.next_request_id(), 77);
}

#[test]
fn slot_reservation_timeout_before_slot_sends_no_request() {
    let limits = limits();
    let mut counter = RsiRequestIdCounter::from_next_request_id(77);

    assert_eq!(
        plan_rsi_slot_reservation(&limits, &mut counter, 2, 1_000),
        Ok(RsiSlotReservationPlan::TimeoutBeforeDispatchNoRequest)
    );
    assert_eq!(counter.next_request_id(), 77);
}

#[test]
fn timed_out_retained_requests_continue_to_count_against_slot_limit() {
    let limits = limits();
    let mut counter = RsiRequestIdCounter::from_next_request_id(77);

    assert_eq!(
        plan_rsi_dispatched_wait(12, limits.request_timeout_ms, 1_250),
        RsiDispatchedWaitPlan::CallerTimedOutRetainRecord {
            request_id: 12,
            retain_request_record: true,
            remains_in_flight: true,
            completion_may_still_occur: true,
        }
    );
    assert_eq!(
        plan_rsi_slot_reservation(&limits, &mut counter, 2, 10),
        Ok(RsiSlotReservationPlan::WaitForSlot {
            remaining_timeout_ms: 990,
        })
    );
    assert_eq!(counter.next_request_id(), 77);
}

#[test]
fn dispatched_request_wait_uses_original_reservation_deadline() {
    assert_eq!(
        plan_rsi_dispatched_wait(12, 1_000, 999),
        RsiDispatchedWaitPlan::ContinueWaiting {
            remaining_timeout_ms: 1,
        }
    );
    assert_eq!(
        plan_rsi_dispatched_wait(12, 1_000, 1_000),
        RsiDispatchedWaitPlan::CallerTimedOutRetainRecord {
            request_id: 12,
            retain_request_record: true,
            remains_in_flight: true,
            completion_may_still_occur: true,
        }
    );
}
