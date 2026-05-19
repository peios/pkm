use lcs_core::{
    RSI_LOOKUP, RsiLateResponseRecordPlan, RsiLateResponseRecordState, RsiMalformedProtocolReason,
    RsiRetainedRequest, plan_rsi_late_response_record,
};

fn retained() -> RsiRetainedRequest {
    RsiRetainedRequest {
        request_id: 44,
        op_code: RSI_LOOKUP,
    }
}

fn teardown(reason: RsiMalformedProtocolReason) -> RsiLateResponseRecordPlan {
    RsiLateResponseRecordPlan::MalformedProtocolTearDown {
        reason,
        tear_down_source: true,
        mark_source_down: true,
    }
}

#[test]
fn late_response_for_retained_request_validates_normally() {
    assert_eq!(
        plan_rsi_late_response_record(RsiLateResponseRecordState::Retained(retained())),
        RsiLateResponseRecordPlan::ValidateNormally(retained())
    );
}

#[test]
fn late_response_for_unknown_request_tears_down_source() {
    assert_eq!(
        plan_rsi_late_response_record(RsiLateResponseRecordState::UnknownRequestId),
        teardown(RsiMalformedProtocolReason::UnknownRequestId)
    );
}

#[test]
fn duplicate_late_response_tears_down_source() {
    assert_eq!(
        plan_rsi_late_response_record(RsiLateResponseRecordState::DuplicateResponse),
        teardown(RsiMalformedProtocolReason::DuplicateResponse)
    );
}

#[test]
fn late_response_for_released_record_tears_down_source() {
    assert_eq!(
        plan_rsi_late_response_record(RsiLateResponseRecordState::ReleasedRequestRecord),
        teardown(RsiMalformedProtocolReason::ReleasedRequestRecord)
    );
}
