use lcs_core::{
    LcsError, RSI_REQUEST_HEADER_LEN, RsiPollPlan, RsiReadPlan, plan_rsi_source_poll,
    plan_rsi_source_read,
};

#[test]
fn source_read_returns_exactly_one_complete_request_when_buffer_fits() {
    assert_eq!(
        plan_rsi_source_read(
            Some(RSI_REQUEST_HEADER_LEN + 12),
            RSI_REQUEST_HEADER_LEN + 12,
            false,
            false
        ),
        Ok(RsiReadPlan::ReturnOneCompleteRequest {
            request_len: RSI_REQUEST_HEADER_LEN + 12,
            consume_request: true,
        })
    );

    assert_eq!(
        plan_rsi_source_read(Some(RSI_REQUEST_HEADER_LEN + 12), usize::MAX, true, true),
        Ok(RsiReadPlan::ReturnOneCompleteRequest {
            request_len: RSI_REQUEST_HEADER_LEN + 12,
            consume_request: true,
        })
    );
}

#[test]
fn source_read_without_queued_request_waits_or_returns_eagain() {
    assert_eq!(
        plan_rsi_source_read(None, 4096, false, false),
        Ok(RsiReadPlan::WaitForRequestOrClose)
    );
    assert_eq!(
        plan_rsi_source_read(None, 4096, true, false),
        Ok(RsiReadPlan::ReturnEagain)
    );
    assert_eq!(
        plan_rsi_source_read(None, 4096, false, true),
        Ok(RsiReadPlan::WakeForClose)
    );
}

#[test]
fn source_read_too_small_buffer_does_not_consume_request() {
    assert_eq!(
        plan_rsi_source_read(
            Some(RSI_REQUEST_HEADER_LEN + 1),
            RSI_REQUEST_HEADER_LEN,
            false,
            false
        ),
        Ok(RsiReadPlan::ReturnEmsgsize {
            required_len: RSI_REQUEST_HEADER_LEN + 1,
            consume_request: false,
        })
    );
}

#[test]
fn source_read_rejects_corrupt_queued_request_lengths() {
    assert_eq!(
        plan_rsi_source_read(Some(RSI_REQUEST_HEADER_LEN - 1), 4096, false, false),
        Err(LcsError::RsiMessageTooShort {
            len: RSI_REQUEST_HEADER_LEN - 1,
            min: RSI_REQUEST_HEADER_LEN,
        })
    );
}

#[test]
fn source_poll_reports_readable_for_queued_requests_and_writable_while_active() {
    assert_eq!(
        plan_rsi_source_poll(1, true, false),
        RsiPollPlan {
            readable: true,
            writable: true,
            hangup: false,
            error: false,
        }
    );
    assert_eq!(
        plan_rsi_source_poll(0, true, false),
        RsiPollPlan {
            readable: false,
            writable: true,
            hangup: false,
            error: false,
        }
    );
}

#[test]
fn source_poll_reports_hup_and_error_when_down_or_closing() {
    let terminal = RsiPollPlan {
        readable: false,
        writable: false,
        hangup: true,
        error: true,
    };

    assert_eq!(plan_rsi_source_poll(1, false, false), terminal);
    assert_eq!(plan_rsi_source_poll(1, true, true), terminal);
}
