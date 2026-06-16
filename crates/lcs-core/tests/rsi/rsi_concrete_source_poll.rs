use lcs_core::{
    Guid, LcsError, RSI_READ_KEY, RsiPollPlan, RsiQueuedRequest, RsiRetainedRequest,
    plan_rsi_source_poll_for_queue, write_rsi_read_key_request_frame,
};

const GUID_A: Guid = [0x11; 16];

fn read_key_request<'a>(buf: &'a mut [u8], request_id: u64) -> RsiQueuedRequest<'a> {
    let built = write_rsi_read_key_request_frame(buf, request_id, 0, GUID_A).expect("write frame");
    RsiQueuedRequest {
        frame: &buf[..built.len],
        retained: built.retained,
    }
}

#[test]
fn concrete_poll_reports_readable_and_writable_for_active_source_with_queue() {
    let mut frame = [0u8; 64];
    let request = read_key_request(&mut frame, 10);
    let queue = [Some(request), None];

    assert_eq!(
        plan_rsi_source_poll_for_queue(&queue, true, false),
        Ok(RsiPollPlan {
            readable: true,
            writable: true,
            hangup: false,
            error: false,
        }),
    );
}

#[test]
fn concrete_poll_reports_writable_only_for_active_source_without_queue() {
    let queue = [None; 2];

    assert_eq!(
        plan_rsi_source_poll_for_queue(&queue, true, false),
        Ok(RsiPollPlan {
            readable: false,
            writable: true,
            hangup: false,
            error: false,
        }),
    );
}

#[test]
fn concrete_poll_reports_terminal_for_down_or_closing_source() {
    let mut frame = [0u8; 64];
    let request = read_key_request(&mut frame, 20);
    let queue = [Some(request)];
    let terminal = RsiPollPlan {
        readable: false,
        writable: false,
        hangup: true,
        error: true,
    };

    assert_eq!(
        plan_rsi_source_poll_for_queue(&queue, false, false),
        Ok(terminal)
    );
    assert_eq!(
        plan_rsi_source_poll_for_queue(&queue, true, true),
        Ok(terminal)
    );
}

#[test]
fn concrete_poll_rejects_sparse_or_metadata_mismatched_queue_before_readiness() {
    let mut frame = [0u8; 64];
    let request = read_key_request(&mut frame, 30);
    let sparse = [None, Some(request)];

    assert_eq!(
        plan_rsi_source_poll_for_queue(&sparse, true, false),
        Err(LcsError::InvalidRsiRequestQueue { index: 1 }),
    );

    let mismatched = [Some(RsiQueuedRequest {
        frame: request.frame,
        retained: RsiRetainedRequest {
            request_id: 31,
            op_code: RSI_READ_KEY,
        },
    })];
    assert_eq!(
        plan_rsi_source_poll_for_queue(&mismatched, true, false),
        Err(LcsError::RsiQueuedRequestMetadataMismatch {
            header_request_id: 30,
            retained_request_id: 31,
            header_op_code: RSI_READ_KEY,
            retained_op_code: RSI_READ_KEY,
        }),
    );
}
