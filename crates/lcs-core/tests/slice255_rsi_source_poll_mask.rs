use lcs_core::{
    Guid, LINUX_POLLERR, LINUX_POLLHUP, LINUX_POLLIN, LINUX_POLLOUT, LcsError, RSI_READ_KEY,
    RsiPollPlan, RsiQueuedRequest, RsiRetainedRequest, TransactionPollPlan,
    linux_poll_mask_from_readiness, plan_rsi_source_poll_mask, plan_rsi_source_poll_mask_for_queue,
    rsi_poll_plan_mask, transaction_poll_plan_mask, write_rsi_read_key_request_frame,
};

const GUID_A: Guid = [0x44; 16];

fn read_key_request<'a>(buf: &'a mut [u8], request_id: u64) -> RsiQueuedRequest<'a> {
    let built = write_rsi_read_key_request_frame(buf, request_id, 0, GUID_A).expect("write frame");
    RsiQueuedRequest {
        frame: &buf[..built.len],
        retained: built.retained,
    }
}

#[test]
fn shared_poll_mask_helper_matches_local_linux_uapi_bits() {
    assert_eq!(
        linux_poll_mask_from_readiness(true, true, true, true),
        LINUX_POLLIN | LINUX_POLLOUT | LINUX_POLLERR | LINUX_POLLHUP
    );
    assert_eq!(
        linux_poll_mask_from_readiness(false, false, true, true),
        LINUX_POLLERR | LINUX_POLLHUP
    );
}

#[test]
fn rsi_source_poll_mask_projects_active_source_readiness() {
    assert_eq!(
        plan_rsi_source_poll_mask(1, true, false),
        LINUX_POLLIN | LINUX_POLLOUT
    );
    assert_eq!(plan_rsi_source_poll_mask(0, true, false), LINUX_POLLOUT);
    assert_eq!(
        rsi_poll_plan_mask(RsiPollPlan {
            readable: true,
            writable: true,
            hangup: false,
            error: false,
        }),
        LINUX_POLLIN | LINUX_POLLOUT
    );
}

#[test]
fn rsi_source_poll_mask_projects_down_or_closing_source_as_error_hangup() {
    assert_eq!(
        plan_rsi_source_poll_mask(1, false, false),
        LINUX_POLLERR | LINUX_POLLHUP
    );
    assert_eq!(
        plan_rsi_source_poll_mask(1, true, true),
        LINUX_POLLERR | LINUX_POLLHUP
    );
}

#[test]
fn concrete_queue_poll_mask_validates_storage_before_projection() {
    let mut frame = [0u8; 64];
    let request = read_key_request(&mut frame, 50);
    let queue = [Some(request), None];

    assert_eq!(
        plan_rsi_source_poll_mask_for_queue(&queue, true, false),
        Ok(LINUX_POLLIN | LINUX_POLLOUT)
    );

    let mismatched = [Some(RsiQueuedRequest {
        frame: request.frame,
        retained: RsiRetainedRequest {
            request_id: 51,
            op_code: RSI_READ_KEY,
        },
    })];
    assert_eq!(
        plan_rsi_source_poll_mask_for_queue(&mismatched, true, false),
        Err(LcsError::RsiQueuedRequestMetadataMismatch {
            header_request_id: 50,
            retained_request_id: 51,
            header_op_code: RSI_READ_KEY,
            retained_op_code: RSI_READ_KEY,
        })
    );
}

#[test]
fn transaction_poll_projection_still_uses_the_same_shared_mask_semantics() {
    assert_eq!(
        transaction_poll_plan_mask(TransactionPollPlan {
            readable: true,
            writable: false,
            hangup: true,
            error: true,
        }),
        LINUX_POLLIN | LINUX_POLLERR | LINUX_POLLHUP
    );
}
