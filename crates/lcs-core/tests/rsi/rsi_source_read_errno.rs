use lcs_core::{
    Guid, LcsError, LinuxErrno, RsiQueuedRequest, RsiReadPlan, RsiRequestQueueReadDrain,
    RsiRetainedRequest, drain_rsi_request_queue_read, insert_rsi_queued_request,
    rsi_request_queue_read_drain_errno, rsi_source_read_plan_errno, summarize_rsi_request_queue,
    write_rsi_read_key_request_frame,
};

const GUID_A: Guid = [0x11; 16];

fn read_key_frame<'a>(
    buf: &'a mut [u8],
    request_id: u64,
    guid: Guid,
) -> (&'a [u8], RsiRetainedRequest) {
    let built = write_rsi_read_key_request_frame(buf, request_id, 0, guid).expect("write frame");
    (&buf[..built.len], built.retained)
}

#[test]
fn symbolic_source_read_plans_project_only_error_states_to_errno() {
    assert_eq!(
        rsi_source_read_plan_errno(RsiReadPlan::ReturnEagain),
        Some(LinuxErrno::Eagain)
    );
    assert_eq!(
        rsi_source_read_plan_errno(RsiReadPlan::ReturnEmsgsize {
            required_len: 64,
            consume_request: false,
        }),
        Some(LinuxErrno::Emsgsize)
    );
    assert_eq!(
        rsi_source_read_plan_errno(RsiReadPlan::ReturnOneCompleteRequest {
            request_len: 64,
            consume_request: true,
        }),
        None
    );
    assert_eq!(
        rsi_source_read_plan_errno(RsiReadPlan::WaitForRequestOrClose),
        None
    );
    assert_eq!(rsi_source_read_plan_errno(RsiReadPlan::WakeForClose), None);
}

#[test]
fn concrete_empty_nonblocking_source_read_projects_eagain() {
    let mut queue = [None; 1];
    let mut out = [0u8; 64];

    let plan = drain_rsi_request_queue_read(&mut queue, &mut out, true, false).unwrap();

    assert_eq!(plan, RsiRequestQueueReadDrain::ReturnEagain);
    assert_eq!(
        rsi_request_queue_read_drain_errno(&plan),
        Some(LinuxErrno::Eagain)
    );
    assert_eq!(queue, [None; 1]);
}

#[test]
fn concrete_too_small_source_read_projects_emsgsize_without_consuming() {
    let mut frame = [0u8; 64];
    let (frame, retained) = read_key_frame(&mut frame, 40, GUID_A);
    let mut queue = [None; 1];
    insert_rsi_queued_request(&mut queue, frame).expect("insert");
    let mut out = [0xaa; 8];

    let plan = drain_rsi_request_queue_read(&mut queue, &mut out, false, false).unwrap();

    assert_eq!(
        plan,
        RsiRequestQueueReadDrain::ReturnEmsgsize {
            required_len: frame.len(),
            consume_request: false,
        }
    );
    assert_eq!(
        rsi_request_queue_read_drain_errno(&plan),
        Some(LinuxErrno::Emsgsize)
    );
    assert_eq!(out, [0xaa; 8]);
    assert_eq!(queue, [Some(RsiQueuedRequest { frame, retained })]);
}

#[test]
fn successful_wait_and_close_source_read_plans_have_no_errno() {
    let mut queue = [None; 1];
    let mut out = [0u8; 64];

    let wait = drain_rsi_request_queue_read(&mut queue, &mut out, false, false).unwrap();
    assert_eq!(wait, RsiRequestQueueReadDrain::WaitForRequestOrClose);
    assert_eq!(rsi_request_queue_read_drain_errno(&wait), None);

    let close = drain_rsi_request_queue_read(&mut queue, &mut out, false, true).unwrap();
    assert_eq!(close, RsiRequestQueueReadDrain::WakeForClose);
    assert_eq!(rsi_request_queue_read_drain_errno(&close), None);
}

#[test]
fn corrupt_source_request_queue_fails_before_errno_projection() {
    let mut frame = [0u8; 64];
    let (frame, retained) = read_key_frame(&mut frame, 50, GUID_A);
    let request = RsiQueuedRequest { frame, retained };
    let mut queue = [None, Some(request)];
    let original = queue;
    let mut out = [0u8; 64];

    assert_eq!(
        summarize_rsi_request_queue(&queue),
        Err(LcsError::InvalidRsiRequestQueue { index: 1 })
    );
    assert_eq!(
        drain_rsi_request_queue_read(&mut queue, &mut out, true, false),
        Err(LcsError::InvalidRsiRequestQueue { index: 1 })
    );
    assert_eq!(queue, original);
}
