use lcs_core::{
    Guid, LcsError, RSI_READ_KEY, RsiQueuedRequest, RsiRequestQueueReadDrain,
    RsiRequestQueueSummary, RsiRetainedRequest, insert_rsi_queued_request,
    rsi_queued_request_from_frame, summarize_rsi_request_queue, write_rsi_read_key_request_frame,
};

const GUID_A: Guid = [0x11; 16];
const GUID_B: Guid = [0x22; 16];

fn read_key_frame<'a>(
    buf: &'a mut [u8],
    request_id: u64,
    guid: Guid,
) -> (&'a [u8], RsiRetainedRequest) {
    let built = write_rsi_read_key_request_frame(buf, request_id, 0, guid).expect("write frame");
    (&buf[..built.len], built.retained)
}

#[test]
fn insert_validates_and_appends_complete_requests_to_dense_fifo_storage() {
    let mut frame1 = [0u8; 64];
    let mut frame2 = [0u8; 64];
    let (frame1, retained1) = read_key_frame(&mut frame1, 10, GUID_A);
    let (frame2, retained2) = read_key_frame(&mut frame2, 11, GUID_B);
    let mut queue = [None; 2];

    assert_eq!(
        insert_rsi_queued_request(&mut queue, frame1),
        Ok(RsiRequestQueueSummary {
            entries: 1,
            capacity: 2,
            full: false,
        }),
    );
    assert_eq!(
        insert_rsi_queued_request(&mut queue, frame2),
        Ok(RsiRequestQueueSummary {
            entries: 2,
            capacity: 2,
            full: true,
        }),
    );

    assert_eq!(
        queue,
        [
            Some(RsiQueuedRequest {
                frame: frame1,
                retained: retained1,
            }),
            Some(RsiQueuedRequest {
                frame: frame2,
                retained: retained2,
            }),
        ],
    );
}

#[test]
fn full_queue_rejects_new_request_without_mutating_existing_entries() {
    let mut frame1 = [0u8; 64];
    let mut frame2 = [0u8; 64];
    let (frame1, retained1) = read_key_frame(&mut frame1, 20, GUID_A);
    let (frame2, _) = read_key_frame(&mut frame2, 21, GUID_B);
    let mut queue = [None; 1];
    insert_rsi_queued_request(&mut queue, frame1).expect("first insert");

    assert_eq!(
        insert_rsi_queued_request(&mut queue, frame2),
        Err(LcsError::RsiRequestQueueFull { capacity: 1 }),
    );
    assert_eq!(
        queue,
        [Some(RsiQueuedRequest {
            frame: frame1,
            retained: retained1,
        })],
    );
}

#[test]
fn read_drain_copies_one_complete_request_and_preserves_fifo_order() {
    let mut frame1 = [0u8; 64];
    let mut frame2 = [0u8; 64];
    let (frame1, retained1) = read_key_frame(&mut frame1, 30, GUID_A);
    let (frame2, retained2) = read_key_frame(&mut frame2, 31, GUID_B);
    let mut queue = [None; 2];
    insert_rsi_queued_request(&mut queue, frame1).expect("first insert");
    insert_rsi_queued_request(&mut queue, frame2).expect("second insert");
    let mut out = [0xaa; 128];

    assert_eq!(
        lcs_core::drain_rsi_request_queue_read(&mut queue, &mut out, false, false),
        Ok(RsiRequestQueueReadDrain::Copied {
            request: RsiQueuedRequest {
                frame: frame1,
                retained: retained1,
            },
            bytes: frame1.len(),
            summary: RsiRequestQueueSummary {
                entries: 1,
                capacity: 2,
                full: false,
            },
        }),
    );
    assert_eq!(&out[..frame1.len()], frame1);
    assert_eq!(
        queue,
        [
            Some(RsiQueuedRequest {
                frame: frame2,
                retained: retained2,
            }),
            None,
        ],
    );
}

#[test]
fn too_small_read_buffer_returns_emsgsize_without_consuming_or_copying() {
    let mut frame = [0u8; 64];
    let (frame, retained) = read_key_frame(&mut frame, 40, GUID_A);
    let mut queue = [None; 1];
    insert_rsi_queued_request(&mut queue, frame).expect("insert");
    let mut out = [0xaa; 8];

    assert_eq!(
        lcs_core::drain_rsi_request_queue_read(&mut queue, &mut out, false, false),
        Ok(RsiRequestQueueReadDrain::ReturnEmsgsize {
            required_len: frame.len(),
            consume_request: false,
        }),
    );
    assert_eq!(out, [0xaa; 8]);
    assert_eq!(queue, [Some(RsiQueuedRequest { frame, retained })],);
}

#[test]
fn empty_queue_read_matches_blocking_nonblocking_and_closing_semantics() {
    let mut queue = [None; 1];
    let mut out = [0u8; 64];

    assert_eq!(
        lcs_core::drain_rsi_request_queue_read(&mut queue, &mut out, false, false),
        Ok(RsiRequestQueueReadDrain::WaitForRequestOrClose),
    );
    assert_eq!(
        lcs_core::drain_rsi_request_queue_read(&mut queue, &mut out, true, false),
        Ok(RsiRequestQueueReadDrain::ReturnEagain),
    );
    assert_eq!(
        lcs_core::drain_rsi_request_queue_read(&mut queue, &mut out, false, true),
        Ok(RsiRequestQueueReadDrain::WakeForClose),
    );
    assert_eq!(queue, [None; 1]);
}

#[test]
fn sparse_queue_is_rejected_before_read_mutation() {
    let mut frame = [0u8; 64];
    let (frame, retained) = read_key_frame(&mut frame, 50, GUID_A);
    let request = RsiQueuedRequest { frame, retained };
    let mut queue = [None, Some(request)];
    let original = queue;
    let mut out = [0u8; 64];

    assert_eq!(
        summarize_rsi_request_queue(&queue),
        Err(LcsError::InvalidRsiRequestQueue { index: 1 }),
    );
    assert_eq!(
        lcs_core::drain_rsi_request_queue_read(&mut queue, &mut out, false, false),
        Err(LcsError::InvalidRsiRequestQueue { index: 1 }),
    );
    assert_eq!(queue, original);
}

#[test]
fn queued_request_metadata_mismatch_fails_closed() {
    let mut frame = [0u8; 64];
    let (frame, _) = read_key_frame(&mut frame, 60, GUID_A);
    let request = RsiQueuedRequest {
        frame,
        retained: RsiRetainedRequest {
            request_id: 61,
            op_code: RSI_READ_KEY,
        },
    };
    let mut queue = [Some(request)];
    let mut out = [0u8; 64];

    assert_eq!(
        summarize_rsi_request_queue(&queue),
        Err(LcsError::RsiQueuedRequestMetadataMismatch {
            header_request_id: 60,
            retained_request_id: 61,
            header_op_code: RSI_READ_KEY,
            retained_op_code: RSI_READ_KEY,
        }),
    );
    assert_eq!(
        lcs_core::drain_rsi_request_queue_read(&mut queue, &mut out, false, false),
        Err(LcsError::RsiQueuedRequestMetadataMismatch {
            header_request_id: 60,
            retained_request_id: 61,
            header_op_code: RSI_READ_KEY,
            retained_op_code: RSI_READ_KEY,
        }),
    );
    assert_eq!(queue, [Some(request)]);
}

#[test]
fn invalid_request_frame_is_rejected_before_queue_mutation() {
    let short = [0u8; 4];
    let mut queue = [None; 1];

    assert_eq!(
        rsi_queued_request_from_frame(&short),
        Err(LcsError::RsiMessageTooShort {
            len: 4,
            min: lcs_core::RSI_REQUEST_HEADER_LEN,
        }),
    );
    assert_eq!(
        insert_rsi_queued_request(&mut queue, &short),
        Err(LcsError::RsiMessageTooShort {
            len: 4,
            min: lcs_core::RSI_REQUEST_HEADER_LEN,
        }),
    );
    assert_eq!(queue, [None; 1]);
}
