use lcs_core::{
    LcsError, RSI_DELETE_LAYER, RSI_OK, RsiRetainedRequest,
    parse_rsi_delete_layer_success_response_payload, rsi_response_op_code,
    validate_rsi_delete_layer_orphaned_guids,
};

fn response_frame(request_id: u64) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(
        &rsi_response_op_code(RSI_DELETE_LAYER)
            .unwrap()
            .to_le_bytes(),
    );
    frame.extend_from_slice(&RSI_OK.to_le_bytes());
    frame
}

fn finish_total_len(frame: &mut [u8]) {
    let total_len = frame.len() as u32;
    frame[..4].copy_from_slice(&total_len.to_le_bytes());
}

fn delete_layer_response(request_id: u64, guids: &[[u8; 16]]) -> Vec<u8> {
    let mut frame = response_frame(request_id);
    frame.extend_from_slice(&(guids.len() as u32).to_le_bytes());
    for guid in guids {
        frame.extend_from_slice(guid);
    }
    finish_total_len(&mut frame);
    frame
}

fn parse_frame(
    request_id: u64,
    frame: &[u8],
) -> lcs_core::RsiDeleteLayerSuccessResponsePayload<'_> {
    parse_rsi_delete_layer_success_response_payload(
        frame,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_DELETE_LAYER,
        },
    )
    .unwrap()
}

#[test]
fn delete_layer_orphan_guid_validation_accepts_empty_and_unique_sets() {
    let empty = delete_layer_response(801, &[]);
    let parsed = parse_frame(801, &empty);
    validate_rsi_delete_layer_orphaned_guids(&parsed).unwrap();

    let unique = delete_layer_response(802, &[[0x11; 16], [0x22; 16], [0x33; 16]]);
    let parsed = parse_frame(802, &unique);
    validate_rsi_delete_layer_orphaned_guids(&parsed).unwrap();
}

#[test]
fn delete_layer_orphan_guid_validation_rejects_nil_guid() {
    let frame = delete_layer_response(803, &[[0x44; 16], [0; 16]]);
    let parsed = parse_frame(803, &frame);
    assert_eq!(
        validate_rsi_delete_layer_orphaned_guids(&parsed),
        Err(LcsError::RsiDeleteLayerOrphanedGuidNil)
    );
}

#[test]
fn delete_layer_orphan_guid_validation_rejects_duplicate_guid() {
    let duplicate = [0x55; 16];
    let frame = delete_layer_response(804, &[[0x66; 16], duplicate, [0x77; 16], duplicate]);
    let parsed = parse_frame(804, &frame);
    assert_eq!(
        validate_rsi_delete_layer_orphaned_guids(&parsed),
        Err(LcsError::RsiDeleteLayerOrphanedGuidDuplicate { guid: duplicate })
    );
}
