use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BACKUP_TRAILER_CHECKSUM_LEN, BACKUP_TRAILER_PAYLOAD_LEN,
    BackupRecordKind, BackupTrailerPayload, LcsError, REG_BACKUP_KEY, parse_backup_trailer_payload,
    parse_backup_trailer_record, write_backup_trailer_record_frame,
};

const CHECKSUM: [u8; BACKUP_TRAILER_CHECKSUM_LEN] = [0x5a; BACKUP_TRAILER_CHECKSUM_LEN];

fn trailer_payload(record_count: u64, checksum: [u8; BACKUP_TRAILER_CHECKSUM_LEN]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&record_count.to_le_bytes());
    payload.extend_from_slice(&checksum);
    payload
}

fn record_frame(kind: BackupRecordKind, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&kind.code().to_le_bytes());
    frame.extend_from_slice(&((BACKUP_RECORD_HEADER_LEN + payload.len()) as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn backup_trailer_payload_parser_validates_count_checksum_and_exact_shape() {
    let payload = trailer_payload(9, CHECKSUM);

    assert_eq!(
        parse_backup_trailer_payload(&payload),
        Ok(BackupTrailerPayload {
            record_count: 9,
            checksum: CHECKSUM,
        })
    );
}

#[test]
fn backup_trailer_record_parser_requires_trailer_record_kind() {
    let payload = trailer_payload(9, CHECKSUM);
    let frame = record_frame(BackupRecordKind::Trailer, &payload);

    assert_eq!(
        parse_backup_trailer_record(&frame).unwrap(),
        BackupTrailerPayload {
            record_count: 9,
            checksum: CHECKSUM,
        }
    );

    let wrong = record_frame(BackupRecordKind::Key, &payload);
    assert_eq!(
        parse_backup_trailer_record(&wrong),
        Err(LcsError::BackupRecordKindMismatch {
            expected: BackupRecordKind::Trailer.code(),
            actual: REG_BACKUP_KEY as u16,
        })
    );
}

#[test]
fn backup_trailer_payload_parser_rejects_impossible_record_counts() {
    assert_eq!(
        parse_backup_trailer_payload(&trailer_payload(0, CHECKSUM)),
        Err(LcsError::BackupRecordCountTooSmall { record_count: 0 })
    );
    assert_eq!(
        parse_backup_trailer_payload(&trailer_payload(1, CHECKSUM)),
        Err(LcsError::BackupRecordCountTooSmall { record_count: 1 })
    );
}

#[test]
fn backup_trailer_payload_parser_rejects_truncated_or_trailing_payloads() {
    let mut truncated_count = trailer_payload(9, CHECKSUM);
    truncated_count.truncate(7);
    assert_eq!(
        parse_backup_trailer_payload(&truncated_count),
        Err(LcsError::BackupPayloadTooShort {
            len: truncated_count.len(),
            min: 8,
        })
    );

    let mut truncated_checksum = trailer_payload(9, CHECKSUM);
    truncated_checksum.pop();
    assert_eq!(
        parse_backup_trailer_payload(&truncated_checksum),
        Err(LcsError::BackupPayloadTooShort {
            len: truncated_checksum.len(),
            min: BACKUP_TRAILER_PAYLOAD_LEN,
        })
    );

    let mut trailing = trailer_payload(9, CHECKSUM);
    trailing.push(0xcc);
    assert_eq!(
        parse_backup_trailer_payload(&trailing),
        Err(LcsError::BackupUnexpectedPayload {
            record_type: BackupRecordKind::Trailer.code(),
            extra_len: 1,
        })
    );
}

#[test]
fn backup_trailer_writer_round_trips_without_partial_short_buffer_writes() {
    let mut frame = [0u8; 64];
    let len = write_backup_trailer_record_frame(&mut frame, 9, CHECKSUM).unwrap();

    assert_eq!(len, BACKUP_RECORD_HEADER_LEN + BACKUP_TRAILER_PAYLOAD_LEN);
    assert_eq!(
        parse_backup_trailer_record(&frame[..len]).unwrap(),
        BackupTrailerPayload {
            record_count: 9,
            checksum: CHECKSUM,
        }
    );

    let mut short = [0xaa; BACKUP_RECORD_HEADER_LEN + BACKUP_TRAILER_PAYLOAD_LEN - 1];
    assert_eq!(
        write_backup_trailer_record_frame(&mut short, 9, CHECKSUM),
        Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: BACKUP_RECORD_HEADER_LEN + BACKUP_TRAILER_PAYLOAD_LEN - 1,
            required: BACKUP_RECORD_HEADER_LEN + BACKUP_TRAILER_PAYLOAD_LEN,
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xaa));
}

#[test]
fn backup_trailer_writer_rejects_invalid_inputs_before_writing() {
    let mut frame = [0xaa; 64];
    assert_eq!(
        write_backup_trailer_record_frame(&mut frame, 1, CHECKSUM),
        Err(LcsError::BackupRecordCountTooSmall { record_count: 1 })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
