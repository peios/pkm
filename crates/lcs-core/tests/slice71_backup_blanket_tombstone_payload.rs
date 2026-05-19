use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BackupBlanketTombstonePayload, BackupRecordKind, Guid, LcsError,
    LcsLimits, NIL_GUID, REG_BACKUP_KEY, parse_backup_blanket_tombstone_payload,
    parse_backup_blanket_tombstone_record, write_backup_blanket_tombstone_record_frame,
};

const KEY_GUID: Guid = [0x33; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn blanket_payload(key_guid: Guid, layer_name: &[u8], sequence: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&key_guid);
    payload.extend_from_slice(&(layer_name.len() as u32).to_le_bytes());
    payload.extend_from_slice(layer_name);
    payload.extend_from_slice(&sequence.to_le_bytes());
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
fn backup_blanket_tombstone_payload_parser_validates_key_layer_and_sequence() {
    let payload = blanket_payload(KEY_GUID, b"base", 101);
    assert_eq!(
        parse_backup_blanket_tombstone_payload(&limits(), &payload),
        Ok(BackupBlanketTombstonePayload {
            key_guid: KEY_GUID,
            layer_name: "base",
            sequence: 101,
        })
    );
}

#[test]
fn backup_blanket_tombstone_record_parser_requires_blanket_record_kind() {
    let payload = blanket_payload(KEY_GUID, b"base", 101);
    let frame = record_frame(BackupRecordKind::BlanketTombstone, &payload);

    assert_eq!(
        parse_backup_blanket_tombstone_record(&limits(), &frame)
            .unwrap()
            .sequence,
        101
    );

    let wrong = record_frame(BackupRecordKind::Key, &payload);
    assert_eq!(
        parse_backup_blanket_tombstone_record(&limits(), &wrong),
        Err(LcsError::BackupRecordKindMismatch {
            expected: BackupRecordKind::BlanketTombstone.code(),
            actual: REG_BACKUP_KEY as u16,
        })
    );
}

#[test]
fn backup_blanket_tombstone_payload_parser_rejects_malformed_fields() {
    let nil_key = blanket_payload(NIL_GUID, b"base", 101);
    assert_eq!(
        parse_backup_blanket_tombstone_payload(&limits(), &nil_key),
        Err(LcsError::NilKeyGuid)
    );

    let bad_layer = blanket_payload(KEY_GUID, b"bad/layer", 101);
    assert_eq!(
        parse_backup_blanket_tombstone_payload(&limits(), &bad_layer),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}

#[test]
fn backup_blanket_tombstone_payload_parser_rejects_truncated_or_trailing_payloads() {
    let mut truncated = blanket_payload(KEY_GUID, b"base", 101);
    truncated.pop();
    assert_eq!(
        parse_backup_blanket_tombstone_payload(&limits(), &truncated),
        Err(LcsError::BackupPayloadTooShort {
            len: truncated.len(),
            min: truncated.len() + 1,
        })
    );

    let mut trailing = blanket_payload(KEY_GUID, b"base", 101);
    trailing.push(0xcc);
    assert_eq!(
        parse_backup_blanket_tombstone_payload(&limits(), &trailing),
        Err(LcsError::BackupUnexpectedPayload {
            record_type: BackupRecordKind::BlanketTombstone.code(),
            extra_len: 1,
        })
    );
}

#[test]
fn backup_blanket_tombstone_writer_round_trips_without_partial_short_buffer_writes() {
    let mut frame = [0u8; 96];
    let len =
        write_backup_blanket_tombstone_record_frame(&limits(), &mut frame, KEY_GUID, "base", 101)
            .unwrap();

    assert_eq!(
        parse_backup_blanket_tombstone_record(&limits(), &frame[..len]).unwrap(),
        BackupBlanketTombstonePayload {
            key_guid: KEY_GUID,
            layer_name: "base",
            sequence: 101,
        }
    );

    let mut short = [0xaa; BACKUP_RECORD_HEADER_LEN + 16];
    assert_eq!(
        write_backup_blanket_tombstone_record_frame(&limits(), &mut short, KEY_GUID, "base", 101),
        Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: BACKUP_RECORD_HEADER_LEN + 16,
            required: BACKUP_RECORD_HEADER_LEN + 16 + 4 + b"base".len() + 8,
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xaa));
}

#[test]
fn backup_blanket_tombstone_writer_rejects_invalid_inputs_before_writing() {
    let mut frame = [0xaa; 96];
    assert_eq!(
        write_backup_blanket_tombstone_record_frame(&limits(), &mut frame, NIL_GUID, "base", 101),
        Err(LcsError::NilKeyGuid)
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));

    assert_eq!(
        write_backup_blanket_tombstone_record_frame(
            &limits(),
            &mut frame,
            KEY_GUID,
            "bad/layer",
            101,
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
