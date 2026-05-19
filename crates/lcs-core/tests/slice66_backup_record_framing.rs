use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BackupRecordHeader, BackupRecordKind, LcsError, REG_BACKUP_HEADER,
    REG_BACKUP_KEY, REG_BACKUP_TRAILER, parse_backup_record_frame, parse_backup_record_header,
    write_backup_record_header,
};

fn frame(record_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&record_type.to_le_bytes());
    bytes.extend_from_slice(&((BACKUP_RECORD_HEADER_LEN + payload.len()) as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn backup_record_header_is_six_bytes_and_little_endian() {
    let bytes = frame(REG_BACKUP_KEY as u16, b"payload");

    assert_eq!(
        parse_backup_record_header(&bytes),
        Ok(BackupRecordHeader {
            record_type: REG_BACKUP_KEY as u16,
            record_len: (BACKUP_RECORD_HEADER_LEN + b"payload".len()) as u32,
        })
    );
}

#[test]
fn backup_record_frame_returns_payload_and_known_kind() {
    let bytes = frame(REG_BACKUP_HEADER as u16, b"header-body");
    let parsed = parse_backup_record_frame(&bytes).unwrap();

    assert_eq!(parsed.kind, BackupRecordKind::Header);
    assert_eq!(parsed.header.record_type, REG_BACKUP_HEADER as u16);
    assert_eq!(parsed.payload, b"header-body");

    let trailer = frame(REG_BACKUP_TRAILER as u16, b"trailer-body");
    assert_eq!(
        parse_backup_record_frame(&trailer).unwrap().kind,
        BackupRecordKind::Trailer,
    );
}

#[test]
fn backup_record_frame_preserves_unknown_record_codes_for_skipping() {
    let bytes = frame(0x4321, b"optional-extension");
    let parsed = parse_backup_record_frame(&bytes).unwrap();

    assert_eq!(parsed.kind, BackupRecordKind::Unknown(0x4321));
    assert_eq!(parsed.kind.code(), 0x4321);
    assert_eq!(parsed.payload, b"optional-extension");
}

#[test]
fn backup_record_frame_rejects_short_small_and_mismatched_frames() {
    assert_eq!(
        parse_backup_record_header(&[0; BACKUP_RECORD_HEADER_LEN - 1]),
        Err(LcsError::BackupRecordHeaderTooShort {
            len: BACKUP_RECORD_HEADER_LEN - 1,
        })
    );

    let mut too_small = frame(REG_BACKUP_KEY as u16, b"");
    too_small[2..6].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(
        parse_backup_record_frame(&too_small),
        Err(LcsError::BackupRecordTooSmall { record_len: 5 })
    );

    let mut mismatch = frame(REG_BACKUP_KEY as u16, b"payload");
    mismatch[2..6].copy_from_slice(&99u32.to_le_bytes());
    assert_eq!(
        parse_backup_record_frame(&mismatch),
        Err(LcsError::BackupRecordLengthMismatch {
            record_len: 99,
            actual_len: BACKUP_RECORD_HEADER_LEN + b"payload".len(),
        })
    );
}

#[test]
fn backup_record_header_writer_uses_little_endian_and_checks_bounds() {
    let mut bytes = [0xaa; BACKUP_RECORD_HEADER_LEN];
    write_backup_record_header(&mut bytes, BackupRecordKind::Value.code(), 42).unwrap();

    assert_eq!(
        parse_backup_record_header(&bytes),
        Ok(BackupRecordHeader {
            record_type: BackupRecordKind::Value.code(),
            record_len: 42,
        })
    );

    let mut short = [0xaa; BACKUP_RECORD_HEADER_LEN - 1];
    assert_eq!(
        write_backup_record_header(&mut short, BackupRecordKind::Value.code(), 42),
        Err(LcsError::BackupRecordHeaderBufferTooSmall {
            len: BACKUP_RECORD_HEADER_LEN - 1,
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xaa));

    assert_eq!(
        write_backup_record_header(&mut bytes, BackupRecordKind::Value.code(), 5),
        Err(LcsError::BackupRecordTooSmall { record_len: 5 })
    );
}
