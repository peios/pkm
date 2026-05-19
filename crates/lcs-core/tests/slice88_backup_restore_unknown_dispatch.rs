use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BackupRecordKind, BackupRestoreRecordDispatchDisposition,
    BackupRestoreUnknownRecordSkipPlan, LcsError, parse_backup_record_frame,
    plan_backup_restore_record_dispatch, write_backup_record_header,
};

fn frame(record_type: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = BACKUP_RECORD_HEADER_LEN + payload.len();
    let mut bytes = vec![0u8; total_len];
    write_backup_record_header(&mut bytes, record_type, total_len as u32).unwrap();
    bytes[BACKUP_RECORD_HEADER_LEN..].copy_from_slice(payload);
    bytes
}

#[test]
fn unknown_restore_records_become_explicit_skip_plans_after_framing() {
    let bytes = frame(0x9001, b"extension");
    let record = parse_backup_record_frame(&bytes).unwrap();

    assert_eq!(
        plan_backup_restore_record_dispatch(record),
        BackupRestoreRecordDispatchDisposition::SkipUnknown(BackupRestoreUnknownRecordSkipPlan {
            record_type: 0x9001,
            record_len: bytes.len() as u32,
            payload_len: b"extension".len(),
        })
    );
}

#[test]
fn known_restore_records_remain_semantic_dispatch_records() {
    let bytes = frame(BackupRecordKind::Key.code(), b"payload");
    let record = parse_backup_record_frame(&bytes).unwrap();

    assert_eq!(
        plan_backup_restore_record_dispatch(record),
        BackupRestoreRecordDispatchDisposition::Known(BackupRecordKind::Key)
    );
}

#[test]
fn malformed_unknown_records_fail_before_dispatch_planning() {
    let mut bytes = frame(0x9002, b"payload");
    let invalid_record_len = bytes.len() as u32 + 1;
    bytes[2..6].copy_from_slice(&invalid_record_len.to_le_bytes());

    assert_eq!(
        parse_backup_record_frame(&bytes),
        Err(LcsError::BackupRecordLengthMismatch {
            record_len: invalid_record_len,
            actual_len: bytes.len(),
        })
    );
}
