use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BackupRecordKind, BackupRestoreRecordDispatchDisposition,
    BackupRestoreUnknownRecordSkipPlan, LcsError, LcsLimits, REG_BACKUP_MAGIC,
    parse_backup_header_record, parse_backup_record_frame, plan_backup_restore_record_dispatch,
    write_backup_record_header,
};

const SUPPORTED_VERSION: u32 = 21;
const ROOT_GUID: [u8; 16] = [0x34; 16];

fn frame(record_type: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = BACKUP_RECORD_HEADER_LEN + payload.len();
    let mut bytes = vec![0u8; total_len];
    write_backup_record_header(&mut bytes, record_type, total_len as u32).unwrap();
    bytes[BACKUP_RECORD_HEADER_LEN..].copy_from_slice(payload);
    bytes
}

fn header_frame(min_reader_version: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&REG_BACKUP_MAGIC);
    payload.extend_from_slice(&SUPPORTED_VERSION.to_le_bytes());
    payload.extend_from_slice(&min_reader_version.to_le_bytes());
    payload.extend_from_slice(&123_456i64.to_le_bytes());
    payload.extend_from_slice(&ROOT_GUID);
    payload.extend_from_slice(&7u32.to_le_bytes());
    payload.extend_from_slice(b"Machine");
    frame(BackupRecordKind::Header.code(), &payload)
}

fn plan_after_header(
    header: &[u8],
    record: &[u8],
) -> Result<BackupRestoreRecordDispatchDisposition, LcsError> {
    let _header = parse_backup_header_record(&LcsLimits::default(), header, SUPPORTED_VERSION)?;
    let record = parse_backup_record_frame(record)?;
    Ok(plan_backup_restore_record_dispatch(record))
}

#[test]
fn unsupported_min_reader_version_rejects_before_unknown_skip_dispatch() {
    let header = header_frame(SUPPORTED_VERSION + 1);
    let unknown = frame(0x9001, b"required-extension");

    assert_eq!(
        plan_after_header(&header, &unknown),
        Err(LcsError::UnsupportedBackupMinReaderVersion {
            min_reader_version: SUPPORTED_VERSION + 1,
            supported_version: SUPPORTED_VERSION,
        })
    );
}

#[test]
fn supported_min_reader_version_allows_opaque_unknown_skip_plan() {
    let header = header_frame(SUPPORTED_VERSION);
    let unknown = frame(0x9002, b"optional-extension-bytes");

    assert_eq!(
        plan_after_header(&header, &unknown),
        Ok(BackupRestoreRecordDispatchDisposition::SkipUnknown(
            BackupRestoreUnknownRecordSkipPlan {
                record_type: 0x9002,
                record_len: unknown.len() as u32,
                payload_len: b"optional-extension-bytes".len(),
            }
        ))
    );
}

#[test]
fn unknown_skip_requires_valid_common_framing_after_version_gate() {
    let header = header_frame(SUPPORTED_VERSION);

    let mut too_small = vec![0u8; BACKUP_RECORD_HEADER_LEN];
    too_small[0..2].copy_from_slice(&0x9003u16.to_le_bytes());
    too_small[2..6].copy_from_slice(&((BACKUP_RECORD_HEADER_LEN - 1) as u32).to_le_bytes());
    assert_eq!(
        plan_after_header(&header, &too_small),
        Err(LcsError::BackupRecordTooSmall {
            record_len: (BACKUP_RECORD_HEADER_LEN - 1) as u32,
        })
    );

    let mut truncated = frame(0x9004, b"truncated");
    let declared_len = truncated.len() as u32 + 1;
    truncated[2..6].copy_from_slice(&declared_len.to_le_bytes());
    assert_eq!(
        plan_after_header(&header, &truncated),
        Err(LcsError::BackupRecordLengthMismatch {
            record_len: declared_len,
            actual_len: truncated.len(),
        })
    );
}
