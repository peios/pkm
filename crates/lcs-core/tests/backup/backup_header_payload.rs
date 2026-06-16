use crate::common::{limits};
use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BackupHeaderPayload, BackupRecordKind, LcsError,
    REG_BACKUP_KEY, REG_BACKUP_MAGIC, parse_backup_header_payload, parse_backup_header_record,
    write_backup_header_record_frame,
};

const SUPPORTED_VERSION: u32 = 21;
const ROOT_GUID: [u8; 16] = [0x5a; 16];


fn header_payload(
    magic: &[u8; 8],
    format_version: u32,
    min_reader_version: u32,
    timestamp_ns: i64,
    root_guid: [u8; 16],
    hive_name: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(magic);
    payload.extend_from_slice(&format_version.to_le_bytes());
    payload.extend_from_slice(&min_reader_version.to_le_bytes());
    payload.extend_from_slice(&timestamp_ns.to_le_bytes());
    payload.extend_from_slice(&root_guid);
    payload.extend_from_slice(&(hive_name.len() as u32).to_le_bytes());
    payload.extend_from_slice(hive_name);
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
fn backup_header_payload_parser_validates_magic_versions_timestamp_guid_and_hive() {
    let payload = header_payload(&REG_BACKUP_MAGIC, 21, 20, -12345, ROOT_GUID, b"Machine");

    assert_eq!(
        parse_backup_header_payload(&limits(), &payload, SUPPORTED_VERSION),
        Ok(BackupHeaderPayload {
            format_version: 21,
            min_reader_version: 20,
            timestamp_ns: -12345,
            root_guid: ROOT_GUID,
            hive_name: "Machine",
        })
    );
}

#[test]
fn backup_header_record_parser_requires_header_record_kind() {
    let payload = header_payload(&REG_BACKUP_MAGIC, 21, 20, 12345, ROOT_GUID, b"Machine");
    let frame = record_frame(BackupRecordKind::Header, &payload);

    assert_eq!(
        parse_backup_header_record(&limits(), &frame, SUPPORTED_VERSION)
            .unwrap()
            .hive_name,
        "Machine"
    );

    let wrong = record_frame(BackupRecordKind::Key, &payload);
    assert_eq!(
        parse_backup_header_record(&limits(), &wrong, SUPPORTED_VERSION),
        Err(LcsError::BackupRecordKindMismatch {
            expected: BackupRecordKind::Header.code(),
            actual: REG_BACKUP_KEY as u16,
        })
    );
}

#[test]
fn backup_header_payload_parser_rejects_bad_magic_newer_reader_and_bad_hive() {
    let bad_magic = *b"NOT-REG!";
    let payload = header_payload(&bad_magic, 21, 20, 0, ROOT_GUID, b"Machine");
    assert_eq!(
        parse_backup_header_payload(&limits(), &payload, SUPPORTED_VERSION),
        Err(LcsError::InvalidBackupMagic { actual: bad_magic })
    );

    let newer = header_payload(&REG_BACKUP_MAGIC, 21, 22, 0, ROOT_GUID, b"Machine");
    assert_eq!(
        parse_backup_header_payload(&limits(), &newer, SUPPORTED_VERSION),
        Err(LcsError::UnsupportedBackupMinReaderVersion {
            min_reader_version: 22,
            supported_version: SUPPORTED_VERSION,
        })
    );

    let bad_hive = header_payload(&REG_BACKUP_MAGIC, 21, 20, 0, ROOT_GUID, b"bad/name");
    assert!(parse_backup_header_payload(&limits(), &bad_hive, SUPPORTED_VERSION).is_err());
}

#[test]
fn backup_header_payload_parser_rejects_truncated_or_trailing_payloads() {
    let mut truncated = header_payload(&REG_BACKUP_MAGIC, 21, 20, 0, ROOT_GUID, b"Machine");
    truncated.pop();
    assert_eq!(
        parse_backup_header_payload(&limits(), &truncated, SUPPORTED_VERSION),
        Err(LcsError::BackupPayloadTooShort {
            len: truncated.len(),
            min: truncated.len() + 1,
        })
    );

    let mut trailing = header_payload(&REG_BACKUP_MAGIC, 21, 20, 0, ROOT_GUID, b"Machine");
    trailing.push(0xcc);
    assert_eq!(
        parse_backup_header_payload(&limits(), &trailing, SUPPORTED_VERSION),
        Err(LcsError::BackupUnexpectedPayload {
            record_type: BackupRecordKind::Header.code(),
            extra_len: 1,
        })
    );
}

#[test]
fn backup_header_record_writer_round_trips_without_partial_short_buffer_writes() {
    let mut frame = [0u8; 128];
    let len =
        write_backup_header_record_frame(&limits(), &mut frame, 21, 20, 999, ROOT_GUID, "Machine")
            .unwrap();

    assert_eq!(
        parse_backup_header_record(&limits(), &frame[..len], SUPPORTED_VERSION).unwrap(),
        BackupHeaderPayload {
            format_version: 21,
            min_reader_version: 20,
            timestamp_ns: 999,
            root_guid: ROOT_GUID,
            hive_name: "Machine",
        }
    );

    let mut short = [0xaa; BACKUP_RECORD_HEADER_LEN + 4];
    assert_eq!(
        write_backup_header_record_frame(&limits(), &mut short, 21, 20, 999, ROOT_GUID, "Machine"),
        Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: BACKUP_RECORD_HEADER_LEN + 4,
            required: BACKUP_RECORD_HEADER_LEN + 8 + 4 + 4 + 8 + 16 + 4 + b"Machine".len(),
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xaa));
}
