use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BackupKeyPayload, BackupRecordKind, Guid, LcsError, NIL_GUID,
    REG_BACKUP_VALUE, parse_backup_key_payload, parse_backup_key_record,
    write_backup_key_record_frame,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const KEY_GUID: Guid = [0x44; 16];

fn system_sid() -> Vec<u8> {
    let mut sid = Vec::new();
    sid.push(1);
    sid.push(1);
    sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    sid.extend_from_slice(&18u32.to_le_bytes());
    sid
}

fn owner_only_sd() -> Vec<u8> {
    let owner = system_sid();
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd
}

fn ownerless_sd() -> Vec<u8> {
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd
}

fn key_payload(guid: Guid, flags: u32, sd: &[u8], last_write_time_ns: i64) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&guid);
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.extend_from_slice(&(sd.len() as u32).to_le_bytes());
    payload.extend_from_slice(sd);
    payload.extend_from_slice(&last_write_time_ns.to_le_bytes());
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
fn backup_key_payload_parser_validates_guid_flags_sd_and_timestamp() {
    let sd = owner_only_sd();
    let payload = key_payload(KEY_GUID, 0x03, &sd, -42);

    assert_eq!(
        parse_backup_key_payload(&payload),
        Ok(BackupKeyPayload {
            guid: KEY_GUID,
            volatile: true,
            symlink: true,
            security_descriptor: sd.as_slice(),
            last_write_time_ns: -42,
        })
    );

    let ordinary = key_payload(KEY_GUID, 0, &sd, 1000);
    let parsed = parse_backup_key_payload(&ordinary).unwrap();
    assert!(!parsed.volatile);
    assert!(!parsed.symlink);
}

#[test]
fn backup_key_record_parser_requires_key_record_kind() {
    let sd = owner_only_sd();
    let payload = key_payload(KEY_GUID, 0x01, &sd, 1000);
    let frame = record_frame(BackupRecordKind::Key, &payload);

    assert!(parse_backup_key_record(&frame).unwrap().volatile);

    let wrong = record_frame(BackupRecordKind::Value, &payload);
    assert_eq!(
        parse_backup_key_record(&wrong),
        Err(LcsError::BackupRecordKindMismatch {
            expected: BackupRecordKind::Key.code(),
            actual: REG_BACKUP_VALUE as u16,
        })
    );
}

#[test]
fn backup_key_payload_parser_rejects_malformed_fields() {
    let sd = owner_only_sd();

    let nil_guid = key_payload(NIL_GUID, 0, &sd, 1000);
    assert_eq!(
        parse_backup_key_payload(&nil_guid),
        Err(LcsError::NilKeyGuid)
    );

    let unknown_flags = key_payload(KEY_GUID, 0x04, &sd, 1000);
    assert_eq!(
        parse_backup_key_payload(&unknown_flags),
        Err(LcsError::UnknownBackupKeyFlags {
            flags: 0x04,
            unknown: 0x04,
        })
    );

    let malformed_sd = key_payload(KEY_GUID, 0, b"bad", 1000);
    assert_eq!(
        parse_backup_key_payload(&malformed_sd),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "backup_key.sd",
        })
    );

    let ownerless = ownerless_sd();
    let ownerless_payload = key_payload(KEY_GUID, 0, &ownerless, 1000);
    assert_eq!(
        parse_backup_key_payload(&ownerless_payload),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "backup_key.sd",
        })
    );
}

#[test]
fn backup_key_payload_parser_rejects_truncated_or_trailing_payloads() {
    let sd = owner_only_sd();
    let mut truncated = key_payload(KEY_GUID, 0, &sd, 1000);
    truncated.pop();
    assert_eq!(
        parse_backup_key_payload(&truncated),
        Err(LcsError::BackupPayloadTooShort {
            len: truncated.len(),
            min: truncated.len() + 1,
        })
    );

    let mut trailing = key_payload(KEY_GUID, 0, &sd, 1000);
    trailing.push(0xcc);
    assert_eq!(
        parse_backup_key_payload(&trailing),
        Err(LcsError::BackupUnexpectedPayload {
            record_type: BackupRecordKind::Key.code(),
            extra_len: 1,
        })
    );
}

#[test]
fn backup_key_writer_round_trips_without_partial_short_buffer_writes() {
    let sd = owner_only_sd();
    let mut frame = [0u8; 128];
    let len = write_backup_key_record_frame(&mut frame, KEY_GUID, true, false, &sd, 1000).unwrap();

    assert_eq!(
        parse_backup_key_record(&frame[..len]).unwrap(),
        BackupKeyPayload {
            guid: KEY_GUID,
            volatile: true,
            symlink: false,
            security_descriptor: sd.as_slice(),
            last_write_time_ns: 1000,
        }
    );

    let mut short = [0xaa; BACKUP_RECORD_HEADER_LEN + 24];
    assert_eq!(
        write_backup_key_record_frame(&mut short, KEY_GUID, true, false, &sd, 1000),
        Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: BACKUP_RECORD_HEADER_LEN + 24,
            required: BACKUP_RECORD_HEADER_LEN + 16 + 4 + 4 + sd.len() + 8,
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xaa));
}

#[test]
fn backup_key_writer_rejects_invalid_inputs_before_writing() {
    let sd = owner_only_sd();
    let mut frame = [0xaa; 128];
    assert_eq!(
        write_backup_key_record_frame(&mut frame, NIL_GUID, false, false, &sd, 1000),
        Err(LcsError::NilKeyGuid)
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));

    assert_eq!(
        write_backup_key_record_frame(&mut frame, KEY_GUID, false, false, b"bad", 1000),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "backup_key.sd",
        })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
