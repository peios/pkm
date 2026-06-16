use crate::common::{limits};
use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BackupRecordKind, BackupValuePayload, Guid, LcsError,
    NIL_GUID, REG_BACKUP_KEY, REG_BINARY, REG_TOMBSTONE, ValidatedValueType,
    parse_backup_value_payload, parse_backup_value_record, write_backup_value_record_frame,
};

const KEY_GUID: Guid = [0x22; 16];


fn value_payload(
    key_guid: Guid,
    name: &[u8],
    value_type: u32,
    data: &[u8],
    layer_name: &[u8],
    sequence: u64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&key_guid);
    payload.extend_from_slice(&(name.len() as u32).to_le_bytes());
    payload.extend_from_slice(name);
    payload.extend_from_slice(&value_type.to_le_bytes());
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
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
fn backup_value_payload_parser_validates_normal_default_and_tombstone_values() {
    let normal = value_payload(KEY_GUID, b"Setting", REG_BINARY, b"payload", b"base", 88);
    assert_eq!(
        parse_backup_value_payload(&limits(), &normal),
        Ok(BackupValuePayload {
            key_guid: KEY_GUID,
            name: "Setting",
            value_type: ValidatedValueType::Normal(lcs_core::RegistryValueType::Binary),
            data: b"payload",
            layer_name: "base",
            sequence: 88,
        })
    );

    let default_value = value_payload(KEY_GUID, b"", REG_BINARY, b"payload", b"base", 89);
    assert_eq!(
        parse_backup_value_payload(&limits(), &default_value)
            .unwrap()
            .name,
        ""
    );

    let tombstone = value_payload(KEY_GUID, b"Setting", REG_TOMBSTONE, b"", b"base", 90);
    assert_eq!(
        parse_backup_value_payload(&limits(), &tombstone)
            .unwrap()
            .value_type,
        ValidatedValueType::Tombstone
    );
}

#[test]
fn backup_value_record_parser_requires_value_record_kind() {
    let payload = value_payload(KEY_GUID, b"Setting", REG_BINARY, b"payload", b"base", 88);
    let frame = record_frame(BackupRecordKind::Value, &payload);

    assert_eq!(
        parse_backup_value_record(&limits(), &frame).unwrap().name,
        "Setting"
    );

    let wrong = record_frame(BackupRecordKind::Key, &payload);
    assert_eq!(
        parse_backup_value_record(&limits(), &wrong),
        Err(LcsError::BackupRecordKindMismatch {
            expected: BackupRecordKind::Value.code(),
            actual: REG_BACKUP_KEY as u16,
        })
    );
}

#[test]
fn backup_value_payload_parser_rejects_malformed_fields() {
    let nil_key = value_payload(NIL_GUID, b"Setting", REG_BINARY, b"payload", b"base", 88);
    assert_eq!(
        parse_backup_value_payload(&limits(), &nil_key),
        Err(LcsError::NilKeyGuid)
    );

    let bad_name = value_payload(KEY_GUID, b"bad\0name", REG_BINARY, b"payload", b"base", 88);
    assert_eq!(
        parse_backup_value_payload(&limits(), &bad_name),
        Err(LcsError::NullByte {
            field: "value_name",
        })
    );

    let bad_layer = value_payload(
        KEY_GUID,
        b"Setting",
        REG_BINARY,
        b"payload",
        b"bad/layer",
        88,
    );
    assert_eq!(
        parse_backup_value_payload(&limits(), &bad_layer),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );

    let unknown_type_code = 0xdead_beef;
    let unknown_type = value_payload(
        KEY_GUID,
        b"Setting",
        unknown_type_code,
        b"payload",
        b"base",
        88,
    );
    assert_eq!(
        parse_backup_value_payload(&limits(), &unknown_type),
        Err(LcsError::UnknownValueType(unknown_type_code))
    );

    let nonempty_tombstone = value_payload(KEY_GUID, b"Setting", REG_TOMBSTONE, b"x", b"base", 88);
    assert_eq!(
        parse_backup_value_payload(&limits(), &nonempty_tombstone),
        Err(LcsError::TombstoneDataMustBeEmpty { len: 1 })
    );
}

#[test]
fn backup_value_payload_parser_enforces_value_size_and_exact_payload() {
    let mut limited = limits();
    limited.max_value_size = 3;
    let too_large = value_payload(KEY_GUID, b"Setting", REG_BINARY, b"1234", b"base", 88);
    assert_eq!(
        parse_backup_value_payload(&limited, &too_large),
        Err(LcsError::ValueDataTooLarge { len: 4, max: 3 })
    );

    let mut truncated = value_payload(KEY_GUID, b"Setting", REG_BINARY, b"payload", b"base", 88);
    truncated.pop();
    assert_eq!(
        parse_backup_value_payload(&limits(), &truncated),
        Err(LcsError::BackupPayloadTooShort {
            len: truncated.len(),
            min: truncated.len() + 1,
        })
    );

    let mut trailing = value_payload(KEY_GUID, b"Setting", REG_BINARY, b"payload", b"base", 88);
    trailing.push(0xcc);
    assert_eq!(
        parse_backup_value_payload(&limits(), &trailing),
        Err(LcsError::BackupUnexpectedPayload {
            record_type: BackupRecordKind::Value.code(),
            extra_len: 1,
        })
    );
}

#[test]
fn backup_value_record_writer_round_trips_without_partial_short_buffer_writes() {
    let mut frame = [0u8; 160];
    let len = write_backup_value_record_frame(
        &limits(),
        &mut frame,
        KEY_GUID,
        "Setting",
        REG_BINARY,
        b"payload",
        "base",
        88,
    )
    .unwrap();

    assert_eq!(
        parse_backup_value_record(&limits(), &frame[..len]).unwrap(),
        BackupValuePayload {
            key_guid: KEY_GUID,
            name: "Setting",
            value_type: ValidatedValueType::Normal(lcs_core::RegistryValueType::Binary),
            data: b"payload",
            layer_name: "base",
            sequence: 88,
        }
    );

    let mut short = [0xaa; BACKUP_RECORD_HEADER_LEN + 32];
    assert_eq!(
        write_backup_value_record_frame(
            &limits(),
            &mut short,
            KEY_GUID,
            "Setting",
            REG_BINARY,
            b"payload",
            "base",
            88,
        ),
        Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: BACKUP_RECORD_HEADER_LEN + 32,
            required: BACKUP_RECORD_HEADER_LEN
                + 16
                + 4
                + b"Setting".len()
                + 4
                + 4
                + b"payload".len()
                + 4
                + b"base".len()
                + 8,
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xaa));
}

#[test]
fn backup_value_record_writer_rejects_invalid_inputs_before_writing() {
    let mut frame = [0xaa; 160];
    assert_eq!(
        write_backup_value_record_frame(
            &limits(),
            &mut frame,
            NIL_GUID,
            "Setting",
            REG_BINARY,
            b"payload",
            "base",
            88,
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));

    assert_eq!(
        write_backup_value_record_frame(
            &limits(),
            &mut frame,
            KEY_GUID,
            "Setting",
            REG_TOMBSTONE,
            b"x",
            "base",
            88,
        ),
        Err(LcsError::TombstoneDataMustBeEmpty { len: 1 })
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
