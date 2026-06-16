use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BackupLayerManifestPayload, BackupRecordKind, LcsError, LcsLimits,
    REG_BACKUP_KEY, parse_backup_layer_manifest_payload, parse_backup_layer_manifest_record,
    write_backup_layer_manifest_record_frame,
};

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn system_sid() -> Vec<u8> {
    let mut sid = Vec::new();
    sid.push(1);
    sid.push(1);
    sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    sid.extend_from_slice(&18u32.to_le_bytes());
    sid
}

fn layer_payload(name: &[u8], precedence: u32, enabled: u8, owner_sid: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(name.len() as u32).to_le_bytes());
    payload.extend_from_slice(name);
    payload.extend_from_slice(&precedence.to_le_bytes());
    payload.push(enabled);
    payload.extend_from_slice(&(owner_sid.len() as u32).to_le_bytes());
    payload.extend_from_slice(owner_sid);
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
fn backup_layer_manifest_payload_parser_validates_name_enabled_and_owner_sid() {
    let owner = system_sid();
    let payload = layer_payload(b"role-web", 12, 1, &owner);

    assert_eq!(
        parse_backup_layer_manifest_payload(&limits(), &payload),
        Ok(BackupLayerManifestPayload {
            name: "role-web",
            precedence: 12,
            enabled: true,
            owner_sid: owner.as_slice(),
        })
    );

    let disabled = layer_payload(b"role-web", 0, 0, &owner);
    assert!(
        !parse_backup_layer_manifest_payload(&limits(), &disabled)
            .unwrap()
            .enabled
    );
}

#[test]
fn backup_layer_manifest_record_parser_requires_layer_record_kind() {
    let owner = system_sid();
    let payload = layer_payload(b"role-web", 12, 1, &owner);
    let frame = record_frame(BackupRecordKind::LayerManifest, &payload);

    assert_eq!(
        parse_backup_layer_manifest_record(&limits(), &frame)
            .unwrap()
            .name,
        "role-web"
    );

    let wrong = record_frame(BackupRecordKind::Key, &payload);
    assert_eq!(
        parse_backup_layer_manifest_record(&limits(), &wrong),
        Err(LcsError::BackupRecordKindMismatch {
            expected: BackupRecordKind::LayerManifest.code(),
            actual: REG_BACKUP_KEY as u16,
        })
    );
}

#[test]
fn backup_layer_manifest_payload_parser_rejects_bad_names_booleans_and_owner_sids() {
    let owner = system_sid();

    let bad_name = layer_payload(b"bad/name", 12, 1, &owner);
    assert!(parse_backup_layer_manifest_payload(&limits(), &bad_name).is_err());

    let bad_enabled = layer_payload(b"role-web", 12, 2, &owner);
    assert_eq!(
        parse_backup_layer_manifest_payload(&limits(), &bad_enabled),
        Err(LcsError::InvalidBooleanFlag {
            field: "backup_layer.enabled",
            value: 2,
        })
    );

    let bad_owner = layer_payload(b"role-web", 12, 1, b"bad");
    assert_eq!(
        parse_backup_layer_manifest_payload(&limits(), &bad_owner),
        Err(LcsError::MalformedBackupSid {
            field: "backup_layer.owner",
        })
    );
}

#[test]
fn backup_layer_manifest_payload_parser_rejects_truncated_or_trailing_payloads() {
    let owner = system_sid();
    let mut truncated = layer_payload(b"role-web", 12, 1, &owner);
    truncated.pop();
    assert_eq!(
        parse_backup_layer_manifest_payload(&limits(), &truncated),
        Err(LcsError::BackupPayloadTooShort {
            len: truncated.len(),
            min: truncated.len() + 1,
        })
    );

    let mut trailing = layer_payload(b"role-web", 12, 1, &owner);
    trailing.push(0xcc);
    assert_eq!(
        parse_backup_layer_manifest_payload(&limits(), &trailing),
        Err(LcsError::BackupUnexpectedPayload {
            record_type: BackupRecordKind::LayerManifest.code(),
            extra_len: 1,
        })
    );
}

#[test]
fn backup_layer_manifest_record_writer_round_trips_without_partial_short_buffer_writes() {
    let owner = system_sid();
    let mut frame = [0u8; 128];
    let len = write_backup_layer_manifest_record_frame(
        &limits(),
        &mut frame,
        "role-web",
        12,
        true,
        &owner,
    )
    .unwrap();

    assert_eq!(
        parse_backup_layer_manifest_record(&limits(), &frame[..len]).unwrap(),
        BackupLayerManifestPayload {
            name: "role-web",
            precedence: 12,
            enabled: true,
            owner_sid: owner.as_slice(),
        }
    );

    let mut short = [0xaa; BACKUP_RECORD_HEADER_LEN + 8];
    assert_eq!(
        write_backup_layer_manifest_record_frame(
            &limits(),
            &mut short,
            "role-web",
            12,
            true,
            &owner,
        ),
        Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: BACKUP_RECORD_HEADER_LEN + 8,
            required: BACKUP_RECORD_HEADER_LEN + 4 + b"role-web".len() + 4 + 1 + 4 + owner.len(),
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xaa));
}
