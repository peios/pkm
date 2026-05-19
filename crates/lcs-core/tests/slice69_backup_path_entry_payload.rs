use lcs_core::{
    BACKUP_RECORD_HEADER_LEN, BackupPathEntryPayload, BackupRecordKind, Guid, LcsError, LcsLimits,
    NIL_GUID, PathTarget, REG_BACKUP_KEY, parse_backup_path_entry_payload,
    parse_backup_path_entry_record, write_backup_path_entry_record_frame,
};

const PARENT_GUID: Guid = [0x10; 16];
const CHILD_GUID: Guid = [0x11; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn path_entry_payload(
    parent_guid: Guid,
    child_name: &[u8],
    child_guid: Guid,
    layer_name: &[u8],
    sequence: u64,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&parent_guid);
    payload.extend_from_slice(&(child_name.len() as u32).to_le_bytes());
    payload.extend_from_slice(child_name);
    payload.extend_from_slice(&child_guid);
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
fn backup_path_entry_payload_parser_validates_visible_and_hidden_entries() {
    let visible = path_entry_payload(PARENT_GUID, b"Software", CHILD_GUID, b"base", 55);
    assert_eq!(
        parse_backup_path_entry_payload(&limits(), &visible),
        Ok(BackupPathEntryPayload {
            parent_guid: PARENT_GUID,
            child_name: "Software",
            target: PathTarget::Guid(CHILD_GUID),
            layer_name: "base",
            sequence: 55,
        })
    );

    let hidden = path_entry_payload(PARENT_GUID, b"Software", NIL_GUID, b"base", 56);
    assert_eq!(
        parse_backup_path_entry_payload(&limits(), &hidden)
            .unwrap()
            .target,
        PathTarget::Hidden
    );
}

#[test]
fn backup_path_entry_record_parser_requires_path_entry_record_kind() {
    let payload = path_entry_payload(PARENT_GUID, b"Software", CHILD_GUID, b"base", 55);
    let frame = record_frame(BackupRecordKind::PathEntry, &payload);

    assert_eq!(
        parse_backup_path_entry_record(&limits(), &frame)
            .unwrap()
            .child_name,
        "Software"
    );

    let wrong = record_frame(BackupRecordKind::Key, &payload);
    assert_eq!(
        parse_backup_path_entry_record(&limits(), &wrong),
        Err(LcsError::BackupRecordKindMismatch {
            expected: BackupRecordKind::PathEntry.code(),
            actual: REG_BACKUP_KEY as u16,
        })
    );
}

#[test]
fn backup_path_entry_payload_parser_rejects_malformed_fields() {
    let nil_parent = path_entry_payload(NIL_GUID, b"Software", CHILD_GUID, b"base", 55);
    assert_eq!(
        parse_backup_path_entry_payload(&limits(), &nil_parent),
        Err(LcsError::NilParentGuid)
    );

    let bad_child = path_entry_payload(PARENT_GUID, b"Bad/Name", CHILD_GUID, b"base", 55);
    assert_eq!(
        parse_backup_path_entry_payload(&limits(), &bad_child),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );

    let bad_layer = path_entry_payload(PARENT_GUID, b"Software", CHILD_GUID, b"bad/layer", 55);
    assert_eq!(
        parse_backup_path_entry_payload(&limits(), &bad_layer),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}

#[test]
fn backup_path_entry_payload_parser_rejects_truncated_or_trailing_payloads() {
    let mut truncated = path_entry_payload(PARENT_GUID, b"Software", CHILD_GUID, b"base", 55);
    truncated.pop();
    assert_eq!(
        parse_backup_path_entry_payload(&limits(), &truncated),
        Err(LcsError::BackupPayloadTooShort {
            len: truncated.len(),
            min: truncated.len() + 1,
        })
    );

    let mut trailing = path_entry_payload(PARENT_GUID, b"Software", CHILD_GUID, b"base", 55);
    trailing.push(0xcc);
    assert_eq!(
        parse_backup_path_entry_payload(&limits(), &trailing),
        Err(LcsError::BackupUnexpectedPayload {
            record_type: BackupRecordKind::PathEntry.code(),
            extra_len: 1,
        })
    );
}

#[test]
fn backup_path_entry_record_writer_round_trips_without_partial_short_buffer_writes() {
    let mut frame = [0u8; 128];
    let len = write_backup_path_entry_record_frame(
        &limits(),
        &mut frame,
        PARENT_GUID,
        "Software",
        PathTarget::Guid(CHILD_GUID),
        "base",
        55,
    )
    .unwrap();

    assert_eq!(
        parse_backup_path_entry_record(&limits(), &frame[..len]).unwrap(),
        BackupPathEntryPayload {
            parent_guid: PARENT_GUID,
            child_name: "Software",
            target: PathTarget::Guid(CHILD_GUID),
            layer_name: "base",
            sequence: 55,
        }
    );

    let hidden_len = write_backup_path_entry_record_frame(
        &limits(),
        &mut frame,
        PARENT_GUID,
        "Software",
        PathTarget::Hidden,
        "base",
        56,
    )
    .unwrap();
    assert_eq!(
        parse_backup_path_entry_record(&limits(), &frame[..hidden_len])
            .unwrap()
            .target,
        PathTarget::Hidden
    );

    let mut short = [0xaa; BACKUP_RECORD_HEADER_LEN + 24];
    assert_eq!(
        write_backup_path_entry_record_frame(
            &limits(),
            &mut short,
            PARENT_GUID,
            "Software",
            PathTarget::Guid(CHILD_GUID),
            "base",
            55,
        ),
        Err(LcsError::BackupRecordFrameBufferTooSmall {
            len: BACKUP_RECORD_HEADER_LEN + 24,
            required: BACKUP_RECORD_HEADER_LEN
                + 16
                + 4
                + b"Software".len()
                + 16
                + 4
                + b"base".len()
                + 8,
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xaa));
}

#[test]
fn backup_path_entry_record_writer_rejects_nil_guid_inputs_before_writing() {
    let mut frame = [0xaa; 128];
    assert_eq!(
        write_backup_path_entry_record_frame(
            &limits(),
            &mut frame,
            NIL_GUID,
            "Software",
            PathTarget::Guid(CHILD_GUID),
            "base",
            55,
        ),
        Err(LcsError::NilParentGuid)
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));

    assert_eq!(
        write_backup_path_entry_record_frame(
            &limits(),
            &mut frame,
            PARENT_GUID,
            "Software",
            PathTarget::Guid(NIL_GUID),
            "base",
            55,
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert!(frame.iter().all(|byte| *byte == 0xaa));
}
