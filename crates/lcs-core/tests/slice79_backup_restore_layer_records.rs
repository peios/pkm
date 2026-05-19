use lcs_core::{
    BackupBlanketTombstonePayload, BackupRestoreBlanketTombstone, BackupRestoreSequenceRemapper,
    BackupRestoreValue, BackupValuePayload, Guid, LcsError, NIL_GUID, RegistryValueType,
    ValidatedValueType, remap_backup_restore_blanket_tombstone, remap_backup_restore_value,
};

const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const CHILD_A: Guid = [0x31; 16];
const OUTSIDE: Guid = [0x40; 16];

fn value(key_guid: Guid, sequence: u64) -> BackupValuePayload<'static> {
    BackupValuePayload {
        key_guid,
        name: "name",
        value_type: ValidatedValueType::Normal(RegistryValueType::Sz),
        data: b"data",
        layer_name: "base",
        sequence,
    }
}

fn blanket(key_guid: Guid, sequence: u64) -> BackupBlanketTombstonePayload<'static> {
    BackupBlanketTombstonePayload {
        key_guid,
        layer_name: "base",
        sequence,
    }
}

#[test]
fn restore_value_remaps_root_key_and_sequence() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);
    let restored = remap_backup_restore_value(
        value(HEADER_ROOT, 5),
        HEADER_ROOT,
        TARGET_ROOT,
        &[],
        &mut remapper,
    )
    .unwrap();

    assert_eq!(
        restored,
        BackupRestoreValue {
            key_guid: TARGET_ROOT,
            name: "name",
            value_type: ValidatedValueType::Normal(RegistryValueType::Sz),
            data: b"data",
            layer_name: "base",
            sequence: 105,
        }
    );
    assert_eq!(remapper.max_dispatched_sequence(), Some(105));
}

#[test]
fn restore_value_accepts_processed_non_root_key() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(
        remap_backup_restore_value(
            value(CHILD_A, 7),
            HEADER_ROOT,
            TARGET_ROOT,
            &[CHILD_A],
            &mut remapper,
        )
        .unwrap()
        .key_guid,
        CHILD_A
    );
    assert_eq!(remapper.max_dispatched_sequence(), Some(107));
}

#[test]
fn restore_blanket_remaps_root_key_and_sequence() {
    let mut remapper = BackupRestoreSequenceRemapper::new(50);

    assert_eq!(
        remap_backup_restore_blanket_tombstone(
            blanket(HEADER_ROOT, 3),
            HEADER_ROOT,
            TARGET_ROOT,
            &[],
            &mut remapper,
        ),
        Ok(BackupRestoreBlanketTombstone {
            key_guid: TARGET_ROOT,
            layer_name: "base",
            sequence: 53,
        })
    );
}

#[test]
fn restore_layer_records_reject_key_guids_outside_subtree_before_sequence_dispatch() {
    let mut value_remapper = BackupRestoreSequenceRemapper::new(100);
    assert_eq!(
        remap_backup_restore_value(
            value(OUTSIDE, 5),
            HEADER_ROOT,
            TARGET_ROOT,
            &[CHILD_A],
            &mut value_remapper,
        ),
        Err(LcsError::BackupRestoreKeyGuidOutsideSubtree { key_guid: OUTSIDE })
    );
    assert_eq!(value_remapper.dispatched_count(), 0);

    let mut blanket_remapper = BackupRestoreSequenceRemapper::new(100);
    assert_eq!(
        remap_backup_restore_blanket_tombstone(
            blanket(OUTSIDE, 5),
            HEADER_ROOT,
            TARGET_ROOT,
            &[CHILD_A],
            &mut blanket_remapper,
        ),
        Err(LcsError::BackupRestoreKeyGuidOutsideSubtree { key_guid: OUTSIDE })
    );
    assert_eq!(blanket_remapper.dispatched_count(), 0);
}

#[test]
fn restore_layer_records_reject_nil_root_inputs_before_sequence_dispatch() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(
        remap_backup_restore_value(
            value(HEADER_ROOT, 5),
            NIL_GUID,
            TARGET_ROOT,
            &[],
            &mut remapper
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(remapper.dispatched_count(), 0);
}

#[test]
fn restore_layer_records_reject_sequence_overflow_before_recording_dispatch() {
    let mut remapper = BackupRestoreSequenceRemapper::new(u64::MAX);

    assert_eq!(
        remap_backup_restore_value(
            value(HEADER_ROOT, 0),
            HEADER_ROOT,
            TARGET_ROOT,
            &[],
            &mut remapper
        ),
        Err(LcsError::SequenceOverflow)
    );
    assert_eq!(remapper.dispatched_count(), 0);
}
