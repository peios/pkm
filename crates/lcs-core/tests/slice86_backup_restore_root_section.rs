use lcs_core::{
    BackupBlanketTombstonePayload, BackupPathEntryPayload, BackupRestoreBlanketTombstone,
    BackupRestoreRootSectionPathEntrySkip, BackupRestoreSequenceRemapper, BackupRestoreValue,
    BackupValuePayload, Guid, LcsError, PathTarget, RegistryValueType, ValidatedValueType,
    plan_backup_restore_root_section_path_entry_skip,
    remap_backup_restore_root_section_blanket_tombstone, remap_backup_restore_root_section_value,
};

const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const OUTSIDE: Guid = [0x40; 16];

fn path_entry(target: PathTarget, sequence: u64) -> BackupPathEntryPayload<'static> {
    BackupPathEntryPayload {
        parent_guid: OUTSIDE,
        child_name: "restore-root",
        target,
        layer_name: "base",
        sequence,
    }
}

fn value(key_guid: Guid, sequence: u64) -> BackupValuePayload<'static> {
    BackupValuePayload {
        key_guid,
        name: "root-value",
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
fn root_section_path_entries_are_explicit_no_dispatch_skips() {
    assert_eq!(
        plan_backup_restore_root_section_path_entry_skip(path_entry(
            PathTarget::Guid(HEADER_ROOT),
            9,
        )),
        BackupRestoreRootSectionPathEntrySkip {
            parent_guid: OUTSIDE,
            child_name: "restore-root",
            target: PathTarget::Guid(HEADER_ROOT),
            layer_name: "base",
            sequence: 9,
        }
    );

    assert_eq!(
        plan_backup_restore_root_section_path_entry_skip(path_entry(PathTarget::Hidden, 10)).target,
        PathTarget::Hidden
    );
}

#[test]
fn root_section_values_remap_root_guid_and_sequence() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(
        remap_backup_restore_root_section_value(
            value(HEADER_ROOT, 7),
            HEADER_ROOT,
            TARGET_ROOT,
            &mut remapper,
        ),
        Ok(BackupRestoreValue {
            key_guid: TARGET_ROOT,
            name: "root-value",
            value_type: ValidatedValueType::Normal(RegistryValueType::Sz),
            data: b"data",
            layer_name: "base",
            sequence: 107,
        })
    );
    assert_eq!(remapper.max_dispatched_sequence(), Some(107));
}

#[test]
fn root_section_blankets_remap_root_guid_and_sequence() {
    let mut remapper = BackupRestoreSequenceRemapper::new(50);

    assert_eq!(
        remap_backup_restore_root_section_blanket_tombstone(
            blanket(HEADER_ROOT, 4),
            HEADER_ROOT,
            TARGET_ROOT,
            &mut remapper,
        ),
        Ok(BackupRestoreBlanketTombstone {
            key_guid: TARGET_ROOT,
            layer_name: "base",
            sequence: 54,
        })
    );
    assert_eq!(remapper.max_dispatched_sequence(), Some(54));
}

#[test]
fn root_section_layer_records_reject_non_root_keys_before_sequence_dispatch() {
    let mut value_remapper = BackupRestoreSequenceRemapper::new(100);
    assert_eq!(
        remap_backup_restore_root_section_value(
            value(OUTSIDE, 7),
            HEADER_ROOT,
            TARGET_ROOT,
            &mut value_remapper,
        ),
        Err(LcsError::BackupRestoreKeyGuidOutsideSubtree { key_guid: OUTSIDE })
    );
    assert_eq!(value_remapper.dispatched_count(), 0);

    let mut blanket_remapper = BackupRestoreSequenceRemapper::new(100);
    assert_eq!(
        remap_backup_restore_root_section_blanket_tombstone(
            blanket(OUTSIDE, 7),
            HEADER_ROOT,
            TARGET_ROOT,
            &mut blanket_remapper,
        ),
        Err(LcsError::BackupRestoreKeyGuidOutsideSubtree { key_guid: OUTSIDE })
    );
    assert_eq!(blanket_remapper.dispatched_count(), 0);
}
