use lcs_core::{
    BackupPathEntryPayload, BackupRestorePathEntry, BackupRestoreSequenceRemapper, Guid, LcsError,
    NIL_GUID, PathTarget, remap_backup_restore_path_entry_for_dispatch_with_key_set,
    remap_backup_restore_path_entry_with_key_set,
    validate_backup_restore_path_entry_target_in_key_set,
};

const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const PARENT_A: Guid = [0x31; 16];
const CHILD_A: Guid = [0x32; 16];
const OUTSIDE: Guid = [0x40; 16];

fn path_entry(
    parent_guid: Guid,
    target: PathTarget,
    sequence: u64,
) -> BackupPathEntryPayload<'static> {
    BackupPathEntryPayload {
        parent_guid,
        child_name: "child",
        target,
        layer_name: "base",
        sequence,
    }
}

#[test]
fn restore_path_entry_key_set_accepts_remapped_root_target() {
    assert_eq!(
        remap_backup_restore_path_entry_with_key_set(
            path_entry(HEADER_ROOT, PathTarget::Guid(HEADER_ROOT), 5),
            HEADER_ROOT,
            TARGET_ROOT,
            &[],
            &[],
        ),
        Ok(BackupRestorePathEntry {
            parent_guid: TARGET_ROOT,
            child_name: "child",
            target: PathTarget::Guid(TARGET_ROOT),
            layer_name: "base",
            sequence: 5,
        })
    );
}

#[test]
fn restore_path_entry_key_set_accepts_known_non_root_target() {
    assert_eq!(
        remap_backup_restore_path_entry_with_key_set(
            path_entry(PARENT_A, PathTarget::Guid(CHILD_A), 6),
            HEADER_ROOT,
            TARGET_ROOT,
            &[PARENT_A],
            &[CHILD_A],
        )
        .unwrap(),
        BackupRestorePathEntry {
            parent_guid: PARENT_A,
            child_name: "child",
            target: PathTarget::Guid(CHILD_A),
            layer_name: "base",
            sequence: 6,
        }
    );
}

#[test]
fn restore_path_entry_key_set_accepts_hidden_target_without_key_record() {
    assert_eq!(
        remap_backup_restore_path_entry_with_key_set(
            path_entry(TARGET_ROOT, PathTarget::Hidden, 7),
            HEADER_ROOT,
            TARGET_ROOT,
            &[],
            &[],
        )
        .unwrap()
        .target,
        PathTarget::Hidden
    );
}

#[test]
fn restore_path_entry_key_set_rejects_unknown_visible_target() {
    assert_eq!(
        remap_backup_restore_path_entry_with_key_set(
            path_entry(TARGET_ROOT, PathTarget::Guid(OUTSIDE), 8),
            HEADER_ROOT,
            TARGET_ROOT,
            &[],
            &[CHILD_A],
        ),
        Err(LcsError::BackupRestoreKeyGuidOutsideSubtree { key_guid: OUTSIDE })
    );
}

#[test]
fn restore_path_entry_key_set_rejects_nil_visible_target() {
    assert_eq!(
        validate_backup_restore_path_entry_target_in_key_set(
            PathTarget::Guid(NIL_GUID),
            TARGET_ROOT,
            &[],
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        validate_backup_restore_path_entry_target_in_key_set(
            PathTarget::Guid(TARGET_ROOT),
            NIL_GUID,
            &[],
        ),
        Err(LcsError::NilKeyGuid)
    );
}

#[test]
fn restore_path_entry_dispatch_rejects_unknown_target_before_sequence_dispatch() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(
        remap_backup_restore_path_entry_for_dispatch_with_key_set(
            path_entry(TARGET_ROOT, PathTarget::Guid(OUTSIDE), 8),
            HEADER_ROOT,
            TARGET_ROOT,
            &[],
            &[CHILD_A],
            &mut remapper,
        ),
        Err(LcsError::BackupRestoreKeyGuidOutsideSubtree { key_guid: OUTSIDE })
    );
    assert_eq!(remapper.dispatched_count(), 0);
}

#[test]
fn restore_path_entry_dispatch_rejects_parent_before_target_or_sequence_dispatch() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(
        remap_backup_restore_path_entry_for_dispatch_with_key_set(
            path_entry(OUTSIDE, PathTarget::Guid(CHILD_A), 8),
            HEADER_ROOT,
            TARGET_ROOT,
            &[],
            &[CHILD_A],
            &mut remapper,
        ),
        Err(LcsError::BackupRestoreParentGuidOutsideSubtree {
            parent_guid: OUTSIDE,
        })
    );
    assert_eq!(remapper.dispatched_count(), 0);
}
