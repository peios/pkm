use lcs_core::{
    BackupPathEntryPayload, BackupRestorePathEntry, Guid, LcsError, NIL_GUID, PathTarget,
    remap_backup_restore_path_entry,
};

const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const PARENT_A: Guid = [0x31; 16];
const CHILD_A: Guid = [0x32; 16];
const OUTSIDE: Guid = [0x40; 16];

fn path_entry(parent_guid: Guid, target: PathTarget) -> BackupPathEntryPayload<'static> {
    BackupPathEntryPayload {
        parent_guid,
        child_name: "child",
        target,
        layer_name: "base",
        sequence: 9,
    }
}

#[test]
fn restore_path_entry_remaps_root_parent_and_child_guids() {
    let entry = path_entry(HEADER_ROOT, PathTarget::Guid(HEADER_ROOT));

    assert_eq!(
        remap_backup_restore_path_entry(entry, HEADER_ROOT, TARGET_ROOT, &[]),
        Ok(BackupRestorePathEntry {
            parent_guid: TARGET_ROOT,
            child_name: "child",
            target: PathTarget::Guid(TARGET_ROOT),
            layer_name: "base",
            sequence: 9,
        })
    );
}

#[test]
fn restore_path_entry_accepts_already_processed_non_root_parent() {
    let entry = path_entry(PARENT_A, PathTarget::Guid(CHILD_A));

    assert_eq!(
        remap_backup_restore_path_entry(entry, HEADER_ROOT, TARGET_ROOT, &[PARENT_A]).unwrap(),
        BackupRestorePathEntry {
            parent_guid: PARENT_A,
            child_name: "child",
            target: PathTarget::Guid(CHILD_A),
            layer_name: "base",
            sequence: 9,
        }
    );
}

#[test]
fn restore_path_entry_preserves_hidden_targets() {
    let entry = path_entry(TARGET_ROOT, PathTarget::Hidden);

    assert_eq!(
        remap_backup_restore_path_entry(entry, HEADER_ROOT, TARGET_ROOT, &[]).unwrap(),
        BackupRestorePathEntry {
            parent_guid: TARGET_ROOT,
            child_name: "child",
            target: PathTarget::Hidden,
            layer_name: "base",
            sequence: 9,
        }
    );
}

#[test]
fn restore_path_entry_rejects_parents_outside_the_remapped_subtree() {
    let entry = path_entry(OUTSIDE, PathTarget::Guid(CHILD_A));

    assert_eq!(
        remap_backup_restore_path_entry(entry, HEADER_ROOT, TARGET_ROOT, &[PARENT_A]),
        Err(LcsError::BackupRestoreParentGuidOutsideSubtree {
            parent_guid: OUTSIDE,
        })
    );
}

#[test]
fn restore_path_entry_rejects_nil_root_inputs() {
    let entry = path_entry(HEADER_ROOT, PathTarget::Guid(CHILD_A));

    assert_eq!(
        remap_backup_restore_path_entry(entry, NIL_GUID, TARGET_ROOT, &[]),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        remap_backup_restore_path_entry(entry, HEADER_ROOT, NIL_GUID, &[]),
        Err(LcsError::NilKeyGuid)
    );
}
