use lcs_core::{
    BackupPathEntryPayload, BackupRestorePathEntry, BackupRestoreSequenceRemapper, Guid, LcsError,
    NIL_GUID, PathTarget, remap_backup_restore_path_entry_for_dispatch,
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
fn restore_path_entry_dispatch_remaps_guid_fields_and_sequence() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);
    let restored = remap_backup_restore_path_entry_for_dispatch(
        path_entry(HEADER_ROOT, PathTarget::Guid(HEADER_ROOT), 7),
        HEADER_ROOT,
        TARGET_ROOT,
        &[],
        &mut remapper,
    )
    .unwrap();

    assert_eq!(
        restored,
        BackupRestorePathEntry {
            parent_guid: TARGET_ROOT,
            child_name: "child",
            target: PathTarget::Guid(TARGET_ROOT),
            layer_name: "base",
            sequence: 107,
        }
    );
    assert_eq!(remapper.max_dispatched_sequence(), Some(107));
}

#[test]
fn restore_path_entry_dispatch_accepts_processed_non_root_parent() {
    let mut remapper = BackupRestoreSequenceRemapper::new(50);

    assert_eq!(
        remap_backup_restore_path_entry_for_dispatch(
            path_entry(PARENT_A, PathTarget::Guid(CHILD_A), 2),
            HEADER_ROOT,
            TARGET_ROOT,
            &[PARENT_A],
            &mut remapper,
        )
        .unwrap()
        .sequence,
        52
    );
}

#[test]
fn restore_path_entry_dispatch_rejects_parent_before_sequence_dispatch() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(
        remap_backup_restore_path_entry_for_dispatch(
            path_entry(OUTSIDE, PathTarget::Guid(CHILD_A), 7),
            HEADER_ROOT,
            TARGET_ROOT,
            &[PARENT_A],
            &mut remapper,
        ),
        Err(LcsError::BackupRestoreParentGuidOutsideSubtree {
            parent_guid: OUTSIDE,
        })
    );
    assert_eq!(remapper.dispatched_count(), 0);
}

#[test]
fn restore_path_entry_dispatch_rejects_nil_root_before_sequence_dispatch() {
    let mut header_remapper = BackupRestoreSequenceRemapper::new(100);
    assert_eq!(
        remap_backup_restore_path_entry_for_dispatch(
            path_entry(HEADER_ROOT, PathTarget::Guid(CHILD_A), 7),
            NIL_GUID,
            TARGET_ROOT,
            &[],
            &mut header_remapper,
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(header_remapper.dispatched_count(), 0);

    let mut target_remapper = BackupRestoreSequenceRemapper::new(100);
    assert_eq!(
        remap_backup_restore_path_entry_for_dispatch(
            path_entry(HEADER_ROOT, PathTarget::Guid(CHILD_A), 7),
            HEADER_ROOT,
            NIL_GUID,
            &[],
            &mut target_remapper,
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(target_remapper.dispatched_count(), 0);
}

#[test]
fn restore_path_entry_dispatch_rejects_sequence_overflow_before_recording_dispatch() {
    let mut remapper = BackupRestoreSequenceRemapper::new(u64::MAX);

    assert_eq!(
        remap_backup_restore_path_entry_for_dispatch(
            path_entry(HEADER_ROOT, PathTarget::Guid(CHILD_A), 0),
            HEADER_ROOT,
            TARGET_ROOT,
            &[],
            &mut remapper,
        ),
        Err(LcsError::SequenceOverflow)
    );
    assert_eq!(remapper.dispatched_count(), 0);
}
