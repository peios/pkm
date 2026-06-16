use lcs_core::{
    BackupExportPathEntrySectionPlan, BackupKeyPayload, BackupPathEntryPayload,
    BackupRestoreNonRootKeyCreatePlan, BackupRestorePathEntry,
    BackupRestoreRootSectionPathEntryPlan, BackupRestoreRootSectionPathEntrySkip,
    BackupRestoreSequenceRemapper, Guid, LcsError, NIL_GUID, PathTarget,
    plan_backup_export_path_entry_section, plan_backup_restore_non_root_key_create,
    plan_backup_restore_root_section_path_entry_for_dispatch,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const CHILD: Guid = [0x31; 16];
const GRANDCHILD: Guid = [0x32; 16];
const OUTSIDE: Guid = [0x40; 16];

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

fn key<'a>(guid: Guid, sd: &'a [u8]) -> BackupKeyPayload<'a> {
    BackupKeyPayload {
        guid,
        volatile: false,
        symlink: false,
        security_descriptor: sd,
        last_write_time_ns: 100,
    }
}

fn path_entry(
    parent_guid: Guid,
    child_name: &'static str,
    target: PathTarget,
    layer_name: &'static str,
    sequence: u64,
) -> BackupPathEntryPayload<'static> {
    BackupPathEntryPayload {
        parent_guid,
        child_name,
        target,
        layer_name,
        sequence,
    }
}

#[test]
fn export_places_guid_entries_in_child_section_and_hidden_entries_in_parent_section() {
    assert_eq!(
        plan_backup_export_path_entry_section(path_entry(
            HEADER_ROOT,
            "child",
            PathTarget::Guid(CHILD),
            "base",
            1,
        )),
        Ok(BackupExportPathEntrySectionPlan::GuidBearingIncoming {
            section_key_guid: CHILD,
        })
    );

    assert_eq!(
        plan_backup_export_path_entry_section(path_entry(
            CHILD,
            "masked",
            PathTarget::Hidden,
            "overlay",
            2,
        )),
        Ok(BackupExportPathEntrySectionPlan::ParentOwnedHidden {
            section_key_guid: CHILD,
        })
    );
}

#[test]
fn export_section_selection_rejects_malformed_path_entry_identity() {
    assert_eq!(
        plan_backup_export_path_entry_section(path_entry(
            NIL_GUID,
            "child",
            PathTarget::Guid(CHILD),
            "base",
            1,
        )),
        Err(LcsError::NilParentGuid)
    );

    assert_eq!(
        plan_backup_export_path_entry_section(path_entry(
            HEADER_ROOT,
            "child",
            PathTarget::Guid(NIL_GUID),
            "base",
            1,
        )),
        Err(LcsError::NilKeyGuid)
    );
}

#[test]
fn non_root_create_ignores_parent_owned_hidden_records_while_finding_anchor() {
    let sd = owner_only_sd();
    let entries = [
        path_entry(CHILD, "masked", PathTarget::Hidden, "overlay", 40),
        path_entry(HEADER_ROOT, "child", PathTarget::Guid(CHILD), "base", 10),
    ];

    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD, &sd),
            &entries,
            &[],
        ),
        Ok(BackupRestoreNonRootKeyCreatePlan {
            guid: CHILD,
            parent_guid: TARGET_ROOT,
            child_name: "child",
            security_descriptor: sd.as_slice(),
            volatile: false,
            symlink: false,
            anchor_path_entry_index: 1,
        })
    );
}

#[test]
fn non_root_create_rejects_hidden_records_in_the_wrong_key_section() {
    let sd = owner_only_sd();
    let entries = [
        path_entry(HEADER_ROOT, "masked", PathTarget::Hidden, "overlay", 40),
        path_entry(HEADER_ROOT, "child", PathTarget::Guid(CHILD), "base", 10),
    ];

    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD, &sd),
            &entries,
            &[],
        ),
        Err(LcsError::BackupRestoreKeyCreateAnchorTargetMismatch {
            key_guid: CHILD,
            child_guid: NIL_GUID,
        })
    );
}

#[test]
fn root_section_skips_incoming_root_aliases_without_consuming_restore_sequence() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(
        plan_backup_restore_root_section_path_entry_for_dispatch(
            path_entry(
                OUTSIDE,
                "backup-root",
                PathTarget::Guid(HEADER_ROOT),
                "base",
                7,
            ),
            HEADER_ROOT,
            TARGET_ROOT,
            &mut remapper,
        ),
        Ok(BackupRestoreRootSectionPathEntryPlan::SkipIncomingRoot(
            BackupRestoreRootSectionPathEntrySkip {
                parent_guid: OUTSIDE,
                child_name: "backup-root",
                target: PathTarget::Guid(HEADER_ROOT),
                layer_name: "base",
                sequence: 7,
            }
        ))
    );
    assert_eq!(remapper.dispatched_count(), 0);
    assert_eq!(remapper.terminal_next_sequence(1000), Ok(1000));
}

#[test]
fn root_section_restores_parent_owned_hidden_after_root_and_sequence_remapping() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(
        plan_backup_restore_root_section_path_entry_for_dispatch(
            path_entry(HEADER_ROOT, "masked", PathTarget::Hidden, "overlay", 7),
            HEADER_ROOT,
            TARGET_ROOT,
            &mut remapper,
        ),
        Ok(BackupRestoreRootSectionPathEntryPlan::RestoreHidden(
            BackupRestorePathEntry {
                parent_guid: TARGET_ROOT,
                child_name: "masked",
                target: PathTarget::Hidden,
                layer_name: "overlay",
                sequence: 107,
            }
        ))
    );
    assert_eq!(remapper.dispatched_count(), 1);
    assert_eq!(remapper.terminal_next_sequence(1000), Ok(1000));
    assert_eq!(remapper.terminal_next_sequence(50), Ok(108));
}

#[test]
fn root_section_rejects_non_root_guid_bearing_path_entries() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(
        plan_backup_restore_root_section_path_entry_for_dispatch(
            path_entry(
                HEADER_ROOT,
                "child",
                PathTarget::Guid(GRANDCHILD),
                "base",
                7
            ),
            HEADER_ROOT,
            TARGET_ROOT,
            &mut remapper,
        ),
        Err(LcsError::BackupRestoreKeyCreateAnchorTargetMismatch {
            key_guid: HEADER_ROOT,
            child_guid: GRANDCHILD,
        })
    );
    assert_eq!(remapper.dispatched_count(), 0);
}
