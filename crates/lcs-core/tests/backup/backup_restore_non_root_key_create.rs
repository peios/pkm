use lcs_core::{
    BackupKeyPayload, BackupPathEntryPayload, BackupRestoreNonRootKeyCreatePlan, Guid, LcsError,
    NIL_GUID, PathTarget, plan_backup_restore_non_root_key_create,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const PARENT_A: Guid = [0x31; 16];
const CHILD_A: Guid = [0x32; 16];
const CHILD_B: Guid = [0x33; 16];
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

fn key<'a>(
    guid: Guid,
    volatile: bool,
    symlink: bool,
    security_descriptor: &'a [u8],
) -> BackupKeyPayload<'a> {
    BackupKeyPayload {
        guid,
        volatile,
        symlink,
        security_descriptor,
        last_write_time_ns: 100,
    }
}

fn path_entry(
    parent_guid: Guid,
    child_name: &'static str,
    target: PathTarget,
) -> BackupPathEntryPayload<'static> {
    BackupPathEntryPayload {
        parent_guid,
        child_name,
        target,
        layer_name: "base",
        sequence: 10,
    }
}

#[test]
fn non_root_key_create_uses_first_guid_bearing_path_entry_as_anchor() {
    let sd = owner_only_sd();
    let path_entries = [
        path_entry(HEADER_ROOT, "child", PathTarget::Guid(CHILD_A)),
        path_entry(HEADER_ROOT, "alias", PathTarget::Guid(CHILD_A)),
    ];

    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD_A, true, false, &sd),
            &path_entries,
            &[],
        ),
        Ok(BackupRestoreNonRootKeyCreatePlan {
            guid: CHILD_A,
            parent_guid: TARGET_ROOT,
            child_name: "child",
            security_descriptor: sd.as_slice(),
            volatile: true,
            symlink: false,
            anchor_path_entry_index: 0,
        })
    );
}

#[test]
fn non_root_key_create_accepts_already_processed_non_root_parent() {
    let sd = owner_only_sd();
    let path_entries = [path_entry(PARENT_A, "leaf", PathTarget::Guid(CHILD_A))];

    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD_A, false, true, &sd),
            &path_entries,
            &[PARENT_A],
        )
        .unwrap()
        .parent_guid,
        PARENT_A
    );
}

#[test]
fn non_root_key_create_rejects_missing_or_hidden_anchor() {
    let sd = owner_only_sd();

    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD_A, false, false, &sd),
            &[],
            &[],
        ),
        Err(LcsError::BackupRestoreKeyCreateAnchorMissing { key_guid: CHILD_A })
    );

    let hidden = [path_entry(HEADER_ROOT, "child", PathTarget::Hidden)];
    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD_A, false, false, &sd),
            &hidden,
            &[],
        ),
        Err(LcsError::BackupRestoreKeyCreateAnchorTargetMismatch {
            key_guid: CHILD_A,
            child_guid: NIL_GUID,
        })
    );
}

#[test]
fn non_root_key_create_rejects_path_entries_for_other_keys() {
    let sd = owner_only_sd();
    let path_entries = [path_entry(HEADER_ROOT, "child", PathTarget::Guid(CHILD_B))];

    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD_A, false, false, &sd),
            &path_entries,
            &[],
        ),
        Err(LcsError::BackupRestoreKeyCreateAnchorTargetMismatch {
            key_guid: CHILD_A,
            child_guid: CHILD_B,
        })
    );
}

#[test]
fn non_root_key_create_rejects_parent_outside_processed_subtree() {
    let sd = owner_only_sd();
    let path_entries = [path_entry(OUTSIDE, "child", PathTarget::Guid(CHILD_A))];

    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD_A, false, false, &sd),
            &path_entries,
            &[PARENT_A],
        ),
        Err(LcsError::BackupRestoreParentGuidOutsideSubtree {
            parent_guid: OUTSIDE,
        })
    );
}

#[test]
fn non_root_key_create_rejects_root_nil_and_bad_sd_inputs() {
    let sd = owner_only_sd();
    let path_entries = [path_entry(HEADER_ROOT, "child", PathTarget::Guid(CHILD_A))];

    assert_eq!(
        plan_backup_restore_non_root_key_create(
            NIL_GUID,
            TARGET_ROOT,
            key(CHILD_A, false, false, &sd),
            &path_entries,
            &[],
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(HEADER_ROOT, false, false, &sd),
            &path_entries,
            &[],
        ),
        Err(LcsError::BackupRestoreRootKeyCreateNotAllowed { guid: HEADER_ROOT })
    );
    assert_eq!(
        plan_backup_restore_non_root_key_create(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD_A, false, false, b"bad"),
            &path_entries,
            &[],
        ),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "backup_key.sd",
        })
    );
}
