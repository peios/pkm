use crate::common::{system_sid};
use lcs_core::{
    BackupKeyPayload, BackupRestoreKeySetSummary, BackupRestoreTargetRoot, Guid, LcsError,
    NIL_GUID, remap_backup_restore_guid, validate_backup_restore_key_set,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const CHILD_A: Guid = [0x31; 16];
const CHILD_B: Guid = [0x32; 16];
const OUTSIDE: Guid = [0x40; 16];


fn owner_only_sd() -> Vec<u8> {
    let owner = system_sid();
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd
}

fn key<'a>(guid: Guid, volatile: bool, symlink: bool, sd: &'a [u8]) -> BackupKeyPayload<'a> {
    BackupKeyPayload {
        guid,
        volatile,
        symlink,
        security_descriptor: sd,
        last_write_time_ns: 100,
    }
}

fn target_root(volatile: bool, symlink: bool) -> BackupRestoreTargetRoot {
    BackupRestoreTargetRoot {
        guid: TARGET_ROOT,
        volatile,
        symlink,
    }
}

#[test]
fn restore_key_set_accepts_single_root_and_unique_non_root_guids() {
    let sd = owner_only_sd();
    let keys = [
        key(HEADER_ROOT, true, false, &sd),
        key(CHILD_A, false, false, &sd),
        key(CHILD_B, false, true, &sd),
    ];

    assert_eq!(
        validate_backup_restore_key_set(HEADER_ROOT, target_root(true, false), &keys, &[OUTSIDE]),
        Ok(BackupRestoreKeySetSummary {
            root_key: keys[0],
            key_count: 3,
            non_root_key_count: 2,
        })
    );
}

#[test]
fn restore_guid_remapping_only_rewrites_header_root_guid() {
    assert_eq!(
        remap_backup_restore_guid(HEADER_ROOT, HEADER_ROOT, TARGET_ROOT),
        TARGET_ROOT
    );
    assert_eq!(
        remap_backup_restore_guid(CHILD_A, HEADER_ROOT, TARGET_ROOT),
        CHILD_A
    );
}

#[test]
fn restore_key_set_rejects_nil_root_inputs_and_missing_root_key() {
    let sd = owner_only_sd();
    let keys = [key(CHILD_A, false, false, &sd)];

    assert_eq!(
        validate_backup_restore_key_set(NIL_GUID, target_root(false, false), &keys, &[]),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        validate_backup_restore_key_set(
            HEADER_ROOT,
            BackupRestoreTargetRoot {
                guid: NIL_GUID,
                volatile: false,
                symlink: false,
            },
            &keys,
            &[],
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        validate_backup_restore_key_set(HEADER_ROOT, target_root(false, false), &keys, &[]),
        Err(LcsError::BackupRestoreRootKeyMissing)
    );
}

#[test]
fn restore_key_set_rejects_duplicate_root_and_immutable_flag_conflicts() {
    let sd = owner_only_sd();
    let duplicate_roots = [
        key(HEADER_ROOT, false, false, &sd),
        key(HEADER_ROOT, false, false, &sd),
    ];
    assert_eq!(
        validate_backup_restore_key_set(
            HEADER_ROOT,
            target_root(false, false),
            &duplicate_roots,
            &[],
        ),
        Err(LcsError::BackupRestoreRootKeyDuplicate)
    );

    let conflicting = [key(HEADER_ROOT, true, false, &sd)];
    assert_eq!(
        validate_backup_restore_key_set(HEADER_ROOT, target_root(false, false), &conflicting, &[]),
        Err(LcsError::BackupRestoreRootImmutableFlagsConflict {
            backup_volatile: true,
            target_volatile: false,
            backup_symlink: false,
            target_symlink: false,
        })
    );
}

#[test]
fn restore_key_set_rejects_duplicate_remapped_non_root_guids() {
    let sd = owner_only_sd();
    let duplicate_children = [
        key(HEADER_ROOT, false, false, &sd),
        key(CHILD_A, false, false, &sd),
        key(CHILD_A, false, true, &sd),
    ];
    assert_eq!(
        validate_backup_restore_key_set(
            HEADER_ROOT,
            target_root(false, false),
            &duplicate_children,
            &[],
        ),
        Err(LcsError::DuplicateBackupKeyGuid { guid: CHILD_A })
    );

    let child_collides_with_remapped_root = [
        key(TARGET_ROOT, false, false, &sd),
        key(HEADER_ROOT, false, false, &sd),
    ];
    assert_eq!(
        validate_backup_restore_key_set(
            HEADER_ROOT,
            target_root(false, false),
            &child_collides_with_remapped_root,
            &[],
        ),
        Err(LcsError::DuplicateBackupKeyGuid { guid: TARGET_ROOT })
    );
}

#[test]
fn restore_key_set_rejects_non_root_outside_subtree_guid_collisions() {
    let sd = owner_only_sd();
    let keys = [
        key(HEADER_ROOT, false, false, &sd),
        key(OUTSIDE, false, false, &sd),
    ];

    assert_eq!(
        validate_backup_restore_key_set(HEADER_ROOT, target_root(false, false), &keys, &[OUTSIDE]),
        Err(LcsError::BackupGuidCollision { guid: OUTSIDE })
    );
}
