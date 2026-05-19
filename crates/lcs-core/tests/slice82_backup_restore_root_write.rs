use lcs_core::{
    BackupKeyPayload, BackupRestoreRootWritePlan, BackupRestoreTargetRoot, Guid, LcsError,
    NIL_GUID, plan_backup_restore_root_write,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const CHILD: Guid = [0x31; 16];

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

fn root_key<'a>(
    guid: Guid,
    volatile: bool,
    symlink: bool,
    security_descriptor: &'a [u8],
    last_write_time_ns: i64,
) -> BackupKeyPayload<'a> {
    BackupKeyPayload {
        guid,
        volatile,
        symlink,
        security_descriptor,
        last_write_time_ns,
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
fn restore_root_write_uses_target_guid_and_only_mutable_root_fields() {
    let sd = owner_only_sd();
    let key = root_key(HEADER_ROOT, true, false, &sd, -44);

    assert_eq!(
        plan_backup_restore_root_write(HEADER_ROOT, target_root(true, false), key),
        Ok(BackupRestoreRootWritePlan {
            target_guid: TARGET_ROOT,
            security_descriptor: sd.as_slice(),
            last_write_time_ns: -44,
        })
    );
}

#[test]
fn restore_root_write_rejects_nil_roots_and_wrong_root_key_guid() {
    let sd = owner_only_sd();
    let key = root_key(HEADER_ROOT, false, false, &sd, 100);

    assert_eq!(
        plan_backup_restore_root_write(NIL_GUID, target_root(false, false), key),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_backup_restore_root_write(
            HEADER_ROOT,
            BackupRestoreTargetRoot {
                guid: NIL_GUID,
                volatile: false,
                symlink: false,
            },
            key,
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_backup_restore_root_write(
            HEADER_ROOT,
            target_root(false, false),
            root_key(CHILD, false, false, &sd, 100),
        ),
        Err(LcsError::BackupRestoreRootKeyGuidMismatch {
            expected: HEADER_ROOT,
            actual: CHILD,
        })
    );
}

#[test]
fn restore_root_write_rejects_immutable_flag_conflicts() {
    let sd = owner_only_sd();
    let volatile_conflict = root_key(HEADER_ROOT, true, false, &sd, 100);
    assert_eq!(
        plan_backup_restore_root_write(HEADER_ROOT, target_root(false, false), volatile_conflict),
        Err(LcsError::BackupRestoreRootImmutableFlagsConflict {
            backup_volatile: true,
            target_volatile: false,
            backup_symlink: false,
            target_symlink: false,
        })
    );

    let symlink_conflict = root_key(HEADER_ROOT, false, true, &sd, 100);
    assert_eq!(
        plan_backup_restore_root_write(HEADER_ROOT, target_root(false, false), symlink_conflict),
        Err(LcsError::BackupRestoreRootImmutableFlagsConflict {
            backup_volatile: false,
            target_volatile: false,
            backup_symlink: true,
            target_symlink: false,
        })
    );
}

#[test]
fn restore_root_write_revalidates_security_descriptor() {
    let bad_sd = b"bad";

    assert_eq!(
        plan_backup_restore_root_write(
            HEADER_ROOT,
            target_root(false, false),
            root_key(HEADER_ROOT, false, false, bad_sd, 100),
        ),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "backup_key.sd",
        })
    );
}
