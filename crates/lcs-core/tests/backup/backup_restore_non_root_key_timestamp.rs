use crate::common::{system_sid};
use lcs_core::{
    BackupKeyPayload, BackupRestoreNonRootKeyTimestampWritePlan, Guid, LcsError, NIL_GUID,
    plan_backup_restore_non_root_key_timestamp_write,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const CHILD: Guid = [0x31; 16];


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
    security_descriptor: &'a [u8],
    last_write_time_ns: i64,
) -> BackupKeyPayload<'a> {
    BackupKeyPayload {
        guid,
        volatile: false,
        symlink: false,
        security_descriptor,
        last_write_time_ns,
    }
}

#[test]
fn non_root_key_timestamp_write_preserves_guid_and_signed_time() {
    let sd = owner_only_sd();

    assert_eq!(
        plan_backup_restore_non_root_key_timestamp_write(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD, &sd, -123),
        ),
        Ok(BackupRestoreNonRootKeyTimestampWritePlan {
            guid: CHILD,
            last_write_time_ns: -123,
        })
    );
}

#[test]
fn non_root_key_timestamp_write_rejects_nil_and_root_keys() {
    let sd = owner_only_sd();

    assert_eq!(
        plan_backup_restore_non_root_key_timestamp_write(NIL_GUID, TARGET_ROOT, key(CHILD, &sd, 1)),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_backup_restore_non_root_key_timestamp_write(HEADER_ROOT, NIL_GUID, key(CHILD, &sd, 1)),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_backup_restore_non_root_key_timestamp_write(
            HEADER_ROOT,
            TARGET_ROOT,
            key(NIL_GUID, &sd, 1),
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_backup_restore_non_root_key_timestamp_write(
            HEADER_ROOT,
            TARGET_ROOT,
            key(HEADER_ROOT, &sd, 1),
        ),
        Err(LcsError::BackupRestoreRootKeyCreateNotAllowed { guid: HEADER_ROOT })
    );
    assert_eq!(
        plan_backup_restore_non_root_key_timestamp_write(
            HEADER_ROOT,
            TARGET_ROOT,
            key(TARGET_ROOT, &sd, 1),
        ),
        Err(LcsError::BackupRestoreRootKeyCreateNotAllowed { guid: TARGET_ROOT })
    );
}

#[test]
fn non_root_key_timestamp_write_revalidates_security_descriptor() {
    assert_eq!(
        plan_backup_restore_non_root_key_timestamp_write(
            HEADER_ROOT,
            TARGET_ROOT,
            key(CHILD, b"bad", 1),
        ),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "backup_key.sd",
        })
    );
}
