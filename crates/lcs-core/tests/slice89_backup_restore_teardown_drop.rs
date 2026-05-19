use lcs_core::{
    BackupRestoreTeardownDropKeyPlan, Guid, LcsError, NIL_GUID,
    plan_backup_restore_teardown_drop_descendant_key,
};

const TARGET_ROOT: Guid = [0x20; 16];
const DESCENDANT: Guid = [0x31; 16];

#[test]
fn teardown_drop_descendant_key_preserves_guid_for_rsi_drop_key() {
    assert_eq!(
        plan_backup_restore_teardown_drop_descendant_key(TARGET_ROOT, DESCENDANT),
        Ok(BackupRestoreTeardownDropKeyPlan { guid: DESCENDANT })
    );
}

#[test]
fn teardown_drop_descendant_key_rejects_nil_inputs() {
    assert_eq!(
        plan_backup_restore_teardown_drop_descendant_key(NIL_GUID, DESCENDANT),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_backup_restore_teardown_drop_descendant_key(TARGET_ROOT, NIL_GUID),
        Err(LcsError::NilKeyGuid)
    );
}

#[test]
fn teardown_drop_descendant_key_never_drops_restore_root() {
    assert_eq!(
        plan_backup_restore_teardown_drop_descendant_key(TARGET_ROOT, TARGET_ROOT),
        Err(LcsError::BackupRestoreTargetRootDropNotAllowed { guid: TARGET_ROOT })
    );
}
