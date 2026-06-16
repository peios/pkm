use crate::common::{limits};
use lcs_core::{
    BackupRestoreTeardownDeletePathEntryPlan, Guid, LcsError, NIL_GUID,
    plan_backup_restore_teardown_delete_path_entry,
};

const TARGET_ROOT: Guid = [0x50; 16];
const DESCENDANT_PARENT: Guid = [0x51; 16];
const OUTSIDE_PARENT: Guid = [0x52; 16];


#[test]
fn teardown_delete_path_entry_accepts_target_root_parent() {
    let limits = limits();

    assert_eq!(
        plan_backup_restore_teardown_delete_path_entry(
            &limits,
            TARGET_ROOT,
            &[],
            TARGET_ROOT,
            "Child",
            "base",
        ),
        Ok(BackupRestoreTeardownDeletePathEntryPlan {
            parent_guid: TARGET_ROOT,
            child_name: "Child",
            layer_name: "base",
        })
    );
}

#[test]
fn teardown_delete_path_entry_accepts_known_descendant_parent() {
    let limits = limits();

    assert_eq!(
        plan_backup_restore_teardown_delete_path_entry(
            &limits,
            TARGET_ROOT,
            &[DESCENDANT_PARENT],
            DESCENDANT_PARENT,
            "Grandchild",
            "policy",
        ),
        Ok(BackupRestoreTeardownDeletePathEntryPlan {
            parent_guid: DESCENDANT_PARENT,
            child_name: "Grandchild",
            layer_name: "policy",
        })
    );
}

#[test]
fn teardown_delete_path_entry_rejects_nil_root_or_parent() {
    let limits = limits();

    assert_eq!(
        plan_backup_restore_teardown_delete_path_entry(
            &limits,
            NIL_GUID,
            &[],
            TARGET_ROOT,
            "Child",
            "base",
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_backup_restore_teardown_delete_path_entry(
            &limits,
            TARGET_ROOT,
            &[],
            NIL_GUID,
            "Child",
            "base",
        ),
        Err(LcsError::NilParentGuid)
    );
}

#[test]
fn teardown_delete_path_entry_rejects_parents_outside_restore_subtree() {
    let limits = limits();

    assert_eq!(
        plan_backup_restore_teardown_delete_path_entry(
            &limits,
            TARGET_ROOT,
            &[DESCENDANT_PARENT],
            OUTSIDE_PARENT,
            "Sibling",
            "base",
        ),
        Err(LcsError::BackupRestoreParentGuidOutsideSubtree {
            parent_guid: OUTSIDE_PARENT,
        })
    );
}

#[test]
fn teardown_delete_path_entry_validates_child_and_layer_before_dispatch() {
    let limits = limits();

    assert_eq!(
        plan_backup_restore_teardown_delete_path_entry(
            &limits,
            TARGET_ROOT,
            &[],
            TARGET_ROOT,
            "Bad/Child",
            "base",
        ),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
    assert_eq!(
        plan_backup_restore_teardown_delete_path_entry(
            &limits,
            TARGET_ROOT,
            &[],
            TARGET_ROOT,
            "Child",
            "bad/layer",
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}
