use lcs_core::{
    BackupRestoreTeardownDeleteBlanketPlan, BackupRestoreTeardownDeleteValuePlan, Guid, LcsError,
    LcsLimits, NIL_GUID, plan_backup_restore_teardown_delete_blanket,
    plan_backup_restore_teardown_delete_value,
};

const ROOT_GUID: Guid = [0x40; 16];
const DESCENDANT_GUID: Guid = [0x41; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

#[test]
fn teardown_delete_value_preserves_root_or_descendant_key_layer_and_name() {
    let limits = limits();

    assert_eq!(
        plan_backup_restore_teardown_delete_value(&limits, ROOT_GUID, "Setting", "base"),
        Ok(BackupRestoreTeardownDeleteValuePlan {
            key_guid: ROOT_GUID,
            name: "Setting",
            layer_name: "base",
        })
    );
    assert_eq!(
        plan_backup_restore_teardown_delete_value(&limits, DESCENDANT_GUID, "", "policy"),
        Ok(BackupRestoreTeardownDeleteValuePlan {
            key_guid: DESCENDANT_GUID,
            name: "",
            layer_name: "policy",
        })
    );
}

#[test]
fn teardown_delete_blanket_preserves_root_or_descendant_key_and_layer() {
    let limits = limits();

    assert_eq!(
        plan_backup_restore_teardown_delete_blanket(&limits, ROOT_GUID, "base"),
        Ok(BackupRestoreTeardownDeleteBlanketPlan {
            key_guid: ROOT_GUID,
            layer_name: "base",
        })
    );
    assert_eq!(
        plan_backup_restore_teardown_delete_blanket(&limits, DESCENDANT_GUID, "policy"),
        Ok(BackupRestoreTeardownDeleteBlanketPlan {
            key_guid: DESCENDANT_GUID,
            layer_name: "policy",
        })
    );
}

#[test]
fn teardown_value_and_blanket_deletes_reject_nil_keys() {
    let limits = limits();

    assert_eq!(
        plan_backup_restore_teardown_delete_value(&limits, NIL_GUID, "Setting", "base"),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_backup_restore_teardown_delete_blanket(&limits, NIL_GUID, "base"),
        Err(LcsError::NilKeyGuid)
    );
}

#[test]
fn teardown_value_and_blanket_deletes_reject_malformed_names_before_dispatch() {
    let limits = limits();

    assert_eq!(
        plan_backup_restore_teardown_delete_value(&limits, ROOT_GUID, "bad\0value", "base"),
        Err(LcsError::NullByte {
            field: "value_name",
        })
    );
    assert_eq!(
        plan_backup_restore_teardown_delete_value(&limits, ROOT_GUID, "Setting", "bad/layer"),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
    assert_eq!(
        plan_backup_restore_teardown_delete_blanket(&limits, ROOT_GUID, "bad/layer"),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}
