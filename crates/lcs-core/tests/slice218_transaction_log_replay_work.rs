use lcs_core::{
    DeleteKeyInput, Guid, HideKeyInput, KEY_CREATE_SUB_KEY, KeyCreateRecordsRequest,
    KeyFdNamespaceView, KeyPathMutationInput, LcsError, LcsLimits, REG_OPTION_VOLATILE, REG_SZ,
    REG_WATCH_SD_CHANGED, RegistrySetSecurityCommitEffects, SequenceCounter,
    TransactionMutationCommitWork, TransactionMutationLogRecord, TransactionOperationIndexCounter,
    ValueWriteInput, WatchAncestryContext, WatchMutationContext, plan_key_create_records,
    plan_key_create_transaction_log_entry, plan_key_delete, plan_key_delete_transaction_log_entry,
    plan_key_hide, plan_key_hide_transaction_log_entry,
    plan_registry_set_security_transaction_log_entry, plan_value_write,
    plan_value_write_transaction_log_entry, transaction_mutation_log_record_commit_work,
};

const ROOT_GUID: Guid = [0x12; 16];
const PARENT_GUID: Guid = [0x23; 16];
const CHILD_GUID: Guid = [0x34; 16];
const KEY_GUID: Guid = [0x45; 16];
const SECURITY_ANCESTORS: [Guid; 2] = [ROOT_GUID, KEY_GUID];
const SECURITY_PATH: [&str; 2] = ["Machine", "Policy"];
const CHILD_ANCESTORS: [Guid; 3] = [ROOT_GUID, PARENT_GUID, CHILD_GUID];
const CHILD_PATH: [&str; 3] = ["Machine", "Parent", "Child"];
const PARENT_ANCESTORS: [Guid; 2] = [ROOT_GUID, PARENT_GUID];
const PARENT_PATH: [&str; 2] = ["Machine", "Parent"];

fn value_watch_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &SECURITY_ANCESTORS,
        path_components: &SECURITY_PATH,
    }
}

fn parent_watch_context() -> WatchAncestryContext<'static> {
    WatchAncestryContext {
        changed_key_guid: PARENT_GUID,
        ancestor_guids: &PARENT_ANCESTORS,
        path_components: &PARENT_PATH,
    }
}

fn pending_set_security_effects<'a>() -> RegistrySetSecurityCommitEffects<'a> {
    RegistrySetSecurityCommitEffects {
        update_hive_generation: false,
        dispatch_watch_events: false,
        record_transaction_mutation_log: true,
        commit_visible_last_write_time_update: false,
        retain_existing_fd_grants: true,
        watch_mutation: Some(WatchMutationContext {
            changed_key_guid: KEY_GUID,
            ancestor_guids: &SECURITY_ANCESTORS,
            path_components: &SECURITY_PATH,
            event_type: REG_WATCH_SD_CHANGED,
        }),
    }
}

fn child_fd<'a>() -> KeyFdNamespaceView<'a> {
    KeyFdNamespaceView {
        resolved_path: &CHILD_PATH,
        ancestor_guids: &CHILD_ANCESTORS,
        orphaned: false,
    }
}

fn create_request<'a>(layer: &'a str) -> KeyCreateRecordsRequest<'a> {
    KeyCreateRecordsRequest {
        parent_guid: PARENT_GUID,
        parent_is_volatile: false,
        parent_granted_access: KEY_CREATE_SUB_KEY,
        child_name: "Child",
        candidate_guid: CHILD_GUID,
        active_key_guids: &[],
        retired_key_guids: &[],
        layer,
        flags: REG_OPTION_VOLATILE,
        caller_has_tcb_or_admin: false,
    }
}

#[test]
fn security_replay_work_preserves_watch_and_commit_intent() {
    let mut counter = TransactionOperationIndexCounter::new();
    let entry = plan_registry_set_security_transaction_log_entry(
        &pending_set_security_effects(),
        &mut counter,
    )
    .expect("security log entry");
    let record = TransactionMutationLogRecord::Security(entry);

    assert_eq!(
        transaction_mutation_log_record_commit_work(&record),
        Ok(TransactionMutationCommitWork::Security {
            operation_index: 1,
            changed_key_guid: KEY_GUID,
            watch_mutation: entry.watch_mutation,
            update_hive_generation: true,
            update_key_last_write_time: true,
        })
    );
}

#[test]
fn value_replay_work_preserves_value_layer_sequence_and_effect_intent() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(42);
    let planned = plan_value_write(
        &limits,
        &mut sequence_counter,
        &ValueWriteInput {
            key_guid: KEY_GUID,
            name: "Setting",
            layer: "base",
            value_type: REG_SZ,
            data: b"enabled",
            explicit_tombstone_operation: false,
            expected_sequence: None,
        },
    )
    .expect("value write plan");
    let mut counter = TransactionOperationIndexCounter::new();
    let entry = plan_value_write_transaction_log_entry(
        &limits,
        &planned,
        value_watch_context(),
        &mut counter,
    )
    .expect("value log entry");
    let record = TransactionMutationLogRecord::Value(entry);

    assert_eq!(
        transaction_mutation_log_record_commit_work(&record),
        Ok(TransactionMutationCommitWork::Value {
            operation_index: 1,
            key_guid: KEY_GUID,
            watch_context: value_watch_context(),
            value_name: Some("Setting"),
            layer: "base",
            sequence: Some(42),
            update_hive_generation: true,
            update_key_last_write_time: true,
            recompute_effective_value_events: true,
        })
    );
}

#[test]
fn key_path_replay_work_preserves_create_delete_and_hide_effect_shapes() {
    let limits = LcsLimits::default();
    let mut operation_counter = TransactionOperationIndexCounter::new();
    let mut sequence_counter = SequenceCounter::new(77);
    let create_plan =
        plan_key_create_records(&limits, &mut sequence_counter, &create_request("policy"))
            .expect("create records plan");
    let create = plan_key_create_transaction_log_entry(
        &limits,
        &create_plan,
        parent_watch_context(),
        &mut operation_counter,
    )
    .expect("create log entry");
    assert_eq!(
        transaction_mutation_log_record_commit_work(&TransactionMutationLogRecord::KeyPath(create)),
        Ok(TransactionMutationCommitWork::KeyPath {
            operation_index: 1,
            parent_guid: PARENT_GUID,
            parent_watch_context: parent_watch_context(),
            child_visibility_watch_context: None,
            child_name: "Child",
            layer: "policy",
            target_guid: Some(CHILD_GUID),
            sequence: Some(77),
            update_hive_generation: true,
            update_parent_last_write_time: false,
            recompute_effective_subkey_events: true,
            evaluate_orphaning: false,
            publish_new_key_guid: true,
        })
    );

    let delete = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(),
                layer: "base",
            },
            visible_child_count: 0,
        },
    )
    .expect("delete plan");
    let delete = plan_key_delete_transaction_log_entry(&limits, &delete, &mut operation_counter)
        .expect("delete log entry");
    assert_eq!(
        transaction_mutation_log_record_commit_work(&TransactionMutationLogRecord::KeyPath(delete)),
        Ok(TransactionMutationCommitWork::KeyPath {
            operation_index: 2,
            parent_guid: PARENT_GUID,
            parent_watch_context: delete.parent_watch_context,
            child_visibility_watch_context: delete.child_visibility_watch_context,
            child_name: "Child",
            layer: "base",
            target_guid: None,
            sequence: None,
            update_hive_generation: true,
            update_parent_last_write_time: true,
            recompute_effective_subkey_events: true,
            evaluate_orphaning: true,
            publish_new_key_guid: false,
        })
    );

    let hide = plan_key_hide(
        &limits,
        &mut sequence_counter,
        &HideKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(),
                layer: "base",
            },
        },
    )
    .expect("hide plan");
    let hide = plan_key_hide_transaction_log_entry(&limits, &hide, &mut operation_counter)
        .expect("hide log entry");
    assert_eq!(
        transaction_mutation_log_record_commit_work(&TransactionMutationLogRecord::KeyPath(hide)),
        Ok(TransactionMutationCommitWork::KeyPath {
            operation_index: 3,
            parent_guid: PARENT_GUID,
            parent_watch_context: hide.parent_watch_context,
            child_visibility_watch_context: hide.child_visibility_watch_context,
            child_name: "Child",
            layer: "base",
            target_guid: None,
            sequence: Some(78),
            update_hive_generation: true,
            update_parent_last_write_time: false,
            recompute_effective_subkey_events: true,
            evaluate_orphaning: false,
            publish_new_key_guid: false,
        })
    );
}

#[test]
fn replay_work_projection_revalidates_record_shape() {
    let limits = LcsLimits::default();
    let delete = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(),
                layer: "base",
            },
            visible_child_count: 0,
        },
    )
    .expect("delete plan");
    let mut counter = TransactionOperationIndexCounter::new();
    let mut entry = plan_key_delete_transaction_log_entry(&limits, &delete, &mut counter)
        .expect("delete log entry");
    entry.publish_new_key_guid_on_commit = true;
    let record = TransactionMutationLogRecord::KeyPath(entry);

    assert_eq!(
        transaction_mutation_log_record_commit_work(&record),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "delete_key.shape",
        })
    );
}
