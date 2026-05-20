use lcs_core::{
    DeleteKeyInput, Guid, KEY_CREATE_SUB_KEY, KeyCreateRecordsRequest, KeyFdNamespaceView,
    KeyPathMutationInput, LcsError, LcsLimits, REG_OPTION_VOLATILE, REG_SZ, REG_WATCH_SD_CHANGED,
    RegistrySetSecurityCommitEffects, SequenceCounter, TransactionMutationLogKind,
    TransactionMutationLogRecord, TransactionOperationIndexCounter, TransactionWatchBatchPlan,
    TransactionWatchBurstPlan, ValueWriteInput, WatchAncestryContext, WatchMutationContext,
    append_transaction_mutation_log_record, plan_key_create_records,
    plan_key_create_transaction_log_entry, plan_key_delete, plan_key_delete_transaction_log_entry,
    plan_registry_set_security_transaction_log_entry, plan_transaction_watch_batch,
    plan_value_write, plan_value_write_transaction_log_entry, summarize_transaction_mutation_log,
    transaction_mutation_log_record_watch_batch_member,
};

const ROOT_GUID: Guid = [0x11; 16];
const PARENT_GUID: Guid = [0x22; 16];
const CHILD_GUID: Guid = [0x33; 16];
const KEY_GUID: Guid = [0x44; 16];
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

fn security_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    TransactionMutationLogRecord::Security(
        plan_registry_set_security_transaction_log_entry(&pending_set_security_effects(), counter)
            .expect("security log entry"),
    )
}

fn value_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
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
    TransactionMutationLogRecord::Value(
        plan_value_write_transaction_log_entry(&limits, &planned, value_watch_context(), counter)
            .expect("value log entry"),
    )
}

fn create_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(77);
    let planned =
        plan_key_create_records(&limits, &mut sequence_counter, &create_request("policy"))
            .expect("create records plan");
    TransactionMutationLogRecord::KeyPath(
        plan_key_create_transaction_log_entry(&limits, &planned, parent_watch_context(), counter)
            .expect("create key log entry"),
    )
}

fn delete_key_record(
    counter: &mut TransactionOperationIndexCounter,
) -> TransactionMutationLogRecord<'static> {
    let limits = LcsLimits::default();
    let planned = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(),
                layer: "base",
            },
            visible_child_count: 0,
        },
    )
    .expect("delete key plan");
    TransactionMutationLogRecord::KeyPath(
        plan_key_delete_transaction_log_entry(&limits, &planned, counter)
            .expect("delete key log entry"),
    )
}

#[test]
fn append_rejects_duplicate_or_descending_operation_index_without_mutation() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut storage = [None; 2];
    append_transaction_mutation_log_record(&mut storage, security_record(&mut counter))
        .expect("append first");

    let mut duplicate = value_record(&mut counter);
    let TransactionMutationLogRecord::Value(entry) = &mut duplicate else {
        unreachable!();
    };
    entry.operation_index = 1;

    assert_eq!(
        append_transaction_mutation_log_record(&mut storage, duplicate),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "operation_index.order",
        })
    );
    assert!(storage[1].is_none());

    let mut descending_storage = [None; 2];
    let mut first = create_key_record(&mut counter);
    let TransactionMutationLogRecord::KeyPath(first_entry) = &mut first else {
        unreachable!();
    };
    first_entry.operation_index = 3;
    append_transaction_mutation_log_record(&mut descending_storage, first)
        .expect("append high-index first record");

    let mut descending = value_record(&mut counter);
    let TransactionMutationLogRecord::Value(entry) = &mut descending else {
        unreachable!();
    };
    entry.operation_index = 2;
    assert_eq!(
        append_transaction_mutation_log_record(&mut descending_storage, descending),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "operation_index.order",
        })
    );
    assert!(descending_storage[1].is_none());

    let mut zero_index = create_key_record(&mut counter);
    let TransactionMutationLogRecord::KeyPath(entry) = &mut zero_index else {
        unreachable!();
    };
    entry.operation_index = 0;
    assert_eq!(
        append_transaction_mutation_log_record(&mut storage, zero_index),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "operation_index",
        })
    );
    assert!(storage[1].is_none());
}

#[test]
fn preexisting_out_of_order_storage_fails_closed() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut first = security_record(&mut counter);
    let TransactionMutationLogRecord::Security(entry) = &mut first else {
        unreachable!();
    };
    entry.operation_index = 2;
    let mut second = value_record(&mut counter);
    let TransactionMutationLogRecord::Value(entry) = &mut second else {
        unreachable!();
    };
    entry.operation_index = 1;
    let storage = [Some(first), Some(second)];

    assert_eq!(
        summarize_transaction_mutation_log(&storage),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "operation_index.order",
        })
    );
}

#[test]
fn generic_record_batch_members_feed_existing_watch_batch_planner() {
    let mut counter = TransactionOperationIndexCounter::new();
    let records = [
        security_record(&mut counter),
        value_record(&mut counter),
        create_key_record(&mut counter),
    ];
    let members = [
        transaction_mutation_log_record_watch_batch_member(&records[0], 1)
            .expect("security member"),
        transaction_mutation_log_record_watch_batch_member(&records[1], 0).expect("value member"),
        transaction_mutation_log_record_watch_batch_member(&records[2], 2)
            .expect("key path member"),
    ];

    assert_eq!(
        plan_transaction_watch_batch(&LcsLimits::default(), &members),
        Ok(TransactionWatchBatchPlan {
            operation_count: 3,
            total_event_count: 3,
            delivery: TransactionWatchBurstPlan::EmitIndividualEvents { event_count: 3 },
            dispatch_without_interleaving: true,
        })
    );
    assert_eq!(records[0].kind(), TransactionMutationLogKind::SetSecurity);
    assert_eq!(members[1].operation_index, records[1].operation_index());
}

#[test]
fn batch_member_conversion_revalidates_record_shape() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut corrupt = delete_key_record(&mut counter);
    let TransactionMutationLogRecord::KeyPath(entry) = &mut corrupt else {
        unreachable!();
    };
    entry.sequence = Some(7);

    assert_eq!(
        transaction_mutation_log_record_watch_batch_member(&corrupt, 1),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "delete_key.shape",
        })
    );
}
