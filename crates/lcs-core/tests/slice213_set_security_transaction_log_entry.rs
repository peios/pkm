use lcs_core::{
    Guid, LcsError, LcsLimits, REG_WATCH_SD_CHANGED, REG_WATCH_VALUE_SET,
    RegistrySetSecurityCommitEffects, TransactionMutationLogKind, TransactionOperationIndexCounter,
    TransactionWatchBatchMember, WatchMutationContext,
    plan_registry_set_security_transaction_log_entry, plan_transaction_mutation_log_entry,
    plan_transaction_watch_batch, transaction_log_entry_watch_batch_member,
};

const ROOT_GUID: Guid = [
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
];
const KEY_GUID: Guid = [
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
];
const ANCESTORS: [Guid; 2] = [ROOT_GUID, KEY_GUID];
const PATH: [&str; 2] = ["Machine", "Policy"];

fn pending_set_security_effects<'a>() -> RegistrySetSecurityCommitEffects<'a> {
    RegistrySetSecurityCommitEffects {
        update_hive_generation: false,
        dispatch_watch_events: false,
        record_transaction_mutation_log: true,
        commit_visible_last_write_time_update: false,
        retain_existing_fd_grants: true,
        watch_mutation: Some(WatchMutationContext {
            changed_key_guid: KEY_GUID,
            ancestor_guids: &ANCESTORS,
            path_components: &PATH,
            event_type: REG_WATCH_SD_CHANGED,
        }),
    }
}

#[test]
fn pending_set_security_effects_allocate_ordered_transaction_log_entries() {
    let mut counter = TransactionOperationIndexCounter::new();

    let first = plan_registry_set_security_transaction_log_entry(
        &pending_set_security_effects(),
        &mut counter,
    )
    .expect("first transaction log entry");
    let second = plan_registry_set_security_transaction_log_entry(
        &pending_set_security_effects(),
        &mut counter,
    )
    .expect("second transaction log entry");

    assert_eq!(first.operation_index, 1);
    assert_eq!(second.operation_index, 2);
    assert_eq!(counter.next_index(), 3);
    assert_eq!(first.kind, TransactionMutationLogKind::SetSecurity);
    assert_eq!(first.watch_mutation.event_type, REG_WATCH_SD_CHANGED);
    assert_eq!(first.watch_mutation.changed_key_guid, KEY_GUID);
    assert_eq!(first.watch_mutation.ancestor_guids, ANCESTORS.as_slice());
    assert_eq!(first.watch_mutation.path_components, PATH.as_slice());
    assert!(first.update_hive_generation_on_commit);
    assert!(first.update_last_write_time_on_commit);

    let members = [
        transaction_log_entry_watch_batch_member(&first, 1),
        transaction_log_entry_watch_batch_member(&second, 2),
    ];
    let batch = plan_transaction_watch_batch(&LcsLimits::default(), &members)
        .expect("ordered SET_SECURITY log batch");
    assert_eq!(batch.operation_count, 2);
    assert_eq!(batch.total_event_count, 3);
    assert!(batch.dispatch_without_interleaving);
}

#[test]
fn set_security_transaction_log_rejects_non_pending_effects() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mut committed = pending_set_security_effects();
    committed.record_transaction_mutation_log = false;
    committed.update_hive_generation = true;
    committed.dispatch_watch_events = true;
    committed.commit_visible_last_write_time_update = true;

    assert_eq!(
        plan_registry_set_security_transaction_log_entry(&committed, &mut counter),
        Err(LcsError::InvalidRegistrySetSecurityPlan {
            field: "reg_set_security.transaction_effects",
        })
    );
    assert_eq!(counter.next_index(), 1);

    let mut missing_mutation = pending_set_security_effects();
    missing_mutation.watch_mutation = None;
    assert_eq!(
        plan_registry_set_security_transaction_log_entry(&missing_mutation, &mut counter),
        Err(LcsError::InvalidRegistrySetSecurityPlan {
            field: "reg_set_security.watch_mutation",
        })
    );
    assert_eq!(counter.next_index(), 1);
}

#[test]
fn operation_index_exhaustion_fails_before_log_entry_is_allocated() {
    assert_eq!(
        TransactionOperationIndexCounter::from_next_index(0),
        Err(LcsError::InvalidTransactionOperationIndex)
    );

    let mut counter = TransactionOperationIndexCounter::from_next_index(u64::MAX)
        .expect("maximum next operation index is representable until allocation");
    assert_eq!(
        plan_registry_set_security_transaction_log_entry(
            &pending_set_security_effects(),
            &mut counter
        ),
        Err(LcsError::TransactionOperationIndexOverflow)
    );
    assert_eq!(counter.next_index(), u64::MAX);
}

#[test]
fn set_security_log_entry_rejects_wrong_event_type_before_counter_advance() {
    let mut counter = TransactionOperationIndexCounter::new();
    let mutation = WatchMutationContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &ANCESTORS,
        path_components: &PATH,
        event_type: REG_WATCH_VALUE_SET,
    };

    assert_eq!(
        plan_transaction_mutation_log_entry(
            &mut counter,
            TransactionMutationLogKind::SetSecurity,
            mutation,
            true,
            true,
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "event_type",
        })
    );
    assert_eq!(counter.next_index(), 1);
}

#[test]
fn transaction_log_batch_member_uses_entry_order_and_caller_event_count() {
    let entry = plan_registry_set_security_transaction_log_entry(
        &pending_set_security_effects(),
        &mut TransactionOperationIndexCounter::new(),
    )
    .expect("transaction log entry");

    assert_eq!(
        transaction_log_entry_watch_batch_member(&entry, 0),
        TransactionWatchBatchMember {
            operation_index: 1,
            event_count: 0,
        }
    );
}
