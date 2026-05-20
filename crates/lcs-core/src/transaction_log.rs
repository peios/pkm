use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::constants::REG_WATCH_SD_CHANGED;
use crate::error::{LcsError, LcsResult};
use crate::key_path::{
    TransactionKeyPathMutationLogEntry, validate_child_visibility_watch_context,
    validate_parent_watch_context,
};
use crate::path::{
    validate_key_component_bytes, validate_layer_name_bytes, validate_value_name_bytes,
};
use crate::resolution::{EnumeratedSubkey, EnumeratedValue, Guid, ResolvedPathEntry};
use crate::source::NIL_GUID;
use crate::transaction::{
    TransactionKernelEffectsPlan, TransactionMutationLogEntry, TransactionMutationLogKind,
    TransactionOperationIndex,
};
use crate::value::TransactionValueMutationLogEntry;
use crate::watch::{
    EffectiveSubkeyWatchEvent, EffectiveValueWatchEvent, TransactionWatchBatchMember,
    TransactionWatchBurstPlan, TransactionWatchQueueApplyPlan, TransactionWatchQueueApplySummary,
    WatchAncestryContext, WatchDispatchDecision, WatchEventRecordPlan, WatchEventRecordRequest,
    WatchMutationContext, WatchQueueEntry, WatchedKeyVisibilityEvent, WatcherView,
    for_each_effective_subkey_watch_event, for_each_effective_value_watch_event,
    overflow_queue_entry, plan_transaction_watch_burst, plan_watch_dispatch,
    plan_watch_event_record, plan_watched_key_visibility_event, push_watch_queue_event,
    validate_watch_ancestry_context, validate_watch_queue_storage, watch_queue_snapshot,
};

/// One kernel-owned transaction mutation-log record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionMutationLogRecord<'a> {
    Security(TransactionMutationLogEntry<'a>),
    Value(TransactionValueMutationLogEntry<'a>),
    KeyPath(TransactionKeyPathMutationLogEntry<'a>),
}

/// Summary of fixed-capacity transaction mutation-log storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionMutationLogStorageSummary {
    pub entries: usize,
    pub capacity: usize,
    pub full: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InternalTransactionMutationLogStorageSummary {
    summary: TransactionMutationLogStorageSummary,
    last_operation_index: Option<TransactionOperationIndex>,
}

/// Result of appending one transaction mutation-log record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionMutationLogAppendPlan {
    pub slot: usize,
    pub operation_index: TransactionOperationIndex,
    pub entries: usize,
    pub capacity: usize,
    pub full: bool,
}

/// Planned storage effects for a transaction completion path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionMutationLogDispositionPlan {
    pub entries: usize,
    pub capacity: usize,
    pub apply_commit_effects: bool,
    pub emit_normal_watch_events: bool,
    pub clear_entries_after_effects: bool,
    pub retain_entries: bool,
}

/// Commit-time kernel work represented by one transaction mutation-log record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionMutationCommitWork<'a> {
    Security {
        operation_index: TransactionOperationIndex,
        changed_key_guid: Guid,
        watch_mutation: WatchMutationContext<'a>,
        update_hive_generation: bool,
        update_key_last_write_time: bool,
    },
    Value {
        operation_index: TransactionOperationIndex,
        key_guid: Guid,
        watch_context: WatchAncestryContext<'a>,
        value_name: Option<&'a str>,
        layer: &'a str,
        sequence: Option<u64>,
        update_hive_generation: bool,
        update_key_last_write_time: bool,
        recompute_effective_value_events: bool,
    },
    KeyPath {
        operation_index: TransactionOperationIndex,
        parent_guid: Guid,
        parent_watch_context: WatchAncestryContext<'a>,
        child_visibility_watch_context: Option<WatchAncestryContext<'a>>,
        child_name: &'a str,
        layer: &'a str,
        target_guid: Option<Guid>,
        sequence: Option<u64>,
        update_hive_generation: bool,
        update_parent_last_write_time: bool,
        recompute_effective_subkey_events: bool,
        evaluate_orphaning: bool,
        publish_new_key_guid: bool,
    },
}

/// Aggregate commit-time replay work for one transaction mutation log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionMutationReplaySummary {
    pub entries: usize,
    pub capacity: usize,
    pub increment_hive_generation_once: bool,
    pub key_last_write_updates: usize,
    pub parent_last_write_updates: usize,
    pub security_watch_mutations: usize,
    pub effective_value_recomputations: usize,
    pub effective_subkey_recomputations: usize,
    pub orphan_evaluations: usize,
    pub new_key_publications: usize,
}

/// Effective-value source snapshot scope needed for transaction watch replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReplayValueWatchScope<'a> {
    NamedValue { name: &'a str },
    AllValues,
}

/// Ordered watch replay input selected from one mutation-log record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReplayWatchInput<'a> {
    DirectSecurity {
        operation_index: TransactionOperationIndex,
        changed_key_guid: Guid,
        watch_mutation: WatchMutationContext<'a>,
    },
    EffectiveValue {
        operation_index: TransactionOperationIndex,
        kind: TransactionMutationLogKind,
        key_guid: Guid,
        watch_context: WatchAncestryContext<'a>,
        scope: TransactionReplayValueWatchScope<'a>,
        layer: &'a str,
        sequence: Option<u64>,
        requires_before_snapshot: bool,
        requires_after_snapshot: bool,
    },
    EffectiveSubkey {
        operation_index: TransactionOperationIndex,
        kind: TransactionMutationLogKind,
        parent_guid: Guid,
        parent_watch_context: WatchAncestryContext<'a>,
        child_visibility_watch_context: Option<WatchAncestryContext<'a>>,
        child_name: &'a str,
        layer: &'a str,
        target_guid: Option<Guid>,
        sequence: Option<u64>,
        requires_before_snapshot: bool,
        requires_after_snapshot: bool,
        evaluate_orphaning: bool,
        publish_new_key_guid: bool,
    },
}

/// Source snapshots needed to derive concrete watch events from one replay input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReplayWatchSnapshots<'a> {
    DirectSecurity,
    EffectiveValue(TransactionReplayValueSnapshots<'a>),
    EffectiveSubkey(TransactionReplaySubkeySnapshots<'a>),
}

/// Before/after effective-value snapshots for one replay input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplayValueSnapshots<'a> {
    pub before: &'a [EnumeratedValue<'a>],
    pub after: &'a [EnumeratedValue<'a>],
}

/// Before/after effective-subkey snapshots for one replay input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplaySubkeySnapshots<'a> {
    pub before_children: &'a [EnumeratedSubkey<'a>],
    pub after_children: &'a [EnumeratedSubkey<'a>],
    pub child_before: Option<ResolvedPathEntry<'a>>,
    pub child_after: Option<ResolvedPathEntry<'a>>,
}

/// Concrete watch event selected during transaction replay before watcher scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplayWatchEvent<'a> {
    pub operation_index: TransactionOperationIndex,
    pub mutation: WatchMutationContext<'a>,
    pub name: &'a str,
}

/// Per-watcher summary for dispatching a transaction replay event stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplayWatchDispatchSummary {
    pub operation_count: usize,
    pub delivered_event_count: usize,
    pub suppressed_event_count: usize,
    pub overflow_substitution_count: usize,
}

/// Aggregate source-query/watch-input work for one transaction mutation log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplayWatchInputSummary {
    pub entries: usize,
    pub capacity: usize,
    pub direct_security_mutations: usize,
    pub named_value_snapshot_inputs: usize,
    pub all_value_snapshot_inputs: usize,
    pub effective_subkey_snapshot_inputs: usize,
    pub requires_before_commit_source_queries: bool,
    pub requires_after_commit_source_queries: bool,
}

/// Concrete event-stream summary for transaction replay before watcher dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplayWatchEventStreamSummary {
    pub entries: usize,
    pub capacity: usize,
    pub direct_security_inputs: usize,
    pub effective_value_inputs: usize,
    pub effective_subkey_inputs: usize,
    pub emitted_events: usize,
}

/// Transaction boundary at which replay snapshot queries must run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReplaySnapshotPhase {
    BeforeCommit,
    AfterCommit,
}

/// Abstract source snapshot query needed for transaction watch replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReplaySnapshotQueryKind<'a> {
    EffectiveValue {
        key_guid: Guid,
        scope: TransactionReplayValueWatchScope<'a>,
    },
    EffectiveSubkeys {
        parent_guid: Guid,
    },
    ChildVisibility {
        parent_guid: Guid,
        child_name: &'a str,
    },
}

/// One ordered snapshot query intent selected from the mutation log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplaySnapshotQuery<'a> {
    pub phase: TransactionReplaySnapshotPhase,
    pub operation_index: TransactionOperationIndex,
    pub kind: TransactionReplaySnapshotQueryKind<'a>,
}

/// Summary of snapshot query intents selected for one transaction phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplaySnapshotQuerySummary {
    pub phase: TransactionReplaySnapshotPhase,
    pub entries: usize,
    pub capacity: usize,
    pub emitted_queries: usize,
    pub effective_value_queries: usize,
    pub effective_subkey_queries: usize,
    pub child_visibility_queries: usize,
    pub direct_security_inputs: usize,
    pub inputs_without_queries: usize,
}

/// Effective snapshot result retained for transaction watch replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReplaySnapshotResultKind<'a> {
    EffectiveValue {
        key_guid: Guid,
        scope: TransactionReplayValueWatchScope<'a>,
        values: &'a [EnumeratedValue<'a>],
    },
    EffectiveSubkeys {
        parent_guid: Guid,
        children: &'a [EnumeratedSubkey<'a>],
    },
    ChildVisibility {
        parent_guid: Guid,
        child_name: &'a str,
        child: Option<ResolvedPathEntry<'a>>,
    },
}

/// One retained source snapshot result selected by a replay snapshot query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplaySnapshotResult<'a> {
    pub phase: TransactionReplaySnapshotPhase,
    pub operation_index: TransactionOperationIndex,
    pub kind: TransactionReplaySnapshotResultKind<'a>,
}

/// Summary of fixed-capacity replay snapshot result storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplaySnapshotResultTableSummary {
    pub entries: usize,
    pub capacity: usize,
    pub effective_value_results: usize,
    pub effective_subkey_results: usize,
    pub child_visibility_results: usize,
}

impl TransactionMutationLogRecord<'_> {
    pub const fn operation_index(&self) -> TransactionOperationIndex {
        match self {
            Self::Security(entry) => entry.operation_index,
            Self::Value(entry) => entry.operation_index,
            Self::KeyPath(entry) => entry.operation_index,
        }
    }

    pub const fn kind(&self) -> TransactionMutationLogKind {
        match self {
            Self::Security(entry) => entry.kind,
            Self::Value(entry) => entry.kind,
            Self::KeyPath(entry) => entry.kind,
        }
    }
}

/// Validates fixed-capacity transaction mutation-log storage.
pub fn summarize_transaction_mutation_log(
    storage: &[Option<TransactionMutationLogRecord<'_>>],
) -> LcsResult<TransactionMutationLogStorageSummary> {
    Ok(summarize_transaction_mutation_log_internal(storage)?.summary)
}

/// Summarizes fixed-capacity replay snapshot result storage.
pub fn summarize_transaction_replay_snapshot_result_table(
    storage: &[Option<TransactionReplaySnapshotResult<'_>>],
) -> LcsResult<TransactionReplaySnapshotResultTableSummary> {
    let mut summary = TransactionReplaySnapshotResultTableSummary {
        entries: 0,
        capacity: storage.len(),
        effective_value_results: 0,
        effective_subkey_results: 0,
        child_visibility_results: 0,
    };
    let mut seen_empty = false;

    for (index, slot) in storage.iter().enumerate() {
        let Some(result) = slot else {
            seen_empty = true;
            continue;
        };
        if seen_empty {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "replay_snapshot.result_table_dense_prefix",
            });
        }
        validate_transaction_replay_snapshot_result(result)?;
        for prior in &storage[..index] {
            let Some(prior_result) = prior else {
                continue;
            };
            if transaction_replay_snapshot_results_same_identity(result, prior_result) {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "replay_snapshot.result_duplicate",
                });
            }
        }
        summary.entries += 1;
        match result.kind {
            TransactionReplaySnapshotResultKind::EffectiveValue { .. } => {
                summary.effective_value_results += 1;
            }
            TransactionReplaySnapshotResultKind::EffectiveSubkeys { .. } => {
                summary.effective_subkey_results += 1;
            }
            TransactionReplaySnapshotResultKind::ChildVisibility { .. } => {
                summary.child_visibility_results += 1;
            }
        }
    }

    Ok(summary)
}

/// Inserts one materialized replay snapshot result into fixed-capacity storage.
pub fn insert_transaction_replay_snapshot_result<'a>(
    storage: &mut [Option<TransactionReplaySnapshotResult<'a>>],
    result: TransactionReplaySnapshotResult<'a>,
) -> LcsResult<TransactionReplaySnapshotResultTableSummary> {
    validate_transaction_replay_snapshot_result(&result)?;
    let summary = summarize_transaction_replay_snapshot_result_table(storage)?;
    for existing in storage[..summary.entries].iter().flatten() {
        if transaction_replay_snapshot_results_same_identity(&result, existing) {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "replay_snapshot.result_duplicate",
            });
        }
    }
    if summary.entries == summary.capacity {
        return Err(LcsError::TransactionReplaySnapshotStorageFull {
            field: "replay_snapshot.results",
            required: summary
                .entries
                .checked_add(1)
                .ok_or(LcsError::RsiPayloadLengthOverflow)?,
            capacity: summary.capacity,
        });
    }
    storage[summary.entries] = Some(result);
    summarize_transaction_replay_snapshot_result_table(storage)
}

/// Visits stored replay snapshot results in deterministic table order.
pub fn for_each_transaction_replay_snapshot_result<'a, F>(
    storage: &[Option<TransactionReplaySnapshotResult<'a>>],
    mut visitor: F,
) -> LcsResult<TransactionReplaySnapshotResultTableSummary>
where
    F: FnMut(TransactionReplaySnapshotResult<'a>) -> LcsResult<()>,
{
    let summary = summarize_transaction_replay_snapshot_result_table(storage)?;
    for slot in &storage[..summary.entries] {
        let Some(result) = slot else {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "replay_snapshot.result_table_dense_prefix",
            });
        };
        visitor(*result)?;
    }
    Ok(summary)
}

/// Appends one validated transaction mutation-log record before source dispatch.
pub fn append_transaction_mutation_log_record<'a>(
    storage: &mut [Option<TransactionMutationLogRecord<'a>>],
    record: TransactionMutationLogRecord<'a>,
) -> LcsResult<TransactionMutationLogAppendPlan> {
    validate_transaction_mutation_log_record(&record)?;
    let internal_summary = summarize_transaction_mutation_log_internal(storage)?;
    let summary = internal_summary.summary;
    if summary.full {
        return Err(LcsError::TransactionMutationLogFull {
            capacity: summary.capacity,
        });
    }
    if internal_summary
        .last_operation_index
        .is_some_and(|last_operation_index| record.operation_index() <= last_operation_index)
    {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "operation_index.order",
        });
    }

    let slot = summary.entries;
    storage[slot] = Some(record);
    let entries = slot + 1;
    Ok(TransactionMutationLogAppendPlan {
        slot,
        operation_index: record.operation_index(),
        entries,
        capacity: summary.capacity,
        full: entries == summary.capacity,
    })
}

/// Converts a stored transaction mutation-log record to a watch batch member.
pub fn transaction_mutation_log_record_watch_batch_member(
    record: &TransactionMutationLogRecord<'_>,
    event_count: usize,
) -> LcsResult<TransactionWatchBatchMember> {
    validate_transaction_mutation_log_record(record)?;
    Ok(TransactionWatchBatchMember {
        operation_index: record.operation_index(),
        event_count,
    })
}

/// Projects one validated mutation-log record into commit-time replay work.
pub fn transaction_mutation_log_record_commit_work<'a>(
    record: &TransactionMutationLogRecord<'a>,
) -> LcsResult<TransactionMutationCommitWork<'a>> {
    validate_transaction_mutation_log_record(record)?;
    Ok(match record {
        TransactionMutationLogRecord::Security(entry) => TransactionMutationCommitWork::Security {
            operation_index: entry.operation_index,
            changed_key_guid: entry.watch_mutation.changed_key_guid,
            watch_mutation: entry.watch_mutation,
            update_hive_generation: entry.update_hive_generation_on_commit,
            update_key_last_write_time: entry.update_last_write_time_on_commit,
        },
        TransactionMutationLogRecord::Value(entry) => TransactionMutationCommitWork::Value {
            operation_index: entry.operation_index,
            key_guid: entry.key_guid,
            watch_context: entry.watch_context,
            value_name: entry.value_name,
            layer: entry.layer,
            sequence: entry.sequence,
            update_hive_generation: entry.update_hive_generation_on_commit,
            update_key_last_write_time: entry.update_last_write_time_on_commit,
            recompute_effective_value_events: entry.recompute_effective_value_events_on_commit,
        },
        TransactionMutationLogRecord::KeyPath(entry) => TransactionMutationCommitWork::KeyPath {
            operation_index: entry.operation_index,
            parent_guid: entry.parent_guid,
            parent_watch_context: entry.parent_watch_context,
            child_visibility_watch_context: entry.child_visibility_watch_context,
            child_name: entry.child_name,
            layer: entry.layer,
            target_guid: entry.target_guid,
            sequence: entry.sequence,
            update_hive_generation: entry.update_hive_generation_on_commit,
            update_parent_last_write_time: entry.update_parent_last_write_time_on_commit,
            recompute_effective_subkey_events: entry.recompute_effective_subkey_events_on_commit,
            evaluate_orphaning: entry.evaluate_orphaning_on_commit,
            publish_new_key_guid: entry.publish_new_key_guid_on_commit,
        },
    })
}

/// Summarizes the kernel work needed after a successful transaction commit.
pub fn summarize_transaction_mutation_log_replay(
    storage: &[Option<TransactionMutationLogRecord<'_>>],
) -> LcsResult<TransactionMutationReplaySummary> {
    let storage_summary = summarize_transaction_mutation_log_internal(storage)?.summary;
    let mut replay_summary = TransactionMutationReplaySummary {
        entries: storage_summary.entries,
        capacity: storage_summary.capacity,
        increment_hive_generation_once: false,
        key_last_write_updates: 0,
        parent_last_write_updates: 0,
        security_watch_mutations: 0,
        effective_value_recomputations: 0,
        effective_subkey_recomputations: 0,
        orphan_evaluations: 0,
        new_key_publications: 0,
    };

    for slot in &storage[..storage_summary.entries] {
        let Some(record) = slot else {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "transaction_log.dense_prefix",
            });
        };
        match transaction_mutation_log_record_commit_work(record)? {
            TransactionMutationCommitWork::Security {
                update_hive_generation,
                update_key_last_write_time,
                ..
            } => {
                replay_summary.increment_hive_generation_once |= update_hive_generation;
                replay_summary.security_watch_mutations += 1;
                if update_key_last_write_time {
                    replay_summary.key_last_write_updates += 1;
                }
            }
            TransactionMutationCommitWork::Value {
                update_hive_generation,
                update_key_last_write_time,
                recompute_effective_value_events,
                ..
            } => {
                replay_summary.increment_hive_generation_once |= update_hive_generation;
                if update_key_last_write_time {
                    replay_summary.key_last_write_updates += 1;
                }
                if recompute_effective_value_events {
                    replay_summary.effective_value_recomputations += 1;
                }
            }
            TransactionMutationCommitWork::KeyPath {
                update_hive_generation,
                update_parent_last_write_time,
                recompute_effective_subkey_events,
                evaluate_orphaning,
                publish_new_key_guid,
                ..
            } => {
                replay_summary.increment_hive_generation_once |= update_hive_generation;
                if update_parent_last_write_time {
                    replay_summary.parent_last_write_updates += 1;
                }
                if recompute_effective_subkey_events {
                    replay_summary.effective_subkey_recomputations += 1;
                }
                if evaluate_orphaning {
                    replay_summary.orphan_evaluations += 1;
                }
                if publish_new_key_guid {
                    replay_summary.new_key_publications += 1;
                }
            }
        }
    }

    Ok(replay_summary)
}

/// Converts one validated mutation-log record into commit-time watch replay input.
pub fn transaction_mutation_log_record_watch_replay_input<'a>(
    limits: &LcsLimits,
    record: &TransactionMutationLogRecord<'a>,
) -> LcsResult<TransactionReplayWatchInput<'a>> {
    let kind = record.kind();
    Ok(match transaction_mutation_log_record_commit_work(record)? {
        TransactionMutationCommitWork::Security {
            operation_index,
            changed_key_guid,
            watch_mutation,
            ..
        } => {
            validate_replay_watch_mutation(limits, &watch_mutation)?;
            TransactionReplayWatchInput::DirectSecurity {
                operation_index,
                changed_key_guid,
                watch_mutation,
            }
        }
        TransactionMutationCommitWork::Value {
            operation_index,
            key_guid,
            watch_context,
            value_name,
            layer,
            sequence,
            recompute_effective_value_events,
            ..
        } => {
            validate_replay_guid("value.key_guid", key_guid)?;
            validate_replay_watch_context(limits, "value.watch_context", &watch_context)?;
            if watch_context.changed_key_guid != key_guid {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "value.watch_context.changed_key_guid",
                });
            }
            let layer = validate_layer_name_bytes(layer.as_bytes(), limits)?;
            let scope = match value_name {
                Some(name) => TransactionReplayValueWatchScope::NamedValue {
                    name: validate_value_name_bytes(name.as_bytes(), limits)?,
                },
                None => TransactionReplayValueWatchScope::AllValues,
            };
            TransactionReplayWatchInput::EffectiveValue {
                operation_index,
                kind,
                key_guid,
                watch_context,
                scope,
                layer,
                sequence,
                requires_before_snapshot: recompute_effective_value_events,
                requires_after_snapshot: recompute_effective_value_events,
            }
        }
        TransactionMutationCommitWork::KeyPath {
            operation_index,
            parent_guid,
            parent_watch_context,
            child_visibility_watch_context,
            child_name,
            layer,
            target_guid,
            sequence,
            recompute_effective_subkey_events,
            evaluate_orphaning,
            publish_new_key_guid,
            ..
        } => {
            validate_replay_guid("key_path.parent_guid", parent_guid)?;
            validate_replay_watch_context(
                limits,
                "key_path.parent_watch_context",
                &parent_watch_context,
            )?;
            if parent_watch_context.changed_key_guid != parent_guid {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "key_path.parent_watch_context.changed_key_guid",
                });
            }
            if let Some(child_context) = child_visibility_watch_context {
                validate_replay_watch_context(
                    limits,
                    "key_path.child_visibility_watch_context",
                    &child_context,
                )?;
            }
            if let Some(target_guid) = target_guid {
                validate_replay_guid("key_path.target_guid", target_guid)?;
            }
            let child_name = validate_key_component_bytes(child_name.as_bytes(), limits)?;
            let layer = validate_layer_name_bytes(layer.as_bytes(), limits)?;
            TransactionReplayWatchInput::EffectiveSubkey {
                operation_index,
                kind,
                parent_guid,
                parent_watch_context,
                child_visibility_watch_context,
                child_name,
                layer,
                target_guid,
                sequence,
                requires_before_snapshot: recompute_effective_subkey_events,
                requires_after_snapshot: recompute_effective_subkey_events,
                evaluate_orphaning,
                publish_new_key_guid,
            }
        }
    })
}

/// Summarizes ordered watch replay inputs after a successful transaction commit.
pub fn summarize_transaction_replay_watch_inputs(
    limits: &LcsLimits,
    storage: &[Option<TransactionMutationLogRecord<'_>>],
) -> LcsResult<TransactionReplayWatchInputSummary> {
    let storage_summary = summarize_transaction_mutation_log_internal(storage)?.summary;
    let mut summary = TransactionReplayWatchInputSummary {
        entries: storage_summary.entries,
        capacity: storage_summary.capacity,
        direct_security_mutations: 0,
        named_value_snapshot_inputs: 0,
        all_value_snapshot_inputs: 0,
        effective_subkey_snapshot_inputs: 0,
        requires_before_commit_source_queries: false,
        requires_after_commit_source_queries: false,
    };

    for slot in &storage[..storage_summary.entries] {
        let Some(record) = slot else {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "transaction_log.dense_prefix",
            });
        };
        match transaction_mutation_log_record_watch_replay_input(limits, record)? {
            TransactionReplayWatchInput::DirectSecurity { .. } => {
                summary.direct_security_mutations += 1;
            }
            TransactionReplayWatchInput::EffectiveValue {
                scope,
                requires_before_snapshot,
                requires_after_snapshot,
                ..
            } => {
                match scope {
                    TransactionReplayValueWatchScope::NamedValue { .. } => {
                        summary.named_value_snapshot_inputs += 1;
                    }
                    TransactionReplayValueWatchScope::AllValues => {
                        summary.all_value_snapshot_inputs += 1;
                    }
                }
                summary.requires_before_commit_source_queries |= requires_before_snapshot;
                summary.requires_after_commit_source_queries |= requires_after_snapshot;
            }
            TransactionReplayWatchInput::EffectiveSubkey {
                requires_before_snapshot,
                requires_after_snapshot,
                ..
            } => {
                summary.effective_subkey_snapshot_inputs += 1;
                summary.requires_before_commit_source_queries |= requires_before_snapshot;
                summary.requires_after_commit_source_queries |= requires_after_snapshot;
            }
        }
    }

    Ok(summary)
}

/// Emits abstract source snapshot queries for one transaction replay phase.
pub fn for_each_transaction_replay_snapshot_query<'a, F>(
    limits: &LcsLimits,
    storage: &[Option<TransactionMutationLogRecord<'a>>],
    phase: TransactionReplaySnapshotPhase,
    mut emit: F,
) -> LcsResult<TransactionReplaySnapshotQuerySummary>
where
    F: FnMut(TransactionReplaySnapshotQuery<'a>) -> LcsResult<()>,
{
    let storage_summary = summarize_transaction_mutation_log_internal(storage)?.summary;
    let mut summary = TransactionReplaySnapshotQuerySummary {
        phase,
        entries: storage_summary.entries,
        capacity: storage_summary.capacity,
        emitted_queries: 0,
        effective_value_queries: 0,
        effective_subkey_queries: 0,
        child_visibility_queries: 0,
        direct_security_inputs: 0,
        inputs_without_queries: 0,
    };

    for slot in &storage[..storage_summary.entries] {
        let Some(record) = slot else {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "transaction_log.dense_prefix",
            });
        };
        let input = transaction_mutation_log_record_watch_replay_input(limits, record)?;
        match input {
            TransactionReplayWatchInput::DirectSecurity { .. } => {
                summary.direct_security_inputs += 1;
                summary.inputs_without_queries += 1;
            }
            TransactionReplayWatchInput::EffectiveValue {
                operation_index,
                key_guid,
                scope,
                requires_before_snapshot,
                requires_after_snapshot,
                ..
            } => {
                if replay_snapshot_required_for_phase(
                    phase,
                    requires_before_snapshot,
                    requires_after_snapshot,
                ) {
                    emit(TransactionReplaySnapshotQuery {
                        phase,
                        operation_index,
                        kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
                            key_guid,
                            scope,
                        },
                    })?;
                    summary.emitted_queries += 1;
                    summary.effective_value_queries += 1;
                } else {
                    summary.inputs_without_queries += 1;
                }
            }
            TransactionReplayWatchInput::EffectiveSubkey {
                operation_index,
                parent_guid,
                child_visibility_watch_context,
                child_name,
                requires_before_snapshot,
                requires_after_snapshot,
                ..
            } => {
                if replay_snapshot_required_for_phase(
                    phase,
                    requires_before_snapshot,
                    requires_after_snapshot,
                ) {
                    emit(TransactionReplaySnapshotQuery {
                        phase,
                        operation_index,
                        kind: TransactionReplaySnapshotQueryKind::EffectiveSubkeys { parent_guid },
                    })?;
                    summary.emitted_queries += 1;
                    summary.effective_subkey_queries += 1;

                    if child_visibility_watch_context.is_some() {
                        emit(TransactionReplaySnapshotQuery {
                            phase,
                            operation_index,
                            kind: TransactionReplaySnapshotQueryKind::ChildVisibility {
                                parent_guid,
                                child_name,
                            },
                        })?;
                        summary.emitted_queries += 1;
                        summary.child_visibility_queries += 1;
                    }
                } else {
                    summary.inputs_without_queries += 1;
                }
            }
        }
    }

    Ok(summary)
}

/// Summarizes concrete transaction replay watch events after snapshot matching.
pub fn summarize_transaction_replay_watch_event_stream<'a>(
    limits: &LcsLimits,
    storage: &[Option<TransactionMutationLogRecord<'a>>],
    results: &'a [TransactionReplaySnapshotResult<'a>],
) -> LcsResult<TransactionReplayWatchEventStreamSummary> {
    summarize_transaction_replay_watch_event_stream_internal(limits, storage, results)
}

/// Emits concrete transaction replay watch events after full prevalidation.
pub fn for_each_transaction_replay_watch_event_stream<'a, F>(
    limits: &LcsLimits,
    storage: &[Option<TransactionMutationLogRecord<'a>>],
    results: &'a [TransactionReplaySnapshotResult<'a>],
    mut emit: F,
) -> LcsResult<TransactionReplayWatchEventStreamSummary>
where
    F: FnMut(TransactionReplayWatchEvent<'a>) -> LcsResult<()>,
{
    let summary =
        summarize_transaction_replay_watch_event_stream_internal(limits, storage, results)?;
    let storage_summary = summarize_transaction_mutation_log_internal(storage)?.summary;
    let mut emitted_events = 0usize;

    for slot in &storage[..storage_summary.entries] {
        let Some(record) = slot else {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "transaction_log.dense_prefix",
            });
        };
        let input = transaction_mutation_log_record_watch_replay_input(limits, record)?;
        let snapshots = resolve_transaction_replay_watch_snapshots(limits, &input, results)?;
        let emitted =
            for_each_transaction_replay_watch_event(limits, &input, snapshots, |event| {
                emit(event)
            })?;
        emitted_events = emitted_events
            .checked_add(emitted)
            .ok_or(LcsError::TransactionWatchBatchEventCountOverflow)?;
    }
    if emitted_events != summary.emitted_events {
        return Err(LcsError::TransactionWatchEventCountMismatch {
            expected: summary.emitted_events,
            actual: emitted_events,
        });
    }
    Ok(summary)
}

/// Matches retained before/after snapshot results to one replay input.
pub fn resolve_transaction_replay_watch_snapshots<'a>(
    limits: &LcsLimits,
    input: &TransactionReplayWatchInput<'a>,
    results: &'a [TransactionReplaySnapshotResult<'a>],
) -> LcsResult<TransactionReplayWatchSnapshots<'a>> {
    match input {
        TransactionReplayWatchInput::DirectSecurity {
            operation_index,
            watch_mutation,
            ..
        } => {
            validate_replay_watch_mutation(limits, watch_mutation)?;
            require_no_replay_snapshot_results(results, *operation_index)?;
            Ok(TransactionReplayWatchSnapshots::DirectSecurity)
        }
        TransactionReplayWatchInput::EffectiveValue {
            operation_index,
            key_guid,
            watch_context,
            scope,
            layer,
            requires_before_snapshot,
            requires_after_snapshot,
            ..
        } => {
            require_replay_snapshot_result_categories(
                results,
                *operation_index,
                ReplaySnapshotInputCategory::EffectiveValue,
            )?;
            let before = select_effective_value_snapshot_result(
                results,
                TransactionReplaySnapshotPhase::BeforeCommit,
                *operation_index,
                *key_guid,
                *scope,
                *requires_before_snapshot,
            )?;
            let after = select_effective_value_snapshot_result(
                results,
                TransactionReplaySnapshotPhase::AfterCommit,
                *operation_index,
                *key_guid,
                *scope,
                *requires_after_snapshot,
            )?;
            let snapshots = TransactionReplayValueSnapshots { before, after };
            validate_effective_value_replay_input(
                limits,
                *key_guid,
                *watch_context,
                *scope,
                layer,
                snapshots,
            )?;
            Ok(TransactionReplayWatchSnapshots::EffectiveValue(snapshots))
        }
        TransactionReplayWatchInput::EffectiveSubkey {
            operation_index,
            parent_guid,
            parent_watch_context,
            child_visibility_watch_context,
            child_name,
            layer,
            requires_before_snapshot,
            requires_after_snapshot,
            ..
        } => {
            require_replay_snapshot_result_categories(
                results,
                *operation_index,
                ReplaySnapshotInputCategory::EffectiveSubkey,
            )?;
            let before_children = select_effective_subkey_snapshot_result(
                results,
                TransactionReplaySnapshotPhase::BeforeCommit,
                *operation_index,
                *parent_guid,
                *requires_before_snapshot,
            )?;
            let after_children = select_effective_subkey_snapshot_result(
                results,
                TransactionReplaySnapshotPhase::AfterCommit,
                *operation_index,
                *parent_guid,
                *requires_after_snapshot,
            )?;
            let child_before = select_child_visibility_snapshot_result(
                results,
                TransactionReplaySnapshotPhase::BeforeCommit,
                *operation_index,
                *parent_guid,
                child_name,
                child_visibility_watch_context.is_some() && *requires_before_snapshot,
            )?;
            let child_after = select_child_visibility_snapshot_result(
                results,
                TransactionReplaySnapshotPhase::AfterCommit,
                *operation_index,
                *parent_guid,
                child_name,
                child_visibility_watch_context.is_some() && *requires_after_snapshot,
            )?;
            let snapshots = TransactionReplaySubkeySnapshots {
                before_children,
                after_children,
                child_before,
                child_after,
            };
            validate_effective_subkey_replay_input(
                limits,
                *parent_guid,
                *parent_watch_context,
                *child_visibility_watch_context,
                child_name,
                layer,
                snapshots,
            )?;
            Ok(TransactionReplayWatchSnapshots::EffectiveSubkey(snapshots))
        }
    }
}

/// Derives concrete watch events for one committed transaction replay input.
pub fn for_each_transaction_replay_watch_event<'a, F>(
    limits: &LcsLimits,
    input: &TransactionReplayWatchInput<'a>,
    snapshots: TransactionReplayWatchSnapshots<'a>,
    mut emit: F,
) -> LcsResult<usize>
where
    F: FnMut(TransactionReplayWatchEvent<'a>) -> LcsResult<()>,
{
    match (input, snapshots) {
        (
            TransactionReplayWatchInput::DirectSecurity {
                operation_index,
                watch_mutation,
                ..
            },
            TransactionReplayWatchSnapshots::DirectSecurity,
        ) => {
            validate_replay_watch_mutation(limits, watch_mutation)?;
            emit(TransactionReplayWatchEvent {
                operation_index: *operation_index,
                mutation: *watch_mutation,
                name: "",
            })?;
            Ok(1)
        }
        (
            TransactionReplayWatchInput::EffectiveValue {
                operation_index,
                key_guid,
                watch_context,
                scope,
                layer,
                ..
            },
            TransactionReplayWatchSnapshots::EffectiveValue(snapshots),
        ) => {
            validate_effective_value_replay_input(
                limits,
                *key_guid,
                *watch_context,
                *scope,
                layer,
                snapshots,
            )?;
            for_each_effective_value_watch_event(
                limits,
                snapshots.before,
                snapshots.after,
                |event| {
                    let (event_type, name) = value_replay_event_parts(event);
                    emit(TransactionReplayWatchEvent {
                        operation_index: *operation_index,
                        mutation: watch_context.with_event(event_type),
                        name,
                    })
                },
            )
        }
        (
            TransactionReplayWatchInput::EffectiveSubkey {
                operation_index,
                parent_guid,
                parent_watch_context,
                child_visibility_watch_context,
                child_name,
                layer,
                ..
            },
            TransactionReplayWatchSnapshots::EffectiveSubkey(snapshots),
        ) => {
            let child_visibility_event = validate_effective_subkey_replay_input(
                limits,
                *parent_guid,
                *parent_watch_context,
                *child_visibility_watch_context,
                child_name,
                layer,
                snapshots,
            )?;
            let mut emitted = for_each_effective_subkey_watch_event(
                limits,
                snapshots.before_children,
                snapshots.after_children,
                |event| {
                    let (event_type, name) = subkey_replay_event_parts(event);
                    emit(TransactionReplayWatchEvent {
                        operation_index: *operation_index,
                        mutation: parent_watch_context.with_event(event_type),
                        name,
                    })
                },
            )?;
            if let Some((context, event)) = child_visibility_event {
                emit(TransactionReplayWatchEvent {
                    operation_index: *operation_index,
                    mutation: context.with_event(event.event_type()),
                    name: "",
                })?;
                emitted = emitted
                    .checked_add(1)
                    .ok_or(LcsError::TransactionWatchBatchEventCountOverflow)?;
            }
            Ok(emitted)
        }
        _ => Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_kind",
        }),
    }
}

/// Summarizes per-watcher dispatch for a concrete transaction replay stream.
pub fn summarize_transaction_replay_watch_dispatch(
    limits: &LcsLimits,
    watcher: WatcherView,
    events: &[TransactionReplayWatchEvent<'_>],
) -> LcsResult<TransactionReplayWatchDispatchSummary> {
    summarize_transaction_replay_watch_dispatch_internal(limits, watcher, events)
}

/// Emits per-watcher transaction batch members and queue-entry shapes.
pub fn for_each_transaction_replay_watch_dispatch<'a, FM, FE>(
    limits: &LcsLimits,
    watcher: WatcherView,
    events: &'a [TransactionReplayWatchEvent<'a>],
    mut emit_member: FM,
    mut emit_entry: FE,
) -> LcsResult<TransactionReplayWatchDispatchSummary>
where
    FM: FnMut(TransactionWatchBatchMember) -> LcsResult<()>,
    FE: FnMut(WatchQueueEntry) -> LcsResult<()>,
{
    let summary = summarize_transaction_replay_watch_dispatch_internal(limits, watcher, events)?;
    let mut current_operation_index = None;
    let mut current_event_count = 0usize;

    for event in events {
        if current_operation_index != Some(event.operation_index) {
            emit_replay_watch_batch_member(
                current_operation_index,
                current_event_count,
                &mut emit_member,
            )?;
            current_operation_index = Some(event.operation_index);
            current_event_count = 0;
        }

        if let Some((entry, _)) = replay_watch_queue_entry_for_watcher(limits, watcher, event)? {
            emit_entry(entry)?;
            current_event_count = current_event_count
                .checked_add(1)
                .ok_or(LcsError::TransactionWatchBatchEventCountOverflow)?;
        }
    }

    emit_replay_watch_batch_member(
        current_operation_index,
        current_event_count,
        &mut emit_member,
    )?;
    Ok(summary)
}

/// Applies a concrete transaction replay event stream to one watch queue.
pub fn apply_transaction_replay_watch_queue(
    limits: &LcsLimits,
    watcher: WatcherView,
    queue: &mut [WatchQueueEntry],
    queued_events: usize,
    events: &[TransactionReplayWatchEvent<'_>],
) -> LcsResult<TransactionWatchQueueApplyPlan> {
    validate_watch_queue_storage(limits.notification_queue_size, queue.len())?;
    let initial_state = watch_queue_snapshot(queue, queued_events)?;
    let summary = summarize_transaction_replay_watch_dispatch_internal(limits, watcher, events)?;

    match plan_transaction_watch_burst(limits, summary.delivered_event_count)? {
        TransactionWatchBurstPlan::NoEvents => {
            Ok(TransactionWatchQueueApplyPlan::NoEvents(initial_state))
        }
        TransactionWatchBurstPlan::EmitOverflowOnly {
            attempted_event_count,
            ..
        } => {
            let push = push_watch_queue_event(
                limits.notification_queue_size,
                queue,
                queued_events,
                overflow_queue_entry(),
            )?;
            Ok(TransactionWatchQueueApplyPlan::Applied(
                TransactionWatchQueueApplySummary {
                    queued_events: push.queued_events,
                    contains_overflow: push.contains_overflow,
                    attempted_event_count,
                    queued_individual_events: 0,
                    queued_overflow_only: true,
                    dispatch_without_interleaving: true,
                },
            ))
        }
        TransactionWatchBurstPlan::EmitIndividualEvents { event_count } => {
            let mut current_queued_events = queued_events;
            let mut contains_overflow = initial_state.contains_overflow;
            for event in events {
                if let Some((entry, _)) =
                    replay_watch_queue_entry_for_watcher(limits, watcher, event)?
                {
                    let push = push_watch_queue_event(
                        limits.notification_queue_size,
                        queue,
                        current_queued_events,
                        entry,
                    )?;
                    current_queued_events = push.queued_events;
                    contains_overflow = push.contains_overflow;
                }
            }
            Ok(TransactionWatchQueueApplyPlan::Applied(
                TransactionWatchQueueApplySummary {
                    queued_events: current_queued_events,
                    contains_overflow,
                    attempted_event_count: summary.delivered_event_count,
                    queued_individual_events: event_count,
                    queued_overflow_only: false,
                    dispatch_without_interleaving: true,
                },
            ))
        }
    }
}

/// Plans whether transaction completion applies, discards, or retains the log.
pub fn plan_transaction_mutation_log_disposition(
    effects: TransactionKernelEffectsPlan,
    storage: &[Option<TransactionMutationLogRecord<'_>>],
) -> LcsResult<TransactionMutationLogDispositionPlan> {
    let summary = summarize_transaction_mutation_log(storage)?;
    let (
        apply_commit_effects,
        emit_normal_watch_events,
        clear_entries_after_effects,
        retain_entries,
    ) = match effects {
        TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects => {
            (true, true, true, false)
        }
        TransactionKernelEffectsPlan::DiscardMutationLogWithoutEvents => {
            (false, false, true, false)
        }
        TransactionKernelEffectsPlan::RetainMutationLogForOpenTransaction
        | TransactionKernelEffectsPlan::RetainMutationLogForLateResponse => {
            (false, false, false, true)
        }
    };

    Ok(TransactionMutationLogDispositionPlan {
        entries: summary.entries,
        capacity: summary.capacity,
        apply_commit_effects,
        emit_normal_watch_events,
        clear_entries_after_effects,
        retain_entries,
    })
}

/// Releases all currently stored mutation-log entries.
pub fn clear_transaction_mutation_log(
    storage: &mut [Option<TransactionMutationLogRecord<'_>>],
) -> LcsResult<TransactionMutationLogStorageSummary> {
    let summary = summarize_transaction_mutation_log(storage)?;
    for slot in &mut storage[..summary.entries] {
        *slot = None;
    }
    Ok(TransactionMutationLogStorageSummary {
        entries: 0,
        capacity: summary.capacity,
        full: false,
    })
}

fn summarize_transaction_mutation_log_internal(
    storage: &[Option<TransactionMutationLogRecord<'_>>],
) -> LcsResult<InternalTransactionMutationLogStorageSummary> {
    let mut entries = 0;
    let mut seen_empty = false;
    let mut last_operation_index = None;

    for slot in storage {
        match (slot, seen_empty) {
            (Some(record), false) => {
                validate_transaction_mutation_log_record(record)?;
                if last_operation_index.is_some_and(|previous| record.operation_index() <= previous)
                {
                    return Err(LcsError::InvalidTransactionMutationLogEntry {
                        field: "operation_index.order",
                    });
                }
                last_operation_index = Some(record.operation_index());
                entries += 1;
            }
            (None, false) => {
                seen_empty = true;
            }
            (Some(_), true) => {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "transaction_log.dense_prefix",
                });
            }
            (None, true) => {}
        }
    }

    Ok(InternalTransactionMutationLogStorageSummary {
        summary: TransactionMutationLogStorageSummary {
            entries,
            capacity: storage.len(),
            full: entries == storage.len(),
        },
        last_operation_index,
    })
}

fn summarize_transaction_replay_watch_event_stream_internal<'a>(
    limits: &LcsLimits,
    storage: &[Option<TransactionMutationLogRecord<'a>>],
    results: &'a [TransactionReplaySnapshotResult<'a>],
) -> LcsResult<TransactionReplayWatchEventStreamSummary> {
    let storage_summary = summarize_transaction_mutation_log_internal(storage)?.summary;
    let mut summary = TransactionReplayWatchEventStreamSummary {
        entries: storage_summary.entries,
        capacity: storage_summary.capacity,
        direct_security_inputs: 0,
        effective_value_inputs: 0,
        effective_subkey_inputs: 0,
        emitted_events: 0,
    };

    for slot in &storage[..storage_summary.entries] {
        let Some(record) = slot else {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "transaction_log.dense_prefix",
            });
        };
        let input = transaction_mutation_log_record_watch_replay_input(limits, record)?;
        let snapshots = resolve_transaction_replay_watch_snapshots(limits, &input, results)?;
        let emitted =
            for_each_transaction_replay_watch_event(limits, &input, snapshots, |_| Ok(()))?;
        summary.emitted_events = summary
            .emitted_events
            .checked_add(emitted)
            .ok_or(LcsError::TransactionWatchBatchEventCountOverflow)?;
        match input {
            TransactionReplayWatchInput::DirectSecurity { .. } => {
                summary.direct_security_inputs += 1;
            }
            TransactionReplayWatchInput::EffectiveValue { .. } => {
                summary.effective_value_inputs += 1;
            }
            TransactionReplayWatchInput::EffectiveSubkey { .. } => {
                summary.effective_subkey_inputs += 1;
            }
        }
    }

    Ok(summary)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplaySnapshotInputCategory {
    EffectiveValue,
    EffectiveSubkey,
}

fn require_no_replay_snapshot_results(
    results: &[TransactionReplaySnapshotResult<'_>],
    operation_index: TransactionOperationIndex,
) -> LcsResult<()> {
    for result in results {
        if result.operation_index == operation_index {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "watch_replay.snapshot_unexpected",
            });
        }
    }
    Ok(())
}

fn validate_transaction_replay_snapshot_result(
    result: &TransactionReplaySnapshotResult<'_>,
) -> LcsResult<()> {
    if result.operation_index == 0 {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_snapshot.operation_index",
        });
    }
    match result.kind {
        TransactionReplaySnapshotResultKind::EffectiveValue { key_guid, .. } => {
            validate_replay_guid("replay_snapshot.key_guid", key_guid)
        }
        TransactionReplaySnapshotResultKind::EffectiveSubkeys { parent_guid, .. }
        | TransactionReplaySnapshotResultKind::ChildVisibility { parent_guid, .. } => {
            validate_replay_guid("replay_snapshot.parent_guid", parent_guid)
        }
    }
}

fn transaction_replay_snapshot_results_same_identity(
    left: &TransactionReplaySnapshotResult<'_>,
    right: &TransactionReplaySnapshotResult<'_>,
) -> bool {
    if left.phase != right.phase || left.operation_index != right.operation_index {
        return false;
    }
    match (left.kind, right.kind) {
        (
            TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid: left_guid,
                scope: left_scope,
                ..
            },
            TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid: right_guid,
                scope: right_scope,
                ..
            },
        ) => left_guid == right_guid && left_scope == right_scope,
        (
            TransactionReplaySnapshotResultKind::EffectiveSubkeys {
                parent_guid: left_guid,
                ..
            },
            TransactionReplaySnapshotResultKind::EffectiveSubkeys {
                parent_guid: right_guid,
                ..
            },
        ) => left_guid == right_guid,
        (
            TransactionReplaySnapshotResultKind::ChildVisibility {
                parent_guid: left_guid,
                child_name: left_name,
                ..
            },
            TransactionReplaySnapshotResultKind::ChildVisibility {
                parent_guid: right_guid,
                child_name: right_name,
                ..
            },
        ) => left_guid == right_guid && casefold_eq(left_name, right_name),
        _ => false,
    }
}

fn require_replay_snapshot_result_categories(
    results: &[TransactionReplaySnapshotResult<'_>],
    operation_index: TransactionOperationIndex,
    category: ReplaySnapshotInputCategory,
) -> LcsResult<()> {
    for result in results {
        if result.operation_index != operation_index {
            continue;
        }
        match (category, result.kind) {
            (
                ReplaySnapshotInputCategory::EffectiveValue,
                TransactionReplaySnapshotResultKind::EffectiveValue { .. },
            )
            | (
                ReplaySnapshotInputCategory::EffectiveSubkey,
                TransactionReplaySnapshotResultKind::EffectiveSubkeys { .. }
                | TransactionReplaySnapshotResultKind::ChildVisibility { .. },
            ) => {}
            _ => {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "watch_replay.snapshot_kind",
                });
            }
        }
    }
    Ok(())
}

fn select_effective_value_snapshot_result<'a>(
    results: &'a [TransactionReplaySnapshotResult<'a>],
    phase: TransactionReplaySnapshotPhase,
    operation_index: TransactionOperationIndex,
    key_guid: Guid,
    scope: TransactionReplayValueWatchScope<'a>,
    required: bool,
) -> LcsResult<&'a [EnumeratedValue<'a>]> {
    let mut matched = None;
    for result in results {
        if result.phase != phase || result.operation_index != operation_index {
            continue;
        }
        let TransactionReplaySnapshotResultKind::EffectiveValue {
            key_guid: result_key_guid,
            scope: result_scope,
            values,
        } = result.kind
        else {
            continue;
        };
        if result_key_guid != key_guid || result_scope != scope {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "watch_replay.snapshot_mismatch",
            });
        }
        if matched.replace(values).is_some() {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "watch_replay.snapshot_duplicate",
            });
        }
    }
    match (required, matched) {
        (true, Some(values)) => Ok(values),
        (true, None) => Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_missing",
        }),
        (false, Some(_)) => Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_unexpected",
        }),
        (false, None) => Ok(&[]),
    }
}

fn select_effective_subkey_snapshot_result<'a>(
    results: &'a [TransactionReplaySnapshotResult<'a>],
    phase: TransactionReplaySnapshotPhase,
    operation_index: TransactionOperationIndex,
    parent_guid: Guid,
    required: bool,
) -> LcsResult<&'a [EnumeratedSubkey<'a>]> {
    let mut matched = None;
    for result in results {
        if result.phase != phase || result.operation_index != operation_index {
            continue;
        }
        let TransactionReplaySnapshotResultKind::EffectiveSubkeys {
            parent_guid: result_parent_guid,
            children,
        } = result.kind
        else {
            continue;
        };
        if result_parent_guid != parent_guid {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "watch_replay.snapshot_mismatch",
            });
        }
        if matched.replace(children).is_some() {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "watch_replay.snapshot_duplicate",
            });
        }
    }
    match (required, matched) {
        (true, Some(children)) => Ok(children),
        (true, None) => Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_missing",
        }),
        (false, Some(_)) => Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_unexpected",
        }),
        (false, None) => Ok(&[]),
    }
}

fn select_child_visibility_snapshot_result<'a>(
    results: &'a [TransactionReplaySnapshotResult<'a>],
    phase: TransactionReplaySnapshotPhase,
    operation_index: TransactionOperationIndex,
    parent_guid: Guid,
    child_name: &str,
    required: bool,
) -> LcsResult<Option<ResolvedPathEntry<'a>>> {
    let mut matched = None;
    for result in results {
        if result.phase != phase || result.operation_index != operation_index {
            continue;
        }
        let TransactionReplaySnapshotResultKind::ChildVisibility {
            parent_guid: result_parent_guid,
            child_name: result_child_name,
            child,
        } = result.kind
        else {
            continue;
        };
        if result_parent_guid != parent_guid || !casefold_eq(result_child_name, child_name) {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "watch_replay.snapshot_mismatch",
            });
        }
        if matched.replace(child).is_some() {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "watch_replay.snapshot_duplicate",
            });
        }
    }
    match (required, matched) {
        (true, Some(child)) => Ok(child),
        (true, None) => Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_missing",
        }),
        (false, Some(_)) => Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.snapshot_unexpected",
        }),
        (false, None) => Ok(None),
    }
}

fn validate_transaction_mutation_log_record(
    record: &TransactionMutationLogRecord<'_>,
) -> LcsResult<()> {
    if record.operation_index() == 0 {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "operation_index",
        });
    }

    match record {
        TransactionMutationLogRecord::Security(entry) => validate_security_log_entry(entry),
        TransactionMutationLogRecord::Value(entry) => validate_value_log_entry(entry),
        TransactionMutationLogRecord::KeyPath(entry) => validate_key_path_log_entry(entry),
    }
}

fn validate_security_log_entry(entry: &TransactionMutationLogEntry<'_>) -> LcsResult<()> {
    if entry.kind != TransactionMutationLogKind::SetSecurity {
        return Err(LcsError::InvalidTransactionMutationLogEntry { field: "kind" });
    }
    if entry.watch_mutation.event_type != REG_WATCH_SD_CHANGED {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "event_type",
        });
    }
    if !entry.update_hive_generation_on_commit || !entry.update_last_write_time_on_commit {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "security.commit_effects",
        });
    }
    if entry.watch_mutation.ancestor_guids.is_empty()
        || entry.watch_mutation.ancestor_guids.len() != entry.watch_mutation.path_components.len()
        || entry.watch_mutation.ancestor_guids[entry.watch_mutation.ancestor_guids.len() - 1]
            != entry.watch_mutation.changed_key_guid
    {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_mutation",
        });
    }
    Ok(())
}

fn validate_replay_watch_mutation(
    limits: &LcsLimits,
    mutation: &WatchMutationContext<'_>,
) -> LcsResult<()> {
    if mutation.event_type != REG_WATCH_SD_CHANGED {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_mutation.event_type",
        });
    }
    let context = WatchAncestryContext {
        changed_key_guid: mutation.changed_key_guid,
        ancestor_guids: mutation.ancestor_guids,
        path_components: mutation.path_components,
    };
    validate_watch_ancestry_context(&context).map_err(|_| {
        LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_mutation",
        }
    })?;
    validate_replay_guid("watch_mutation.changed_key_guid", mutation.changed_key_guid)?;
    for guid in mutation.ancestor_guids {
        validate_replay_guid("watch_mutation.ancestor_guid", *guid)?;
    }
    for path_component in mutation.path_components {
        validate_key_component_bytes(path_component.as_bytes(), limits)?;
    }
    crate::watch::watch_event_category(mutation.event_type)?;
    Ok(())
}

fn validate_replay_watch_context(
    limits: &LcsLimits,
    field: &'static str,
    context: &WatchAncestryContext<'_>,
) -> LcsResult<()> {
    validate_watch_ancestry_context(context)
        .map_err(|_| LcsError::InvalidTransactionMutationLogEntry { field })?;
    validate_replay_guid(field, context.changed_key_guid)?;
    for guid in context.ancestor_guids {
        validate_replay_guid(field, *guid)?;
    }
    for path_component in context.path_components {
        validate_key_component_bytes(path_component.as_bytes(), limits)?;
    }
    Ok(())
}

fn validate_effective_value_replay_input(
    limits: &LcsLimits,
    key_guid: Guid,
    watch_context: WatchAncestryContext<'_>,
    scope: TransactionReplayValueWatchScope<'_>,
    layer: &str,
    snapshots: TransactionReplayValueSnapshots<'_>,
) -> LcsResult<()> {
    validate_replay_guid("value.key_guid", key_guid)?;
    validate_replay_watch_context(limits, "value.watch_context", &watch_context)?;
    if watch_context.changed_key_guid != key_guid {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.watch_context.changed_key_guid",
        });
    }
    validate_layer_name_bytes(layer.as_bytes(), limits)?;
    if let TransactionReplayValueWatchScope::NamedValue { name } = scope {
        validate_value_name_bytes(name.as_bytes(), limits)?;
        validate_named_value_snapshot_scope(name, snapshots.before)?;
        validate_named_value_snapshot_scope(name, snapshots.after)?;
    }
    Ok(())
}

fn validate_effective_subkey_replay_input<'a>(
    limits: &LcsLimits,
    parent_guid: Guid,
    parent_context: WatchAncestryContext<'a>,
    child_context: Option<WatchAncestryContext<'a>>,
    child_name: &str,
    layer: &str,
    snapshots: TransactionReplaySubkeySnapshots<'a>,
) -> LcsResult<Option<(WatchAncestryContext<'a>, WatchedKeyVisibilityEvent)>> {
    validate_replay_guid("key_path.parent_guid", parent_guid)?;
    validate_replay_watch_context(limits, "key_path.parent_watch_context", &parent_context)?;
    if parent_context.changed_key_guid != parent_guid {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_path.parent_watch_context.changed_key_guid",
        });
    }
    validate_key_component_bytes(child_name.as_bytes(), limits)?;
    validate_layer_name_bytes(layer.as_bytes(), limits)?;

    match child_context {
        Some(context) => {
            validate_replay_watch_context(
                limits,
                "key_path.child_visibility_watch_context",
                &context,
            )?;
            validate_child_visibility_context_extends(&parent_context, &context, child_name)?;
            let event = plan_watched_key_visibility_event(
                limits,
                context.changed_key_guid,
                snapshots.child_before,
                snapshots.child_after,
            )?;
            Ok(event.map(|event| (context, event)))
        }
        None => {
            if snapshots.child_before.is_some() || snapshots.child_after.is_some() {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "key_path.child_visibility_snapshot",
                });
            }
            Ok(None)
        }
    }
}

fn validate_named_value_snapshot_scope(
    expected_name: &str,
    values: &[EnumeratedValue<'_>],
) -> LcsResult<()> {
    for value in values {
        if !casefold_eq(value.name, expected_name) {
            return Err(LcsError::InvalidTransactionMutationLogEntry {
                field: "value.snapshot_scope",
            });
        }
    }
    Ok(())
}

fn value_replay_event_parts(event: EffectiveValueWatchEvent<'_>) -> (u32, &str) {
    match event {
        EffectiveValueWatchEvent::ValueSet { name }
        | EffectiveValueWatchEvent::ValueDeleted { name } => (event.event_type(), name),
    }
}

fn subkey_replay_event_parts(event: EffectiveSubkeyWatchEvent<'_>) -> (u32, &str) {
    match event {
        EffectiveSubkeyWatchEvent::SubkeyCreated { name }
        | EffectiveSubkeyWatchEvent::SubkeyDeleted { name } => (event.event_type(), name),
    }
}

fn replay_snapshot_required_for_phase(
    phase: TransactionReplaySnapshotPhase,
    requires_before_snapshot: bool,
    requires_after_snapshot: bool,
) -> bool {
    match phase {
        TransactionReplaySnapshotPhase::BeforeCommit => requires_before_snapshot,
        TransactionReplaySnapshotPhase::AfterCommit => requires_after_snapshot,
    }
}

fn summarize_transaction_replay_watch_dispatch_internal(
    limits: &LcsLimits,
    watcher: WatcherView,
    events: &[TransactionReplayWatchEvent<'_>],
) -> LcsResult<TransactionReplayWatchDispatchSummary> {
    let mut summary = TransactionReplayWatchDispatchSummary {
        operation_count: 0,
        delivered_event_count: 0,
        suppressed_event_count: 0,
        overflow_substitution_count: 0,
    };
    let mut previous_operation_index = None;

    for (index, event) in events.iter().enumerate() {
        validate_replay_watch_event_order(index, event.operation_index, previous_operation_index)?;
        if previous_operation_index != Some(event.operation_index) {
            summary.operation_count = summary
                .operation_count
                .checked_add(1)
                .ok_or(LcsError::TransactionWatchBatchEventCountOverflow)?;
            previous_operation_index = Some(event.operation_index);
        }

        match replay_watch_queue_entry_for_watcher(limits, watcher, event)? {
            Some((_, overflow_substitution)) => {
                summary.delivered_event_count = summary
                    .delivered_event_count
                    .checked_add(1)
                    .ok_or(LcsError::TransactionWatchBatchEventCountOverflow)?;
                if overflow_substitution {
                    summary.overflow_substitution_count = summary
                        .overflow_substitution_count
                        .checked_add(1)
                        .ok_or(LcsError::TransactionWatchBatchEventCountOverflow)?;
                }
            }
            None => {
                summary.suppressed_event_count = summary
                    .suppressed_event_count
                    .checked_add(1)
                    .ok_or(LcsError::TransactionWatchBatchEventCountOverflow)?;
            }
        }
    }

    Ok(summary)
}

fn replay_watch_queue_entry_for_watcher(
    limits: &LcsLimits,
    watcher: WatcherView,
    event: &TransactionReplayWatchEvent<'_>,
) -> LcsResult<Option<(WatchQueueEntry, bool)>> {
    let decision = plan_watch_dispatch(limits, watcher, &event.mutation)?;
    let WatchDispatchDecision::Deliver(delivery) = decision else {
        return Ok(None);
    };
    let request = WatchEventRecordRequest {
        event_type: delivery.event_type,
        name: event.name,
        subtree: delivery.subtree_record,
        path_components: delivery.relative_path_components,
    };
    match plan_watch_event_record(&request)? {
        WatchEventRecordPlan::Record(shape) => Ok(Some((
            WatchQueueEntry {
                event_type: delivery.event_type,
                total_len: shape.total_len,
            },
            false,
        ))),
        WatchEventRecordPlan::OverflowInstead => Ok(Some((overflow_queue_entry(), true))),
    }
}

fn validate_replay_watch_event_order(
    index: usize,
    operation_index: TransactionOperationIndex,
    previous_operation_index: Option<TransactionOperationIndex>,
) -> LcsResult<()> {
    if operation_index == 0 {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.operation_index",
        });
    }
    if previous_operation_index.is_some_and(|previous| operation_index < previous) {
        return Err(LcsError::InvalidTransactionWatchBatchOrder { index });
    }
    Ok(())
}

fn emit_replay_watch_batch_member<F>(
    operation_index: Option<TransactionOperationIndex>,
    event_count: usize,
    emit_member: &mut F,
) -> LcsResult<()>
where
    F: FnMut(TransactionWatchBatchMember) -> LcsResult<()>,
{
    if let Some(operation_index) = operation_index {
        emit_member(TransactionWatchBatchMember {
            operation_index,
            event_count,
        })?;
    }
    Ok(())
}

fn validate_replay_guid(field: &'static str, guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::InvalidTransactionMutationLogEntry { field });
    }
    Ok(())
}

fn validate_value_log_entry(entry: &TransactionValueMutationLogEntry<'_>) -> LcsResult<()> {
    if !entry.update_hive_generation_on_commit
        || !entry.update_last_write_time_on_commit
        || !entry.recompute_effective_value_events_on_commit
    {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.commit_effects",
        });
    }
    validate_replay_guid("value.key_guid", entry.key_guid)?;
    validate_watch_ancestry_context(&entry.watch_context).map_err(|_| {
        LcsError::InvalidTransactionMutationLogEntry {
            field: "value.watch_context",
        }
    })?;
    if entry.watch_context.changed_key_guid != entry.key_guid {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.watch_context.changed_key_guid",
        });
    }

    match entry.kind {
        TransactionMutationLogKind::SetValue => {
            if entry.value_name.is_none() || entry.sequence.is_none() {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "set_value.shape",
                });
            }
        }
        TransactionMutationLogKind::DeleteValue => {
            if entry.value_name.is_none() || entry.sequence.is_some() {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "delete_value.shape",
                });
            }
        }
        TransactionMutationLogKind::BlanketTombstone => {
            if entry.value_name.is_some() {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "blanket_tombstone.shape",
                });
            }
        }
        TransactionMutationLogKind::SetSecurity
        | TransactionMutationLogKind::CreateKey
        | TransactionMutationLogKind::DeleteKey
        | TransactionMutationLogKind::HideKey => {
            return Err(LcsError::InvalidTransactionMutationLogEntry { field: "kind" });
        }
    }
    Ok(())
}

fn validate_key_path_log_entry(entry: &TransactionKeyPathMutationLogEntry<'_>) -> LcsResult<()> {
    if !entry.update_hive_generation_on_commit || !entry.recompute_effective_subkey_events_on_commit
    {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_path.commit_effects",
        });
    }
    validate_parent_watch_context(entry.parent_guid, &entry.parent_watch_context)?;

    match entry.kind {
        TransactionMutationLogKind::CreateKey => {
            if entry.target_guid.is_none()
                || entry.sequence.is_none()
                || entry.update_parent_last_write_time_on_commit
                || entry.evaluate_orphaning_on_commit
                || !entry.publish_new_key_guid_on_commit
                || entry.child_visibility_watch_context.is_some()
            {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "create_key.shape",
                });
            }
        }
        TransactionMutationLogKind::DeleteKey => {
            if entry.target_guid.is_some()
                || entry.sequence.is_some()
                || !entry.update_parent_last_write_time_on_commit
                || !entry.evaluate_orphaning_on_commit
                || entry.publish_new_key_guid_on_commit
                || entry.child_visibility_watch_context.is_none()
            {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "delete_key.shape",
                });
            }
            if let Some(context) = entry.child_visibility_watch_context {
                validate_child_visibility_watch_context(&context)?;
                validate_child_visibility_context_extends_parent(entry, &context)?;
            }
        }
        TransactionMutationLogKind::HideKey => {
            if entry.target_guid.is_some()
                || entry.sequence.is_none()
                || entry.update_parent_last_write_time_on_commit
                || entry.evaluate_orphaning_on_commit
                || entry.publish_new_key_guid_on_commit
                || entry.child_visibility_watch_context.is_none()
            {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "hide_key.shape",
                });
            }
            if let Some(context) = entry.child_visibility_watch_context {
                validate_child_visibility_watch_context(&context)?;
                validate_child_visibility_context_extends_parent(entry, &context)?;
            }
        }
        TransactionMutationLogKind::SetSecurity
        | TransactionMutationLogKind::SetValue
        | TransactionMutationLogKind::DeleteValue
        | TransactionMutationLogKind::BlanketTombstone => {
            return Err(LcsError::InvalidTransactionMutationLogEntry { field: "kind" });
        }
    }
    Ok(())
}

fn validate_child_visibility_context_extends_parent(
    entry: &TransactionKeyPathMutationLogEntry<'_>,
    child_context: &WatchAncestryContext<'_>,
) -> LcsResult<()> {
    validate_child_visibility_context_extends(
        &entry.parent_watch_context,
        child_context,
        entry.child_name,
    )
}

fn validate_child_visibility_context_extends(
    parent_context: &WatchAncestryContext<'_>,
    child_context: &WatchAncestryContext<'_>,
    child_name: &str,
) -> LcsResult<()> {
    let parent_depth = parent_context.ancestor_guids.len();
    if child_context.ancestor_guids.len() != parent_depth + 1
        || child_context.path_components.len() != parent_depth + 1
        || &child_context.ancestor_guids[..parent_depth] != parent_context.ancestor_guids
        || &child_context.path_components[..parent_depth] != parent_context.path_components
        || child_context.path_components[parent_depth] != child_name
    {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_path.child_visibility_watch_context",
        });
    }
    Ok(())
}
