use crate::constants::REG_WATCH_SD_CHANGED;
use crate::error::{LcsError, LcsResult};
use crate::key_path::TransactionKeyPathMutationLogEntry;
use crate::transaction::{
    TransactionKernelEffectsPlan, TransactionMutationLogEntry, TransactionMutationLogKind,
    TransactionOperationIndex,
};
use crate::value::TransactionValueMutationLogEntry;
use crate::watch::{TransactionWatchBatchMember, WatchMutationContext};

use crate::resolution::Guid;

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

fn validate_value_log_entry(entry: &TransactionValueMutationLogEntry<'_>) -> LcsResult<()> {
    if !entry.update_hive_generation_on_commit
        || !entry.update_last_write_time_on_commit
        || !entry.recompute_effective_value_events_on_commit
    {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.commit_effects",
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

    match entry.kind {
        TransactionMutationLogKind::CreateKey => {
            if entry.target_guid.is_none()
                || entry.sequence.is_none()
                || entry.update_parent_last_write_time_on_commit
                || entry.evaluate_orphaning_on_commit
                || !entry.publish_new_key_guid_on_commit
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
            {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "delete_key.shape",
                });
            }
        }
        TransactionMutationLogKind::HideKey => {
            if entry.target_guid.is_some()
                || entry.sequence.is_none()
                || entry.update_parent_last_write_time_on_commit
                || entry.evaluate_orphaning_on_commit
                || entry.publish_new_key_guid_on_commit
            {
                return Err(LcsError::InvalidTransactionMutationLogEntry {
                    field: "hide_key.shape",
                });
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
