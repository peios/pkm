use crate::error::{LcsError, LcsResult};
use crate::output_buffer::{
    OutputBufferAggregate, OutputBufferCopyPlan, OutputBufferDecision, OutputBufferRequest,
    plan_output_buffer_copy, validate_output_buffer_required_size,
};
use crate::transaction_log::TransactionMutationReplaySummary;

/// Volatile LCS-owned per-hive generation number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HiveGenerationCounter {
    generation: u64,
}

impl HiveGenerationCounter {
    /// Creates a generation counter with baseline 0.
    pub const fn new() -> Self {
        Self { generation: 0 }
    }

    /// Creates a generation counter from an explicit baseline.
    pub const fn from_baseline(generation: u64) -> Self {
        Self { generation }
    }

    /// Returns the current generation number.
    pub const fn current(&self) -> u64 {
        self.generation
    }

    /// Records one committed non-transactional mutation for this hive.
    pub fn record_committed_mutation(&mut self) -> LcsResult<u64> {
        self.increment()
    }

    /// Records one committed transaction that affected this hive.
    pub fn record_committed_transaction_for_affected_hive(&mut self) -> LcsResult<u64> {
        self.increment()
    }

    fn increment(&mut self) -> LcsResult<u64> {
        let next = self
            .generation
            .checked_add(1)
            .ok_or(LcsError::HiveGenerationOverflow)?;
        self.generation = next;
        Ok(next)
    }
}

impl Default for HiveGenerationCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of applying transaction replay generation work to one hive counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionReplayGenerationApplyPlan {
    pub previous_generation: u64,
    pub current_generation: u64,
    pub incremented: bool,
}

/// Applies transaction replay generation work to the affected hive counter.
pub fn record_transaction_replay_generation(
    counter: &mut HiveGenerationCounter,
    summary: &TransactionMutationReplaySummary,
) -> LcsResult<TransactionReplayGenerationApplyPlan> {
    validate_transaction_replay_summary(summary)?;

    let previous_generation = counter.current();
    let (current_generation, incremented) = if summary.increment_hive_generation_once {
        (
            counter.record_committed_transaction_for_affected_hive()?,
            true,
        )
    } else {
        (previous_generation, false)
    };

    Ok(TransactionReplayGenerationApplyPlan {
        previous_generation,
        current_generation,
        incremented,
    })
}

fn validate_transaction_replay_summary(
    summary: &TransactionMutationReplaySummary,
) -> LcsResult<()> {
    if summary.entries > summary.capacity {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_summary.entries",
        });
    }
    if summary.entries == 0 && summary.increment_hive_generation_once {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_summary.generation",
        });
    }

    validate_replay_summary_count(
        "replay_summary.key_last_write_updates",
        summary.key_last_write_updates,
        summary.entries,
    )?;
    validate_replay_summary_count(
        "replay_summary.parent_last_write_updates",
        summary.parent_last_write_updates,
        summary.entries,
    )?;
    validate_replay_summary_count(
        "replay_summary.security_watch_mutations",
        summary.security_watch_mutations,
        summary.entries,
    )?;
    validate_replay_summary_count(
        "replay_summary.effective_value_recomputations",
        summary.effective_value_recomputations,
        summary.entries,
    )?;
    validate_replay_summary_count(
        "replay_summary.effective_subkey_recomputations",
        summary.effective_subkey_recomputations,
        summary.entries,
    )?;
    validate_replay_summary_count(
        "replay_summary.orphan_evaluations",
        summary.orphan_evaluations,
        summary.entries,
    )?;
    validate_replay_summary_count(
        "replay_summary.new_key_publications",
        summary.new_key_publications,
        summary.entries,
    )?;

    validate_replay_summary_sum(
        "replay_summary.last_write_updates",
        summary.key_last_write_updates,
        summary.parent_last_write_updates,
        summary.entries,
    )?;
    let value_and_subkey = validate_replay_summary_sum(
        "replay_summary.effective_recomputations",
        summary.effective_value_recomputations,
        summary.effective_subkey_recomputations,
        summary.entries,
    )?;
    validate_replay_summary_sum(
        "replay_summary.watch_work",
        summary.security_watch_mutations,
        value_and_subkey,
        summary.entries,
    )?;
    validate_replay_summary_count(
        "replay_summary.orphan_evaluations",
        summary.orphan_evaluations,
        summary.effective_subkey_recomputations,
    )?;
    validate_replay_summary_count(
        "replay_summary.new_key_publications",
        summary.new_key_publications,
        summary.effective_subkey_recomputations,
    )
}

fn validate_replay_summary_count(
    field: &'static str,
    count: usize,
    entries: usize,
) -> LcsResult<()> {
    if count > entries {
        return Err(LcsError::InvalidTransactionMutationLogEntry { field });
    }
    Ok(())
}

fn validate_replay_summary_sum(
    field: &'static str,
    left: usize,
    right: usize,
    entries: usize,
) -> LcsResult<usize> {
    let sum = left
        .checked_add(right)
        .ok_or(LcsError::MemoryBoundOverflow { field })?;
    validate_replay_summary_count(field, sum, entries)?;
    Ok(sum)
}

/// Kernel/source metadata needed to answer `REG_IOC_QUERY_KEY_INFO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryKeyInfoInput<'a> {
    pub name: &'a str,
    pub last_write_time: u64,
    pub subkey_count: u32,
    pub value_count: u32,
    pub max_subkey_name_len: u32,
    pub max_value_name_len: u32,
    pub max_value_data_size: u32,
    pub sd_size: u32,
    pub volatile: bool,
    pub symlink: bool,
    pub hive_generation: u64,
}

/// Caller-facing `REG_IOC_QUERY_KEY_INFO` result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryKeyInfoResult<'a> {
    pub name: &'a str,
    pub name_len: usize,
    pub last_write_time: u64,
    pub subkey_count: u32,
    pub value_count: u32,
    pub max_subkey_name_len: u32,
    pub max_value_name_len: u32,
    pub max_value_data_size: u32,
    pub sd_size: u32,
    pub volatile: bool,
    pub symlink: bool,
    pub hive_generation: u64,
}

/// Required-size decision for `REG_IOC_QUERY_KEY_INFO` name output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryKeyInfoOutputBufferDecision {
    pub name: OutputBufferDecision,
    pub aggregate: OutputBufferAggregate,
    pub copy_plan: OutputBufferCopyPlan,
}

/// Shapes key metadata for `REG_IOC_QUERY_KEY_INFO`.
pub fn query_key_info_result(input: QueryKeyInfoInput<'_>) -> QueryKeyInfoResult<'_> {
    QueryKeyInfoResult {
        name: input.name,
        name_len: input.name.len(),
        last_write_time: input.last_write_time,
        subkey_count: input.subkey_count,
        value_count: input.value_count,
        max_subkey_name_len: input.max_subkey_name_len,
        max_value_name_len: input.max_value_name_len,
        max_value_data_size: input.max_value_data_size,
        sd_size: input.sd_size,
        volatile: input.volatile,
        symlink: input.symlink,
        hive_generation: input.hive_generation,
    }
}

/// Computes query-key-info name-buffer decisions before output fills.
pub fn validate_query_key_info_output_buffer(
    result: &QueryKeyInfoResult<'_>,
    name: OutputBufferRequest,
) -> LcsResult<QueryKeyInfoOutputBufferDecision> {
    let name = validate_output_buffer_required_size(name, result.name_len)?;
    let decisions = [name];
    let copy_plan = plan_output_buffer_copy(&decisions);

    Ok(QueryKeyInfoOutputBufferDecision {
        name,
        aggregate: copy_plan.aggregate,
        copy_plan,
    })
}
