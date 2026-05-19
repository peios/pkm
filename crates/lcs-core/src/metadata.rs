use crate::error::{LcsError, LcsResult};
use crate::output_buffer::{
    OutputBufferAggregate, OutputBufferDecision, OutputBufferRequest,
    aggregate_output_buffer_decisions, validate_output_buffer_required_size,
};

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
    let aggregate = aggregate_output_buffer_decisions(&decisions);

    Ok(QueryKeyInfoOutputBufferDecision { name, aggregate })
}
