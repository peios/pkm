use crate::error::LcsResult;
use crate::output_buffer::{
    OutputBufferAggregate, OutputBufferDecision, OutputBufferRequest,
    aggregate_output_buffer_decisions, validate_output_buffer_required_size,
};
use crate::resolution::{ResolvedValueEntry, ValueResolution};
use crate::value::RegistryValueType;

/// Caller-facing `REG_IOC_QUERY_VALUE` result after value resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryValueResult<'a> {
    pub value_type: RegistryValueType,
    pub data: &'a [u8],
    pub data_len: usize,
    pub sequence: u64,
    pub layer: &'a str,
    pub layer_len: usize,
}

/// Query-value outcome before integer errno mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryValueOutcome<'a> {
    Found(QueryValueResult<'a>),
    NotFound,
}

/// Data/layer output buffers for `REG_IOC_QUERY_VALUE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryValueOutputBuffers {
    pub data: OutputBufferRequest,
    pub layer: OutputBufferRequest,
}

/// Required-size decisions for `REG_IOC_QUERY_VALUE` output buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryValueOutputBufferDecision {
    pub data: OutputBufferDecision,
    pub layer: OutputBufferDecision,
    pub aggregate: OutputBufferAggregate,
}

/// Converts resolver output into the caller-facing query-value shape.
pub fn query_value_result_from_resolution<'a>(
    resolution: ValueResolution<'a>,
) -> QueryValueOutcome<'a> {
    match resolution {
        ValueResolution::Found(value) => QueryValueOutcome::Found(query_value_result(value)),
        ValueResolution::NotFound => QueryValueOutcome::NotFound,
    }
}

/// Computes output-buffer decisions for a found query-value result.
pub fn validate_query_value_output_buffers(
    result: &QueryValueResult<'_>,
    buffers: QueryValueOutputBuffers,
) -> LcsResult<QueryValueOutputBufferDecision> {
    let data = validate_output_buffer_required_size(buffers.data, result.data_len)?;
    let layer = validate_output_buffer_required_size(buffers.layer, result.layer_len)?;
    let decisions = [data, layer];
    let aggregate = aggregate_output_buffer_decisions(&decisions);

    Ok(QueryValueOutputBufferDecision {
        data,
        layer,
        aggregate,
    })
}

fn query_value_result(value: ResolvedValueEntry<'_>) -> QueryValueResult<'_> {
    QueryValueResult {
        value_type: value.value_type,
        data: value.data,
        data_len: value.data.len(),
        sequence: value.sequence,
        layer: value.layer,
        layer_len: value.layer.len(),
    }
}
