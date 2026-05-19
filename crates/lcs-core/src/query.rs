use crate::error::{LcsError, LcsResult};
use crate::output_buffer::{
    OutputBufferAggregate, OutputBufferDecision, OutputBufferRequest,
    aggregate_output_buffer_decisions, validate_output_buffer_required_size,
};
use crate::resolution::{EnumeratedValue, ResolvedValueEntry, ValueResolution};
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

/// Batch query output sizing plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryValuesBatchOutputDecision {
    pub count: usize,
    pub required_len: usize,
    pub buffer: OutputBufferDecision,
    pub aggregate: OutputBufferAggregate,
}

/// Caller-facing `REG_IOC_ENUM_VALUES` result after effective enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumValueResult<'a> {
    pub name: &'a str,
    pub name_len: usize,
    pub value_type: RegistryValueType,
    pub data: &'a [u8],
    pub data_len: usize,
}

/// Indexed value enumeration outcome before integer errno mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnumValueOutcome<'a> {
    Found(EnumValueResult<'a>),
    NotFound,
}

/// Name/data output buffers for `REG_IOC_ENUM_VALUES`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumValueOutputBuffers {
    pub name: OutputBufferRequest,
    pub data: OutputBufferRequest,
}

/// Required-size decisions for `REG_IOC_ENUM_VALUES` output buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumValueOutputBufferDecision {
    pub name: OutputBufferDecision,
    pub data: OutputBufferDecision,
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

/// Computes the packed byte length for one batch value record.
pub fn packed_batch_value_len(value: &EnumeratedValue<'_>) -> LcsResult<usize> {
    checked_sum3(12, value.name.len(), value.value.data.len())
}

/// Computes the required output byte length for `REG_IOC_QUERY_VALUES_BATCH`.
pub fn query_values_batch_required_len(values: &[EnumeratedValue<'_>]) -> LcsResult<usize> {
    let mut total = 0usize;
    for value in values {
        total = total
            .checked_add(packed_batch_value_len(value)?)
            .ok_or(LcsError::OutputSizeOverflow)?;
    }
    Ok(total)
}

/// Computes batch output sizing before any output buffer is filled.
pub fn validate_query_values_batch_output(
    values: &[EnumeratedValue<'_>],
    buffer: OutputBufferRequest,
) -> LcsResult<QueryValuesBatchOutputDecision> {
    let required_len = query_values_batch_required_len(values)?;
    let buffer = validate_output_buffer_required_size(buffer, required_len)?;
    let decisions = [buffer];
    let aggregate = aggregate_output_buffer_decisions(&decisions);

    Ok(QueryValuesBatchOutputDecision {
        count: values.len(),
        required_len,
        buffer,
        aggregate,
    })
}

/// Selects one effective value by index for `REG_IOC_ENUM_VALUES`.
pub fn enum_value_result_at<'a>(
    values: &'a [EnumeratedValue<'a>],
    index: usize,
) -> EnumValueOutcome<'a> {
    let Some(value) = values.get(index) else {
        return EnumValueOutcome::NotFound;
    };

    EnumValueOutcome::Found(EnumValueResult {
        name: value.name,
        name_len: value.name.len(),
        value_type: value.value.value_type,
        data: value.value.data,
        data_len: value.value.data.len(),
    })
}

/// Computes indexed value output-buffer decisions before output fills.
pub fn validate_enum_value_output_buffers(
    result: &EnumValueResult<'_>,
    buffers: EnumValueOutputBuffers,
) -> LcsResult<EnumValueOutputBufferDecision> {
    let name = validate_output_buffer_required_size(buffers.name, result.name_len)?;
    let data = validate_output_buffer_required_size(buffers.data, result.data_len)?;
    let decisions = [name, data];
    let aggregate = aggregate_output_buffer_decisions(&decisions);

    Ok(EnumValueOutputBufferDecision {
        name,
        data,
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

fn checked_sum3(a: usize, b: usize, c: usize) -> LcsResult<usize> {
    a.checked_add(b)
        .and_then(|sum| sum.checked_add(c))
        .ok_or(LcsError::OutputSizeOverflow)
}
