use crate::error::{LcsError, LcsResult};
use crate::output_buffer::{
    OutputBufferAggregate, OutputBufferCopyPlan, OutputBufferDecision, OutputBufferRequest,
    plan_output_buffer_copy, validate_output_buffer_required_size,
};
use crate::resolution::{EnumeratedSubkey, EnumeratedValue, ResolvedValueEntry, ValueResolution};
use crate::rsi::RsiMappedErrno;
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
    pub copy_plan: OutputBufferCopyPlan,
}

/// Batch query output sizing plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryValuesBatchOutputDecision {
    pub count: usize,
    pub required_len: usize,
    pub buffer: OutputBufferDecision,
    pub aggregate: OutputBufferAggregate,
    pub copy_plan: OutputBufferCopyPlan,
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
    pub copy_plan: OutputBufferCopyPlan,
}

/// One visible subkey plus metadata required by `REG_IOC_ENUM_SUBKEYS`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumeratedSubkeyInfo<'a> {
    pub subkey: EnumeratedSubkey<'a>,
    pub last_write_time: u64,
    pub subkey_count: u32,
    pub value_count: u32,
}

/// Caller-facing `REG_IOC_ENUM_SUBKEYS` result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumSubkeyResult<'a> {
    pub name: &'a str,
    pub name_len: usize,
    pub last_write_time: u64,
    pub subkey_count: u32,
    pub value_count: u32,
}

/// Indexed subkey enumeration outcome before integer errno mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnumSubkeyOutcome<'a> {
    Found(EnumSubkeyResult<'a>),
    NotFound,
}

/// Required-size decision for `REG_IOC_ENUM_SUBKEYS` name output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumSubkeyOutputBufferDecision {
    pub name: OutputBufferDecision,
    pub aggregate: OutputBufferAggregate,
    pub copy_plan: OutputBufferCopyPlan,
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

/// Maps caller-visible query-value absence to the required errno.
pub fn query_value_not_found_errno(outcome: &QueryValueOutcome<'_>) -> Option<RsiMappedErrno> {
    match outcome {
        QueryValueOutcome::Found(_) => None,
        QueryValueOutcome::NotFound => Some(RsiMappedErrno::Enoent),
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
    let copy_plan = plan_output_buffer_copy(&decisions);

    Ok(QueryValueOutputBufferDecision {
        data,
        layer,
        aggregate: copy_plan.aggregate,
        copy_plan,
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
    let copy_plan = plan_output_buffer_copy(&decisions);

    Ok(QueryValuesBatchOutputDecision {
        count: values.len(),
        required_len,
        buffer,
        aggregate: copy_plan.aggregate,
        copy_plan,
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
    let copy_plan = plan_output_buffer_copy(&decisions);

    Ok(EnumValueOutputBufferDecision {
        name,
        data,
        aggregate: copy_plan.aggregate,
        copy_plan,
    })
}

/// Selects one visible subkey by index for `REG_IOC_ENUM_SUBKEYS`.
pub fn enum_subkey_result_at<'a>(
    subkeys: &'a [EnumeratedSubkeyInfo<'a>],
    index: usize,
) -> EnumSubkeyOutcome<'a> {
    let Some(subkey) = subkeys.get(index) else {
        return EnumSubkeyOutcome::NotFound;
    };

    EnumSubkeyOutcome::Found(EnumSubkeyResult {
        name: subkey.subkey.child_name,
        name_len: subkey.subkey.child_name.len(),
        last_write_time: subkey.last_write_time,
        subkey_count: subkey.subkey_count,
        value_count: subkey.value_count,
    })
}

/// Computes subkey enumeration name-buffer decisions before output fills.
pub fn validate_enum_subkey_output_buffer(
    result: &EnumSubkeyResult<'_>,
    name: OutputBufferRequest,
) -> LcsResult<EnumSubkeyOutputBufferDecision> {
    let name = validate_output_buffer_required_size(name, result.name_len)?;
    let decisions = [name];
    let copy_plan = plan_output_buffer_copy(&decisions);

    Ok(EnumSubkeyOutputBufferDecision {
        name,
        aggregate: copy_plan.aggregate,
        copy_plan,
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
