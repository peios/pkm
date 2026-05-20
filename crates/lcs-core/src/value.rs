use crate::config::LcsLimits;
use crate::constants::{
    REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ, REG_FULL_RESOURCE_DESCRIPTOR,
    REG_LINK, REG_MULTI_SZ, REG_NONE, REG_QWORD, REG_RESOURCE_LIST, REG_RESOURCE_REQUIREMENTS_LIST,
    REG_SZ, REG_TOMBSTONE,
};
use crate::errno::LinuxErrno;
use crate::error::{LcsError, LcsResult};
use crate::path::{validate_layer_name_bytes, validate_value_name_bytes};
use crate::resolution::Guid;
use crate::sequence::SequenceCounter;
use crate::source::NIL_GUID;
use crate::transaction::{
    TransactionMutationLogKind, TransactionOperationIndex, TransactionOperationIndexCounter,
};
use crate::watch::{WatchAncestryContext, validate_watch_ancestry_payload};

/// User-visible Windows registry value types accepted by LCS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RegistryValueType {
    None = REG_NONE,
    Sz = REG_SZ,
    ExpandSz = REG_EXPAND_SZ,
    Binary = REG_BINARY,
    Dword = REG_DWORD,
    DwordBigEndian = REG_DWORD_BIG_ENDIAN,
    Link = REG_LINK,
    MultiSz = REG_MULTI_SZ,
    ResourceList = REG_RESOURCE_LIST,
    FullResourceDescriptor = REG_FULL_RESOURCE_DESCRIPTOR,
    ResourceRequirementsList = REG_RESOURCE_REQUIREMENTS_LIST,
    Qword = REG_QWORD,
}

impl RegistryValueType {
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            REG_NONE => Some(Self::None),
            REG_SZ => Some(Self::Sz),
            REG_EXPAND_SZ => Some(Self::ExpandSz),
            REG_BINARY => Some(Self::Binary),
            REG_DWORD => Some(Self::Dword),
            REG_DWORD_BIG_ENDIAN => Some(Self::DwordBigEndian),
            REG_LINK => Some(Self::Link),
            REG_MULTI_SZ => Some(Self::MultiSz),
            REG_RESOURCE_LIST => Some(Self::ResourceList),
            REG_FULL_RESOURCE_DESCRIPTOR => Some(Self::FullResourceDescriptor),
            REG_RESOURCE_REQUIREMENTS_LIST => Some(Self::ResourceRequirementsList),
            REG_QWORD => Some(Self::Qword),
            _ => None,
        }
    }

    pub fn code(self) -> u32 {
        self as u32
    }
}

/// Validated value write type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatedValueType {
    Normal(RegistryValueType),
    Tombstone,
}

/// Caller-facing errno class for value type validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueTypeValidationErrno {
    Einval,
}

/// LCS-produced value write before source dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueWriteRequest<'a> {
    pub key_guid: Guid,
    pub name: &'a str,
    pub layer: &'a str,
    pub sequence: u64,
    pub value_type: u32,
    pub data: &'a [u8],
    pub explicit_tombstone_operation: bool,
    pub expected_sequence: Option<u64>,
}

/// Caller-visible value write fields before LCS sequence allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueWriteInput<'a> {
    pub key_guid: Guid,
    pub name: &'a str,
    pub layer: &'a str,
    pub value_type: u32,
    pub data: &'a [u8],
    pub explicit_tombstone_operation: bool,
    pub expected_sequence: Option<u64>,
}

/// Validated value write fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedValueWrite<'a> {
    pub key_guid: Guid,
    pub name: &'a str,
    pub layer: &'a str,
    pub sequence: u64,
    pub value_type: ValidatedValueType,
    pub data: &'a [u8],
    pub expected_sequence: Option<u64>,
}

/// Source-dispatch-ready value write plus direct key side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedValueWrite<'a> {
    pub write: ValidatedValueWrite<'a>,
    pub updates_last_write_time: bool,
}

/// Source-observed layer-count admission input for a value write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLayerAdmissionInput {
    pub current_distinct_layers: usize,
    pub replacing_existing_layer_entry: bool,
}

/// Best-effort per-value layer cap admission plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueLayerAdmissionPlan {
    pub distinct_layers_after_write: usize,
    pub best_effort_admission_control: bool,
}

/// Caller-facing errno class for per-value layer admission failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueLayerAdmissionErrno {
    Enospc,
}

/// Caller-facing errno class for value payload length failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueDataLenErrno {
    Enospc,
}

/// LCS-produced value delete before source dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueDeleteRequest<'a> {
    pub key_guid: Guid,
    pub name: &'a str,
    pub layer: &'a str,
}

/// Validated value delete fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedValueDelete<'a> {
    pub key_guid: Guid,
    pub name: &'a str,
    pub layer: &'a str,
}

/// Source-dispatch-ready value delete plus direct key side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedValueDelete<'a> {
    pub delete: ValidatedValueDelete<'a>,
    pub updates_last_write_time: bool,
}

/// LCS-produced blanket tombstone mutation before source dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlanketTombstoneRequest<'a> {
    pub key_guid: Guid,
    pub layer: &'a str,
    pub action: BlanketTombstoneAction,
}

/// Caller-visible blanket tombstone mutation before sequence allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlanketTombstoneInput<'a> {
    pub key_guid: Guid,
    pub layer: &'a str,
    pub set: bool,
}

/// Blanket tombstone action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlanketTombstoneAction {
    Set { sequence: u64 },
    Remove,
}

/// Validated blanket tombstone mutation fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedBlanketTombstone<'a> {
    pub key_guid: Guid,
    pub layer: &'a str,
    pub action: BlanketTombstoneAction,
}

/// Source-dispatch-ready blanket tombstone mutation plus side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedBlanketTombstone<'a> {
    pub blanket: ValidatedBlanketTombstone<'a>,
    pub updates_last_write_time: bool,
    pub recomputes_effective_value_events: bool,
}

/// Value-side transaction mutation-log entry for commit-time kernel effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionValueMutationLogEntry<'a> {
    pub operation_index: TransactionOperationIndex,
    pub kind: TransactionMutationLogKind,
    pub key_guid: Guid,
    pub watch_context: WatchAncestryContext<'a>,
    pub value_name: Option<&'a str>,
    pub layer: &'a str,
    pub sequence: Option<u64>,
    pub update_hive_generation_on_commit: bool,
    pub update_last_write_time_on_commit: bool,
    pub recompute_effective_value_events_on_commit: bool,
}

/// Validates a value write before source dispatch.
pub fn validate_value_write_request<'a>(
    limits: &LcsLimits,
    request: &ValueWriteRequest<'a>,
) -> LcsResult<ValidatedValueWrite<'a>> {
    validate_value_key_guid(request.key_guid)?;
    let name = validate_value_name_bytes(request.name.as_bytes(), limits)?;
    let layer = validate_layer_name_bytes(request.layer.as_bytes(), limits)?;
    validate_value_data_len(request.data.len(), limits)?;
    let value_type = validate_value_write_type(
        request.value_type,
        request.data.len(),
        request.explicit_tombstone_operation,
    )?;

    Ok(ValidatedValueWrite {
        key_guid: request.key_guid,
        name,
        layer,
        sequence: request.sequence,
        value_type,
        data: request.data,
        expected_sequence: request.expected_sequence,
    })
}

/// Validates a caller value write and assigns the next global sequence number.
pub fn plan_value_write<'a>(
    limits: &LcsLimits,
    sequence_counter: &mut SequenceCounter,
    input: &ValueWriteInput<'a>,
) -> LcsResult<PlannedValueWrite<'a>> {
    let preallocation_request = ValueWriteRequest {
        key_guid: input.key_guid,
        name: input.name,
        layer: input.layer,
        sequence: 0,
        value_type: input.value_type,
        data: input.data,
        explicit_tombstone_operation: input.explicit_tombstone_operation,
        expected_sequence: input.expected_sequence,
    };
    let validated = validate_value_write_request(limits, &preallocation_request)?;
    let sequence = sequence_counter.allocate()?;

    Ok(PlannedValueWrite {
        write: ValidatedValueWrite {
            sequence,
            ..validated
        },
        updates_last_write_time: true,
    })
}

/// Applies MaxLayersPerValue before dispatching a value write to the source.
pub fn plan_value_layer_admission(
    limits: &LcsLimits,
    input: ValueLayerAdmissionInput,
) -> LcsResult<ValueLayerAdmissionPlan> {
    if input.replacing_existing_layer_entry {
        return Ok(ValueLayerAdmissionPlan {
            distinct_layers_after_write: input.current_distinct_layers,
            best_effort_admission_control: true,
        });
    }

    if input.current_distinct_layers >= limits.max_layers_per_value {
        return Err(LcsError::TooManyLayersPerValue {
            count: input.current_distinct_layers,
            max: limits.max_layers_per_value,
        });
    }

    Ok(ValueLayerAdmissionPlan {
        distinct_layers_after_write: input.current_distinct_layers + 1,
        best_effort_admission_control: true,
    })
}

/// Maps per-value layer admission failures to caller-visible errno classes.
pub fn value_layer_admission_errno(error: &LcsError) -> Option<ValueLayerAdmissionErrno> {
    match error {
        LcsError::TooManyLayersPerValue { .. } => Some(ValueLayerAdmissionErrno::Enospc),
        _ => None,
    }
}

/// Projects per-value layer admission failures to Linux errno.
pub fn value_layer_admission_linux_errno(error: &LcsError) -> Option<LinuxErrno> {
    value_layer_admission_errno(error).map(LinuxErrno::from)
}

/// Validates a value delete before source dispatch.
pub fn validate_value_delete_request<'a>(
    limits: &LcsLimits,
    request: &ValueDeleteRequest<'a>,
) -> LcsResult<ValidatedValueDelete<'a>> {
    validate_value_key_guid(request.key_guid)?;
    let name = validate_value_name_bytes(request.name.as_bytes(), limits)?;
    let layer = validate_layer_name_bytes(request.layer.as_bytes(), limits)?;

    Ok(ValidatedValueDelete {
        key_guid: request.key_guid,
        name,
        layer,
    })
}

/// Validates a value delete and records its direct key side effects.
pub fn plan_value_delete<'a>(
    limits: &LcsLimits,
    request: &ValueDeleteRequest<'a>,
) -> LcsResult<PlannedValueDelete<'a>> {
    let delete = validate_value_delete_request(limits, request)?;
    Ok(PlannedValueDelete {
        delete,
        updates_last_write_time: true,
    })
}

/// Validates a blanket tombstone mutation before source dispatch.
pub fn validate_blanket_tombstone_request<'a>(
    limits: &LcsLimits,
    request: &BlanketTombstoneRequest<'a>,
) -> LcsResult<ValidatedBlanketTombstone<'a>> {
    validate_value_key_guid(request.key_guid)?;
    let layer = validate_layer_name_bytes(request.layer.as_bytes(), limits)?;

    Ok(ValidatedBlanketTombstone {
        key_guid: request.key_guid,
        layer,
        action: request.action,
    })
}

/// Validates a blanket tombstone mutation and assigns a sequence for set.
pub fn plan_blanket_tombstone<'a>(
    limits: &LcsLimits,
    sequence_counter: &mut SequenceCounter,
    input: &BlanketTombstoneInput<'a>,
) -> LcsResult<PlannedBlanketTombstone<'a>> {
    let preallocation_action = if input.set {
        BlanketTombstoneAction::Set { sequence: 0 }
    } else {
        BlanketTombstoneAction::Remove
    };
    let preallocation_request = BlanketTombstoneRequest {
        key_guid: input.key_guid,
        layer: input.layer,
        action: preallocation_action,
    };
    let validated = validate_blanket_tombstone_request(limits, &preallocation_request)?;
    let action = match validated.action {
        BlanketTombstoneAction::Set { .. } => BlanketTombstoneAction::Set {
            sequence: sequence_counter.allocate()?,
        },
        BlanketTombstoneAction::Remove => BlanketTombstoneAction::Remove,
    };

    Ok(PlannedBlanketTombstone {
        blanket: ValidatedBlanketTombstone {
            action,
            ..validated
        },
        updates_last_write_time: true,
        recomputes_effective_value_events: true,
    })
}

/// Plans a transaction mutation-log entry for a validated SET_VALUE operation.
pub fn plan_value_write_transaction_log_entry<'a>(
    limits: &LcsLimits,
    planned: &PlannedValueWrite<'a>,
    watch_context: WatchAncestryContext<'a>,
    counter: &mut TransactionOperationIndexCounter,
) -> LcsResult<TransactionValueMutationLogEntry<'a>> {
    validate_planned_value_write_for_log(limits, planned)?;
    validate_value_watch_context(limits, planned.write.key_guid, &watch_context)?;
    Ok(TransactionValueMutationLogEntry {
        operation_index: counter.allocate()?,
        kind: TransactionMutationLogKind::SetValue,
        key_guid: planned.write.key_guid,
        watch_context,
        value_name: Some(planned.write.name),
        layer: planned.write.layer,
        sequence: Some(planned.write.sequence),
        update_hive_generation_on_commit: true,
        update_last_write_time_on_commit: true,
        recompute_effective_value_events_on_commit: true,
    })
}

/// Plans a transaction mutation-log entry for a validated DELETE_VALUE operation.
pub fn plan_value_delete_transaction_log_entry<'a>(
    limits: &LcsLimits,
    planned: &PlannedValueDelete<'a>,
    watch_context: WatchAncestryContext<'a>,
    counter: &mut TransactionOperationIndexCounter,
) -> LcsResult<TransactionValueMutationLogEntry<'a>> {
    validate_planned_value_delete_for_log(limits, planned)?;
    validate_value_watch_context(limits, planned.delete.key_guid, &watch_context)?;
    Ok(TransactionValueMutationLogEntry {
        operation_index: counter.allocate()?,
        kind: TransactionMutationLogKind::DeleteValue,
        key_guid: planned.delete.key_guid,
        watch_context,
        value_name: Some(planned.delete.name),
        layer: planned.delete.layer,
        sequence: None,
        update_hive_generation_on_commit: true,
        update_last_write_time_on_commit: true,
        recompute_effective_value_events_on_commit: true,
    })
}

/// Plans a transaction mutation-log entry for a validated BLANKET_TOMBSTONE operation.
pub fn plan_blanket_tombstone_transaction_log_entry<'a>(
    limits: &LcsLimits,
    planned: &PlannedBlanketTombstone<'a>,
    watch_context: WatchAncestryContext<'a>,
    counter: &mut TransactionOperationIndexCounter,
) -> LcsResult<TransactionValueMutationLogEntry<'a>> {
    validate_planned_blanket_tombstone_for_log(limits, planned)?;
    validate_value_watch_context(limits, planned.blanket.key_guid, &watch_context)?;
    let sequence = match planned.blanket.action {
        BlanketTombstoneAction::Set { sequence } => Some(sequence),
        BlanketTombstoneAction::Remove => None,
    };

    Ok(TransactionValueMutationLogEntry {
        operation_index: counter.allocate()?,
        kind: TransactionMutationLogKind::BlanketTombstone,
        key_guid: planned.blanket.key_guid,
        watch_context,
        value_name: None,
        layer: planned.blanket.layer,
        sequence,
        update_hive_generation_on_commit: true,
        update_last_write_time_on_commit: true,
        recompute_effective_value_events_on_commit: true,
    })
}

/// Validates the type/data shape for a value-write style operation.
pub fn validate_value_write_type(
    value_type: u32,
    data_len: usize,
    explicit_tombstone_operation: bool,
) -> LcsResult<ValidatedValueType> {
    if value_type == REG_TOMBSTONE {
        if !explicit_tombstone_operation {
            return Err(LcsError::TombstoneNotExplicit);
        }
        if data_len != 0 {
            return Err(LcsError::TombstoneDataMustBeEmpty { len: data_len });
        }
        return Ok(ValidatedValueType::Tombstone);
    }

    RegistryValueType::from_code(value_type)
        .map(ValidatedValueType::Normal)
        .ok_or(LcsError::UnknownValueType(value_type))
}

/// Classifies value-type validation errors before sequence allocation or dispatch.
pub fn value_type_validation_errno(error: &LcsError) -> Option<ValueTypeValidationErrno> {
    match error {
        LcsError::UnknownValueType(_)
        | LcsError::TombstoneNotExplicit
        | LcsError::TombstoneDataMustBeEmpty { .. } => Some(ValueTypeValidationErrno::Einval),
        _ => None,
    }
}

/// Projects value-type validation failures to Linux errno.
pub fn value_type_validation_linux_errno(error: &LcsError) -> Option<LinuxErrno> {
    value_type_validation_errno(error).map(LinuxErrno::from)
}

/// Validates the configured maximum value payload length.
pub fn validate_value_data_len(data_len: usize, limits: &LcsLimits) -> LcsResult<()> {
    if data_len > limits.max_value_size {
        return Err(LcsError::ValueDataTooLarge {
            len: data_len,
            max: limits.max_value_size,
        });
    }
    Ok(())
}

/// Maps value payload length failures to caller-visible errno classes.
pub fn value_data_len_errno(error: &LcsError) -> Option<ValueDataLenErrno> {
    match error {
        LcsError::ValueDataTooLarge { .. } => Some(ValueDataLenErrno::Enospc),
        _ => None,
    }
}

/// Projects value payload length failures to Linux errno.
pub fn value_data_len_linux_errno(error: &LcsError) -> Option<LinuxErrno> {
    value_data_len_errno(error).map(LinuxErrno::from)
}

fn validate_planned_value_write_for_log(
    limits: &LcsLimits,
    planned: &PlannedValueWrite<'_>,
) -> LcsResult<()> {
    validate_value_key_guid(planned.write.key_guid)?;
    validate_value_name_bytes(planned.write.name.as_bytes(), limits)?;
    validate_layer_name_bytes(planned.write.layer.as_bytes(), limits)?;
    validate_value_data_len(planned.write.data.len(), limits)?;
    match planned.write.value_type {
        ValidatedValueType::Normal(value_type) => {
            validate_value_write_type(value_type.code(), planned.write.data.len(), false)?;
        }
        ValidatedValueType::Tombstone => {
            validate_value_write_type(REG_TOMBSTONE, planned.write.data.len(), true)?;
        }
    }
    if !planned.updates_last_write_time {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "updates_last_write_time",
        });
    }
    Ok(())
}

fn validate_planned_value_delete_for_log(
    limits: &LcsLimits,
    planned: &PlannedValueDelete<'_>,
) -> LcsResult<()> {
    validate_value_key_guid(planned.delete.key_guid)?;
    validate_value_name_bytes(planned.delete.name.as_bytes(), limits)?;
    validate_layer_name_bytes(planned.delete.layer.as_bytes(), limits)?;
    if !planned.updates_last_write_time {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "updates_last_write_time",
        });
    }
    Ok(())
}

fn validate_planned_blanket_tombstone_for_log(
    limits: &LcsLimits,
    planned: &PlannedBlanketTombstone<'_>,
) -> LcsResult<()> {
    validate_value_key_guid(planned.blanket.key_guid)?;
    validate_layer_name_bytes(planned.blanket.layer.as_bytes(), limits)?;
    if !planned.updates_last_write_time {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "updates_last_write_time",
        });
    }
    if !planned.recomputes_effective_value_events {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "recomputes_effective_value_events",
        });
    }
    Ok(())
}

fn validate_value_watch_context(
    limits: &LcsLimits,
    key_guid: Guid,
    watch_context: &WatchAncestryContext<'_>,
) -> LcsResult<()> {
    validate_watch_ancestry_payload(limits, "value.watch_context", watch_context)?;
    if watch_context.changed_key_guid != key_guid {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "value.watch_context.changed_key_guid",
        });
    }
    Ok(())
}

fn validate_value_key_guid(guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::NilKeyGuid);
    }
    Ok(())
}
