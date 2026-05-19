use crate::config::LcsLimits;
use crate::constants::{
    REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ, REG_FULL_RESOURCE_DESCRIPTOR,
    REG_LINK, REG_MULTI_SZ, REG_NONE, REG_QWORD, REG_RESOURCE_LIST, REG_RESOURCE_REQUIREMENTS_LIST,
    REG_SZ, REG_TOMBSTONE,
};
use crate::error::{LcsError, LcsResult};
use crate::path::{validate_layer_name_bytes, validate_value_name_bytes};
use crate::resolution::Guid;
use crate::source::NIL_GUID;

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

/// LCS-produced blanket tombstone mutation before source dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlanketTombstoneRequest<'a> {
    pub key_guid: Guid,
    pub layer: &'a str,
    pub action: BlanketTombstoneAction,
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

fn validate_value_key_guid(guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::NilKeyGuid);
    }
    Ok(())
}
