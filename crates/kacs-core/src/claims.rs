use crate::error::{KacsError, KacsResult};
use crate::pkm_alloc::{slice_to_vec, String, Vec};
#[cfg(feature = "kernel")]
use crate::pkm_alloc::TryClone;
use crate::sid::Sid;

/// Claim flag requesting case-sensitive string comparisons.
pub const CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE: u32 = 0x0002;
/// Claim flag marking the attribute as deny-only.
pub const CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY: u32 = 0x0004;
/// Claim flag marking the attribute as disabled.
pub const CLAIM_SECURITY_ATTRIBUTE_DISABLED: u32 = 0x0010;

/// Claim value type for signed 64-bit integers.
pub const CLAIM_TYPE_INT64: u16 = 0x0001;
/// Claim value type for unsigned 64-bit integers.
pub const CLAIM_TYPE_UINT64: u16 = 0x0002;
/// Claim value type for UTF-16 strings.
pub const CLAIM_TYPE_STRING: u16 = 0x0003;
/// Claim value type for SIDs.
pub const CLAIM_TYPE_SID: u16 = 0x0005;
/// Claim value type for booleans.
pub const CLAIM_TYPE_BOOLEAN: u16 = 0x0006;
/// Claim value type for octet strings.
pub const CLAIM_TYPE_OCTET: u16 = 0x0010;

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// One parsed claim value.
pub enum ClaimValue {
    /// Signed 64-bit integer claim value.
    Int64(i64),
    /// Unsigned 64-bit integer claim value.
    UInt64(u64),
    /// String claim value.
    String(String),
    /// SID claim value encoded as raw SID bytes.
    Sid(Vec<u8>),
    /// Octet claim value.
    Octet(Vec<u8>),
    /// Boolean claim value.
    Boolean(bool),
    /// Composite claim value.
    Composite(Vec<ClaimValue>),
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// One parsed claim attribute entry.
pub struct ClaimAttribute {
    /// Attribute name.
    pub name: String,
    /// Attribute flags.
    pub flags: u32,
    /// Parsed attribute values.
    pub values: Vec<ClaimValue>,
}

impl ClaimAttribute {
    /// Builds a claim attribute from owned parts.
    pub fn new(name: impl Into<String>, flags: u32, values: impl Into<Vec<ClaimValue>>) -> Self {
        Self {
            name: name.into(),
            flags,
            values: values.into(),
        }
    }
}

#[cfg(feature = "kernel")]
impl TryClone for ClaimValue {
    fn try_clone(&self) -> Result<Self, crate::pkm_alloc::AllocError> {
        match self {
            Self::Int64(value) => Ok(Self::Int64(*value)),
            Self::UInt64(value) => Ok(Self::UInt64(*value)),
            Self::String(value) => Ok(Self::String(value.try_clone()?)),
            Self::Sid(value) => Ok(Self::Sid(value.try_clone()?)),
            Self::Octet(value) => Ok(Self::Octet(value.try_clone()?)),
            Self::Boolean(value) => Ok(Self::Boolean(*value)),
            Self::Composite(values) => Ok(Self::Composite(values.try_clone()?)),
        }
    }
}

#[cfg(feature = "kernel")]
impl TryClone for ClaimAttribute {
    fn try_clone(&self) -> Result<Self, crate::pkm_alloc::AllocError> {
        Ok(Self {
            name: self.name.try_clone()?,
            flags: self.flags,
            values: self.values.try_clone()?,
        })
    }
}

/// Parses one claim attribute entry payload.
pub fn parse_claim_attribute_entry(bytes: &[u8]) -> KacsResult<ClaimAttribute> {
    if bytes.len() < 16 {
        return Err(KacsError::InvalidClaimFormat("claim entry header"));
    }

    let name_offset = read_u32(bytes, 0)? as usize;
    let value_type = read_u16(bytes, 4)?;
    let flags = read_u32(bytes, 8)?;
    let value_count = read_u32(bytes, 12)? as usize;
    let offsets_end = 16usize
        .checked_add(
            value_count
                .checked_mul(4)
                .ok_or(KacsError::InvalidClaimFormat("claim value offsets"))?,
        )
        .ok_or(KacsError::InvalidClaimFormat("claim value offsets"))?;
    if offsets_end > bytes.len() {
        return Err(KacsError::InvalidClaimFormat("claim value offsets"));
    }

    let name = read_utf16_cstr(bytes, name_offset)?;
    let mut values = Vec::with_capacity(value_count)?;
    for index in 0..value_count {
        let offset = read_u32(bytes, 16 + (index * 4))? as usize;
        values.push(parse_claim_value(bytes, value_type, offset)?)?;
    }

    Ok(ClaimAttribute {
        name,
        flags,
        values,
    })
}

/// Parses a packed array of claim attribute entries.
pub fn parse_claim_attribute_array(bytes: &[u8]) -> KacsResult<Vec<ClaimAttribute>> {
    let mut claims = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(KacsError::InvalidClaimFormat("claim array entry length"));
        }
        let entry_len = read_u32(bytes, offset)? as usize;
        offset += 4;

        if entry_len == 0 {
            return Err(KacsError::InvalidClaimFormat("zero-length claim entry"));
        }
        let end = offset
            .checked_add(entry_len)
            .ok_or(KacsError::InvalidClaimFormat("claim array entry length"))?;
        if end > bytes.len() {
            return Err(KacsError::InvalidClaimFormat("claim array entry length"));
        }

        claims.push(parse_claim_attribute_entry(&bytes[offset..end])?)?;
        offset = end;
    }

    Ok(claims)
}

fn parse_claim_value(bytes: &[u8], value_type: u16, offset: usize) -> KacsResult<ClaimValue> {
    match value_type {
        CLAIM_TYPE_INT64 => Ok(ClaimValue::Int64(read_i64(bytes, offset)?)),
        CLAIM_TYPE_UINT64 => Ok(ClaimValue::UInt64(read_u64(bytes, offset)?)),
        CLAIM_TYPE_BOOLEAN => Ok(ClaimValue::Boolean(read_u64(bytes, offset)? != 0)),
        CLAIM_TYPE_STRING => {
            let string_offset = read_u32(bytes, offset)? as usize;
            Ok(ClaimValue::String(read_utf16_cstr(bytes, string_offset)?))
        }
        CLAIM_TYPE_SID => {
            let sid_offset = read_u32(bytes, offset)? as usize;
            let (sid, _) = Sid::parse_prefix(bytes_at(bytes, sid_offset)?)?;
            Ok(ClaimValue::Sid(slice_to_vec(sid.as_bytes())?))
        }
        CLAIM_TYPE_OCTET => {
            let octet_offset = read_u32(bytes, offset)? as usize;
            let length = read_u32(bytes, octet_offset)? as usize;
            let data_offset = octet_offset
                .checked_add(4)
                .ok_or(KacsError::InvalidClaimFormat("octet length"))?;
            let data = read_slice(bytes, data_offset, length)?;
            Ok(ClaimValue::Octet(slice_to_vec(data)?))
        }
        _ => Err(KacsError::InvalidClaimType(value_type)),
    }
}

fn bytes_at(bytes: &[u8], offset: usize) -> KacsResult<&[u8]> {
    if offset >= bytes.len() {
        return Err(KacsError::InvalidClaimFormat("claim offset out of bounds"));
    }
    Ok(&bytes[offset..])
}

fn read_slice(bytes: &[u8], offset: usize, len: usize) -> KacsResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(KacsError::InvalidClaimFormat("claim slice length"))?;
    if end > bytes.len() {
        return Err(KacsError::InvalidClaimFormat("claim slice length"));
    }
    Ok(&bytes[offset..end])
}

fn read_u16(bytes: &[u8], offset: usize) -> KacsResult<u16> {
    let slice = read_slice(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> KacsResult<u32> {
    let slice = read_slice(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> KacsResult<u64> {
    let slice = read_slice(bytes, offset, 8)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_i64(bytes: &[u8], offset: usize) -> KacsResult<i64> {
    Ok(read_u64(bytes, offset)? as i64)
}

fn read_utf16_cstr(bytes: &[u8], offset: usize) -> KacsResult<String> {
    let input = bytes_at(bytes, offset)?;
    let mut units = Vec::new();
    let mut cursor = 0usize;

    loop {
        let code_unit_bytes = input
            .get(cursor..cursor + 2)
            .ok_or(KacsError::InvalidClaimFormat("unterminated utf16 string"))?;
        let code_unit = u16::from_le_bytes([code_unit_bytes[0], code_unit_bytes[1]]);
        if code_unit == 0 {
            break;
        }
        units.push(code_unit)?;
        cursor += 2;
    }

    let mut output = String::new();
    for scalar in core::char::decode_utf16(units.iter().copied()) {
        let scalar = scalar.map_err(|_| KacsError::InvalidClaimFormat("invalid utf16 string"))?;
        output.push(scalar)?;
    }
    Ok(output)
}
