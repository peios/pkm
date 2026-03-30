use alloc::string::String;
use alloc::vec::Vec;

pub const CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE: u32 = 0x0002;
pub const CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY: u32 = 0x0004;
pub const CLAIM_SECURITY_ATTRIBUTE_DISABLED: u32 = 0x0010;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimValue {
    Int64(i64),
    UInt64(u64),
    String(String),
    Sid(Vec<u8>),
    Octet(Vec<u8>),
    Boolean(bool),
    Composite(Vec<ClaimValue>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimAttribute {
    pub name: String,
    pub flags: u32,
    pub values: Vec<ClaimValue>,
}

impl ClaimAttribute {
    pub fn new(name: impl Into<String>, flags: u32, values: Vec<ClaimValue>) -> Self {
        Self {
            name: name.into(),
            flags,
            values,
        }
    }
}
