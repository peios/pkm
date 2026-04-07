#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KacsError {
    Truncated(&'static str),
    InvalidClaimFormat(&'static str),
    InvalidClaimType(u16),
    InvalidSidRevision(u8),
    InvalidSidSubAuthorityCount(u8),
    InvalidSidLength {
        expected: usize,
        actual: usize,
    },
    InvalidSecurityDescriptorRevision(u8),
    MissingSelfRelativeControl(u16),
    InconsistentSecurityDescriptorField {
        field: &'static str,
        present: bool,
        offset: u32,
    },
    SecurityDescriptorOffsetOutOfBounds {
        field: &'static str,
        offset: u32,
        buffer_len: usize,
    },
    InvalidAclSize(u16),
    AclSizeExceedsBuffer {
        size: u16,
        buffer_len: usize,
    },
    AclAceCountMismatch {
        expected: u16,
        actual: u16,
    },
    AclTrailingBytes {
        remaining: usize,
    },
    InvalidAceSize(u16),
    InvalidObjectAceLayout(&'static str),
    InvalidResourceAttributeSid,
    InvalidMandatoryLabelSid,
    InvalidProcessTrustLabelSid,
    EmptyObjectTypeList,
    InvalidObjectTypeRootLevel(u16),
    MultipleObjectTypeRoots,
    ObjectTypeLevelGap {
        previous: u16,
        current: u16,
    },
    DuplicateObjectTypeGuid([u8; 16]),
    UnsupportedAceInDacl {
        ace_type: u8,
        reason: &'static str,
    },
    ReservedAccessMaskBits(u32),
    MaximumAllowedInAce(u32),
}

pub type KacsResult<T> = core::result::Result<T, KacsError>;
