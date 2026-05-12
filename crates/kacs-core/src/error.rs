use crate::pkm_alloc::AllocError;

/// Canonical error type for the slow-track semantic core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KacsError {
    /// Access was denied by an explicit gate.
    AccessDenied,
    /// A fallible allocation request failed.
    AllocationFailure,
    /// An internal invariant was violated.
    InvariantViolation(&'static str),
    /// Token construction violated a required external invariant.
    InvalidTokenInvariant(&'static str),
    /// A CAAP policy spec was malformed or unsupported.
    InvalidCaapSpec(&'static str),
    /// The ABI struct was smaller than the minimum accepted version.
    InvalidAbiStructSize {
        /// Caller-provided structure size.
        provided: u32,
        /// Minimum accepted size.
        minimum: u32,
    },
    /// A caller-provided ABI field failed validation.
    InvalidAbiInput(&'static str),
    /// A reserved ABI field was non-zero.
    NonZeroAbiReservedField(&'static str),
    /// A user-memory read or write faulted at the kernel ingress boundary.
    UserMemoryFault {
        /// Logical field name associated with the fault.
        field: &'static str,
        /// Faulting pointer.
        ptr: u64,
        /// Requested transfer length.
        len: usize,
    },
    /// Result-list writeback count did not match the computed node count.
    AccessCheckListResultsCountMismatch {
        /// Expected result count.
        expected: u32,
        /// Caller-supplied result count.
        actual: u32,
    },
    /// AccessCheck was called with no security descriptor.
    NullSecurityDescriptor,
    /// An input buffer ended before the required bytes were available.
    Truncated(&'static str),
    /// A claim structure was malformed.
    InvalidClaimFormat(&'static str),
    /// A claim value type was unknown or unsupported.
    InvalidClaimType(u16),
    /// SID revision was invalid.
    InvalidSidRevision(u8),
    /// SID sub-authority count was invalid.
    InvalidSidSubAuthorityCount(u8),
    /// SID length did not match the encoded sub-authority count.
    InvalidSidLength {
        /// Expected SID length.
        expected: usize,
        /// Actual SID length.
        actual: usize,
    },
    /// Security descriptor revision was invalid.
    InvalidSecurityDescriptorRevision(u8),
    /// Security descriptor exceeded the architectural size limit.
    SecurityDescriptorTooLarge {
        /// Actual descriptor length.
        len: usize,
        /// Maximum permitted descriptor length.
        max: usize,
    },
    /// Self-relative control bit was missing.
    MissingSelfRelativeControl(u16),
    /// Descriptor owner SID was required but missing.
    MissingSecurityDescriptorOwner,
    /// Descriptor group SID was required but missing.
    MissingSecurityDescriptorGroup,
    /// A security descriptor presence bit and offset disagreed.
    InconsistentSecurityDescriptorField {
        /// Logical field name.
        field: &'static str,
        /// Whether the corresponding present bit was set.
        present: bool,
        /// Recorded field offset.
        offset: u32,
    },
    /// A security descriptor component offset pointed outside the buffer.
    SecurityDescriptorOffsetOutOfBounds {
        /// Logical field name.
        field: &'static str,
        /// Faulting offset.
        offset: u32,
        /// Total descriptor length.
        buffer_len: usize,
    },
    /// A security descriptor component offset pointed into the fixed header.
    SecurityDescriptorOffsetInsideHeader {
        /// Logical field name.
        field: &'static str,
        /// Faulting offset.
        offset: u32,
        /// Header length.
        header_len: usize,
    },
    /// Two descriptor components overlapped in the source buffer.
    SecurityDescriptorComponentsOverlap {
        /// First overlapping component.
        first: &'static str,
        /// Second overlapping component.
        second: &'static str,
    },
    /// ACL size field was structurally invalid.
    InvalidAclSize(u16),
    /// ACL size field exceeded the available buffer.
    AclSizeExceedsBuffer {
        /// Encoded ACL size.
        size: u16,
        /// Available buffer length.
        buffer_len: usize,
    },
    /// Parsed ACE count did not match the ACL header.
    AclAceCountMismatch {
        /// ACE count declared in the ACL header.
        expected: u16,
        /// ACE count actually parsed.
        actual: u16,
    },
    /// Parsed ACL ended before the buffer did.
    AclTrailingBytes {
        /// Trailing byte count.
        remaining: usize,
    },
    /// ACE size field was structurally invalid.
    InvalidAceSize(u16),
    /// Object ACE layout was malformed.
    InvalidObjectAceLayout(&'static str),
    /// Resource-attribute ACE carried an invalid SID.
    InvalidResourceAttributeSid,
    /// Mandatory-label ACE carried an invalid SID.
    InvalidMandatoryLabelSid,
    /// Process-trust-label ACE carried an invalid SID.
    InvalidProcessTrustLabelSid,
    /// Object-type list must not be empty.
    EmptyObjectTypeList,
    /// Root object-type node had a non-zero level.
    InvalidObjectTypeRootLevel(u16),
    /// Object-type list contained multiple roots.
    MultipleObjectTypeRoots,
    /// Object-type list skipped one or more levels.
    ObjectTypeLevelGap {
        /// Previous node level.
        previous: u16,
        /// Current node level.
        current: u16,
    },
    /// Object-type list contained a duplicate GUID.
    DuplicateObjectTypeGuid([u8; 16]),
    /// DACL evaluation encountered an ACE type it does not support.
    UnsupportedAceInDacl {
        /// Unsupported ACE type.
        ace_type: u8,
        /// Reason the ACE type is unsupported in this context.
        reason: &'static str,
    },
    /// Reserved access-mask bits were set.
    ReservedAccessMaskBits(u32),
    /// `MAXIMUM_ALLOWED` appeared in an ACE mask.
    MaximumAllowedInAce(u32),
}

/// Standard result type for the slow-track semantic core.
pub type KacsResult<T> = core::result::Result<T, KacsError>;

impl From<AllocError> for KacsError {
    fn from(_: AllocError) -> Self {
        KacsError::AllocationFailure
    }
}
