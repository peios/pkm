use crate::error::{KacsError, KacsResult};
#[cfg(feature = "kernel")]
use crate::pkm_alloc::{AllocError, TryClone};
use core::fmt;

/// Group attribute bit marking a group that cannot be disabled.
pub const SE_GROUP_MANDATORY: u32 = 0x0000_0001;
/// Group attribute bit marking a group enabled by default at token creation.
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
/// Group attribute bit marking an enabled SID.
pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;
/// Group attribute bit marking a group usable as the default owner.
pub const SE_GROUP_OWNER: u32 = 0x0000_0008;
/// Group attribute bit marking a SID as deny-only.
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
/// Group attribute bit marking an integrity level SID.
pub const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;
/// Group attribute bit used with `SE_GROUP_INTEGRITY`.
pub const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x0000_0040;
/// Group attribute bit marking a per-session logon SID.
pub const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
/// Group attribute bit marking a resource-domain local group.
pub const SE_GROUP_RESOURCE: u32 = 0x2000_0000;

/// Borrowed SID view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sid<'a> {
    bytes: &'a [u8],
}

#[cfg(feature = "kernel")]
impl<'a> TryClone for Sid<'a> {
    fn try_clone(&self) -> Result<Self, AllocError> {
        Ok(*self)
    }
}

impl<'a> Sid<'a> {
    /// Minimum valid SID length in bytes.
    pub const MIN_SIZE: usize = 8;
    /// Maximum valid sub-authority count accepted by the parser.
    pub const MAX_SUB_AUTHORITIES: u8 = 15;

    /// Parses a SID that must occupy the entire provided slice.
    pub fn parse(bytes: &'a [u8]) -> KacsResult<Self> {
        if bytes.len() < Self::MIN_SIZE {
            return Err(KacsError::Truncated("sid"));
        }

        let revision = bytes[0];
        if revision != 1 {
            return Err(KacsError::InvalidSidRevision(revision));
        }

        let sub_authority_count = bytes[1];
        if sub_authority_count > Self::MAX_SUB_AUTHORITIES {
            return Err(KacsError::InvalidSidSubAuthorityCount(sub_authority_count));
        }

        let expected_len = Self::MIN_SIZE + (usize::from(sub_authority_count) * 4);
        if bytes.len() != expected_len {
            return Err(KacsError::InvalidSidLength {
                expected: expected_len,
                actual: bytes.len(),
            });
        }

        Ok(Self { bytes })
    }

    /// Parses a SID from the start of a larger buffer and returns the consumed
    /// length.
    pub fn parse_prefix(bytes: &'a [u8]) -> KacsResult<(Self, usize)> {
        if bytes.len() < Self::MIN_SIZE {
            return Err(KacsError::Truncated("sid"));
        }

        let revision = bytes[0];
        if revision != 1 {
            return Err(KacsError::InvalidSidRevision(revision));
        }

        let sub_authority_count = bytes[1];
        if sub_authority_count > Self::MAX_SUB_AUTHORITIES {
            return Err(KacsError::InvalidSidSubAuthorityCount(sub_authority_count));
        }

        let expected_len = Self::MIN_SIZE + (usize::from(sub_authority_count) * 4);
        if bytes.len() < expected_len {
            return Err(KacsError::Truncated("sid"));
        }

        let sid_bytes = &bytes[..expected_len];
        Ok((Self { bytes: sid_bytes }, expected_len))
    }

    /// Returns the raw SID bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the SID revision.
    pub fn revision(&self) -> u8 {
        self.bytes[0]
    }

    /// Returns the sub-authority count.
    pub fn sub_authority_count(&self) -> u8 {
        self.bytes[1]
    }

    /// Returns the six-byte identifier authority field.
    pub fn identifier_authority(&self) -> [u8; 6] {
        let mut authority = [0u8; 6];
        authority.copy_from_slice(&self.bytes[2..8]);
        authority
    }

    /// Returns one sub-authority by index, if it exists.
    pub fn sub_authority(&self, index: usize) -> Option<u32> {
        if index >= usize::from(self.sub_authority_count()) {
            return None;
        }

        let start = Self::MIN_SIZE + (index * 4);
        let end = start + 4;
        let mut word = [0u8; 4];
        word.copy_from_slice(&self.bytes[start..end]);
        Some(u32::from_le_bytes(word))
    }

    /// Returns the last sub-authority, also known as the relative identifier.
    pub fn relative_identifier(&self) -> Option<u32> {
        let count = usize::from(self.sub_authority_count());
        count
            .checked_sub(1)
            .and_then(|index| self.sub_authority(index))
    }
}

impl fmt::Display for Sid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}", self.revision())?;

        let authority = self.identifier_authority();
        if authority[0] == 0 && authority[1] == 0 {
            let lower =
                u32::from_be_bytes([authority[2], authority[3], authority[4], authority[5]]);
            write!(f, "-{}", lower)?;
        } else {
            let full = u64::from_be_bytes([
                0,
                0,
                authority[0],
                authority[1],
                authority[2],
                authority[3],
                authority[4],
                authority[5],
            ]);
            write!(f, "-0x{:012x}", full)?;
        }

        for index in 0..usize::from(self.sub_authority_count()) {
            let sub_authority = self
                .sub_authority(index)
                .expect("validated SID count matches backing bytes");
            write!(f, "-{}", sub_authority)?;
        }

        Ok(())
    }
}
