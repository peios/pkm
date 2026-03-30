use crate::error::{KacsError, KacsResult};

pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sid<'a> {
    bytes: &'a [u8],
}

impl<'a> Sid<'a> {
    pub const MIN_SIZE: usize = 8;
    pub const MAX_SUB_AUTHORITIES: u8 = 15;

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

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn revision(&self) -> u8 {
        self.bytes[0]
    }

    pub fn sub_authority_count(&self) -> u8 {
        self.bytes[1]
    }

    pub fn identifier_authority(&self) -> [u8; 6] {
        let mut authority = [0u8; 6];
        authority.copy_from_slice(&self.bytes[2..8]);
        authority
    }

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
}
