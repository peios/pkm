use crate::ace::Ace;
use crate::error::{KacsError, KacsResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acl<'a> {
    bytes: &'a [u8],
    revision: u8,
    sbz1: u8,
    size: u16,
    ace_count: u16,
    sbz2: u16,
}

impl<'a> Acl<'a> {
    pub const HEADER_SIZE: usize = 8;

    pub fn parse(bytes: &'a [u8]) -> KacsResult<Self> {
        let (acl, consumed) = Self::parse_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(KacsError::AclSizeExceedsBuffer {
                size: acl.size,
                buffer_len: bytes.len(),
            });
        }
        Ok(acl)
    }

    pub fn parse_prefix(bytes: &'a [u8]) -> KacsResult<(Self, usize)> {
        if bytes.len() < Self::HEADER_SIZE {
            return Err(KacsError::Truncated("acl"));
        }

        let revision = bytes[0];
        let sbz1 = bytes[1];
        let size = u16::from_le_bytes([bytes[2], bytes[3]]);
        let ace_count = u16::from_le_bytes([bytes[4], bytes[5]]);
        let sbz2 = u16::from_le_bytes([bytes[6], bytes[7]]);

        if size < Self::HEADER_SIZE as u16 {
            return Err(KacsError::InvalidAclSize(size));
        }
        let size_usize = usize::from(size);
        if bytes.len() < size_usize {
            return Err(KacsError::AclSizeExceedsBuffer {
                size,
                buffer_len: bytes.len(),
            });
        }

        let acl_bytes = &bytes[..size_usize];
        let mut offset = Self::HEADER_SIZE;
        let mut actual_count: u16 = 0;

        while offset < acl_bytes.len() && actual_count < ace_count {
            let (_, consumed) = Ace::parse_prefix(&acl_bytes[offset..])?;
            offset += consumed;
            actual_count += 1;
        }

        if actual_count != ace_count {
            return Err(KacsError::AclAceCountMismatch {
                expected: ace_count,
                actual: actual_count,
            });
        }
        if offset != acl_bytes.len() {
            return Err(KacsError::AclTrailingBytes {
                remaining: acl_bytes.len() - offset,
            });
        }

        Ok((
            Self {
                bytes: acl_bytes,
                revision,
                sbz1,
                size,
                ace_count,
                sbz2,
            },
            size_usize,
        ))
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn revision(&self) -> u8 {
        self.revision
    }

    pub fn ace_count(&self) -> u16 {
        self.ace_count
    }

    pub fn entries(&self) -> AclEntries<'a> {
        AclEntries {
            bytes: &self.bytes[Self::HEADER_SIZE..],
            remaining: self.ace_count,
        }
    }

    #[allow(dead_code)]
    pub fn sbz1(&self) -> u8 {
        self.sbz1
    }

    #[allow(dead_code)]
    pub fn sbz2(&self) -> u16 {
        self.sbz2
    }
}

pub struct AclEntries<'a> {
    bytes: &'a [u8],
    remaining: u16,
}

impl<'a> Iterator for AclEntries<'a> {
    type Item = KacsResult<Ace<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        match Ace::parse_prefix(self.bytes) {
            Ok((ace, consumed)) => {
                self.bytes = &self.bytes[consumed..];
                self.remaining -= 1;
                Some(Ok(ace))
            }
            Err(err) => {
                self.remaining = 0;
                self.bytes = &[];
                Some(Err(err))
            }
        }
    }
}
