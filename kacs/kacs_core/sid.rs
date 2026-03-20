// Security Identifier (SID) — unique hierarchical principal identifier.
//
// Format: S-{revision}-{authority}-{sub1}-{sub2}-...
// Binary: revision (1 byte) + sub_authority_count (1 byte) +
//         identifier_authority (6 bytes) + sub_authorities (4 bytes each)
//
// SIDs are byte-compatible with the Windows binary format (MS-DTYP §2.4.2).

use crate::compat::{self, AllocError, Vec};
use core::fmt;

/// Maximum sub-authorities in a SID (Windows limit).
pub const SID_MAX_SUB_AUTHORITIES: usize = 15;

/// A Security Identifier.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Eq, PartialEq, Hash)]
pub struct Sid {
    /// Always 1.
    pub revision: u8,
    /// 6-byte identifier authority (big-endian).
    pub authority: [u8; 6],
    /// Up to 15 sub-authority values.
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Construct a SID from an authority value and sub-authorities.
    ///
    /// The authority is a 48-bit value stored big-endian in 6 bytes.
    /// Most well-known authorities fit in the low byte (1, 5, 15, 16, 19).
    pub fn new(authority: u64, sub_authorities: &[u32]) -> Result<Self, AllocError> {
        debug_assert!(authority <= 0xFFFF_FFFF_FFFF);
        debug_assert!(sub_authorities.len() <= SID_MAX_SUB_AUTHORITIES);
        Ok(Sid {
            revision: 1,
            authority: [
                (authority >> 40) as u8,
                (authority >> 32) as u8,
                (authority >> 24) as u8,
                (authority >> 16) as u8,
                (authority >> 8) as u8,
                authority as u8,
            ],
            sub_authorities: compat::slice_to_vec(sub_authorities)?,
        })
    }

    /// Parse a SID from its binary representation (MS-DTYP §2.4.2.1).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let revision = data[0];
        if revision != 1 {
            return None;
        }

        let sub_authority_count = data[1] as usize;
        if sub_authority_count > SID_MAX_SUB_AUTHORITIES {
            return None;
        }

        let expected_len = 8 + sub_authority_count * 4;
        if data.len() < expected_len {
            return None;
        }

        let mut authority = [0u8; 6];
        authority.copy_from_slice(&data[2..8]);

        let mut sub_authorities = compat::vec_with_capacity(sub_authority_count).ok()?;
        for i in 0..sub_authority_count {
            let offset = 8 + i * 4;
            let sa = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            compat::vec_push(&mut sub_authorities, sa).ok()?;
        }

        Some(Sid {
            revision,
            authority,
            sub_authorities,
        })
    }

    /// Serialize to binary representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AllocError> {
        let mut buf = compat::vec_with_capacity(8 + self.sub_authorities.len() * 4)?;
        compat::vec_push(&mut buf, self.revision)?;
        compat::vec_push(&mut buf, self.sub_authorities.len() as u8)?;
        compat::vec_extend(&mut buf, &self.authority)?;
        for &sa in &self.sub_authorities {
            compat::vec_extend(&mut buf, &sa.to_le_bytes())?;
        }
        Ok(buf)
    }

    /// Byte length of this SID's binary representation.
    pub fn byte_len(&self) -> usize {
        8 + self.sub_authorities.len() * 4
    }

    /// The identifier authority as a u64 (big-endian 6-byte value).
    fn authority_value(&self) -> u64 {
        let a = &self.authority;
        ((a[0] as u64) << 40)
            | ((a[1] as u64) << 32)
            | ((a[2] as u64) << 24)
            | ((a[3] as u64) << 16)
            | ((a[4] as u64) << 8)
            | (a[5] as u64)
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let authority = self.authority_value();
        write!(f, "S-{}-{}", self.revision, authority)?;
        for sa in &self.sub_authorities {
            write!(f, "-{}", sa)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({})", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn parse_system_sid() {
        // S-1-5-18 (SYSTEM)
        let bytes = [
            1,  // revision
            1,  // sub_authority_count
            0, 0, 0, 0, 0, 5, // authority = 5
            18, 0, 0, 0, // sub_authority = 18 (little-endian)
        ];
        let sid = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid.to_string(), "S-1-5-18");
        assert_eq!(sid.sub_authorities, &[18]);
    }

    #[test]
    fn parse_administrators_sid() {
        // S-1-5-32-544 (BUILTIN\Administrators)
        let bytes = [
            1, 2, // revision, 2 sub-authorities
            0, 0, 0, 0, 0, 5, // authority = 5
            32, 0, 0, 0, // sub_authority[0] = 32
            0x20, 0x02, 0, 0, // sub_authority[1] = 544 (0x220)
        ];
        let sid = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid.to_string(), "S-1-5-32-544");
    }

    #[test]
    fn round_trip() {
        let original = Sid {
            revision: 1,
            authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: alloc::vec![21, 1234567890, 987654321, 1001],
        };
        let bytes = original.to_bytes().unwrap();
        let parsed = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(parsed.to_string(), "S-1-5-21-1234567890-987654321-1001");
    }

    #[test]
    fn reject_truncated() {
        assert!(Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5]).is_none());
    }

    #[test]
    fn reject_bad_revision() {
        let bytes = [
            2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
        ];
        assert!(Sid::from_bytes(&bytes).is_none());
    }

    #[test]
    fn reject_too_many_sub_authorities() {
        let bytes = [
            1, 16, // 16 sub-authorities exceeds max of 15
            0, 0, 0, 0, 0, 5,
        ];
        assert!(Sid::from_bytes(&bytes).is_none());
    }

    #[test]
    fn everyone_sid() {
        // S-1-1-0 (Everyone)
        let bytes = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let sid = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid.to_string(), "S-1-1-0");
    }

    #[test]
    fn byte_len() {
        let sid = Sid {
            revision: 1,
            authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: alloc::vec![21, 100, 200, 1001],
        };
        assert_eq!(sid.byte_len(), 8 + 4 * 4);
        assert_eq!(sid.to_bytes().unwrap().len(), sid.byte_len());
    }

    #[test]
    fn equality() {
        let a = Sid {
            revision: 1,
            authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: alloc::vec![18],
        };
        let b = Sid::from_bytes(&a.to_bytes().unwrap()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn new_zero_sub_authorities() {
        let sid = Sid::new(5, &[]).unwrap();
        assert_eq!(sid.to_string(), "S-1-5");
        assert_eq!(sid.sub_authorities.len(), 0);
        assert_eq!(sid.byte_len(), 8);
        let parsed = Sid::from_bytes(&sid.to_bytes().unwrap()).unwrap();
        assert_eq!(sid, parsed);
    }

    #[test]
    fn new_max_sub_authorities() {
        let sas: Vec<u32> = (1..=15).collect();
        let sid = Sid::new(5, &sas).unwrap();
        assert_eq!(sid.sub_authorities.len(), 15);
        let parsed = Sid::from_bytes(&sid.to_bytes().unwrap()).unwrap();
        assert_eq!(sid, parsed);
    }

    #[test]
    fn from_bytes_with_trailing_data() {
        // Extra bytes after a valid SID should not prevent parsing
        let mut data = alloc::vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        data.extend_from_slice(&[0xFF; 20]); // trailing garbage
        let sid = Sid::from_bytes(&data).unwrap();
        assert_eq!(sid.to_string(), "S-1-5-18");
    }

    #[test]
    fn zero_sub_authority_count_valid() {
        // A SID with 0 sub-authorities is valid (just authority, no RIDs)
        let bytes = [1, 0, 0, 0, 0, 0, 0, 5]; // revision=1, count=0, authority=5
        let sid = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid.sub_authorities.len(), 0);
        assert_eq!(sid.to_string(), "S-1-5");
    }
}
