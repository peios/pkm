// Security Identifier (SID) — unique hierarchical principal identifier.
//
// Format: S-{revision}-{authority}-{sub1}-{sub2}-...
// Binary: revision (1 byte) + sub_authority_count (1 byte) +
//         identifier_authority (6 bytes) + sub_authorities (4 bytes each)
//
// SIDs are byte-compatible with the Windows binary format (MS-DTYP §2.4.2).

use alloc::vec::Vec;
use core::fmt;

/// Maximum sub-authorities in a SID (Windows limit).
pub const SID_MAX_SUB_AUTHORITIES: usize = 15;

/// A Security Identifier.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Sid {
    /// Always 1.
    pub revision: u8,
    /// 6-byte identifier authority (big-endian).
    pub authority: [u8; 6],
    /// Up to 15 sub-authority values.
    pub sub_authorities: Vec<u32>,
}

impl Sid {
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

        let mut sub_authorities = Vec::with_capacity(sub_authority_count);
        for i in 0..sub_authority_count {
            let offset = 8 + i * 4;
            let sa = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            sub_authorities.push(sa);
        }

        Some(Sid {
            revision,
            authority,
            sub_authorities,
        })
    }

    /// Serialize to binary representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.sub_authorities.len() * 4);
        buf.push(self.revision);
        buf.push(self.sub_authorities.len() as u8);
        buf.extend_from_slice(&self.authority);
        for &sa in &self.sub_authorities {
            buf.extend_from_slice(&sa.to_le_bytes());
        }
        buf
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
        let bytes = original.to_bytes();
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
        assert_eq!(sid.to_bytes().len(), sid.byte_len());
    }

    #[test]
    fn equality() {
        let a = Sid {
            revision: 1,
            authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: alloc::vec![18],
        };
        let b = Sid::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(a, b);
    }
}
