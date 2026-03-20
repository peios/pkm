// GUID — 16-byte globally unique identifier for object ACEs (§9.3).
//
// Used in object-type ACEs to scope access rules to specific properties
// or object classes. The same GUIDs as Windows Active Directory schema
// (schemaIDGUID, rightsGuid).

use core::fmt;

/// A 128-bit GUID in Windows mixed-endian format.
///
/// Binary layout (MS-DTYP §2.3.4):
///   data1: u32 (little-endian)
///   data2: u16 (little-endian)
///   data3: u16 (little-endian)
///   data4: [u8; 8] (big-endian / raw bytes)
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Guid {
    /// First 32-bit component (little-endian in binary).
    pub data1: u32,
    /// Second 16-bit component (little-endian in binary).
    pub data2: u16,
    /// Third 16-bit component (little-endian in binary).
    pub data3: u16,
    /// Final 8 bytes (raw byte order in binary).
    pub data4: [u8; 8],
}

impl Guid {
    /// The all-zeros GUID (00000000-0000-0000-0000-000000000000).
    pub const ZERO: Guid = Guid {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    /// Parse from 16-byte binary representation.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let data1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let data2 = u16::from_le_bytes([data[4], data[5]]);
        let data3 = u16::from_le_bytes([data[6], data[7]]);
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&data[8..16]);
        Some(Guid { data1, data2, data3, data4 })
    }

    /// Serialize to 16-byte binary representation.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.data1.to_le_bytes());
        buf[4..6].copy_from_slice(&self.data2.to_le_bytes());
        buf[6..8].copy_from_slice(&self.data3.to_le_bytes());
        buf[8..16].copy_from_slice(&self.data4);
        buf
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3,
            self.data4[0], self.data4[1],
            self.data4[2], self.data4[3], self.data4[4],
            self.data4[5], self.data4[6], self.data4[7],
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({})", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn zero_guid() {
        assert_eq!(Guid::ZERO.to_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn round_trip() {
        let guid = Guid {
            data1: 0xDEADBEEF,
            data2: 0xCAFE,
            data3: 0xBABE,
            data4: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        };
        let bytes = guid.to_bytes();
        let parsed = Guid::from_bytes(&bytes).unwrap();
        assert_eq!(guid, parsed);
    }

    #[test]
    fn display_format() {
        let guid = Guid {
            data1: 0x6ba7b810,
            data2: 0x9dad,
            data3: 0x11d1,
            data4: [0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8],
        };
        assert_eq!(guid.to_string(), "6ba7b810-9dad-11d1-80b4-00c04fd430c8");
    }

    #[test]
    fn reject_truncated() {
        assert!(Guid::from_bytes(&[0u8; 15]).is_none());
    }
}
