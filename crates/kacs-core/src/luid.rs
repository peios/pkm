// LUID — Locally Unique Identifier (§7.3).
//
// 64-bit value used for token IDs, logon session IDs, and privilege
// identifiers. Unique within a single boot — not globally unique.

/// A 64-bit locally unique identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Luid(pub u64);

impl Luid {
    pub const ZERO: Luid = Luid(0);

    /// Parse from 8-byte little-endian representation.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Luid(u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ])))
    }

    /// Serialize to 8-byte little-endian representation.
    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}
