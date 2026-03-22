// LUID — Locally Unique Identifier (§7.3).
//
// 64-bit value used for token IDs, logon session IDs, and privilege
// identifiers. Unique within a single boot — not globally unique.

/// A 64-bit locally unique identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Luid(pub u64);

impl Luid {
    /// The zero LUID, used as a sentinel/default value.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_luid() {
        assert_eq!(Luid::ZERO.0, 0);
        assert_eq!(Luid::ZERO.to_bytes(), [0u8; 8]);
    }

    #[test]
    fn round_trip() {
        let luid = Luid(0xDEADBEEFCAFEBABE);
        let bytes = luid.to_bytes();
        let parsed = Luid::from_bytes(&bytes).unwrap();
        assert_eq!(luid, parsed);
    }

    #[test]
    fn from_bytes_max() {
        let luid = Luid(u64::MAX);
        let bytes = luid.to_bytes();
        let parsed = Luid::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.0, u64::MAX);
    }

    #[test]
    fn reject_truncated() {
        assert!(Luid::from_bytes(&[0u8; 7]).is_none());
    }

    #[test]
    fn from_bytes_with_trailing_data() {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&42u64.to_le_bytes());
        let luid = Luid::from_bytes(&data).unwrap();
        assert_eq!(luid.0, 42);
    }

    #[test]
    fn equality() {
        assert_eq!(Luid(1), Luid(1));
        assert_ne!(Luid(1), Luid(2));
    }

    #[test]
    fn luid_is_64_bits() {
        // §7.3: LUID is a 64-bit value
        assert_eq!(core::mem::size_of::<Luid>(), 8);
    }

    #[test]
    fn luid_little_endian_wire_format() {
        let luid = Luid(0x0102030405060708);
        let bytes = luid.to_bytes();
        assert_eq!(bytes[0], 0x08); // least significant byte first
        assert_eq!(bytes[7], 0x01); // most significant byte last
    }

    #[test]
    fn luid_clone_produces_equal() {
        let a = Luid(42);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn luid_copy_semantics() {
        let a = Luid(42);
        let b = a; // Copy
        assert_eq!(a, b); // both still valid
    }
}
