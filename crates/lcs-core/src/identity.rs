//! Identity comparison primitives.

/// Compares two binary SID encodings exactly as PSD-005 defines SID equality.
///
/// This is intentionally not a SID validator. Callers that need structural SID
/// validation must perform it before comparing admitted SID bytes.
pub fn sid_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    left == right
}
