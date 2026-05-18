use crate::error::{LcsError, LcsResult};

/// Decodes an LCS string as UTF-8 and rejects embedded null bytes.
pub fn validate_lcs_str<'a>(bytes: &'a [u8], field: &'static str) -> LcsResult<&'a str> {
    let value = core::str::from_utf8(bytes).map_err(|_| LcsError::InvalidUtf8 { field })?;
    if value.as_bytes().contains(&0) {
        return Err(LcsError::NullByte { field });
    }
    Ok(value)
}

/// ASCII-only equality for fixed ASCII sentinel words.
///
/// This is not the general PSD-005 Unicode Simple Case Folding algorithm. It is
/// intentionally limited to ASCII-only reserved literals such as `CurrentUser`
/// and `base`.
pub fn ascii_case_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}
