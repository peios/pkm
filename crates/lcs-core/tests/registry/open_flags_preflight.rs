use lcs_core::{LcsError, REG_OPEN_LINK, validate_registry_open_flags};

#[test]
fn open_flags_accept_only_defined_bits_before_resolution() {
    assert_eq!(validate_registry_open_flags(0), Ok(()));
    assert_eq!(validate_registry_open_flags(REG_OPEN_LINK), Ok(()));
}

#[test]
fn open_flags_reject_unknown_bits_before_resolution() {
    assert_eq!(
        validate_registry_open_flags(REG_OPEN_LINK | 0x80),
        Err(LcsError::UnknownOpenFlags {
            flags: REG_OPEN_LINK | 0x80,
            unknown: 0x80,
        })
    );
}
