use kacs_core::{
    validate_ace_mask, GenericMapping, KacsError, NormalizedDesiredAccess, ACCESS_SYSTEM_SECURITY,
    DELETE, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, MAXIMUM_ALLOWED,
    READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};

fn test_mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL | 0x0000_0001,
        write: WRITE_DAC | 0x0000_0002,
        execute: 0x0000_0004,
        all: DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | 0x0000_000f,
    }
}

#[test]
fn access_mask_constants_match_psd_004_bit_layout() {
    assert_eq!(DELETE, 0x0001_0000);
    assert_eq!(READ_CONTROL, 0x0002_0000);
    assert_eq!(WRITE_DAC, 0x0004_0000);
    assert_eq!(WRITE_OWNER, 0x0008_0000);
    assert_eq!(SYNCHRONIZE, 0x0010_0000);
    assert_eq!(ACCESS_SYSTEM_SECURITY, 0x0100_0000);
    assert_eq!(MAXIMUM_ALLOWED, 0x0200_0000);
    assert_eq!(GENERIC_ALL, 0x1000_0000);
    assert_eq!(GENERIC_EXECUTE, 0x2000_0000);
    assert_eq!(GENERIC_WRITE, 0x4000_0000);
    assert_eq!(GENERIC_READ, 0x8000_0000);
}

#[test]
fn maps_generic_bits_and_clears_generic_flags() {
    let mapping = test_mapping();
    let mask = GENERIC_READ | GENERIC_WRITE | 0x0000_0040;

    let mapped = mapping
        .map_mask(mask)
        .expect("generic mapping should succeed");

    assert_eq!(
        mapped,
        READ_CONTROL | WRITE_DAC | 0x0000_0001 | 0x0000_0002 | 0x0000_0040
    );
}

#[test]
fn normalize_desired_access_strips_maximum_allowed_and_records_mode() {
    let mapping = test_mapping();

    let normalized = mapping
        .normalize_desired_access(MAXIMUM_ALLOWED | GENERIC_EXECUTE | 0x0000_0040)
        .expect("desired access normalization should succeed");

    assert_eq!(
        normalized,
        NormalizedDesiredAccess {
            requested: MAXIMUM_ALLOWED | GENERIC_EXECUTE | 0x0000_0040,
            mapped: 0x0000_0004 | 0x0000_0040,
            maximum_allowed: true,
        }
    );
}

#[test]
fn validate_ace_mask_rejects_maximum_allowed() {
    let err = validate_ace_mask(MAXIMUM_ALLOWED | READ_CONTROL)
        .expect_err("ace mask with maximum allowed must fail");

    assert_eq!(
        err,
        KacsError::MaximumAllowedInAce(MAXIMUM_ALLOWED | READ_CONTROL)
    );
}

#[test]
fn rejects_reserved_bits_in_requests_and_ace_masks() {
    let mapping = test_mapping();

    let err = mapping
        .map_mask(0x0400_0000)
        .expect_err("reserved bits must fail during mapping");
    assert_eq!(err, KacsError::ReservedAccessMaskBits(0x0400_0000));

    let err = validate_ace_mask(0x0020_0000).expect_err("reserved bits must fail in ace masks");
    assert_eq!(err, KacsError::ReservedAccessMaskBits(0x0020_0000));
}

#[test]
fn rejects_every_reserved_access_mask_bit() {
    let mapping = test_mapping();

    for bit in [21, 22, 23, 26, 27] {
        let mask = 1u32 << bit;
        let err = mapping
            .map_mask(mask)
            .expect_err("reserved desired-access bit must fail");
        assert_eq!(err, KacsError::ReservedAccessMaskBits(mask));

        let err = validate_ace_mask(mask).expect_err("reserved ace-mask bit must fail");
        assert_eq!(err, KacsError::ReservedAccessMaskBits(mask));
    }
}

#[test]
fn generic_all_uses_all_mapping_entry() {
    let mapping = test_mapping();
    let mapped = mapping
        .map_mask(GENERIC_ALL)
        .expect("generic all should map successfully");

    assert_eq!(
        mapped,
        DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | 0x0000_000f
    );
}
