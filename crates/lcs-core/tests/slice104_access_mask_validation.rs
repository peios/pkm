use lcs_core::{
    ACCESS_SYSTEM_SECURITY, DELETE, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
    KEY_ALL_ACCESS, KEY_CREATE_LINK, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY,
    KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WRITE, LcsError, MAXIMUM_ALLOWED, READ_CONTROL,
    REG_VALID_ACE_ACCESS_MASK, REG_VALID_DESIRED_ACCESS_MASK, REG_VALID_MAPPED_ACCESS_MASK,
    SYNCHRONIZE, WRITE_DAC, WRITE_OWNER, map_registry_generic_bits, validate_registry_ace_mask,
    validate_registry_desired_access,
};

#[test]
fn registry_access_constants_and_generic_mapping_match_psd_005() {
    assert_eq!(KEY_QUERY_VALUE, 0x0000_0001);
    assert_eq!(KEY_SET_VALUE, 0x0000_0002);
    assert_eq!(KEY_CREATE_SUB_KEY, 0x0000_0004);
    assert_eq!(KEY_ENUMERATE_SUB_KEYS, 0x0000_0008);
    assert_eq!(KEY_NOTIFY, 0x0000_0010);
    assert_eq!(KEY_CREATE_LINK, 0x0000_0020);
    assert_eq!(DELETE, 0x0001_0000);
    assert_eq!(READ_CONTROL, 0x0002_0000);
    assert_eq!(WRITE_DAC, 0x0004_0000);
    assert_eq!(WRITE_OWNER, 0x0008_0000);
    assert_eq!(ACCESS_SYSTEM_SECURITY, 0x0100_0000);

    assert_eq!(
        KEY_READ,
        KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL
    );
    assert_eq!(KEY_WRITE, KEY_SET_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL);
    assert_eq!(
        KEY_ALL_ACCESS,
        KEY_QUERY_VALUE
            | KEY_SET_VALUE
            | KEY_CREATE_SUB_KEY
            | KEY_ENUMERATE_SUB_KEYS
            | KEY_NOTIFY
            | KEY_CREATE_LINK
            | DELETE
            | READ_CONTROL
            | WRITE_DAC
            | WRITE_OWNER
    );

    assert_eq!(map_registry_generic_bits(GENERIC_READ), KEY_READ);
    assert_eq!(map_registry_generic_bits(GENERIC_WRITE), KEY_WRITE);
    assert_eq!(map_registry_generic_bits(GENERIC_EXECUTE), 0);
    assert_eq!(map_registry_generic_bits(GENERIC_ALL), KEY_ALL_ACCESS);
    assert_eq!(
        map_registry_generic_bits(GENERIC_READ | GENERIC_WRITE | KEY_CREATE_LINK),
        KEY_READ | KEY_WRITE | KEY_CREATE_LINK
    );

    assert_eq!(REG_VALID_DESIRED_ACCESS_MASK & SYNCHRONIZE, 0);
    assert_eq!(REG_VALID_ACE_ACCESS_MASK & MAXIMUM_ALLOWED, 0);
    assert_eq!(REG_VALID_MAPPED_ACCESS_MASK & GENERIC_READ, 0);
}

#[test]
fn desired_access_validation_rejects_zero_synchronize_and_unknown_bits() {
    assert_eq!(
        validate_registry_desired_access(0),
        Err(LcsError::ZeroDesiredAccess)
    );
    assert_eq!(
        validate_registry_desired_access(SYNCHRONIZE),
        Err(LcsError::UnknownAccessBits(SYNCHRONIZE))
    );
    assert_eq!(
        validate_registry_desired_access(0x0400_0000),
        Err(LcsError::UnknownAccessBits(0x0400_0000))
    );
}

#[test]
fn desired_access_validation_permits_maximum_allowed_with_valid_rights() {
    let normalized = validate_registry_desired_access(
        MAXIMUM_ALLOWED | KEY_QUERY_VALUE | ACCESS_SYSTEM_SECURITY | GENERIC_READ,
    )
    .unwrap();

    assert_eq!(
        normalized.requested,
        MAXIMUM_ALLOWED | KEY_QUERY_VALUE | ACCESS_SYSTEM_SECURITY | GENERIC_READ
    );
    assert_eq!(
        normalized.mapped,
        KEY_READ | KEY_QUERY_VALUE | ACCESS_SYSTEM_SECURITY
    );
    assert!(normalized.maximum_allowed);

    let only_maximum = validate_registry_desired_access(MAXIMUM_ALLOWED).unwrap();
    assert_eq!(only_maximum.mapped, 0);
    assert!(only_maximum.maximum_allowed);
}

#[test]
fn source_ace_mask_validation_maps_generics_and_rejects_malformed_masks() {
    assert_eq!(
        validate_registry_ace_mask(KEY_QUERY_VALUE | GENERIC_READ | GENERIC_WRITE),
        Ok(KEY_QUERY_VALUE | KEY_READ | KEY_WRITE)
    );
    assert_eq!(validate_registry_ace_mask(GENERIC_EXECUTE), Ok(0));
    assert_eq!(
        validate_registry_ace_mask(ACCESS_SYSTEM_SECURITY | GENERIC_ALL),
        Ok(ACCESS_SYSTEM_SECURITY | KEY_ALL_ACCESS)
    );

    assert_eq!(
        validate_registry_ace_mask(MAXIMUM_ALLOWED),
        Err(LcsError::MaximumAllowedInAce(MAXIMUM_ALLOWED))
    );
    assert_eq!(
        validate_registry_ace_mask(SYNCHRONIZE),
        Err(LcsError::UnknownAccessBits(SYNCHRONIZE))
    );
    assert_eq!(
        validate_registry_ace_mask(0x0400_0000),
        Err(LcsError::UnknownAccessBits(0x0400_0000))
    );
}
