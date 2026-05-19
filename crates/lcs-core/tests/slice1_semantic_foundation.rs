use lcs_core::{
    ACCESS_SYSTEM_SECURITY, BASE_LAYER_NAME, DELETE, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ,
    GENERIC_WRITE, KEY_ALL_ACCESS, KEY_CREATE_LINK, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS,
    KEY_NOTIFY, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WRITE, LcsError, LcsLimits,
    MAX_PATH_COMPONENT_LENGTH, MAX_TOTAL_PATH_LENGTH, MAX_VALUE_SIZE, MAXIMUM_ALLOWED, PathKind,
    READ_CONTROL, REG_BINARY, REG_DWORD, REG_FULL_RESOURCE_DESCRIPTOR, REG_LINK, REG_NONE,
    REG_NOTIFY_ALL, REG_NOTIFY_SD, REG_NOTIFY_SUBKEY, REG_NOTIFY_VALUE, REG_QWORD,
    REG_RESOURCE_LIST, REG_RESOURCE_REQUIREMENTS_LIST, REG_SZ, REG_TOMBSTONE,
    REG_VALID_ACE_ACCESS_MASK, REG_VALID_DESIRED_ACCESS_MASK, REG_VALID_MAPPED_ACCESS_MASK,
    REG_WATCH_OVERFLOW, RSI_CREATE_KEY, RSI_LOOKUP, RSI_RESPONSE_BIT, SYNCHRONIZE, SequenceCounter,
    WRITE_DAC, WRITE_OWNER, casefold_eq, is_base_layer_name, is_reserved_current_user_name,
    map_registry_generic_bits, registry_fd_has_right, validate_config_value,
    validate_hive_name_bytes, validate_key_component_bytes, validate_layer_name_bytes,
    validate_lcs_str, validate_registry_ace_mask, validate_registry_desired_access,
    validate_registry_path_bytes, validate_registry_path_str, validate_value_data_len,
    validate_value_name_bytes, validate_value_write_type,
};

#[test]
fn constants_match_psd_005_appendix_a() {
    assert_eq!(KEY_QUERY_VALUE, 0x0001);
    assert_eq!(KEY_SET_VALUE, 0x0002);
    assert_eq!(KEY_CREATE_SUB_KEY, 0x0004);
    assert_eq!(KEY_ENUMERATE_SUB_KEYS, 0x0008);
    assert_eq!(KEY_NOTIFY, 0x0010);
    assert_eq!(KEY_CREATE_LINK, 0x0020);
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
    assert_eq!(KEY_READ, 0x0002_0019);
    assert_eq!(KEY_WRITE, 0x0002_0006);
    assert_eq!(KEY_ALL_ACCESS, 0x000f_003f);
    assert_eq!(REG_VALID_DESIRED_ACCESS_MASK, 0xf30f_003f);
    assert_eq!(REG_VALID_MAPPED_ACCESS_MASK, 0x010f_003f);
    assert_eq!(REG_VALID_ACE_ACCESS_MASK, 0xf10f_003f);
    assert_eq!(REG_NONE, 0);
    assert_eq!(REG_SZ, 1);
    assert_eq!(REG_BINARY, 3);
    assert_eq!(REG_LINK, 6);
    assert_eq!(REG_RESOURCE_LIST, 8);
    assert_eq!(REG_FULL_RESOURCE_DESCRIPTOR, 9);
    assert_eq!(REG_RESOURCE_REQUIREMENTS_LIST, 10);
    assert_eq!(REG_QWORD, 11);
    assert_eq!(REG_TOMBSTONE, 0xffff);
    assert_eq!(
        REG_NOTIFY_ALL,
        REG_NOTIFY_VALUE | REG_NOTIFY_SUBKEY | REG_NOTIFY_SD
    );
    assert_eq!(REG_WATCH_OVERFLOW, 7);
    assert_eq!(RSI_LOOKUP, 0x01);
    assert_eq!(RSI_CREATE_KEY | RSI_RESPONSE_BIT, 0x8010);
    assert_eq!(BASE_LAYER_NAME, "base");
}

#[test]
fn compiled_in_limits_match_psd_005_defaults_and_ranges() {
    let limits = LcsLimits::default();
    assert_eq!(limits.max_key_depth, 512);
    assert_eq!(limits.max_path_component_length, 255);
    assert_eq!(limits.max_total_path_length, 16_383);
    assert_eq!(limits.symlink_depth_limit, 16);
    assert_eq!(limits.max_value_size, 1_048_576);
    assert_eq!(limits.max_layers_per_value, 128);
    assert_eq!(limits.max_total_layers, 1024);
    assert_eq!(limits.max_registered_sources, 32);
    assert_eq!(limits.max_hives_per_source, 64);
    assert_eq!(limits.max_scope_guids_per_token, 8);
    assert_eq!(limits.max_private_layers_per_token, 16);

    assert_eq!(validate_config_value(MAX_PATH_COMPONENT_LENGTH, 64), Ok(64));
    assert_eq!(
        validate_config_value(MAX_TOTAL_PATH_LENGTH, 65_535),
        Ok(65_535)
    );
    assert_eq!(
        validate_config_value(MAX_VALUE_SIZE, 1_048_576),
        Ok(1_048_576)
    );
    assert_eq!(
        validate_config_value(MAX_PATH_COMPONENT_LENGTH, 63),
        Err(LcsError::InvalidConfigValue {
            parameter: "MaxPathComponentLength",
            value: 63,
            min: 64,
            max: 1024,
        })
    );
}

#[test]
fn string_validation_rejects_invalid_utf8_and_nulls() {
    assert_eq!(
        validate_lcs_str("Machine".as_bytes(), "hive"),
        Ok("Machine")
    );
    assert_eq!(
        validate_lcs_str(&[0xff], "hive"),
        Err(LcsError::InvalidUtf8 { field: "hive" })
    );
    assert_eq!(
        validate_lcs_str(b"Mach\0ine", "hive"),
        Err(LcsError::NullByte { field: "hive" })
    );
}

#[test]
fn name_validation_distinguishes_key_like_names_from_value_names() {
    let limits = LcsLimits::default();

    assert_eq!(
        validate_key_component_bytes("System".as_bytes(), &limits),
        Ok("System")
    );
    assert_eq!(
        validate_key_component_bytes(b"", &limits),
        Err(LcsError::EmptyString {
            field: "key_component",
        })
    );
    assert_eq!(
        validate_key_component_bytes(b"System/Setup", &limits),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
    assert_eq!(validate_value_name_bytes(b"", &limits), Ok(""));
    assert_eq!(
        validate_value_name_bytes(b"Path/With\\Separators", &limits),
        Ok("Path/With\\Separators")
    );
}

#[test]
fn hive_and_layer_sentinel_names_are_ascii_case_insensitive_only() {
    let limits = LcsLimits::default();

    assert_eq!(
        validate_hive_name_bytes(b"currentuser", &limits),
        Err(LcsError::ReservedHiveName)
    );
    assert_eq!(
        validate_hive_name_bytes("Machine".as_bytes(), &limits),
        Ok("Machine")
    );
    assert_eq!(
        validate_layer_name_bytes(b"role-jellyfin", &limits),
        Ok("role-jellyfin")
    );
    assert!(is_reserved_current_user_name("CURRENTUSER"));
    assert!(is_base_layer_name("BASE"));
    assert!(casefold_eq("CurrentUser", "currentuser"));
}

#[test]
fn path_validation_accepts_forward_slashes_and_rejects_malformed_paths() {
    let limits = LcsLimits::default();

    let path = validate_registry_path_str("Machine/System/Registry", PathKind::Absolute, &limits)
        .expect("slash-normalized path should validate");
    assert_eq!(path.component_count, 3);
    assert_eq!(path.first_component, "Machine");
    assert_eq!(path.final_component, "Registry");
    assert!(path.used_forward_separator);

    assert_eq!(
        validate_registry_path_bytes(b"", PathKind::Absolute, &limits),
        Err(LcsError::EmptyPath)
    );
    assert_eq!(
        validate_registry_path_str("Machine\\\\System", PathKind::Absolute, &limits),
        Err(LcsError::EmptyPathComponent)
    );
    assert_eq!(
        validate_registry_path_str("Machine\\System\\", PathKind::Absolute, &limits),
        Err(LcsError::TrailingPathSeparator)
    );
}

#[test]
fn path_validation_enforces_byte_lengths_and_depth() {
    let mut limits = LcsLimits::default();
    limits.max_path_component_length = 4;
    limits.max_total_path_length = 12;
    limits.max_key_depth = 2;

    assert_eq!(
        validate_registry_path_str("Machine", PathKind::Absolute, &limits),
        Err(LcsError::NameTooLong {
            field: "path_component",
            len: 7,
            max: 4,
        })
    );

    limits.max_path_component_length = 255;
    assert_eq!(
        validate_registry_path_str("Machine\\System", PathKind::Absolute, &limits),
        Err(LcsError::PathTooLong { len: 14, max: 12 })
    );

    limits.max_total_path_length = 255;
    assert_eq!(
        validate_registry_path_str("A\\B\\C", PathKind::Absolute, &limits),
        Err(LcsError::KeyDepthExceeded { depth: 3, max: 2 })
    );
}

#[test]
fn registry_desired_access_validation_maps_generics_and_rejects_unknowns() {
    let normalized = validate_registry_desired_access(GENERIC_READ | GENERIC_EXECUTE)
        .expect("raw generic bits should be accepted");
    assert_eq!(normalized.mapped, KEY_READ);
    assert!(!normalized.maximum_allowed);

    let normalized = validate_registry_desired_access(MAXIMUM_ALLOWED | KEY_QUERY_VALUE)
        .expect("maximum allowed may be combined with concrete rights");
    assert_eq!(normalized.mapped, KEY_QUERY_VALUE);
    assert!(normalized.maximum_allowed);

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
fn registry_ace_mask_validation_rejects_maximum_allowed_and_bad_mapped_bits() {
    assert_eq!(validate_registry_ace_mask(GENERIC_ALL), Ok(KEY_ALL_ACCESS));
    assert_eq!(map_registry_generic_bits(GENERIC_EXECUTE), 0);
    assert_eq!(
        validate_registry_ace_mask(MAXIMUM_ALLOWED),
        Err(LcsError::MaximumAllowedInAce(MAXIMUM_ALLOWED))
    );
    assert_eq!(
        validate_registry_ace_mask(SYNCHRONIZE),
        Err(LcsError::UnknownAccessBits(SYNCHRONIZE))
    );
    assert!(registry_fd_has_right(KEY_READ, KEY_QUERY_VALUE));
    assert!(!registry_fd_has_right(KEY_READ, KEY_SET_VALUE));
}

#[test]
fn value_type_validation_accepts_windows_types_and_constrains_tombstones() {
    assert_eq!(
        validate_value_write_type(REG_DWORD, 4, false).expect("REG_DWORD should validate"),
        lcs_core::ValidatedValueType::Normal(lcs_core::RegistryValueType::Dword)
    );
    assert_eq!(
        validate_value_write_type(REG_RESOURCE_REQUIREMENTS_LIST, 64, false)
            .expect("resource requirement type should round-trip"),
        lcs_core::ValidatedValueType::Normal(lcs_core::RegistryValueType::ResourceRequirementsList)
    );
    assert_eq!(
        validate_value_write_type(12, 0, false),
        Err(LcsError::UnknownValueType(12))
    );
    assert_eq!(
        validate_value_write_type(REG_TOMBSTONE, 0, false),
        Err(LcsError::TombstoneNotExplicit)
    );
    assert_eq!(
        validate_value_write_type(REG_TOMBSTONE, 1, true),
        Err(LcsError::TombstoneDataMustBeEmpty { len: 1 })
    );
    assert_eq!(
        validate_value_write_type(REG_TOMBSTONE, 0, true),
        Ok(lcs_core::ValidatedValueType::Tombstone)
    );
}

#[test]
fn value_payload_length_uses_configured_limit() {
    let mut limits = LcsLimits::default();
    limits.max_value_size = 3;
    assert_eq!(validate_value_data_len(3, &limits), Ok(()));
    assert_eq!(
        validate_value_data_len(4, &limits),
        Err(LcsError::ValueDataTooLarge { len: 4, max: 3 })
    );
}

#[test]
fn sequence_counter_allocates_advances_and_rejects_future_source_entries() {
    let mut counter = SequenceCounter::from_highest_persisted(41)
        .expect("highest persisted sequence below u64::MAX should initialise");
    assert_eq!(counter.next_sequence(), 42);
    assert_eq!(counter.allocate(), Ok(42));
    assert_eq!(counter.next_sequence(), 43);

    counter
        .advance_past_source_max(99)
        .expect("source max should advance next_sequence");
    assert_eq!(counter.next_sequence(), 100);
    counter
        .advance_past_source_max(7)
        .expect("older source max should not decrement next_sequence");
    assert_eq!(counter.next_sequence(), 100);

    assert_eq!(counter.validate_source_entry_sequence(99), Ok(()));
    assert_eq!(
        counter.validate_source_entry_sequence(100),
        Err(LcsError::FutureSequence {
            sequence: 100,
            next_sequence: 100,
        })
    );
}

#[test]
fn sequence_counter_fails_closed_on_overflow() {
    assert_eq!(
        SequenceCounter::from_highest_persisted(u64::MAX),
        Err(LcsError::SequenceOverflow)
    );

    let mut counter = SequenceCounter::new(u64::MAX);
    assert_eq!(counter.allocate(), Err(LcsError::SequenceOverflow));
    assert_eq!(counter.next_sequence(), u64::MAX);
    assert_eq!(
        counter.advance_past_source_max(u64::MAX),
        Err(LcsError::SequenceOverflow)
    );
}
