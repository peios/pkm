use crate::common::{limits};
use lcs_core::{
    BlanketTombstoneAction, BlanketTombstoneRequest, Guid, LcsError, NIL_GUID,
    REG_BINARY, REG_TOMBSTONE, ValidatedValueType, ValueDeleteRequest, ValueWriteRequest,
    validate_blanket_tombstone_request, validate_value_delete_request,
    validate_value_write_request,
};

const KEY_GUID: Guid = [0x10; 16];


fn write_request<'a>(value_type: u32, data: &'a [u8]) -> ValueWriteRequest<'a> {
    ValueWriteRequest {
        key_guid: KEY_GUID,
        name: "Setting",
        layer: "base",
        sequence: 7,
        value_type,
        data,
        explicit_tombstone_operation: false,
        expected_sequence: None,
    }
}

#[test]
fn value_write_validation_accepts_normal_values_and_expected_sequence() {
    let limits = limits();
    let mut request = write_request(REG_BINARY, b"payload");
    request.expected_sequence = Some(44);

    let validated = validate_value_write_request(&limits, &request)
        .expect("normal value write should validate");

    assert_eq!(validated.key_guid, KEY_GUID);
    assert_eq!(validated.name, "Setting");
    assert_eq!(validated.layer, "base");
    assert_eq!(validated.sequence, 7);
    assert_eq!(
        validated.value_type,
        ValidatedValueType::Normal(lcs_core::RegistryValueType::Binary)
    );
    assert_eq!(validated.data, b"payload");
    assert_eq!(validated.expected_sequence, Some(44));
}

#[test]
fn value_write_validation_accepts_default_value_name_and_separators() {
    let limits = limits();
    let mut request = write_request(REG_BINARY, b"payload");
    request.name = "";
    assert_eq!(
        validate_value_write_request(&limits, &request)
            .expect("default value name should validate")
            .name,
        ""
    );

    request.name = "Policy/With\\Separators";
    assert_eq!(
        validate_value_write_request(&limits, &request)
            .expect("value names may contain separators")
            .name,
        "Policy/With\\Separators"
    );
}

#[test]
fn value_write_validation_accepts_explicit_empty_tombstone() {
    let limits = limits();
    let mut request = write_request(REG_TOMBSTONE, b"");
    request.explicit_tombstone_operation = true;

    assert_eq!(
        validate_value_write_request(&limits, &request)
            .expect("explicit tombstone should validate")
            .value_type,
        ValidatedValueType::Tombstone
    );
}

#[test]
fn value_write_validation_rejects_malformed_inputs_before_dispatch() {
    let limits = limits();

    let mut nil_key = write_request(REG_BINARY, b"payload");
    nil_key.key_guid = NIL_GUID;
    assert_eq!(
        validate_value_write_request(&limits, &nil_key),
        Err(LcsError::NilKeyGuid)
    );

    let mut bad_name = write_request(REG_BINARY, b"payload");
    bad_name.name = "bad\0name";
    assert_eq!(
        validate_value_write_request(&limits, &bad_name),
        Err(LcsError::NullByte {
            field: "value_name"
        })
    );

    let mut bad_layer = write_request(REG_BINARY, b"payload");
    bad_layer.layer = "bad/layer";
    assert_eq!(
        validate_value_write_request(&limits, &bad_layer),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );

    let mut unknown_type = write_request(0xdead_beef, b"payload");
    assert_eq!(
        validate_value_write_request(&limits, &unknown_type),
        Err(LcsError::UnknownValueType(0xdead_beef))
    );

    unknown_type.value_type = REG_TOMBSTONE;
    assert_eq!(
        validate_value_write_request(&limits, &unknown_type),
        Err(LcsError::TombstoneNotExplicit)
    );

    let mut nonempty_tombstone = write_request(REG_TOMBSTONE, b"x");
    nonempty_tombstone.explicit_tombstone_operation = true;
    assert_eq!(
        validate_value_write_request(&limits, &nonempty_tombstone),
        Err(LcsError::TombstoneDataMustBeEmpty { len: 1 })
    );
}

#[test]
fn value_write_validation_enforces_configured_payload_limit() {
    let mut limits = limits();
    limits.max_value_size = 3;

    assert_eq!(
        validate_value_write_request(&limits, &write_request(REG_BINARY, b"1234")),
        Err(LcsError::ValueDataTooLarge { len: 4, max: 3 })
    );
}

#[test]
fn value_delete_validation_accepts_idempotent_delete_shape() {
    let limits = limits();
    let request = ValueDeleteRequest {
        key_guid: KEY_GUID,
        name: "Setting",
        layer: "base",
    };
    let validated =
        validate_value_delete_request(&limits, &request).expect("delete request should validate");

    assert_eq!(validated.key_guid, KEY_GUID);
    assert_eq!(validated.name, "Setting");
    assert_eq!(validated.layer, "base");
}

#[test]
fn value_delete_validation_rejects_malformed_shape() {
    let limits = limits();

    assert_eq!(
        validate_value_delete_request(
            &limits,
            &ValueDeleteRequest {
                key_guid: NIL_GUID,
                name: "Setting",
                layer: "base",
            },
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        validate_value_delete_request(
            &limits,
            &ValueDeleteRequest {
                key_guid: KEY_GUID,
                name: "Setting",
                layer: "bad\\layer",
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}

#[test]
fn blanket_tombstone_validation_accepts_set_and_remove() {
    let limits = limits();
    let set = BlanketTombstoneRequest {
        key_guid: KEY_GUID,
        layer: "base",
        action: BlanketTombstoneAction::Set { sequence: 9 },
    };
    let remove = BlanketTombstoneRequest {
        action: BlanketTombstoneAction::Remove,
        ..set
    };

    assert_eq!(
        validate_blanket_tombstone_request(&limits, &set)
            .expect("set blanket request should validate")
            .action,
        BlanketTombstoneAction::Set { sequence: 9 }
    );
    assert_eq!(
        validate_blanket_tombstone_request(&limits, &remove)
            .expect("remove blanket request should validate")
            .action,
        BlanketTombstoneAction::Remove
    );
}

#[test]
fn blanket_tombstone_validation_rejects_malformed_shape() {
    let limits = limits();

    assert_eq!(
        validate_blanket_tombstone_request(
            &limits,
            &BlanketTombstoneRequest {
                key_guid: NIL_GUID,
                layer: "base",
                action: BlanketTombstoneAction::Set { sequence: 9 },
            },
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        validate_blanket_tombstone_request(
            &limits,
            &BlanketTombstoneRequest {
                key_guid: KEY_GUID,
                layer: "bad/layer",
                action: BlanketTombstoneAction::Remove,
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}
