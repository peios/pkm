use lcs_core::{
    EnumeratedValue, LayerResolutionContext, LayerView, LcsError, LcsLimits, NamedValueEntry,
    REG_SZ, ValueEntry, ValueWriteRequest, casefold_eq, for_each_effective_value,
    validate_key_component_bytes, validate_value_name_bytes, validate_value_write_request,
};

const KEY_GUID: lcs_core::Guid = [0x61; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn context<'a>(layers: &'a [LayerView<'a>], limits: &'a LcsLimits) -> LayerResolutionContext<'a> {
    LayerResolutionContext {
        layers,
        private_layers: &[],
        limits,
        next_sequence: 100,
    }
}

fn write_request(name: &str) -> ValueWriteRequest<'_> {
    ValueWriteRequest {
        key_guid: KEY_GUID,
        name,
        layer: "base",
        sequence: 7,
        value_type: REG_SZ,
        data: b"value",
        explicit_tombstone_operation: false,
        expected_sequence: None,
    }
}

#[test]
fn value_names_accept_default_name_and_literal_separators() {
    let limits = limits();

    assert_eq!(validate_value_name_bytes(b"", &limits), Ok(""));
    assert_eq!(
        validate_value_name_bytes(b"Policy/With\\Separators", &limits),
        Ok("Policy/With\\Separators")
    );

    assert_eq!(
        validate_key_component_bytes(b"Policy/With", &limits),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
    assert_eq!(
        validate_key_component_bytes(b"Policy\\With", &limits),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
}

#[test]
fn value_names_reject_only_null_and_invalid_utf8_boundaries() {
    let limits = limits();

    assert_eq!(
        validate_value_name_bytes(b"bad\0value", &limits),
        Err(LcsError::NullByte {
            field: "value_name",
        })
    );
    assert_eq!(
        validate_value_name_bytes(&[0xff], &limits),
        Err(LcsError::InvalidUtf8 {
            field: "value_name",
        })
    );
}

#[test]
fn value_write_validation_preserves_default_and_separator_spelling() {
    let limits = limits();

    let default_value = validate_value_write_request(&limits, &write_request(""))
        .expect("empty value name is the default value");
    assert_eq!(default_value.name, "");

    let separator_name = "Policy/With\\Separators";
    let separator_value = validate_value_write_request(&limits, &write_request(separator_name))
        .expect("separators are literal value-name characters");
    assert_eq!(separator_value.name, separator_name);
}

#[test]
fn folded_value_enumeration_preserves_winning_separator_spelling() {
    let limits = limits();
    let layers = [
        LayerView {
            name: "base",
            precedence: 0,
            enabled: true,
        },
        LayerView {
            name: "policy",
            precedence: 10,
            enabled: true,
        },
    ];
    let context = context(&layers, &limits);
    let entries = [
        NamedValueEntry {
            name: "Policy/Setting\\Name",
            entry: ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_SZ,
                data: b"base",
            },
        },
        NamedValueEntry {
            name: "policy/setting\\name",
            entry: ValueEntry {
                layer: "policy",
                sequence: 2,
                value_type: REG_SZ,
                data: b"policy",
            },
        },
    ];
    let mut values = Vec::<EnumeratedValue<'_>>::new();

    let count = for_each_effective_value(&context, &entries, &[], |value| {
        values.push(value);
        Ok(())
    })
    .expect("folded value enumeration should succeed");

    assert_eq!(count, 1);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name, "policy/setting\\name");
    assert!(casefold_eq(values[0].name, "Policy/Setting\\Name"));
    assert_eq!(values[0].value.layer, "policy");
    assert_eq!(values[0].value.data, b"policy");
}

#[test]
fn separator_characters_are_ordinary_value_name_bytes() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &limits);
    let entries = [
        NamedValueEntry {
            name: "Path/Name",
            entry: ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_SZ,
                data: b"slash",
            },
        },
        NamedValueEntry {
            name: "Path\\Name",
            entry: ValueEntry {
                layer: "base",
                sequence: 2,
                value_type: REG_SZ,
                data: b"backslash",
            },
        },
    ];
    let mut names = Vec::<&str>::new();

    let count = for_each_effective_value(&context, &entries, &[], |value| {
        names.push(value.name);
        Ok(())
    })
    .expect("literal separator value names should enumerate independently");

    assert_eq!(count, 2);
    assert!(names.contains(&"Path/Name"));
    assert!(names.contains(&"Path\\Name"));
}
