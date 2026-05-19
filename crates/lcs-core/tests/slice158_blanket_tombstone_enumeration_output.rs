use lcs_core::{
    BlanketTombstoneEntry, EnumValueOutcome, EnumeratedValue, LayerResolutionContext, LayerView,
    LcsLimits, REG_DWORD, REG_SZ, RegistryValueType, ValueEntry, enum_value_result_at,
    for_each_effective_value, query_values_batch_required_len,
};

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

fn value_by_name<'a>(values: &'a [EnumeratedValue<'a>], name: &str) -> &'a EnumeratedValue<'a> {
    values
        .iter()
        .find(|value| value.name == name)
        .expect("expected effective value name")
}

#[test]
fn blanket_tombstone_enumeration_output_excludes_masked_lower_values() {
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
        LayerView {
            name: "override",
            precedence: 20,
            enabled: true,
        },
    ];
    let context = context(&layers, &limits);
    let entries = [
        lower_value("Masked", b"must-not-leak"),
        lower_value("Specific", b"lower"),
        NamedValue {
            name: "Specific",
            layer: "policy",
            sequence: 11,
            value_type: REG_SZ,
            data: b"same-layer-visible",
        }
        .into_entry(),
        NamedValue {
            name: "Higher",
            layer: "override",
            sequence: 12,
            value_type: REG_DWORD,
            data: &[7, 0, 0, 0],
        }
        .into_entry(),
    ];
    let blankets = [BlanketTombstoneEntry {
        layer: "policy",
        sequence: 10,
    }];
    let mut values = Vec::<EnumeratedValue<'_>>::new();

    let count = for_each_effective_value(&context, &entries, &blankets, |value| {
        values.push(value);
        Ok(())
    })
    .expect("effective enumeration should succeed");

    assert_eq!(count, 2);
    assert_eq!(values.len(), 2);
    assert!(values.iter().all(|value| value.name != "Masked"));

    let specific = value_by_name(&values, "Specific");
    assert_eq!(specific.value.layer, "policy");
    assert_eq!(specific.value.data, b"same-layer-visible");

    let higher = value_by_name(&values, "Higher");
    assert_eq!(higher.value.layer, "override");
    assert_eq!(higher.value.value_type, RegistryValueType::Dword);
    assert_eq!(higher.value.data, &[7, 0, 0, 0]);
}

#[test]
fn caller_facing_enum_and_batch_shapes_use_only_effective_values() {
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
        lower_value("Masked", b"masked"),
        NamedValue {
            name: "Visible",
            layer: "policy",
            sequence: 11,
            value_type: REG_SZ,
            data: b"visible",
        }
        .into_entry(),
    ];
    let blankets = [BlanketTombstoneEntry {
        layer: "policy",
        sequence: 10,
    }];
    let mut values = Vec::<EnumeratedValue<'_>>::new();

    for_each_effective_value(&context, &entries, &blankets, |value| {
        values.push(value);
        Ok(())
    })
    .expect("effective enumeration should succeed");

    let EnumValueOutcome::Found(result) = enum_value_result_at(&values, 0) else {
        panic!("expected one effective value");
    };
    assert_eq!(result.name, "Visible");
    assert_eq!(result.data, b"visible");
    assert_eq!(enum_value_result_at(&values, 1), EnumValueOutcome::NotFound);

    assert_eq!(
        query_values_batch_required_len(&values),
        Ok(12 + "Visible".len() + b"visible".len())
    );
}

struct NamedValue<'a> {
    name: &'a str,
    layer: &'a str,
    sequence: u64,
    value_type: u32,
    data: &'a [u8],
}

impl<'a> NamedValue<'a> {
    fn into_entry(self) -> lcs_core::NamedValueEntry<'a> {
        lcs_core::NamedValueEntry {
            name: self.name,
            entry: ValueEntry {
                layer: self.layer,
                sequence: self.sequence,
                value_type: self.value_type,
                data: self.data,
            },
        }
    }
}

fn lower_value(name: &'static str, data: &'static [u8]) -> lcs_core::NamedValueEntry<'static> {
    NamedValue {
        name,
        layer: "base",
        sequence: 1,
        value_type: REG_SZ,
        data,
    }
    .into_entry()
}
