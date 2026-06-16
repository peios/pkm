use crate::common::{context, limits};
use lcs_core::{
    BlanketTombstoneEntry, EnumeratedSubkey, EnumeratedValue, Guid,
    LayerView, NamedPathEntry, NamedValueEntry, PathEntry, PathTarget, REG_SZ,
    REG_TOMBSTONE, RegistryValueType, ValueEntry, for_each_effective_value,
    for_each_visible_subkey,
};

const BASE_GUID: Guid = [0x11; 16];
const POLICY_GUID: Guid = [0x22; 16];
const VISIBLE_GUID: Guid = [0x33; 16];



fn base_policy_layers() -> [LayerView<'static>; 2] {
    [
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
    ]
}

#[test]
fn value_enumeration_returns_only_effective_value_not_raw_layer_entries() {
    let limits = limits();
    let layers = base_policy_layers();
    let context = context(&layers, &limits);
    let entries = [
        NamedValueEntry {
            name: "Setting",
            entry: ValueEntry {
                layer: "base",
                sequence: 90,
                value_type: REG_SZ,
                data: b"raw-lower-layer",
            },
        },
        NamedValueEntry {
            name: "SETTING",
            entry: ValueEntry {
                layer: "policy",
                sequence: 1,
                value_type: REG_SZ,
                data: b"effective",
            },
        },
    ];
    let mut values = Vec::<EnumeratedValue<'_>>::new();

    let count = for_each_effective_value(&context, &entries, &[], |value| {
        values.push(value);
        Ok(())
    })
    .expect("value enumeration should succeed");

    assert_eq!(count, 1);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name, "SETTING");
    assert_eq!(values[0].value.value_type, RegistryValueType::Sz);
    assert_eq!(values[0].value.data, b"effective");
    assert_eq!(values[0].value.layer, "policy");
}

#[test]
fn value_enumeration_omits_tombstoned_and_blanket_masked_values() {
    let limits = limits();
    let layers = base_policy_layers();
    let context = context(&layers, &limits);
    let entries = [
        NamedValueEntry {
            name: "Deleted",
            entry: ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_TOMBSTONE,
                data: b"",
            },
        },
        NamedValueEntry {
            name: "Masked",
            entry: ValueEntry {
                layer: "base",
                sequence: 2,
                value_type: REG_SZ,
                data: b"masked",
            },
        },
        NamedValueEntry {
            name: "Visible",
            entry: ValueEntry {
                layer: "policy",
                sequence: 4,
                value_type: REG_SZ,
                data: b"visible",
            },
        },
    ];
    let blankets = [BlanketTombstoneEntry {
        layer: "policy",
        sequence: 3,
    }];
    let mut values = Vec::<EnumeratedValue<'_>>::new();

    let count = for_each_effective_value(&context, &entries, &blankets, |value| {
        values.push(value);
        Ok(())
    })
    .expect("value enumeration should succeed");

    assert_eq!(count, 1);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name, "Visible");
    assert_eq!(values[0].value.data, b"visible");
}

#[test]
fn subkey_enumeration_returns_only_effective_visible_child_not_raw_layer_entries() {
    let limits = limits();
    let layers = base_policy_layers();
    let context = context(&layers, &limits);
    let entries = [
        NamedPathEntry {
            child_name: "Service",
            entry: PathEntry {
                layer: "base",
                sequence: 90,
                target: PathTarget::Guid(BASE_GUID),
            },
        },
        NamedPathEntry {
            child_name: "SERVICE",
            entry: PathEntry {
                layer: "policy",
                sequence: 1,
                target: PathTarget::Guid(POLICY_GUID),
            },
        },
    ];
    let mut subkeys = Vec::<EnumeratedSubkey<'_>>::new();

    let count = for_each_visible_subkey(&context, &entries, |subkey| {
        subkeys.push(subkey);
        Ok(())
    })
    .expect("subkey enumeration should succeed");

    assert_eq!(count, 1);
    assert_eq!(subkeys.len(), 1);
    assert_eq!(subkeys[0].child_name, "SERVICE");
    assert_eq!(subkeys[0].path.guid, POLICY_GUID);
    assert_eq!(subkeys[0].path.layer, "policy");
}

#[test]
fn subkey_enumeration_omits_hidden_effective_children() {
    let limits = limits();
    let layers = base_policy_layers();
    let context = context(&layers, &limits);
    let entries = [
        NamedPathEntry {
            child_name: "Hidden",
            entry: PathEntry {
                layer: "base",
                sequence: 1,
                target: PathTarget::Guid(BASE_GUID),
            },
        },
        NamedPathEntry {
            child_name: "hidden",
            entry: PathEntry {
                layer: "policy",
                sequence: 2,
                target: PathTarget::Hidden,
            },
        },
        NamedPathEntry {
            child_name: "Visible",
            entry: PathEntry {
                layer: "base",
                sequence: 3,
                target: PathTarget::Guid(VISIBLE_GUID),
            },
        },
    ];
    let mut subkeys = Vec::<EnumeratedSubkey<'_>>::new();

    let count = for_each_visible_subkey(&context, &entries, |subkey| {
        subkeys.push(subkey);
        Ok(())
    })
    .expect("subkey enumeration should succeed");

    assert_eq!(count, 1);
    assert_eq!(subkeys.len(), 1);
    assert_eq!(subkeys[0].child_name, "Visible");
    assert_eq!(subkeys[0].path.guid, VISIBLE_GUID);
}
