use crate::common::{limits};
use lcs_core::{
    EnumeratedSubkey, EnumeratedValue, Guid, KEY_CREATE_SUB_KEY, KeyCreateRequest, LayerView,
    LcsLimits, NamedPathEntry, NamedValueEntry, PathEntry, PathEntryWriteRequest, PathTarget,
    REG_SZ, ValueEntry, ValueWriteRequest, casefold_eq, for_each_effective_value,
    for_each_visible_subkey, validate_key_create_request, validate_path_entry_write_request,
    validate_value_write_request,
};

const PARENT_GUID: Guid = [0x41; 16];
const CHILD_GUID: Guid = [0x42; 16];
const KEY_GUID: Guid = [0x43; 16];
const VISIBLE_GUID: Guid = [0x44; 16];


fn layer_context<'a>(
    layers: &'a [LayerView<'a>],
    limits: &'a LcsLimits,
) -> lcs_core::LayerResolutionContext<'a> {
    lcs_core::LayerResolutionContext {
        layers,
        private_layers: &[],
        limits,
        next_sequence: 100,
    }
}

#[test]
fn create_and_write_validation_preserves_original_spelling() {
    let limits = limits();
    let key_name = "ΚernelPolicy";
    let path_child = "ChildΚey";
    let value_name = "PolicyΣetting";

    let key_plan = validate_key_create_request(
        &limits,
        &KeyCreateRequest {
            parent_guid: PARENT_GUID,
            parent_is_volatile: false,
            parent_granted_access: KEY_CREATE_SUB_KEY,
            child_name: key_name,
            child_guid: CHILD_GUID,
            flags: 0,
            caller_has_tcb_or_admin: false,
        },
    )
    .unwrap();
    let path_plan = validate_path_entry_write_request(
        &limits,
        &PathEntryWriteRequest {
            parent_guid: PARENT_GUID,
            child_name: path_child,
            layer: "Ba\u{017F}e",
            sequence: 11,
            target: PathTarget::Guid(CHILD_GUID),
        },
    )
    .unwrap();
    let value_plan = validate_value_write_request(
        &limits,
        &ValueWriteRequest {
            key_guid: KEY_GUID,
            name: value_name,
            layer: "Policy",
            sequence: 12,
            value_type: REG_SZ,
            data: b"value",
            explicit_tombstone_operation: false,
            expected_sequence: None,
        },
    )
    .unwrap();

    assert_eq!(key_plan.name, key_name);
    assert_eq!(path_plan.child_name, path_child);
    assert_eq!(path_plan.layer, "Ba\u{017F}e");
    assert_eq!(value_plan.name, value_name);
}

#[test]
fn folded_value_enumeration_returns_winning_original_spelling() {
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
    let context = layer_context(&layers, &limits);
    let entries = [
        NamedValueEntry {
            name: "Micro-\u{00B5}",
            entry: ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_SZ,
                data: b"base",
            },
        },
        NamedValueEntry {
            name: "micro-\u{03BC}",
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
    .unwrap();

    assert_eq!(count, 1);
    assert_eq!(values[0].name, "micro-\u{03BC}");
    assert!(casefold_eq(values[0].name, "Micro-\u{00B5}"));
    assert_eq!(values[0].value.data, b"policy");
}

#[test]
fn folded_subkey_enumeration_returns_winning_original_spelling() {
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
    let context = layer_context(&layers, &limits);
    let entries = [
        NamedPathEntry {
            child_name: "\u{039A}ey",
            entry: PathEntry {
                layer: "base",
                sequence: 1,
                target: PathTarget::Guid(KEY_GUID),
            },
        },
        NamedPathEntry {
            child_name: "\u{03BA}EY",
            entry: PathEntry {
                layer: "policy",
                sequence: 2,
                target: PathTarget::Guid(VISIBLE_GUID),
            },
        },
    ];
    let mut subkeys = Vec::<EnumeratedSubkey<'_>>::new();

    let count = for_each_visible_subkey(&context, &entries, |subkey| {
        subkeys.push(subkey);
        Ok(())
    })
    .unwrap();

    assert_eq!(count, 1);
    assert_eq!(subkeys[0].child_name, "\u{03BA}EY");
    assert!(casefold_eq(subkeys[0].child_name, "\u{039A}ey"));
    assert_eq!(subkeys[0].path.guid, VISIBLE_GUID);
}
