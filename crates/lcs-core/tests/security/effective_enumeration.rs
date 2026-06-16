use crate::common::{limits};
use lcs_core::{
    BlanketTombstoneEntry, EnumeratedSubkey, EnumeratedValue, Guid, LayerResolutionContext,
    LayerView, LcsError, LcsLimits, NamedPathEntry, NamedValueEntry, PathEntry, PathTarget,
    REG_DWORD, REG_SZ, RegistryValueType, ValueEntry, for_each_effective_value,
    for_each_visible_subkey,
};

const GUID_LOW: Guid = [0x11; 16];
const GUID_HIGH: Guid = [0x22; 16];
const GUID_VISIBLE: Guid = [0x33; 16];


fn context<'a>(
    layers: &'a [LayerView<'a>],
    private_layers: &'a [&'a str],
    limits: &'a LcsLimits,
) -> LayerResolutionContext<'a> {
    LayerResolutionContext {
        layers,
        private_layers,
        limits,
        next_sequence: 100,
    }
}

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
fn value_enumeration_groups_folded_names_and_returns_winning_spelling() {
    let limits = limits();
    let layers = base_policy_layers();
    let context = context(&layers, &[], &limits);
    let entries = [
        NamedValueEntry {
            name: "Setting",
            entry: ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_SZ,
                data: b"base",
            },
        },
        NamedValueEntry {
            name: "SETTING",
            entry: ValueEntry {
                layer: "policy",
                sequence: 2,
                value_type: REG_DWORD,
                data: &[1, 0, 0, 0],
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
    assert_eq!(values[0].value.value_type, RegistryValueType::Dword);
    assert_eq!(values[0].value.data, &[1, 0, 0, 0]);
    assert_eq!(values[0].value.layer, "policy");
    assert_eq!(values[0].value.precedence, 10);
    assert_eq!(values[0].value.sequence, 2);
}

#[test]
fn blanket_tombstone_masks_lower_values_during_enumeration() {
    let limits = limits();
    let layers = base_policy_layers();
    let context = context(&layers, &[], &limits);
    let entries = [
        NamedValueEntry {
            name: "Masked",
            entry: ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_SZ,
                data: b"masked",
            },
        },
        NamedValueEntry {
            name: "Specific",
            entry: ValueEntry {
                layer: "base",
                sequence: 2,
                value_type: REG_SZ,
                data: b"lower",
            },
        },
        NamedValueEntry {
            name: "Specific",
            entry: ValueEntry {
                layer: "policy",
                sequence: 11,
                value_type: REG_SZ,
                data: b"visible",
            },
        },
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
    .expect("value enumeration should succeed");

    assert_eq!(count, 1);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name, "Specific");
    assert_eq!(values[0].value.data, b"visible");
    assert_eq!(values[0].value.layer, "policy");
    assert_eq!(values[0].value.sequence, 11);
}

#[test]
fn value_enumeration_ignores_unknown_well_formed_layers() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &[], &limits);
    let entries = [NamedValueEntry {
        name: "Future",
        entry: ValueEntry {
            layer: "future-layer",
            sequence: 1,
            value_type: REG_SZ,
            data: b"latent",
        },
    }];
    let mut values = Vec::<EnumeratedValue<'_>>::new();

    let count = for_each_effective_value(&context, &entries, &[], |value| {
        values.push(value);
        Ok(())
    })
    .expect("unknown layers should be latent");

    assert_eq!(count, 0);
    assert!(values.is_empty());
}

#[test]
fn value_enumeration_fails_closed_on_malformed_names_duplicate_winners_and_payloads() {
    let limits = limits();
    let layers = [
        LayerView {
            name: "base",
            precedence: 0,
            enabled: true,
        },
        LayerView {
            name: "role-a",
            precedence: 0,
            enabled: true,
        },
    ];
    let context = context(&layers, &[], &limits);
    let malformed_name = [NamedValueEntry {
        name: "bad\0name",
        entry: ValueEntry {
            layer: "base",
            sequence: 1,
            value_type: REG_SZ,
            data: b"value",
        },
    }];
    assert_eq!(
        for_each_effective_value(&context, &malformed_name, &[], |_| Ok(())),
        Err(LcsError::NullByte {
            field: "value_name",
        })
    );

    let duplicate_winners = [
        NamedValueEntry {
            name: "Setting",
            entry: ValueEntry {
                layer: "base",
                sequence: 5,
                value_type: REG_SZ,
                data: b"base",
            },
        },
        NamedValueEntry {
            name: "SETTING",
            entry: ValueEntry {
                layer: "role-a",
                sequence: 5,
                value_type: REG_SZ,
                data: b"role",
            },
        },
    ];
    assert_eq!(
        for_each_effective_value(&context, &duplicate_winners, &[], |_| Ok(())),
        Err(LcsError::DuplicateWinningSequenceTie {
            precedence: 0,
            sequence: 5,
        })
    );

    let invalid_payload = [NamedValueEntry {
        name: "BadType",
        entry: ValueEntry {
            layer: "base",
            sequence: 1,
            value_type: 12,
            data: b"",
        },
    }];
    assert_eq!(
        for_each_effective_value(&context, &invalid_payload, &[], |_| Ok(())),
        Err(LcsError::UnknownValueType(12))
    );

    let malformed_after_visible = [
        NamedValueEntry {
            name: "Visible",
            entry: ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_SZ,
                data: b"value",
            },
        },
        NamedValueEntry {
            name: "bad\0name",
            entry: ValueEntry {
                layer: "base",
                sequence: 2,
                value_type: REG_SZ,
                data: b"bad",
            },
        },
    ];
    let mut callback_called = false;
    assert_eq!(
        for_each_effective_value(&context, &malformed_after_visible, &[], |_| {
            callback_called = true;
            Ok(())
        }),
        Err(LcsError::NullByte {
            field: "value_name",
        })
    );
    assert!(!callback_called);
}

#[test]
fn subkey_enumeration_groups_folded_names_and_returns_winning_spelling() {
    let limits = limits();
    let layers = base_policy_layers();
    let context = context(&layers, &[], &limits);
    let entries = [
        NamedPathEntry {
            child_name: "Service",
            entry: PathEntry {
                layer: "base",
                sequence: 1,
                target: PathTarget::Guid(GUID_LOW),
            },
        },
        NamedPathEntry {
            child_name: "SERVICE",
            entry: PathEntry {
                layer: "policy",
                sequence: 2,
                target: PathTarget::Guid(GUID_HIGH),
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
    assert_eq!(subkeys[0].path.guid, GUID_HIGH);
    assert_eq!(subkeys[0].path.layer, "policy");
    assert_eq!(subkeys[0].path.precedence, 10);
    assert_eq!(subkeys[0].path.sequence, 2);
}

#[test]
fn subkey_enumeration_omits_hidden_winners() {
    let limits = limits();
    let layers = base_policy_layers();
    let context = context(&layers, &[], &limits);
    let entries = [
        NamedPathEntry {
            child_name: "Child",
            entry: PathEntry {
                layer: "base",
                sequence: 1,
                target: PathTarget::Guid(GUID_LOW),
            },
        },
        NamedPathEntry {
            child_name: "child",
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
                target: PathTarget::Guid(GUID_VISIBLE),
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
    assert_eq!(subkeys[0].path.guid, GUID_VISIBLE);
}

#[test]
fn subkey_enumeration_fails_closed_on_malformed_names_and_duplicate_winners() {
    let limits = limits();
    let layers = [
        LayerView {
            name: "base",
            precedence: 0,
            enabled: true,
        },
        LayerView {
            name: "role-a",
            precedence: 0,
            enabled: true,
        },
    ];
    let context = context(&layers, &[], &limits);
    let malformed_name = [NamedPathEntry {
        child_name: "bad/name",
        entry: PathEntry {
            layer: "base",
            sequence: 1,
            target: PathTarget::Guid(GUID_LOW),
        },
    }];
    assert_eq!(
        for_each_visible_subkey(&context, &malformed_name, |_| Ok(())),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );

    let duplicate_winners = [
        NamedPathEntry {
            child_name: "Child",
            entry: PathEntry {
                layer: "base",
                sequence: 5,
                target: PathTarget::Guid(GUID_LOW),
            },
        },
        NamedPathEntry {
            child_name: "child",
            entry: PathEntry {
                layer: "role-a",
                sequence: 5,
                target: PathTarget::Guid(GUID_HIGH),
            },
        },
    ];
    assert_eq!(
        for_each_visible_subkey(&context, &duplicate_winners, |_| Ok(())),
        Err(LcsError::DuplicateWinningSequenceTie {
            precedence: 0,
            sequence: 5,
        })
    );

    let malformed_after_visible = [
        NamedPathEntry {
            child_name: "Visible",
            entry: PathEntry {
                layer: "base",
                sequence: 1,
                target: PathTarget::Guid(GUID_VISIBLE),
            },
        },
        NamedPathEntry {
            child_name: "bad/name",
            entry: PathEntry {
                layer: "base",
                sequence: 2,
                target: PathTarget::Guid(GUID_LOW),
            },
        },
    ];
    let mut callback_called = false;
    assert_eq!(
        for_each_visible_subkey(&context, &malformed_after_visible, |_| {
            callback_called = true;
            Ok(())
        }),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
    assert!(!callback_called);
}
