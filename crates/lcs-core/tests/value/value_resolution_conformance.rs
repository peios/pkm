use crate::common::{limits};
use lcs_core::{
    BlanketTombstoneEntry, LayerResolutionContext, LayerView, LcsLimits, REG_DWORD, REG_SZ,
    REG_TOMBSTONE, RegistryValueType, ValueEntry, ValueResolution, resolve_value,
};


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

#[test]
fn value_resolution_discards_unknown_and_inactive_layers() {
    let limits = limits();
    let layers = [
        LayerView {
            name: "base",
            precedence: 0,
            enabled: true,
        },
        LayerView {
            name: "disabled",
            precedence: 100,
            enabled: false,
        },
    ];
    let context = context(&layers, &[], &limits);
    let entries = [
        ValueEntry {
            layer: "unknown",
            sequence: 99,
            value_type: REG_SZ,
            data: b"unknown",
        },
        ValueEntry {
            layer: "disabled",
            sequence: 98,
            value_type: REG_SZ,
            data: b"inactive",
        },
        ValueEntry {
            layer: "base",
            sequence: 1,
            value_type: REG_SZ,
            data: b"base",
        },
    ];

    assert_eq!(
        resolve_value(&context, &entries, &[]),
        Ok(ValueResolution::Found(lcs_core::ResolvedValueEntry {
            value_type: RegistryValueType::Sz,
            data: b"base",
            layer: "base",
            precedence: 0,
            sequence: 1,
        }))
    );
}

#[test]
fn private_layer_membership_activates_disabled_value_layer() {
    let limits = limits();
    let layers = [
        LayerView {
            name: "base",
            precedence: 0,
            enabled: true,
        },
        LayerView {
            name: "private",
            precedence: 10,
            enabled: false,
        },
    ];
    let private_layers = ["PRIVATE"];
    let context = context(&layers, &private_layers, &limits);
    let entries = [
        ValueEntry {
            layer: "base",
            sequence: 90,
            value_type: REG_SZ,
            data: b"base",
        },
        ValueEntry {
            layer: "private",
            sequence: 1,
            value_type: REG_SZ,
            data: b"private",
        },
    ];

    assert_eq!(
        resolve_value(&context, &entries, &[]),
        Ok(ValueResolution::Found(lcs_core::ResolvedValueEntry {
            value_type: RegistryValueType::Sz,
            data: b"private",
            layer: "private",
            precedence: 10,
            sequence: 1,
        }))
    );
}

#[test]
fn value_resolution_prefers_highest_precedence_before_highest_sequence() {
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
    let context = context(&layers, &[], &limits);
    let entries = [
        ValueEntry {
            layer: "base",
            sequence: 99,
            value_type: REG_DWORD,
            data: b"base-newer-sequence",
        },
        ValueEntry {
            layer: "policy",
            sequence: 1,
            value_type: REG_SZ,
            data: b"policy-higher-precedence",
        },
    ];

    assert_eq!(
        resolve_value(&context, &entries, &[]),
        Ok(ValueResolution::Found(lcs_core::ResolvedValueEntry {
            value_type: RegistryValueType::Sz,
            data: b"policy-higher-precedence",
            layer: "policy",
            precedence: 10,
            sequence: 1,
        }))
    );
}

#[test]
fn value_resolution_prefers_highest_sequence_within_precedence() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &[], &limits);
    let entries = [
        ValueEntry {
            layer: "base",
            sequence: 1,
            value_type: REG_SZ,
            data: b"old",
        },
        ValueEntry {
            layer: "base",
            sequence: 2,
            value_type: REG_SZ,
            data: b"new",
        },
    ];

    assert_eq!(
        resolve_value(&context, &entries, &[]),
        Ok(ValueResolution::Found(lcs_core::ResolvedValueEntry {
            value_type: RegistryValueType::Sz,
            data: b"new",
            layer: "base",
            precedence: 0,
            sequence: 2,
        }))
    );
}

#[test]
fn blanket_tombstone_winner_masks_lower_precedence_value() {
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
    let context = context(&layers, &[], &limits);
    let entries = [ValueEntry {
        layer: "base",
        sequence: 99,
        value_type: REG_SZ,
        data: b"base",
    }];
    let blankets = [BlanketTombstoneEntry {
        layer: "policy",
        sequence: 1,
    }];

    assert_eq!(
        resolve_value(&context, &entries, &blankets),
        Ok(ValueResolution::NotFound)
    );
}

#[test]
fn per_value_tombstone_winner_resolves_not_found() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &[], &limits);
    let entries = [ValueEntry {
        layer: "base",
        sequence: 1,
        value_type: REG_TOMBSTONE,
        data: b"",
    }];

    assert_eq!(
        resolve_value(&context, &entries, &[]),
        Ok(ValueResolution::NotFound)
    );
}
