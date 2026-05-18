use lcs_core::{
    BlanketTombstoneEntry, Guid, LayerResolutionContext, LayerView, LcsError, LcsLimits, PathEntry,
    PathResolution, PathTarget, REG_DWORD, REG_SZ, REG_TOMBSTONE, RegistryValueType, ValueEntry,
    ValueResolution, resolve_path_entry, resolve_value,
};

const GUID_LOW: Guid = [0x11; 16];
const GUID_HIGH: Guid = [0x22; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

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
fn path_resolution_selects_highest_precedence_then_highest_sequence() {
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
        PathEntry {
            layer: "base",
            sequence: 90,
            target: PathTarget::Guid(GUID_LOW),
        },
        PathEntry {
            layer: "policy",
            sequence: 1,
            target: PathTarget::Guid(GUID_HIGH),
        },
        PathEntry {
            layer: "base",
            sequence: 95,
            target: PathTarget::Guid([0x33; 16]),
        },
    ];

    let resolved = resolve_path_entry(&context, &entries).expect("path resolution should succeed");

    assert_eq!(
        resolved,
        PathResolution::Found(lcs_core::ResolvedPathEntry {
            guid: GUID_HIGH,
            layer: "policy",
            precedence: 10,
            sequence: 1,
        })
    );
}

#[test]
fn path_resolution_treats_hidden_winner_as_not_found() {
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
        PathEntry {
            layer: "base",
            sequence: 90,
            target: PathTarget::Guid(GUID_LOW),
        },
        PathEntry {
            layer: "policy",
            sequence: 91,
            target: PathTarget::Hidden,
        },
    ];

    assert_eq!(
        resolve_path_entry(&context, &entries),
        Ok(PathResolution::NotFound)
    );
}

#[test]
fn disabled_layers_are_ignored_unless_attached_as_private_layers() {
    let limits = limits();
    let layers = [
        LayerView {
            name: "base",
            precedence: 0,
            enabled: true,
        },
        LayerView {
            name: "PrivateΚ", // Greek kappa exercises Unicode folded lookup.
            precedence: 5,
            enabled: false,
        },
    ];
    let entries = [
        PathEntry {
            layer: "base",
            sequence: 1,
            target: PathTarget::Guid(GUID_LOW),
        },
        PathEntry {
            layer: "privateκ",
            sequence: 2,
            target: PathTarget::Guid(GUID_HIGH),
        },
    ];

    let no_private = context(&layers, &[], &limits);
    assert_eq!(
        resolve_path_entry(&no_private, &entries),
        Ok(PathResolution::Found(lcs_core::ResolvedPathEntry {
            guid: GUID_LOW,
            layer: "base",
            precedence: 0,
            sequence: 1,
        }))
    );

    let private_names = ["PRIVATEκ"];
    let with_private = context(&layers, &private_names, &limits);
    assert_eq!(
        resolve_path_entry(&with_private, &entries),
        Ok(PathResolution::Found(lcs_core::ResolvedPathEntry {
            guid: GUID_HIGH,
            layer: "PrivateΚ",
            precedence: 5,
            sequence: 2,
        }))
    );
}

#[test]
fn unknown_well_formed_layers_are_latent_and_ignored() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &[], &limits);
    let entries = [
        PathEntry {
            layer: "future-layer",
            sequence: 90,
            target: PathTarget::Guid(GUID_HIGH),
        },
        PathEntry {
            layer: "base",
            sequence: 1,
            target: PathTarget::Guid(GUID_LOW),
        },
    ];

    assert_eq!(
        resolve_path_entry(&context, &entries),
        Ok(PathResolution::Found(lcs_core::ResolvedPathEntry {
            guid: GUID_LOW,
            layer: "base",
            precedence: 0,
            sequence: 1,
        }))
    );
}

#[test]
fn malformed_layer_names_and_future_sequences_fail_closed() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &[], &limits);

    assert_eq!(
        resolve_path_entry(
            &context,
            &[PathEntry {
                layer: "bad/name",
                sequence: 1,
                target: PathTarget::Guid(GUID_LOW),
            }],
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );

    assert_eq!(
        resolve_path_entry(
            &context,
            &[PathEntry {
                layer: "base",
                sequence: 100,
                target: PathTarget::Guid(GUID_LOW),
            }],
        ),
        Err(LcsError::FutureSequence {
            sequence: 100,
            next_sequence: 100,
        })
    );
}

#[test]
fn duplicate_winning_tuple_fails_but_lower_duplicate_ties_do_not() {
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
        LayerView {
            name: "policy",
            precedence: 10,
            enabled: true,
        },
    ];
    let context = context(&layers, &[], &limits);

    let lower_duplicate_with_higher_winner = [
        PathEntry {
            layer: "base",
            sequence: 5,
            target: PathTarget::Guid(GUID_LOW),
        },
        PathEntry {
            layer: "role-a",
            sequence: 5,
            target: PathTarget::Hidden,
        },
        PathEntry {
            layer: "policy",
            sequence: 1,
            target: PathTarget::Guid(GUID_HIGH),
        },
    ];
    assert_eq!(
        resolve_path_entry(&context, &lower_duplicate_with_higher_winner),
        Ok(PathResolution::Found(lcs_core::ResolvedPathEntry {
            guid: GUID_HIGH,
            layer: "policy",
            precedence: 10,
            sequence: 1,
        }))
    );

    let winning_duplicate = [
        PathEntry {
            layer: "base",
            sequence: 5,
            target: PathTarget::Guid(GUID_LOW),
        },
        PathEntry {
            layer: "role-a",
            sequence: 5,
            target: PathTarget::Hidden,
        },
    ];
    assert_eq!(
        resolve_path_entry(&context, &winning_duplicate),
        Err(LcsError::DuplicateWinningSequenceTie {
            precedence: 0,
            sequence: 5,
        })
    );
}

#[test]
fn duplicate_folded_layer_table_identity_fails_closed() {
    let limits = limits();
    let layers = [
        LayerView {
            name: "RoleA",
            precedence: 0,
            enabled: true,
        },
        LayerView {
            name: "rolea",
            precedence: 1,
            enabled: true,
        },
    ];
    let context = context(&layers, &[], &limits);

    assert_eq!(
        resolve_path_entry(
            &context,
            &[PathEntry {
                layer: "ROLEA",
                sequence: 1,
                target: PathTarget::Guid(GUID_LOW),
            }],
        ),
        Err(LcsError::DuplicateLayerIdentity)
    );
}

#[test]
fn value_resolution_handles_entries_per_value_and_blanket_tombstones() {
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

    assert_eq!(
        resolve_value(
            &context,
            &[ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_SZ,
                data: b"lower",
            }],
            &[BlanketTombstoneEntry {
                layer: "policy",
                sequence: 2,
            }],
        ),
        Ok(ValueResolution::NotFound)
    );

    assert_eq!(
        resolve_value(
            &context,
            &[
                ValueEntry {
                    layer: "base",
                    sequence: 1,
                    value_type: REG_SZ,
                    data: b"lower",
                },
                ValueEntry {
                    layer: "policy",
                    sequence: 3,
                    value_type: REG_DWORD,
                    data: &[1, 0, 0, 0],
                },
            ],
            &[BlanketTombstoneEntry {
                layer: "policy",
                sequence: 2,
            }],
        ),
        Ok(ValueResolution::Found(lcs_core::ResolvedValueEntry {
            value_type: RegistryValueType::Dword,
            data: &[1, 0, 0, 0],
            layer: "policy",
            precedence: 10,
            sequence: 3,
        }))
    );
}

#[test]
fn value_resolution_treats_per_value_tombstone_as_not_found() {
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
            sequence: 1,
            value_type: REG_SZ,
            data: b"lower",
        },
        ValueEntry {
            layer: "policy",
            sequence: 2,
            value_type: REG_TOMBSTONE,
            data: &[],
        },
    ];

    assert_eq!(
        resolve_value(&context, &entries, &[]),
        Ok(ValueResolution::NotFound)
    );
}

#[test]
fn value_resolution_rejects_invalid_source_value_payloads() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &[], &limits);

    assert_eq!(
        resolve_value(
            &context,
            &[ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: 12,
                data: &[],
            }],
            &[],
        ),
        Err(LcsError::UnknownValueType(12))
    );

    assert_eq!(
        resolve_value(
            &context,
            &[ValueEntry {
                layer: "base",
                sequence: 1,
                value_type: REG_TOMBSTONE,
                data: b"not-empty",
            }],
            &[],
        ),
        Err(LcsError::TombstoneDataMustBeEmpty { len: 9 })
    );
}
