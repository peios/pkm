use lcs_core::{
    BASE_LAYER_VIEW, Guid, LayerResolutionContext, LcsError, LcsLimits, NamedPathEntry,
    NamedPathResolution, PathEntry, PathTarget, ResolvedNamedPathEntry, ResolvedPathEntry,
    resolve_named_path_entry,
};

const BASE_GUID: Guid = [0x31; 16];
const POLICY_GUID: Guid = [0x32; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn context<'a>(
    layers: &'a [lcs_core::LayerView<'a>],
    limits: &'a LcsLimits,
) -> LayerResolutionContext<'a> {
    LayerResolutionContext {
        layers,
        private_layers: &[],
        limits,
        next_sequence: 100,
    }
}

#[test]
fn key_lookup_uses_unicode_simple_casefold_and_returns_winning_spelling() {
    let limits = limits();
    let layers = [
        BASE_LAYER_VIEW,
        lcs_core::LayerView {
            name: "policy",
            precedence: 10,
            enabled: true,
        },
    ];
    let context = context(&layers, &limits);
    let entries = [
        NamedPathEntry {
            child_name: "\u{212A}ey",
            entry: PathEntry {
                layer: "base",
                sequence: 1,
                target: PathTarget::Guid(BASE_GUID),
            },
        },
        NamedPathEntry {
            child_name: "key",
            entry: PathEntry {
                layer: "policy",
                sequence: 2,
                target: PathTarget::Guid(POLICY_GUID),
            },
        },
    ];

    assert_eq!(
        resolve_named_path_entry(&context, "KEY", &entries),
        Ok(NamedPathResolution::Found(ResolvedNamedPathEntry {
            child_name: "key",
            path: ResolvedPathEntry {
                guid: POLICY_GUID,
                layer: "policy",
                precedence: 10,
                sequence: 2,
            },
        }))
    );
}

#[test]
fn key_lookup_does_not_perform_unicode_normalization() {
    let limits = limits();
    let layers = [BASE_LAYER_VIEW];
    let context = context(&layers, &limits);
    let entries = [NamedPathEntry {
        child_name: "e\u{0301}",
        entry: PathEntry {
            layer: "base",
            sequence: 1,
            target: PathTarget::Guid(BASE_GUID),
        },
    }];

    assert_eq!(
        resolve_named_path_entry(&context, "\u{00E9}", &entries),
        Ok(NamedPathResolution::NotFound)
    );
}

#[test]
fn key_lookup_hidden_winner_masks_lower_visible_entry() {
    let limits = limits();
    let layers = [
        BASE_LAYER_VIEW,
        lcs_core::LayerView {
            name: "policy",
            precedence: 10,
            enabled: true,
        },
    ];
    let context = context(&layers, &limits);
    let entries = [
        NamedPathEntry {
            child_name: "Service",
            entry: PathEntry {
                layer: "base",
                sequence: 1,
                target: PathTarget::Guid(BASE_GUID),
            },
        },
        NamedPathEntry {
            child_name: "service",
            entry: PathEntry {
                layer: "policy",
                sequence: 2,
                target: PathTarget::Hidden,
            },
        },
    ];

    assert_eq!(
        resolve_named_path_entry(&context, "SERVICE", &entries),
        Ok(NamedPathResolution::NotFound)
    );
}

#[test]
fn key_lookup_fails_closed_on_malformed_source_names() {
    let limits = limits();
    let layers = [BASE_LAYER_VIEW];
    let context = context(&layers, &limits);
    let entries = [
        NamedPathEntry {
            child_name: "Wanted",
            entry: PathEntry {
                layer: "base",
                sequence: 1,
                target: PathTarget::Guid(BASE_GUID),
            },
        },
        NamedPathEntry {
            child_name: "Bad/Name",
            entry: PathEntry {
                layer: "base",
                sequence: 2,
                target: PathTarget::Guid(POLICY_GUID),
            },
        },
    ];

    assert_eq!(
        resolve_named_path_entry(&context, "wanted", &entries),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
}
