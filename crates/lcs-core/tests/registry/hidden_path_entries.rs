use lcs_core::{
    BASE_LAYER_VIEW, Guid, LayerResolutionContext, LayerView, LcsLimits, NamedPathEntry,
    NamedPathResolution, PathEntry, PathResolution, PathTarget, ResolvedNamedPathEntry,
    ResolvedPathEntry, resolve_named_path_entry, resolve_path_entry,
};

const BASE_GUID: Guid = [0x21; 16];
const ROLE_GUID: Guid = [0x22; 16];
const POLICY_GUID: Guid = [0x23; 16];

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
fn hidden_path_entry_masks_lower_precedence_guid_entry() {
    let limits = limits();
    let layers = [
        BASE_LAYER_VIEW,
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
            target: PathTarget::Guid(BASE_GUID),
        },
        PathEntry {
            layer: "policy",
            sequence: 1,
            target: PathTarget::Hidden,
        },
    ];

    assert_eq!(
        resolve_path_entry(&context, &entries),
        Ok(PathResolution::NotFound)
    );
}

#[test]
fn same_precedence_hidden_and_guid_entries_use_sequence_tiebreaking() {
    let limits = limits();
    let layers = [
        BASE_LAYER_VIEW,
        LayerView {
            name: "role",
            precedence: 0,
            enabled: true,
        },
    ];
    let context = context(&layers, &[], &limits);
    let hidden_is_newer = [
        PathEntry {
            layer: "base",
            sequence: 10,
            target: PathTarget::Guid(BASE_GUID),
        },
        PathEntry {
            layer: "role",
            sequence: 11,
            target: PathTarget::Hidden,
        },
    ];
    let guid_is_newer = [
        PathEntry {
            layer: "base",
            sequence: 12,
            target: PathTarget::Guid(ROLE_GUID),
        },
        PathEntry {
            layer: "role",
            sequence: 11,
            target: PathTarget::Hidden,
        },
    ];

    assert_eq!(
        resolve_path_entry(&context, &hidden_is_newer),
        Ok(PathResolution::NotFound)
    );
    assert_eq!(
        resolve_path_entry(&context, &guid_is_newer),
        Ok(PathResolution::Found(ResolvedPathEntry {
            guid: ROLE_GUID,
            layer: "base",
            precedence: 0,
            sequence: 12,
        }))
    );
}

#[test]
fn named_lookup_applies_hidden_sequence_tiebreak_after_casefolding() {
    let limits = limits();
    let layers = [
        BASE_LAYER_VIEW,
        LayerView {
            name: "role",
            precedence: 0,
            enabled: true,
        },
    ];
    let context = context(&layers, &[], &limits);
    let entries = [
        NamedPathEntry {
            child_name: "Service",
            entry: PathEntry {
                layer: "base",
                sequence: 8,
                target: PathTarget::Hidden,
            },
        },
        NamedPathEntry {
            child_name: "service",
            entry: PathEntry {
                layer: "role",
                sequence: 9,
                target: PathTarget::Guid(POLICY_GUID),
            },
        },
    ];

    assert_eq!(
        resolve_named_path_entry(&context, "SERVICE", &entries),
        Ok(NamedPathResolution::Found(ResolvedNamedPathEntry {
            child_name: "service",
            path: ResolvedPathEntry {
                guid: POLICY_GUID,
                layer: "role",
                precedence: 0,
                sequence: 9,
            },
        }))
    );
}
