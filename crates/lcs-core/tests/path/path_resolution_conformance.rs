use crate::common::{limits};
use lcs_core::{
    Guid, LayerResolutionContext, LayerView, LcsLimits, PathEntry, PathResolution, PathTarget,
    ResolvedPathEntry, resolve_path_entry,
};

const BASE_GUID: Guid = [0x11; 16];
const PRIVATE_GUID: Guid = [0x22; 16];
const POLICY_GUID: Guid = [0x33; 16];
const NEW_GUID: Guid = [0x44; 16];


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
fn path_resolution_discards_unknown_and_inactive_layers() {
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
        PathEntry {
            layer: "unknown",
            sequence: 99,
            target: PathTarget::Guid(POLICY_GUID),
        },
        PathEntry {
            layer: "disabled",
            sequence: 98,
            target: PathTarget::Guid(PRIVATE_GUID),
        },
        PathEntry {
            layer: "base",
            sequence: 1,
            target: PathTarget::Guid(BASE_GUID),
        },
    ];

    assert_eq!(
        resolve_path_entry(&context, &entries),
        Ok(PathResolution::Found(ResolvedPathEntry {
            guid: BASE_GUID,
            layer: "base",
            precedence: 0,
            sequence: 1,
        }))
    );
}

#[test]
fn private_layer_membership_activates_disabled_path_layer() {
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
        PathEntry {
            layer: "base",
            sequence: 90,
            target: PathTarget::Guid(BASE_GUID),
        },
        PathEntry {
            layer: "private",
            sequence: 1,
            target: PathTarget::Guid(PRIVATE_GUID),
        },
    ];

    assert_eq!(
        resolve_path_entry(&context, &entries),
        Ok(PathResolution::Found(ResolvedPathEntry {
            guid: PRIVATE_GUID,
            layer: "private",
            precedence: 10,
            sequence: 1,
        }))
    );
}

#[test]
fn path_resolution_prefers_highest_precedence_before_highest_sequence() {
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
            sequence: 99,
            target: PathTarget::Guid(BASE_GUID),
        },
        PathEntry {
            layer: "policy",
            sequence: 1,
            target: PathTarget::Guid(POLICY_GUID),
        },
    ];

    assert_eq!(
        resolve_path_entry(&context, &entries),
        Ok(PathResolution::Found(ResolvedPathEntry {
            guid: POLICY_GUID,
            layer: "policy",
            precedence: 10,
            sequence: 1,
        }))
    );
}

#[test]
fn path_resolution_prefers_highest_sequence_within_precedence() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let context = context(&layers, &[], &limits);
    let entries = [
        PathEntry {
            layer: "base",
            sequence: 1,
            target: PathTarget::Guid(BASE_GUID),
        },
        PathEntry {
            layer: "base",
            sequence: 2,
            target: PathTarget::Guid(NEW_GUID),
        },
    ];

    assert_eq!(
        resolve_path_entry(&context, &entries),
        Ok(PathResolution::Found(ResolvedPathEntry {
            guid: NEW_GUID,
            layer: "base",
            precedence: 0,
            sequence: 2,
        }))
    );
}

#[test]
fn hidden_winner_masks_lower_precedence_visible_path() {
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
            sequence: 99,
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
