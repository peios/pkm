use lcs_core::{
    BASE_LAYER_VIEW, Guid, LayerResolutionContext, LcsError, LcsLimits, NIL_GUID, PathEntry,
    PathEntryWriteRequest, PathResolution, PathTarget, ResolvedPathEntry, for_each_visible_subkey,
    resolve_path_entry, validate_path_entry_write_request, validate_path_target,
};

const PARENT_GUID: Guid = [0x10; 16];
const CHILD_GUID: Guid = [0x11; 16];
const OTHER_GUID: Guid = [0x12; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn context<'a>(limits: &'a LcsLimits) -> LayerResolutionContext<'a> {
    LayerResolutionContext {
        layers: &[BASE_LAYER_VIEW],
        private_layers: &[],
        limits,
        next_sequence: 100,
    }
}

#[test]
fn path_target_validation_accepts_guid_and_hidden_targets() {
    assert_eq!(
        validate_path_target(PathTarget::Guid(CHILD_GUID)),
        Ok(PathTarget::Guid(CHILD_GUID))
    );
    assert_eq!(
        validate_path_target(PathTarget::Hidden),
        Ok(PathTarget::Hidden)
    );
}

#[test]
fn path_target_validation_rejects_nil_guid_targets() {
    assert_eq!(
        validate_path_target(PathTarget::Guid(NIL_GUID)),
        Err(LcsError::NilKeyGuid)
    );
}

#[test]
fn path_entry_write_validation_accepts_guid_and_hidden_writes() {
    let limits = limits();
    let create = PathEntryWriteRequest {
        parent_guid: PARENT_GUID,
        child_name: "Software",
        layer: "base",
        sequence: 7,
        target: PathTarget::Guid(CHILD_GUID),
    };
    let hide = PathEntryWriteRequest {
        target: PathTarget::Hidden,
        ..create
    };

    assert_eq!(
        validate_path_entry_write_request(&limits, &create)
            .expect("GUID path-entry write should validate")
            .target,
        PathTarget::Guid(CHILD_GUID)
    );
    assert_eq!(
        validate_path_entry_write_request(&limits, &hide)
            .expect("HIDDEN path-entry write should validate")
            .target,
        PathTarget::Hidden
    );
}

#[test]
fn path_entry_write_validation_rejects_malformed_fields() {
    let limits = limits();
    let valid = PathEntryWriteRequest {
        parent_guid: PARENT_GUID,
        child_name: "Software",
        layer: "base",
        sequence: 7,
        target: PathTarget::Guid(CHILD_GUID),
    };

    assert_eq!(
        validate_path_entry_write_request(
            &limits,
            &PathEntryWriteRequest {
                parent_guid: NIL_GUID,
                ..valid
            },
        ),
        Err(LcsError::NilParentGuid)
    );
    assert_eq!(
        validate_path_entry_write_request(
            &limits,
            &PathEntryWriteRequest {
                child_name: "Bad/Name",
                ..valid
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
    assert_eq!(
        validate_path_entry_write_request(
            &limits,
            &PathEntryWriteRequest {
                layer: "Bad\\Layer",
                ..valid
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
    assert_eq!(
        validate_path_entry_write_request(
            &limits,
            &PathEntryWriteRequest {
                target: PathTarget::Guid(NIL_GUID),
                ..valid
            },
        ),
        Err(LcsError::NilKeyGuid)
    );
}

#[test]
fn path_resolution_rejects_active_nil_guid_targets() {
    let limits = limits();
    let context = context(&limits);
    let entries = [PathEntry {
        layer: "base",
        sequence: 1,
        target: PathTarget::Guid(NIL_GUID),
    }];

    assert_eq!(
        resolve_path_entry(&context, &entries),
        Err(LcsError::NilKeyGuid)
    );
}

#[test]
fn path_resolution_still_allows_hidden_and_valid_guid_targets() {
    let limits = limits();
    let context = context(&limits);
    let hidden = [PathEntry {
        layer: "base",
        sequence: 1,
        target: PathTarget::Hidden,
    }];
    let visible = [PathEntry {
        layer: "base",
        sequence: 2,
        target: PathTarget::Guid(OTHER_GUID),
    }];

    assert_eq!(
        resolve_path_entry(&context, &hidden),
        Ok(PathResolution::NotFound)
    );
    assert_eq!(
        resolve_path_entry(&context, &visible),
        Ok(PathResolution::Found(ResolvedPathEntry {
            guid: OTHER_GUID,
            layer: "base",
            precedence: 0,
            sequence: 2,
        }))
    );
}

#[test]
fn subkey_enumeration_rejects_active_nil_guid_targets() {
    let limits = limits();
    let context = context(&limits);
    let entries = [lcs_core::NamedPathEntry {
        child_name: "Software",
        entry: PathEntry {
            layer: "base",
            sequence: 1,
            target: PathTarget::Guid(NIL_GUID),
        },
    }];

    assert_eq!(
        for_each_visible_subkey(&context, &entries, |_| Ok(())),
        Err(LcsError::NilKeyGuid)
    );
}
