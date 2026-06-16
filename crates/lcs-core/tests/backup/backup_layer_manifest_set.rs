use crate::common::{limits, system_sid};
use lcs_core::{
    BackupLayerManifestPayload, BackupLayerManifestSetSummary, LcsError,
    validate_backup_layer_manifest_set,
};



fn manifest<'a>(
    name: &'a str,
    precedence: u32,
    enabled: bool,
    owner_sid: &'a [u8],
) -> BackupLayerManifestPayload<'a> {
    BackupLayerManifestPayload {
        name,
        precedence,
        enabled,
        owner_sid,
    }
}

#[test]
fn backup_layer_manifest_set_accepts_unique_manifests_and_all_references() {
    let owner = system_sid();
    let manifests = [
        manifest("base", 0, true, &owner),
        manifest("role-web", 10, true, &owner),
        manifest("staging", 0, false, &owner),
    ];
    let referenced_layers = ["BASE", "Role-Web", "staging", "role-web"];

    assert_eq!(
        validate_backup_layer_manifest_set(&limits(), &manifests, &referenced_layers),
        Ok(BackupLayerManifestSetSummary {
            manifest_count: 3,
            referenced_layer_count: 4,
        })
    );
}

#[test]
fn backup_layer_manifest_set_rejects_duplicate_folded_manifest_identities() {
    let owner = system_sid();
    let manifests = [
        manifest("role-web", 10, true, &owner),
        manifest("ROLE-WEB", 0, false, &owner),
    ];

    assert_eq!(
        validate_backup_layer_manifest_set(&limits(), &manifests, &[]),
        Err(LcsError::DuplicateBackupLayerManifest)
    );
}

#[test]
fn backup_layer_manifest_set_rejects_missing_referenced_manifest() {
    let owner = system_sid();
    let manifests = [manifest("base", 0, true, &owner)];
    let referenced_layers = ["base", "missing"];

    assert_eq!(
        validate_backup_layer_manifest_set(&limits(), &manifests, &referenced_layers),
        Err(LcsError::MissingBackupLayerManifest)
    );
}

#[test]
fn backup_layer_manifest_set_revalidates_manifest_and_reference_shapes() {
    let owner = system_sid();
    let bad_manifest = [manifest("bad/layer", 0, true, &owner)];
    assert_eq!(
        validate_backup_layer_manifest_set(&limits(), &bad_manifest, &[]),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );

    let bad_reference = [manifest("base", 0, true, &owner)];
    assert_eq!(
        validate_backup_layer_manifest_set(&limits(), &bad_reference, &["bad/layer"]),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}

#[test]
fn backup_layer_manifest_set_revalidates_owner_sids() {
    let manifests = [manifest("base", 0, true, b"not-a-sid")];

    assert_eq!(
        validate_backup_layer_manifest_set(&limits(), &manifests, &[]),
        Err(LcsError::MalformedBackupSid {
            field: "backup_layer.owner",
        })
    );
}
