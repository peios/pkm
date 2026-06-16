use lcs_core::{
    BackupLayerManifestAuthorityPlan, BackupLayerManifestPayload, LcsError, LcsLimits,
    plan_backup_layer_manifest_authority,
};

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn system_sid() -> Vec<u8> {
    let mut sid = Vec::new();
    sid.push(1);
    sid.push(1);
    sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    sid.extend_from_slice(&18u32.to_le_bytes());
    sid
}

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
fn layer_manifest_is_restore_validation_only_not_authoritative_metadata() {
    let owner = system_sid();
    let plan =
        plan_backup_layer_manifest_authority(&limits(), manifest("role-web", 42, false, &owner))
            .unwrap();

    assert_eq!(
        plan,
        BackupLayerManifestAuthorityPlan {
            name: "role-web",
            precedence_for_validation: 42,
            enabled_for_validation: false,
            owner_sid_for_validation: &owner,
            creates_layer_metadata: false,
            updates_layer_metadata: false,
            deletes_layer_metadata: false,
            enables_or_disables_layer: false,
            authorizes_layer_metadata: false,
            ordinary_metadata_records_authoritative: true,
        }
    );
}

#[test]
fn layer_manifest_authority_plan_revalidates_manifest_identity_and_owner() {
    let owner = system_sid();
    assert_eq!(
        plan_backup_layer_manifest_authority(&limits(), manifest("bad/layer", 0, true, &owner)),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );

    assert_eq!(
        plan_backup_layer_manifest_authority(&limits(), manifest("role-web", 0, true, b"bad")),
        Err(LcsError::MalformedBackupSid {
            field: "backup_layer.owner",
        })
    );
}
