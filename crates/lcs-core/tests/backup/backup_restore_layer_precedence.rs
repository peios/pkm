use lcs_core::{
    BASE_LAYER_VIEW, BackupLayerManifestPayload, BackupRestoreLayerPrecedencePlan, LayerView,
    LcsError, LcsLimits, plan_backup_restore_layer_precedence_gate,
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
    owner_sid: &'a [u8],
) -> BackupLayerManifestPayload<'a> {
    BackupLayerManifestPayload {
        name,
        precedence,
        enabled: true,
        owner_sid,
    }
}

fn existing_layer(name: &'static str, precedence: u32) -> LayerView<'static> {
    LayerView {
        name,
        precedence,
        enabled: true,
    }
}

#[test]
fn restore_layer_precedence_gate_allows_low_precedence_without_tcb() {
    let owner = system_sid();
    let manifests = [manifest("role-web", 0, &owner)];
    let existing = [BASE_LAYER_VIEW, existing_layer("role-web", 0)];

    assert_eq!(
        plan_backup_restore_layer_precedence_gate(&limits(), &manifests, &existing, false),
        Ok(BackupRestoreLayerPrecedencePlan {
            tcb_required_for_precedence: false,
        })
    );
}

#[test]
fn restore_layer_precedence_gate_rejects_declared_high_precedence_without_tcb() {
    let owner = system_sid();
    let manifests = [manifest("role-web", 1, &owner)];
    let existing = [BASE_LAYER_VIEW, existing_layer("role-web", 0)];

    assert_eq!(
        plan_backup_restore_layer_precedence_gate(&limits(), &manifests, &existing, false),
        Err(LcsError::MissingLayerPrecedenceTcb)
    );
    assert_eq!(
        plan_backup_restore_layer_precedence_gate(&limits(), &manifests, &existing, true),
        Ok(BackupRestoreLayerPrecedencePlan {
            tcb_required_for_precedence: true,
        })
    );
}

#[test]
fn restore_layer_precedence_gate_rejects_existing_high_precedence_identity_without_tcb() {
    let owner = system_sid();
    let manifests = [manifest("role-web", 0, &owner)];
    let existing = [BASE_LAYER_VIEW, existing_layer("Role-Web", 7)];

    assert_eq!(
        plan_backup_restore_layer_precedence_gate(&limits(), &manifests, &existing, false),
        Err(LcsError::MissingLayerPrecedenceTcb)
    );
}

#[test]
fn restore_layer_precedence_gate_ignores_unreferenced_existing_high_precedence_layers() {
    let owner = system_sid();
    let manifests = [manifest("role-web", 0, &owner)];
    let existing = [BASE_LAYER_VIEW, existing_layer("different", 7)];

    assert_eq!(
        plan_backup_restore_layer_precedence_gate(&limits(), &manifests, &existing, false),
        Ok(BackupRestoreLayerPrecedencePlan {
            tcb_required_for_precedence: false,
        })
    );
}

#[test]
fn restore_layer_precedence_gate_validates_manifests_and_existing_layer_cache() {
    let owner = system_sid();
    let duplicate_manifests = [
        manifest("role-web", 0, &owner),
        manifest("ROLE-WEB", 0, &owner),
    ];
    assert_eq!(
        plan_backup_restore_layer_precedence_gate(
            &limits(),
            &duplicate_manifests,
            &[BASE_LAYER_VIEW],
            true,
        ),
        Err(LcsError::DuplicateBackupLayerManifest)
    );

    let manifests = [manifest("role-web", 0, &owner)];
    assert_eq!(
        plan_backup_restore_layer_precedence_gate(
            &limits(),
            &manifests,
            &[existing_layer("role-web", 0)],
            true,
        ),
        Err(LcsError::MissingBaseLayer)
    );
}
