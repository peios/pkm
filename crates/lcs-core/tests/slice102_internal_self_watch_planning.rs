use lcs_core::{
    Guid, InternalSelfWatchPlan, InternalSelfWatchRoots, InternalWatchRegistration,
    InternalWatchTarget, LcsError, plan_internal_self_watch,
};

const MACHINE_ROOT: Guid = [0x10; 16];
const REGISTRY: Guid = [0x20; 16];
const LAYERS: Guid = [0x30; 16];
const NIL: Guid = [0; 16];

fn internal_registration(
    watched_guid: Guid,
    target: InternalWatchTarget,
) -> InternalWatchRegistration {
    InternalWatchRegistration {
        watched_guid,
        target,
        subtree: true,
        has_fd: false,
        has_granted_access_mask: false,
        has_filter: false,
        receives_all_event_types: true,
        subject_to_notification_queue_limit: false,
    }
}

#[test]
fn internal_self_watch_targets_registry_and_layers_when_both_exist() {
    assert_eq!(
        plan_internal_self_watch(InternalSelfWatchRoots {
            machine_root_guid: MACHINE_ROOT,
            registry_guid: Some(REGISTRY),
            layers_guid: Some(LAYERS),
        }),
        Ok(InternalSelfWatchPlan::Targeted {
            registry: internal_registration(REGISTRY, InternalWatchTarget::SelfConfiguration),
            layers: internal_registration(LAYERS, InternalWatchTarget::LayerMetadata),
        })
    );
}

#[test]
fn internal_self_watch_falls_back_to_machine_root_when_specific_subtrees_are_missing() {
    for roots in [
        InternalSelfWatchRoots {
            machine_root_guid: MACHINE_ROOT,
            registry_guid: None,
            layers_guid: None,
        },
        InternalSelfWatchRoots {
            machine_root_guid: MACHINE_ROOT,
            registry_guid: Some(REGISTRY),
            layers_guid: None,
        },
        InternalSelfWatchRoots {
            machine_root_guid: MACHINE_ROOT,
            registry_guid: None,
            layers_guid: Some(LAYERS),
        },
    ] {
        assert_eq!(
            plan_internal_self_watch(roots),
            Ok(InternalSelfWatchPlan::MachineRootFallback {
                root: internal_registration(MACHINE_ROOT, InternalWatchTarget::MachineRootFallback),
            })
        );
    }
}

#[test]
fn internal_self_watch_registrations_are_not_userspace_fd_watches() {
    let Ok(InternalSelfWatchPlan::Targeted { registry, layers }) =
        plan_internal_self_watch(InternalSelfWatchRoots {
            machine_root_guid: MACHINE_ROOT,
            registry_guid: Some(REGISTRY),
            layers_guid: Some(LAYERS),
        })
    else {
        panic!("targeted self-watch plan expected");
    };

    for registration in [registry, layers] {
        assert!(registration.subtree);
        assert!(!registration.has_fd);
        assert!(!registration.has_granted_access_mask);
        assert!(!registration.has_filter);
        assert!(registration.receives_all_event_types);
        assert!(!registration.subject_to_notification_queue_limit);
    }
}

#[test]
fn internal_self_watch_rejects_nil_guids_before_publication_planning() {
    assert_eq!(
        plan_internal_self_watch(InternalSelfWatchRoots {
            machine_root_guid: NIL,
            registry_guid: Some(REGISTRY),
            layers_guid: Some(LAYERS),
        }),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_internal_self_watch(InternalSelfWatchRoots {
            machine_root_guid: MACHINE_ROOT,
            registry_guid: Some(NIL),
            layers_guid: Some(LAYERS),
        }),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_internal_self_watch(InternalSelfWatchRoots {
            machine_root_guid: MACHINE_ROOT,
            registry_guid: Some(REGISTRY),
            layers_guid: Some(NIL),
        }),
        Err(LcsError::NilKeyGuid)
    );
}
