use crate::common::{limits};
use lcs_core::{
    Guid, LcsError, REG_NOTIFY_SD, REG_NOTIFY_SUBKEY, REG_NOTIFY_VALUE,
    REG_WATCH_KEY_DELETED, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED, REG_WATCH_VALUE_SET,
    WatchDelivery, WatchDispatchDecision, WatchMutationContext, WatcherView, plan_watch_dispatch,
};

const ROOT_GUID: Guid = [0x01; 16];
const SERVICES_GUID: Guid = [0x02; 16];
const CHILD_GUID: Guid = [0x03; 16];
const OTHER_GUID: Guid = [0x04; 16];


fn mutation<'a>(
    event_type: u32,
    ancestor_guids: &'a [Guid],
    path_components: &'a [&'a str],
) -> WatchMutationContext<'a> {
    WatchMutationContext {
        changed_key_guid: CHILD_GUID,
        ancestor_guids,
        path_components,
        event_type,
    }
}

#[test]
fn direct_watch_delivers_only_for_the_changed_key_guid() {
    let ancestors = [ROOT_GUID, SERVICES_GUID, CHILD_GUID];
    let path = ["Machine", "Services", "Child"];
    let decision = plan_watch_dispatch(
        &limits(),
        WatcherView {
            watched_guid: CHILD_GUID,
            filter: REG_NOTIFY_VALUE,
            subtree: false,
        },
        &mutation(REG_WATCH_VALUE_SET, &ancestors, &path),
    )
    .expect("dispatch should plan");

    assert_eq!(
        decision,
        WatchDispatchDecision::Deliver(WatchDelivery {
            event_type: REG_WATCH_VALUE_SET,
            subtree_record: false,
            relative_path_components: &[],
        })
    );

    assert_eq!(
        plan_watch_dispatch(
            &limits(),
            WatcherView {
                watched_guid: SERVICES_GUID,
                filter: REG_NOTIFY_VALUE,
                subtree: false,
            },
            &mutation(REG_WATCH_VALUE_SET, &ancestors, &path),
        ),
        Ok(WatchDispatchDecision::NoMatch)
    );
}

#[test]
fn subtree_watch_uses_captured_ancestor_chain_and_relative_components() {
    let ancestors = [ROOT_GUID, SERVICES_GUID, CHILD_GUID];
    let path = ["Machine", "Services", "Child"];

    assert_eq!(
        plan_watch_dispatch(
            &limits(),
            WatcherView {
                watched_guid: ROOT_GUID,
                filter: REG_NOTIFY_SUBKEY,
                subtree: true,
            },
            &mutation(REG_WATCH_SUBKEY_CREATED, &ancestors, &path),
        ),
        Ok(WatchDispatchDecision::Deliver(WatchDelivery {
            event_type: REG_WATCH_SUBKEY_CREATED,
            subtree_record: true,
            relative_path_components: &["Services", "Child"],
        }))
    );

    assert_eq!(
        plan_watch_dispatch(
            &limits(),
            WatcherView {
                watched_guid: OTHER_GUID,
                filter: REG_NOTIFY_SUBKEY,
                subtree: true,
            },
            &mutation(REG_WATCH_SUBKEY_CREATED, &ancestors, &path),
        ),
        Ok(WatchDispatchDecision::NoMatch)
    );
}

#[test]
fn subtree_watch_on_changed_key_uses_zero_depth_subtree_record() {
    let ancestors = [ROOT_GUID, SERVICES_GUID, CHILD_GUID];
    let path = ["Machine", "Services", "Child"];

    assert_eq!(
        plan_watch_dispatch(
            &limits(),
            WatcherView {
                watched_guid: CHILD_GUID,
                filter: REG_NOTIFY_SD,
                subtree: true,
            },
            &mutation(REG_WATCH_SD_CHANGED, &ancestors, &path),
        ),
        Ok(WatchDispatchDecision::Deliver(WatchDelivery {
            event_type: REG_WATCH_SD_CHANGED,
            subtree_record: true,
            relative_path_components: &[],
        }))
    );
}

#[test]
fn filters_apply_to_dispatch_but_key_deleted_bypasses_filter() {
    let ancestors = [ROOT_GUID, SERVICES_GUID, CHILD_GUID];
    let path = ["Machine", "Services", "Child"];

    assert_eq!(
        plan_watch_dispatch(
            &limits(),
            WatcherView {
                watched_guid: CHILD_GUID,
                filter: REG_NOTIFY_SUBKEY,
                subtree: false,
            },
            &mutation(REG_WATCH_VALUE_SET, &ancestors, &path),
        ),
        Ok(WatchDispatchDecision::NoMatch)
    );

    assert_eq!(
        plan_watch_dispatch(
            &limits(),
            WatcherView {
                watched_guid: SERVICES_GUID,
                filter: 0,
                subtree: true,
            },
            &mutation(REG_WATCH_KEY_DELETED, &ancestors, &path),
        ),
        Ok(WatchDispatchDecision::Deliver(WatchDelivery {
            event_type: REG_WATCH_KEY_DELETED,
            subtree_record: true,
            relative_path_components: &["Child"],
        }))
    );
}

#[test]
fn subtree_depth_limit_suppresses_deep_descendant_events() {
    let mut limits = limits();
    limits.max_subtree_watch_depth = 1;
    let ancestors = [ROOT_GUID, SERVICES_GUID, CHILD_GUID];
    let path = ["Machine", "Services", "Child"];

    assert_eq!(
        plan_watch_dispatch(
            &limits,
            WatcherView {
                watched_guid: ROOT_GUID,
                filter: REG_NOTIFY_SUBKEY,
                subtree: true,
            },
            &mutation(REG_WATCH_SUBKEY_CREATED, &ancestors, &path),
        ),
        Ok(WatchDispatchDecision::SuppressedByDepthLimit { depth: 2, max: 1 })
    );

    limits.max_subtree_watch_depth = 0;
    assert!(matches!(
        plan_watch_dispatch(
            &limits,
            WatcherView {
                watched_guid: ROOT_GUID,
                filter: REG_NOTIFY_SUBKEY,
                subtree: true,
            },
            &mutation(REG_WATCH_SUBKEY_CREATED, &ancestors, &path),
        ),
        Ok(WatchDispatchDecision::Deliver(_))
    ));
}

#[test]
fn malformed_mutation_ancestry_fails_closed_before_dispatch() {
    assert_eq!(
        plan_watch_dispatch(
            &limits(),
            WatcherView {
                watched_guid: ROOT_GUID,
                filter: REG_NOTIFY_VALUE,
                subtree: true,
            },
            &WatchMutationContext {
                changed_key_guid: CHILD_GUID,
                ancestor_guids: &[ROOT_GUID, CHILD_GUID],
                path_components: &["Machine"],
                event_type: REG_WATCH_VALUE_SET,
            },
        ),
        Err(LcsError::InvalidWatchAncestry)
    );

    assert_eq!(
        plan_watch_dispatch(
            &limits(),
            WatcherView {
                watched_guid: ROOT_GUID,
                filter: REG_NOTIFY_VALUE,
                subtree: true,
            },
            &WatchMutationContext {
                changed_key_guid: CHILD_GUID,
                ancestor_guids: &[ROOT_GUID, SERVICES_GUID],
                path_components: &["Machine", "Services"],
                event_type: REG_WATCH_VALUE_SET,
            },
        ),
        Err(LcsError::WatchChangedKeyNotLastAncestor)
    );
}
