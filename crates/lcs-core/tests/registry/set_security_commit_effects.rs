use crate::common::{sid};
use kacs_core::{ACCESS_ALLOWED_ACE_TYPE, SE_DACL_PRESENT, SE_SELF_RELATIVE};
use lcs_core::{
    DACL_SECURITY_INFORMATION, Guid, KEY_READ, LcsError, LcsLimits, OWNER_SECURITY_INFORMATION,
    REG_NOTIFY_SD, REG_WATCH_SD_CHANGED, RegistrySetSecurityEffectTiming, WatchDelivery,
    WatchDispatchDecision, WatcherView, plan_registry_set_security,
    plan_registry_set_security_commit_effects, plan_watch_dispatch,
};

const ROOT_GUID: Guid = [
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
];
const PARENT_GUID: Guid = [
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
];
const KEY_GUID: Guid = [
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
];
const OTHER_GUID: Guid = [
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
];


fn basic_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + sid.len());
    bytes.push(ACCESS_ALLOWED_ACE_TYPE);
    bytes.push(0);
    bytes.extend_from_slice(&(8 + sid.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl(ace: &[u8]) -> Vec<u8> {
    let size = 8 + ace.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(2);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(ace);
    bytes
}

fn sd(owner: Option<&[u8]>, dacl: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    let mut control = SE_SELF_RELATIVE;

    let owner_offset = append_optional_component(&mut bytes, owner);
    let dacl_offset = append_optional_component(&mut bytes, dacl);
    if dacl.is_some() {
        control |= SE_DACL_PRESENT;
    }

    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes
}

fn append_optional_component(bytes: &mut Vec<u8>, component: Option<&[u8]>) -> u32 {
    let Some(component) = component else {
        return 0;
    };
    let offset = bytes.len() as u32;
    bytes.extend_from_slice(component);
    offset
}

fn set_security_plan() -> lcs_core::RegistrySetSecurityPlan {
    let owner = sid(5, &[18]);
    let replacement_owner = sid(5, &[21, 2000]);
    let user = sid(5, &[21, 1000]);
    let dacl = acl(&basic_ace(KEY_READ, &user));
    let existing = sd(Some(&owner), Some(&dacl));
    let input = sd(Some(&replacement_owner), None);

    plan_registry_set_security(&existing, &input, OWNER_SECURITY_INFORMATION)
        .expect("set-security merge plan")
}

#[test]
fn nontransactional_set_security_commits_generation_and_sd_changed_watch_effects() {
    let plan = set_security_plan();
    let ancestors = [ROOT_GUID, PARENT_GUID, KEY_GUID];
    let path = ["Machine", "Software", "Policy"];
    let effects = plan_registry_set_security_commit_effects(
        &plan,
        RegistrySetSecurityEffectTiming::NonTransactionalCommitted,
        KEY_GUID,
        &ancestors,
        &path,
    )
    .expect("set-security commit effects");

    assert!(effects.update_hive_generation);
    assert!(effects.dispatch_watch_events);
    assert!(!effects.record_transaction_mutation_log);
    assert!(effects.commit_visible_last_write_time_update);
    assert!(effects.retain_existing_fd_grants);

    let mutation = effects.watch_mutation.expect("sd-changed watch mutation");
    assert_eq!(mutation.changed_key_guid, KEY_GUID);
    assert_eq!(mutation.ancestor_guids, ancestors.as_slice());
    assert_eq!(mutation.path_components, path.as_slice());
    assert_eq!(mutation.event_type, REG_WATCH_SD_CHANGED);

    let direct = WatcherView {
        watched_guid: KEY_GUID,
        filter: REG_NOTIFY_SD,
        subtree: false,
    };
    assert_eq!(
        plan_watch_dispatch(&LcsLimits::default(), direct, &mutation),
        Ok(WatchDispatchDecision::Deliver(WatchDelivery {
            event_type: REG_WATCH_SD_CHANGED,
            subtree_record: false,
            relative_path_components: &[],
        }))
    );

    let subtree = WatcherView {
        watched_guid: PARENT_GUID,
        filter: REG_NOTIFY_SD,
        subtree: true,
    };
    assert_eq!(
        plan_watch_dispatch(&LcsLimits::default(), subtree, &mutation),
        Ok(WatchDispatchDecision::Deliver(WatchDelivery {
            event_type: REG_WATCH_SD_CHANGED,
            subtree_record: true,
            relative_path_components: &["Policy"],
        }))
    );
}

#[test]
fn transaction_pending_set_security_records_but_does_not_publish_effects() {
    let plan = set_security_plan();
    let ancestors = [ROOT_GUID, KEY_GUID];
    let path = ["Machine", "Policy"];
    let effects = plan_registry_set_security_commit_effects(
        &plan,
        RegistrySetSecurityEffectTiming::TransactionPending,
        KEY_GUID,
        &ancestors,
        &path,
    )
    .expect("pending transaction effects");

    assert!(!effects.update_hive_generation);
    assert!(!effects.dispatch_watch_events);
    assert!(effects.record_transaction_mutation_log);
    assert!(!effects.commit_visible_last_write_time_update);
    assert!(effects.retain_existing_fd_grants);
    assert_eq!(
        effects
            .watch_mutation
            .expect("recorded mutation")
            .event_type,
        REG_WATCH_SD_CHANGED
    );
}

#[test]
fn transaction_commit_publishes_recorded_set_security_effects_but_abort_drops_them() {
    let plan = set_security_plan();
    let ancestors = [ROOT_GUID, KEY_GUID];
    let path = ["Machine", "Policy"];
    let committed = plan_registry_set_security_commit_effects(
        &plan,
        RegistrySetSecurityEffectTiming::TransactionCommitSucceeded,
        KEY_GUID,
        &ancestors,
        &path,
    )
    .expect("transaction commit effects");
    assert!(committed.update_hive_generation);
    assert!(committed.dispatch_watch_events);
    assert!(!committed.record_transaction_mutation_log);
    assert!(committed.commit_visible_last_write_time_update);
    assert_eq!(
        committed
            .watch_mutation
            .expect("commit mutation")
            .event_type,
        REG_WATCH_SD_CHANGED
    );

    let aborted = plan_registry_set_security_commit_effects(
        &plan,
        RegistrySetSecurityEffectTiming::AbortedOrFailed,
        KEY_GUID,
        &ancestors,
        &path,
    )
    .expect("aborted transaction effects");
    assert!(!aborted.update_hive_generation);
    assert!(!aborted.dispatch_watch_events);
    assert!(!aborted.record_transaction_mutation_log);
    assert!(!aborted.commit_visible_last_write_time_update);
    assert!(aborted.watch_mutation.is_none());
}

#[test]
fn set_security_commit_effects_fail_closed_on_invalid_watch_ancestry() {
    let plan = set_security_plan();
    let path = ["Machine", "Policy"];

    assert_eq!(
        plan_registry_set_security_commit_effects(
            &plan,
            RegistrySetSecurityEffectTiming::NonTransactionalCommitted,
            KEY_GUID,
            &[],
            &[],
        ),
        Err(LcsError::InvalidWatchAncestry)
    );
    assert_eq!(
        plan_registry_set_security_commit_effects(
            &plan,
            RegistrySetSecurityEffectTiming::NonTransactionalCommitted,
            KEY_GUID,
            &[ROOT_GUID, KEY_GUID],
            &path[..1],
        ),
        Err(LcsError::InvalidWatchAncestry)
    );
    assert_eq!(
        plan_registry_set_security_commit_effects(
            &plan,
            RegistrySetSecurityEffectTiming::NonTransactionalCommitted,
            KEY_GUID,
            &[ROOT_GUID, OTHER_GUID],
            &path,
        ),
        Err(LcsError::WatchChangedKeyNotLastAncestor)
    );
}

#[test]
fn set_security_commit_effects_fail_closed_on_corrupt_set_security_plan() {
    let mut plan = set_security_plan();
    plan.direct_key_mutation = false;

    assert_eq!(
        plan_registry_set_security_commit_effects(
            &plan,
            RegistrySetSecurityEffectTiming::NonTransactionalCommitted,
            KEY_GUID,
            &[KEY_GUID],
            &["Policy"],
        ),
        Err(LcsError::InvalidRegistrySetSecurityPlan {
            field: "direct_key_mutation",
        })
    );
}

#[test]
fn set_security_commit_effects_do_not_accept_invalid_acl_merge_plans() {
    let owner = sid(5, &[18]);
    let user = sid(5, &[21, 1000]);
    let good_dacl = acl(&basic_ace(KEY_READ, &user));
    let mut bad_dacl = good_dacl.clone();
    bad_dacl[2..4].copy_from_slice(&4u16.to_le_bytes());
    let existing = sd(Some(&owner), Some(&good_dacl));
    let malformed_input = sd(None, Some(&bad_dacl));

    assert_eq!(
        plan_registry_set_security(&existing, &malformed_input, DACL_SECURITY_INFORMATION,),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "reg_set_security.input_sd",
        })
    );
}
