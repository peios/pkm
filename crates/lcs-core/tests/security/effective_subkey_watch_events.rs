use lcs_core::{
    EffectiveSubkeyWatchEvent, EnumeratedSubkey, Guid, LcsError, LcsLimits, ResolvedPathEntry,
    WatchedKeyVisibilityEvent, for_each_effective_subkey_watch_event,
    plan_watched_key_visibility_event,
};

const OLD_GUID: Guid = [0x11; 16];
const NEW_GUID: Guid = [0x22; 16];
const STABLE_GUID: Guid = [0x33; 16];
const OTHER_GUID: Guid = [0x44; 16];
const NIL_GUID: Guid = [0x00; 16];

fn path(guid: Guid, layer: &'static str, sequence: u64) -> ResolvedPathEntry<'static> {
    ResolvedPathEntry {
        guid,
        layer,
        precedence: 0,
        sequence,
    }
}

fn subkey(
    name: &'static str,
    guid: Guid,
    layer: &'static str,
    sequence: u64,
) -> EnumeratedSubkey<'static> {
    EnumeratedSubkey {
        child_name: name,
        path: path(guid, layer, sequence),
    }
}

fn collect<'a>(
    before: &'a [EnumeratedSubkey<'a>],
    after: &'a [EnumeratedSubkey<'a>],
) -> Result<(usize, Vec<EffectiveSubkeyWatchEvent<'a>>), LcsError> {
    let mut events = Vec::new();
    let count =
        for_each_effective_subkey_watch_event(&LcsLimits::default(), before, after, |event| {
            events.push(event);
            Ok(())
        })?;
    Ok((count, events))
}

#[test]
fn effective_subkey_diff_emits_deletes_replacements_and_creates() {
    let before = [
        subkey("Old", OLD_GUID, "base", 1),
        subkey("Replaced", OLD_GUID, "base", 2),
        subkey("Stable", STABLE_GUID, "base", 3),
    ];
    let after = [
        subkey("Replaced", NEW_GUID, "policy", 4),
        subkey("Stable", STABLE_GUID, "policy", 5),
        subkey("New", NEW_GUID, "policy", 6),
    ];

    assert_eq!(
        collect(&before, &after),
        Ok((
            4,
            vec![
                EffectiveSubkeyWatchEvent::SubkeyDeleted { name: "Old" },
                EffectiveSubkeyWatchEvent::SubkeyDeleted { name: "Replaced" },
                EffectiveSubkeyWatchEvent::SubkeyCreated { name: "Replaced" },
                EffectiveSubkeyWatchEvent::SubkeyCreated { name: "New" },
            ],
        ))
    );
}

#[test]
fn same_guid_subkey_remains_visible_without_layer_mechanics_event() {
    let before = [subkey("Stable", STABLE_GUID, "base", 1)];
    let after = [subkey("stable", STABLE_GUID, "policy", 9)];

    assert_eq!(collect(&before, &after), Ok((0, vec![])));
}

#[test]
fn watched_key_visibility_emits_key_deleted_only_when_bound_guid_disappears() {
    assert_eq!(
        plan_watched_key_visibility_event(
            &LcsLimits::default(),
            OLD_GUID,
            Some(path(OLD_GUID, "base", 1)),
            None,
        ),
        Ok(Some(WatchedKeyVisibilityEvent::KeyDeleted))
    );
    assert_eq!(
        plan_watched_key_visibility_event(
            &LcsLimits::default(),
            OLD_GUID,
            Some(path(OLD_GUID, "base", 1)),
            Some(path(NEW_GUID, "policy", 2)),
        ),
        Ok(Some(WatchedKeyVisibilityEvent::KeyDeleted))
    );
}

#[test]
fn watched_key_reemergence_and_same_guid_changes_have_no_explicit_event() {
    assert_eq!(
        plan_watched_key_visibility_event(
            &LcsLimits::default(),
            OLD_GUID,
            None,
            Some(path(OLD_GUID, "base", 10)),
        ),
        Ok(None)
    );
    assert_eq!(
        plan_watched_key_visibility_event(
            &LcsLimits::default(),
            OLD_GUID,
            Some(path(OLD_GUID, "base", 1)),
            Some(path(OLD_GUID, "policy", 2)),
        ),
        Ok(None)
    );
    assert_eq!(
        plan_watched_key_visibility_event(
            &LcsLimits::default(),
            OLD_GUID,
            Some(path(OTHER_GUID, "base", 1)),
            Some(path(NEW_GUID, "policy", 2)),
        ),
        Ok(None)
    );
}

#[test]
fn subkey_snapshot_fails_closed_on_ambiguous_or_malformed_inputs() {
    let duplicate_before = [
        subkey("Child", OLD_GUID, "base", 1),
        subkey("child", NEW_GUID, "policy", 2),
    ];
    assert_eq!(
        collect(&duplicate_before, &[]),
        Err(LcsError::DuplicateEffectiveWatchSubkeyName {
            snapshot: "before",
            index: 1,
        })
    );

    let malformed_after = [subkey("Bad/Child", OLD_GUID, "base", 1)];
    assert!(matches!(
        collect(&[], &malformed_after),
        Err(LcsError::NameContainsSeparator {
            field: "key_component"
        })
    ));
}

#[test]
fn watched_key_visibility_fails_closed_on_nil_guids_and_bad_layers() {
    assert_eq!(
        plan_watched_key_visibility_event(&LcsLimits::default(), NIL_GUID, None, None),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_watched_key_visibility_event(
            &LcsLimits::default(),
            OLD_GUID,
            Some(path(NIL_GUID, "base", 1)),
            None,
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert!(matches!(
        plan_watched_key_visibility_event(
            &LcsLimits::default(),
            OLD_GUID,
            Some(path(OLD_GUID, "bad/layer", 1)),
            None,
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name"
        })
    ));
}
