use lcs_core::{
    DeleteKeyInput, Guid, HideKeyInput, KeyFdNamespaceView, KeyPathMutationErrno,
    KeyPathMutationInput, LcsError, LcsLimits, SequenceCounter, key_path_mutation_errno,
    plan_key_delete, plan_key_hide,
};

const ROOT_GUID: Guid = [0x11; 16];

fn root_fd<'a>(path: &'a [&'a str]) -> KeyFdNamespaceView<'a> {
    KeyFdNamespaceView {
        resolved_path: path,
        ancestor_guids: &[ROOT_GUID],
        orphaned: false,
    }
}

#[test]
fn hive_root_delete_fails_einval_before_delete_plan() {
    let limits = LcsLimits::default();
    let root_path = ["Machine"];
    let err = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: root_fd(&root_path),
                layer: "base",
            },
            visible_child_count: 99,
        },
    )
    .unwrap_err();

    assert_eq!(err, LcsError::HiveRootKeyOperation);
    assert_eq!(
        key_path_mutation_errno(&err),
        Some(KeyPathMutationErrno::Einval)
    );
}

#[test]
fn hive_root_hide_fails_einval_before_sequence_or_hide_plan() {
    let limits = LcsLimits::default();
    let root_path = ["Machine"];
    let mut counter = SequenceCounter::new(77);
    let err = plan_key_hide(
        &limits,
        &mut counter,
        &HideKeyInput {
            mutation: KeyPathMutationInput {
                fd: root_fd(&root_path),
                layer: "base",
            },
        },
    )
    .unwrap_err();

    assert_eq!(err, LcsError::HiveRootKeyOperation);
    assert_eq!(
        key_path_mutation_errno(&err),
        Some(KeyPathMutationErrno::Einval)
    );
    assert_eq!(counter.next_sequence(), 77);
}

#[test]
fn non_root_delete_and_hide_still_produce_source_dispatch_ready_plans() {
    let limits = LcsLimits::default();
    let path = ["Machine", "Parent", "Child"];
    let ancestors = [[0x01; 16], [0x02; 16], [0x03; 16]];
    let fd = KeyFdNamespaceView {
        resolved_path: &path,
        ancestor_guids: &ancestors,
        orphaned: false,
    };
    let mutation = KeyPathMutationInput { fd, layer: "base" };

    let delete = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation,
            visible_child_count: 0,
        },
    )
    .expect("non-root delete should produce a source-dispatch-ready plan");
    assert_eq!(delete.target.parent_guid, ancestors[1]);
    assert_eq!(delete.target.child_name, "Child");
    assert!(delete.updates_parent_last_write_time);

    let mut counter = SequenceCounter::new(88);
    let hide = plan_key_hide(&limits, &mut counter, &HideKeyInput { mutation })
        .expect("non-root hide should produce a source-dispatch-ready plan");
    assert_eq!(hide.path_entry.parent_guid, ancestors[1]);
    assert_eq!(hide.path_entry.child_name, "Child");
    assert_eq!(hide.path_entry.sequence, 88);
    assert_eq!(counter.next_sequence(), 89);
}
