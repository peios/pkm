use lcs_core::{
    DeleteKeyInput, Guid, HideKeyInput, KeyFdNamespaceView, KeyPathMutationInput, LcsError,
    LcsLimits, NIL_GUID, PathTarget, SequenceCounter, derive_key_path_mutation, plan_key_delete,
    plan_key_hide,
};

const ROOT_GUID: Guid = [0x01; 16];
const PARENT_GUID: Guid = [0x02; 16];
const CHILD_GUID: Guid = [0x03; 16];
static CHILD_ANCESTORS: [Guid; 3] = [ROOT_GUID, PARENT_GUID, CHILD_GUID];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn child_fd<'a>(path: &'a [&'a str]) -> KeyFdNamespaceView<'a> {
    KeyFdNamespaceView {
        resolved_path: path,
        ancestor_guids: &CHILD_ANCESTORS,
        orphaned: false,
    }
}

#[test]
fn key_path_mutation_derives_parent_child_and_layer_from_fd_state() {
    let limits = limits();
    let path = ["Machine", "Parent", "Child"];
    let derived = derive_key_path_mutation(
        &limits,
        &KeyPathMutationInput {
            fd: child_fd(&path),
            layer: "base",
        },
    )
    .expect("fd path should derive");

    assert_eq!(derived.parent_guid, PARENT_GUID);
    assert_eq!(derived.child_name, "Child");
    assert_eq!(derived.layer, "base");
}

#[test]
fn delete_key_plan_rejects_visible_children_and_marks_parent_timestamp() {
    let limits = limits();
    let path = ["Machine", "Parent", "Child"];
    let mutation = KeyPathMutationInput {
        fd: child_fd(&path),
        layer: "base",
    };

    assert_eq!(
        plan_key_delete(
            &limits,
            &DeleteKeyInput {
                mutation,
                visible_child_count: 2,
            },
        ),
        Err(LcsError::KeyHasVisibleChildren { count: 2 })
    );

    let planned = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation,
            visible_child_count: 0,
        },
    )
    .expect("delete should plan");

    assert_eq!(planned.target.parent_guid, PARENT_GUID);
    assert_eq!(planned.target.child_name, "Child");
    assert!(planned.updates_parent_last_write_time);
}

#[test]
fn hide_key_plan_allocates_hidden_path_entry_sequence() {
    let limits = limits();
    let path = ["Machine", "Parent", "Child"];
    let mut counter = SequenceCounter::new(60);
    let planned = plan_key_hide(
        &limits,
        &mut counter,
        &HideKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(&path),
                layer: "policy",
            },
        },
    )
    .expect("hide should plan");

    assert_eq!(planned.path_entry.parent_guid, PARENT_GUID);
    assert_eq!(planned.path_entry.child_name, "Child");
    assert_eq!(planned.path_entry.layer, "policy");
    assert_eq!(planned.path_entry.sequence, 60);
    assert_eq!(planned.path_entry.target, PathTarget::Hidden);
    assert!(planned.masks_lower_layers);
    assert_eq!(counter.next_sequence(), 61);
}

#[test]
fn hive_root_and_orphaned_namespace_mutations_fail_before_sequence_allocation() {
    let limits = limits();
    let root_path = ["Machine"];
    let root_fd = KeyFdNamespaceView {
        resolved_path: &root_path,
        ancestor_guids: &[ROOT_GUID],
        orphaned: false,
    };
    let mut counter = SequenceCounter::new(10);

    assert_eq!(
        plan_key_hide(
            &limits,
            &mut counter,
            &HideKeyInput {
                mutation: KeyPathMutationInput {
                    fd: root_fd,
                    layer: "base",
                },
            },
        ),
        Err(LcsError::HiveRootKeyOperation)
    );
    assert_eq!(counter.next_sequence(), 10);

    let child_path = ["Machine", "Parent", "Child"];
    let orphaned_fd = KeyFdNamespaceView {
        orphaned: true,
        ..child_fd(&child_path)
    };
    assert_eq!(
        plan_key_delete(
            &limits,
            &DeleteKeyInput {
                mutation: KeyPathMutationInput {
                    fd: orphaned_fd,
                    layer: "base",
                },
                visible_child_count: 0,
            },
        ),
        Err(LcsError::OrphanedKeyNamespaceOperation)
    );
}

#[test]
fn malformed_fd_or_names_fail_before_hide_sequence_allocation() {
    let limits = limits();
    let path = ["Machine", "Parent", "Bad/Child"];
    let mut counter = SequenceCounter::new(10);

    assert_eq!(
        plan_key_hide(
            &limits,
            &mut counter,
            &HideKeyInput {
                mutation: KeyPathMutationInput {
                    fd: child_fd(&path),
                    layer: "base",
                },
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
    assert_eq!(counter.next_sequence(), 10);

    let short_ancestry = KeyFdNamespaceView {
        resolved_path: &["Machine", "Child"],
        ancestor_guids: &[ROOT_GUID],
        orphaned: false,
    };
    assert_eq!(
        derive_key_path_mutation(
            &limits,
            &KeyPathMutationInput {
                fd: short_ancestry,
                layer: "base",
            },
        ),
        Err(LcsError::InvalidFdAncestry)
    );

    let nil_parent = KeyFdNamespaceView {
        resolved_path: &["Machine", "Child"],
        ancestor_guids: &[NIL_GUID, CHILD_GUID],
        orphaned: false,
    };
    assert_eq!(
        derive_key_path_mutation(
            &limits,
            &KeyPathMutationInput {
                fd: nil_parent,
                layer: "base",
            },
        ),
        Err(LcsError::NilParentGuid)
    );
}
