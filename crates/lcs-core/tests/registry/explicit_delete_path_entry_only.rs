use lcs_core::{
    DeleteKeyInput, Guid, KeyDeleteEffects, KeyFdNamespaceView, KeyPathMutationInput, LcsLimits,
    plan_key_delete,
};

const ROOT_GUID: Guid = [0x01; 16];
const PARENT_GUID: Guid = [0x02; 16];
const CHILD_GUID: Guid = [0x03; 16];
static CHILD_ANCESTORS: [Guid; 3] = [ROOT_GUID, PARENT_GUID, CHILD_GUID];

fn child_fd<'a>(path: &'a [&'a str]) -> KeyFdNamespaceView<'a> {
    KeyFdNamespaceView {
        resolved_path: path,
        ancestor_guids: &CHILD_ANCESTORS,
        orphaned: false,
    }
}

#[test]
fn explicit_key_delete_targets_only_the_named_layer_path_entry() {
    let limits = LcsLimits::default();
    let path = ["Machine", "Parent", "Child"];
    let planned = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(&path),
                layer: "policy",
            },
            visible_child_count: 0,
        },
    )
    .expect("explicit delete should plan");

    assert_eq!(planned.target.parent_guid, PARENT_GUID);
    assert_eq!(planned.target.child_name, "Child");
    assert_eq!(planned.target.layer, "policy");
    assert_eq!(
        planned.effects,
        KeyDeleteEffects {
            removes_target_layer_path_entry: true,
            preserves_key_data: true,
            preserves_other_layer_path_entries: true,
        }
    );
    assert!(planned.updates_parent_last_write_time);
}

#[test]
fn delete_layer_spelling_is_preserved_for_source_dispatch() {
    let limits = LcsLimits::default();
    let path = ["Machine", "Parent", "Child"];
    let planned = plan_key_delete(
        &limits,
        &DeleteKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(&path),
                layer: "PolicyLayer",
            },
            visible_child_count: 0,
        },
    )
    .expect("explicit delete should preserve requested layer spelling");

    assert_eq!(planned.target.layer, "PolicyLayer");
    assert!(planned.effects.preserves_other_layer_path_entries);
}
