use lcs_core::{
    DeleteKeyInput, DeleteVisibleChildGateInput, DeleteVisibleChildGatePlan, Guid,
    KeyFdNamespaceView, KeyPathMutationErrno, KeyPathMutationInput, LcsError, LcsLimits,
    key_path_mutation_errno, plan_delete_visible_child_gate, plan_key_delete,
};

const ROOT_GUID: Guid = [0x11; 16];
const CHILD_GUID: Guid = [0x22; 16];

fn delete_input(visible_child_count: u32) -> DeleteKeyInput<'static> {
    static PATH: [&str; 2] = ["Machine", "Parent"];
    static ANCESTORS: [Guid; 2] = [ROOT_GUID, CHILD_GUID];

    DeleteKeyInput {
        mutation: KeyPathMutationInput {
            fd: KeyFdNamespaceView {
                resolved_path: &PATH,
                ancestor_guids: &ANCESTORS,
                orphaned: false,
            },
            layer: "base",
        },
        visible_child_count,
    }
}

#[test]
fn delete_visible_child_gate_uses_global_enabled_visibility_not_private_set() {
    assert_eq!(
        plan_delete_visible_child_gate(DeleteVisibleChildGateInput {
            global_enabled_visible_child_count: 0,
            caller_private_visible_child_count: 7,
        }),
        Ok(DeleteVisibleChildGatePlan {
            visible_child_count_used: 0,
            evaluates_global_enabled_layers: true,
            ignores_caller_private_layer_set: true,
            recursive_delete_is_client_side: true,
        })
    );
}

#[test]
fn delete_visible_child_gate_rejects_global_children_as_enotempty() {
    let error = plan_delete_visible_child_gate(DeleteVisibleChildGateInput {
        global_enabled_visible_child_count: 3,
        caller_private_visible_child_count: 0,
    })
    .unwrap_err();

    assert_eq!(error, LcsError::KeyHasVisibleChildren { count: 3 });
    assert_eq!(
        key_path_mutation_errno(&error),
        Some(KeyPathMutationErrno::Enotempty)
    );
}

#[test]
fn key_delete_plan_rejects_visible_children_without_source_dispatch_shape() {
    let error = plan_key_delete(&LcsLimits::default(), &delete_input(2)).unwrap_err();

    assert_eq!(error, LcsError::KeyHasVisibleChildren { count: 2 });
    assert_eq!(
        key_path_mutation_errno(&error),
        Some(KeyPathMutationErrno::Enotempty)
    );
}

#[test]
fn key_delete_plan_admits_zero_global_visible_children() {
    assert!(
        plan_key_delete(&LcsLimits::default(), &delete_input(0))
            .expect("delete with no global visible children should plan")
            .effects
            .removes_target_layer_path_entry
    );
}
