use lcs_core::{
    BlanketTombstoneAction, BlanketTombstoneInput, Guid, HideKeyInput, KeyFdNamespaceView,
    KeyPathMutationInput, LcsError, LcsLimits, NIL_GUID, PathEntryWriteRequest, PathTarget, REG_SZ,
    SequenceCounter, ValueWriteInput, plan_blanket_tombstone, plan_key_hide, plan_value_write,
    validate_path_entry_write_request,
};

const ROOT_GUID: Guid = [0x51; 16];
const PARENT_GUID: Guid = [0x52; 16];
const CHILD_GUID: Guid = [0x53; 16];
const VALUE_KEY_GUID: Guid = [0x54; 16];
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
fn one_global_counter_feeds_path_value_hide_and_blanket_mutations() {
    let limits = limits();
    let mut counter = SequenceCounter::new(700);

    let path_sequence = counter.allocate().unwrap();
    let path_entry = validate_path_entry_write_request(
        &limits,
        &PathEntryWriteRequest {
            parent_guid: PARENT_GUID,
            child_name: "Created",
            layer: "base",
            sequence: path_sequence,
            target: PathTarget::Guid(CHILD_GUID),
        },
    )
    .unwrap();
    let value_write = plan_value_write(
        &limits,
        &mut counter,
        &ValueWriteInput {
            key_guid: VALUE_KEY_GUID,
            name: "Setting",
            layer: "policy",
            value_type: REG_SZ,
            data: b"value",
            explicit_tombstone_operation: false,
            expected_sequence: None,
        },
    )
    .unwrap();
    let hide = plan_key_hide(
        &limits,
        &mut counter,
        &HideKeyInput {
            mutation: KeyPathMutationInput {
                fd: child_fd(&["Machine", "Parent", "Child"]),
                layer: "policy",
            },
        },
    )
    .unwrap();
    let blanket = plan_blanket_tombstone(
        &limits,
        &mut counter,
        &BlanketTombstoneInput {
            key_guid: VALUE_KEY_GUID,
            layer: "policy",
            set: true,
        },
    )
    .unwrap();

    assert_eq!(path_entry.sequence, 700);
    assert_eq!(value_write.write.sequence, 701);
    assert_eq!(hide.path_entry.sequence, 702);
    assert_eq!(
        blanket.blanket.action,
        BlanketTombstoneAction::Set { sequence: 703 }
    );
    assert_eq!(counter.next_sequence(), 704);
}

#[test]
fn malformed_mutations_do_not_consume_sequence_numbers() {
    let limits = limits();
    let mut counter = SequenceCounter::new(30);

    assert_eq!(
        plan_value_write(
            &limits,
            &mut counter,
            &ValueWriteInput {
                key_guid: NIL_GUID,
                name: "Setting",
                layer: "policy",
                value_type: REG_SZ,
                data: b"value",
                explicit_tombstone_operation: false,
                expected_sequence: None,
            },
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(counter.next_sequence(), 30);

    assert_eq!(
        plan_key_hide(
            &limits,
            &mut counter,
            &HideKeyInput {
                mutation: KeyPathMutationInput {
                    fd: KeyFdNamespaceView {
                        resolved_path: &["Machine"],
                        ancestor_guids: &[ROOT_GUID],
                        orphaned: false,
                    },
                    layer: "policy",
                },
            },
        ),
        Err(LcsError::HiveRootKeyOperation)
    );
    assert_eq!(counter.next_sequence(), 30);

    assert_eq!(
        plan_blanket_tombstone(
            &limits,
            &mut counter,
            &BlanketTombstoneInput {
                key_guid: NIL_GUID,
                layer: "policy",
                set: true,
            },
        ),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(counter.next_sequence(), 30);
}
