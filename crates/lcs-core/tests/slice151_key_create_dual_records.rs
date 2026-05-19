use lcs_core::{
    Guid, KEY_CREATE_SUB_KEY, KeyCreateRecordsPlan, KeyCreateRecordsRequest, LcsError, LcsLimits,
    PathTarget, REG_OPTION_VOLATILE, RSI_CREATE_ENTRY, RSI_CREATE_KEY, RSI_REQUEST_HEADER_LEN,
    RsiLengthPrefixedField, SequenceCounter, parse_rsi_create_entry_request_payload,
    parse_rsi_create_key_request_payload, parse_rsi_request_header, plan_key_create_records,
    write_rsi_create_key_request_frame, write_rsi_path_entry_request_frame,
};

const PARENT_GUID: Guid = [0x51; 16];
const CHILD_GUID: Guid = [0x52; 16];
const OTHER_GUID: Guid = [0x53; 16];
const CHILD_SD: &[u8] = b"self-relative-sd";

fn field(data: &'static [u8]) -> RsiLengthPrefixedField<'static> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
    }
}

fn request<'a>(
    candidate_guid: Guid,
    active_key_guids: &'a [Guid],
    retired_key_guids: &'a [Guid],
    layer: &'a str,
) -> KeyCreateRecordsRequest<'a> {
    KeyCreateRecordsRequest {
        parent_guid: PARENT_GUID,
        parent_is_volatile: false,
        parent_granted_access: KEY_CREATE_SUB_KEY,
        child_name: "Child",
        candidate_guid,
        active_key_guids,
        retired_key_guids,
        layer,
        flags: REG_OPTION_VOLATILE,
        caller_has_tcb_or_admin: false,
    }
}

#[test]
fn key_create_plan_produces_fresh_guid_path_entry_and_key_record() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(900);

    let plan = plan_key_create_records(
        &limits,
        &mut sequence_counter,
        &request(CHILD_GUID, &[], &[], "policy"),
    )
    .unwrap();

    assert_eq!(
        plan,
        KeyCreateRecordsPlan {
            guid_assignment: lcs_core::KeyGuidAssignmentPlan {
                guid: CHILD_GUID,
                assigned_by_lcs: true,
                persist_in_key_record: true,
            },
            key_record: lcs_core::KeyCreatePlan {
                guid: CHILD_GUID,
                name: "Child",
                parent_guid: PARENT_GUID,
                volatile: true,
                symlink: false,
            },
            path_entry: lcs_core::ValidatedPathEntryWrite {
                parent_guid: PARENT_GUID,
                child_name: "Child",
                layer: "policy",
                sequence: 900,
                target: PathTarget::Guid(CHILD_GUID),
            },
        }
    );
    assert_eq!(sequence_counter.next_sequence(), 901);

    let mut path_frame = [0u8; 128];
    let path_built =
        write_rsi_path_entry_request_frame(&mut path_frame, 100, 7, plan.path_entry).unwrap();
    let path_header = parse_rsi_request_header(&path_frame[..path_built.len]).unwrap();
    let path_payload =
        parse_rsi_create_entry_request_payload(&path_frame[RSI_REQUEST_HEADER_LEN..path_built.len])
            .unwrap();
    assert_eq!(path_header.op_code, RSI_CREATE_ENTRY);
    assert_eq!(path_payload.parent_guid, PARENT_GUID);
    assert_eq!(path_payload.child_name, field(b"Child"));
    assert_eq!(path_payload.layer_name, field(b"policy"));
    assert_eq!(path_payload.child_guid, CHILD_GUID);
    assert_eq!(path_payload.sequence, 900);

    let mut key_frame = [0u8; 128];
    let key_built = write_rsi_create_key_request_frame(
        &mut key_frame,
        101,
        7,
        plan.key_record.guid,
        plan.key_record.name.as_bytes(),
        plan.key_record.parent_guid,
        CHILD_SD,
        plan.key_record.volatile,
        plan.key_record.symlink,
    )
    .unwrap();
    let key_header = parse_rsi_request_header(&key_frame[..key_built.len]).unwrap();
    let key_payload =
        parse_rsi_create_key_request_payload(&key_frame[RSI_REQUEST_HEADER_LEN..key_built.len])
            .unwrap();
    assert_eq!(key_header.op_code, RSI_CREATE_KEY);
    assert_eq!(key_payload.guid, CHILD_GUID);
    assert_eq!(key_payload.name, field(b"Child"));
    assert_eq!(key_payload.parent_guid, PARENT_GUID);
    assert_eq!(key_payload.sd, field(CHILD_SD));
    assert!(key_payload.volatile);
    assert!(!key_payload.symlink);
}

#[test]
fn key_create_plan_rejects_existing_guid_before_sequence_allocation() {
    let limits = LcsLimits::default();
    let active = [CHILD_GUID, OTHER_GUID];
    let mut sequence_counter = SequenceCounter::new(900);

    assert_eq!(
        plan_key_create_records(
            &limits,
            &mut sequence_counter,
            &request(CHILD_GUID, &active, &[], "policy"),
        ),
        Err(LcsError::KeyGuidAlreadyExists { guid: CHILD_GUID })
    );
    assert_eq!(sequence_counter.next_sequence(), 900);
}

#[test]
fn key_create_plan_rejects_bad_layer_before_sequence_allocation() {
    let limits = LcsLimits::default();
    let mut sequence_counter = SequenceCounter::new(900);

    assert_eq!(
        plan_key_create_records(
            &limits,
            &mut sequence_counter,
            &request(CHILD_GUID, &[], &[], "bad/layer"),
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
    assert_eq!(sequence_counter.next_sequence(), 900);
}
