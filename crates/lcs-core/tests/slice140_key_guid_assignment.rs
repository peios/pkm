use lcs_core::{
    Guid, KeyGuidAssignmentPlan, KeyGuidAssignmentRequest, LcsError, plan_key_guid_assignment,
};

const CANDIDATE: Guid = [0x40; 16];
const ACTIVE: Guid = [0x41; 16];
const ACTIVE_2: Guid = [0x42; 16];
const RETIRED: Guid = [0x50; 16];
const RETIRED_2: Guid = [0x51; 16];

fn request<'a>(
    candidate_guid: Guid,
    active_key_guids: &'a [Guid],
    retired_key_guids: &'a [Guid],
) -> KeyGuidAssignmentRequest<'a> {
    KeyGuidAssignmentRequest {
        candidate_guid,
        active_key_guids,
        retired_key_guids,
    }
}

#[test]
fn fresh_candidate_guid_becomes_lcs_assigned_persistent_identity() {
    assert_eq!(
        plan_key_guid_assignment(request(
            CANDIDATE,
            &[ACTIVE, ACTIVE_2],
            &[RETIRED, RETIRED_2]
        )),
        Ok(KeyGuidAssignmentPlan {
            guid: CANDIDATE,
            assigned_by_lcs: true,
            persist_in_key_record: true,
        })
    );
}

#[test]
fn nil_active_collision_and_retired_reuse_fail_closed() {
    assert_eq!(
        plan_key_guid_assignment(request([0; 16], &[], &[])),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_key_guid_assignment(request(ACTIVE, &[ACTIVE], &[RETIRED])),
        Err(LcsError::KeyGuidAlreadyExists { guid: ACTIVE })
    );
    assert_eq!(
        plan_key_guid_assignment(request(RETIRED, &[ACTIVE], &[RETIRED])),
        Err(LcsError::RetiredKeyGuidReuse { guid: RETIRED })
    );
}

#[test]
fn corrupt_guid_reuse_trackers_fail_before_assignment() {
    assert_eq!(
        plan_key_guid_assignment(request(CANDIDATE, &[[0; 16]], &[])),
        Err(LcsError::NilTrackedKeyGuid {
            field: "active_key_guids",
            index: 0,
        })
    );
    assert_eq!(
        plan_key_guid_assignment(request(CANDIDATE, &[ACTIVE, ACTIVE], &[])),
        Err(LcsError::DuplicateTrackedKeyGuid {
            field: "active_key_guids",
            index: 1,
        })
    );
    assert_eq!(
        plan_key_guid_assignment(request(CANDIDATE, &[ACTIVE], &[ACTIVE])),
        Err(LcsError::KeyGuidTrackerOverlap { guid: ACTIVE })
    );
}
