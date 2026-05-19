use lcs_core::{
    LcsError, SourceRestartKeyFdPlan, SourceRestartWatchPlan, plan_source_restart_key_fd_operation,
    plan_source_restart_watch_overflow,
};

const KEY_GUID: [u8; 16] = [0x55; 16];

#[test]
fn resumed_source_overflows_only_watches_in_that_source_slot() {
    assert_eq!(
        plan_source_restart_watch_overflow(7, 7),
        SourceRestartWatchPlan {
            affected_by_resume: true,
            enqueue_overflow: true,
        }
    );
    assert_eq!(
        plan_source_restart_watch_overflow(7, 8),
        SourceRestartWatchPlan {
            affected_by_resume: false,
            enqueue_overflow: false,
        }
    );
}

#[test]
fn existing_key_fd_resumes_when_guid_still_exists_after_restart() {
    assert_eq!(
        plan_source_restart_key_fd_operation(7, 7, KEY_GUID, true),
        Ok(SourceRestartKeyFdPlan {
            affected_by_resume: true,
            dispatch_to_source: true,
        })
    );
}

#[test]
fn existing_key_fd_returns_not_found_when_guid_disappeared_after_restart() {
    assert_eq!(
        plan_source_restart_key_fd_operation(7, 7, KEY_GUID, false),
        Err(LcsError::RestartedSourceKeyNotFound)
    );
}

#[test]
fn unrelated_key_fd_is_not_affected_by_a_different_source_restart() {
    assert_eq!(
        plan_source_restart_key_fd_operation(7, 8, KEY_GUID, false),
        Ok(SourceRestartKeyFdPlan {
            affected_by_resume: false,
            dispatch_to_source: false,
        })
    );
}

#[test]
fn restart_key_fd_planning_rejects_corrupt_nil_key_guid() {
    assert_eq!(
        plan_source_restart_key_fd_operation(7, 7, [0; 16], true),
        Err(LcsError::NilKeyGuid)
    );
}
