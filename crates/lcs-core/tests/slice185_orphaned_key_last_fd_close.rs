use lcs_core::{
    Guid, LcsError, NIL_GUID, OrphanedKeyLastFdClosePlan, SourceSlotStatus,
    plan_orphaned_key_last_fd_close,
};

const KEY_GUID: Guid = [0x51; 16];

#[test]
fn active_source_last_orphan_fd_close_sends_drop_before_release() {
    assert_eq!(
        plan_orphaned_key_last_fd_close(KEY_GUID, SourceSlotStatus::Active),
        Ok(OrphanedKeyLastFdClosePlan {
            send_rsi_drop_key: true,
            dispatch_drop_before_releasing_kernel_state: true,
            release_kernel_key_state: true,
            queue_deferred_drop: false,
            close_reports_cleanup_failure: false,
            source_startup_cleanup_responsible: false,
        })
    );
}

#[test]
fn down_source_last_orphan_fd_close_releases_without_deferred_drop() {
    assert_eq!(
        plan_orphaned_key_last_fd_close(KEY_GUID, SourceSlotStatus::Down),
        Ok(OrphanedKeyLastFdClosePlan {
            send_rsi_drop_key: false,
            dispatch_drop_before_releasing_kernel_state: false,
            release_kernel_key_state: true,
            queue_deferred_drop: false,
            close_reports_cleanup_failure: false,
            source_startup_cleanup_responsible: true,
        })
    );
}

#[test]
fn orphan_drop_cleanup_failure_is_never_reported_through_close() {
    for status in [SourceSlotStatus::Active, SourceSlotStatus::Down] {
        assert!(
            !plan_orphaned_key_last_fd_close(KEY_GUID, status)
                .unwrap()
                .close_reports_cleanup_failure
        );
    }
}

#[test]
fn orphan_last_fd_close_rejects_nil_guid_before_cleanup_planning() {
    assert_eq!(
        plan_orphaned_key_last_fd_close(NIL_GUID, SourceSlotStatus::Active),
        Err(LcsError::NilKeyGuid)
    );
}
