use lcs_core::{HiveStatus, KeyFdHiveView, LcsError, LcsLimits, RSI_FLUSH, plan_flush_for_key_fd};

#[test]
fn flush_plan_targets_key_fd_hive_name_and_source() {
    let plan = plan_flush_for_key_fd(
        &LcsLimits::default(),
        &KeyFdHiveView {
            hive_name: "Machine",
            source_id: 42,
            status: HiveStatus::Active,
        },
    )
    .expect("active hive should flush");

    assert_eq!(plan.source_id, 42);
    assert_eq!(plan.hive_name, "Machine");
    assert_eq!(plan.rsi_op_code, RSI_FLUSH);
    assert_eq!(plan.request_payload_len, 4 + "Machine".len());
}

#[test]
fn flush_rejects_unavailable_hive_source_before_dispatch() {
    assert_eq!(
        plan_flush_for_key_fd(
            &LcsLimits::default(),
            &KeyFdHiveView {
                hive_name: "Machine",
                source_id: 42,
                status: HiveStatus::Unavailable,
            },
        ),
        Err(LcsError::HiveSourceUnavailable)
    );
}

#[test]
fn flush_validates_captured_hive_name_shape() {
    assert_eq!(
        plan_flush_for_key_fd(
            &LcsLimits::default(),
            &KeyFdHiveView {
                hive_name: "CurrentUser",
                source_id: 42,
                status: HiveStatus::Active,
            },
        ),
        Err(LcsError::ReservedHiveName)
    );

    assert_eq!(
        plan_flush_for_key_fd(
            &LcsLimits::default(),
            &KeyFdHiveView {
                hive_name: "Bad/Hive",
                source_id: 42,
                status: HiveStatus::Active,
            },
        ),
        Err(LcsError::NameContainsSeparator { field: "hive_name" })
    );
}
