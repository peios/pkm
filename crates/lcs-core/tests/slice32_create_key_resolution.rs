use lcs_core::{
    REG_CREATED_NEW, REG_OPENED_EXISTING, RegCreateKeyResolutionPlan, RegCreateKeySourceResultPlan,
    RegCreateKeyTarget, RsiStatus, plan_reg_create_key_resolution,
    plan_reg_create_key_source_result,
};

#[test]
fn create_key_existing_target_opens_existing_and_ignores_layer() {
    assert_eq!(
        plan_reg_create_key_resolution(RegCreateKeyTarget::Exists),
        RegCreateKeyResolutionPlan::OpenExisting {
            disposition: REG_OPENED_EXISTING,
            ignore_layer_parameter: true,
        }
    );
}

#[test]
fn create_key_missing_target_uses_layer_and_reports_created() {
    assert_eq!(
        plan_reg_create_key_resolution(RegCreateKeyTarget::Missing),
        RegCreateKeyResolutionPlan::CreateMissing {
            disposition: REG_CREATED_NEW,
            use_layer_parameter: true,
        }
    );
}

#[test]
fn source_create_ok_reports_new_key_created() {
    assert_eq!(
        plan_reg_create_key_source_result(RsiStatus::Ok),
        RegCreateKeySourceResultPlan::CreatedNew {
            disposition: REG_CREATED_NEW,
        }
    );
}

#[test]
fn source_already_exists_race_retries_as_open_existing() {
    assert_eq!(
        plan_reg_create_key_source_result(RsiStatus::AlreadyExists),
        RegCreateKeySourceResultPlan::RetryOpenExisting {
            disposition: REG_OPENED_EXISTING,
        }
    );
}

#[test]
fn non_race_source_failures_are_not_recast_as_eexist() {
    for status in [
        RsiStatus::NotFound,
        RsiStatus::NotEmpty,
        RsiStatus::TooLarge,
        RsiStatus::TxnBusy,
        RsiStatus::CasFailed,
        RsiStatus::Invalid,
        RsiStatus::StorageError,
        RsiStatus::TxnNotSupported,
    ] {
        assert_eq!(
            plan_reg_create_key_source_result(status),
            RegCreateKeySourceResultPlan::PropagateSourceStatus(status)
        );
    }
}
