use lcs_core::{LcsError, SourceDeviceOpenPlan, plan_source_device_open};

#[test]
fn source_device_open_requires_tcb_privilege() {
    assert_eq!(
        plan_source_device_open(false),
        Err(LcsError::MissingTcbPrivilege)
    );
}

#[test]
fn source_device_open_with_tcb_grants_source_fd() {
    assert_eq!(
        plan_source_device_open(true),
        Ok(SourceDeviceOpenPlan {
            grants_source_fd: true,
        })
    );
}
