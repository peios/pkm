use kacs_core::SE_SELF_RELATIVE;
use lcs_core::{
    OWNER_SECURITY_INFORMATION, OutputBufferAggregate, OutputBufferDecision, OutputBufferRequest,
    plan_registry_get_security, validate_registry_get_security_output_buffer,
};

fn sid(authority: u8, subauths: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + subauths.len() * 4);
    bytes.push(1);
    bytes.push(subauths.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, authority]);
    for subauth in subauths {
        bytes.extend_from_slice(&subauth.to_le_bytes());
    }
    bytes
}

fn owner_sd(owner: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    let owner_offset = bytes.len() as u32;
    bytes.extend_from_slice(owner);
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes
}

#[test]
fn get_security_fit_buffer_allows_sd_copyout() {
    let owner = sid(5, &[18]);
    let existing = owner_sd(&owner);
    let plan = plan_registry_get_security(&existing, OWNER_SECURITY_INFORMATION)
        .expect("owner subset should plan");

    let decision = validate_registry_get_security_output_buffer(
        &plan,
        OutputBufferRequest {
            buffer_len: plan.required_len,
            pointer_present: true,
        },
    )
    .expect("fit sd buffer should validate");

    assert_eq!(decision.aggregate, OutputBufferAggregate::AllFit);
    assert_eq!(
        decision.sd,
        OutputBufferDecision::Fits {
            provided_len: plan.required_len,
            required_len: plan.required_len,
        }
    );
    assert!(decision.copy_plan.fill_output_buffers);
    assert!(!decision.copy_plan.report_required_sizes);
}

#[test]
fn get_security_short_buffer_reports_required_size_without_partial_fill() {
    let owner = sid(5, &[18]);
    let existing = owner_sd(&owner);
    let plan = plan_registry_get_security(&existing, OWNER_SECURITY_INFORMATION)
        .expect("owner subset should plan");

    let decision = validate_registry_get_security_output_buffer(
        &plan,
        OutputBufferRequest {
            buffer_len: 4,
            pointer_present: true,
        },
    )
    .expect("short sd buffer is ERANGE-class");

    assert_eq!(decision.aggregate, OutputBufferAggregate::TooSmall);
    assert_eq!(
        decision.sd,
        OutputBufferDecision::TooSmall {
            provided_len: 4,
            required_len: plan.required_len,
        }
    );
    assert!(!decision.copy_plan.fill_output_buffers);
    assert!(decision.copy_plan.report_required_sizes);
}

#[test]
fn get_security_zero_length_probe_ignores_pointer_and_reports_required_size() {
    let owner = sid(5, &[18]);
    let existing = owner_sd(&owner);
    let plan = plan_registry_get_security(&existing, OWNER_SECURITY_INFORMATION)
        .expect("owner subset should plan");

    for pointer_present in [false, true] {
        let decision = validate_registry_get_security_output_buffer(
            &plan,
            OutputBufferRequest {
                buffer_len: 0,
                pointer_present,
            },
        )
        .expect("zero-length probe should be ERANGE-class");

        assert_eq!(decision.aggregate, OutputBufferAggregate::TooSmall);
        assert_eq!(
            decision.sd,
            OutputBufferDecision::TooSmall {
                provided_len: 0,
                required_len: plan.required_len,
            }
        );
        assert!(!decision.copy_plan.fill_output_buffers);
        assert!(decision.copy_plan.report_required_sizes);
    }
}
