use lcs_core::{
    OutputBufferAggregate, OutputBufferDecision, OutputBufferRequest, plan_output_buffer_copy,
    validate_output_buffer_required_size,
};

#[test]
fn all_fit_plan_allows_output_buffer_fills() {
    let decisions = [
        OutputBufferDecision::Fits {
            provided_len: 16,
            required_len: 16,
        },
        OutputBufferDecision::Fits {
            provided_len: 64,
            required_len: 32,
        },
    ];

    let plan = plan_output_buffer_copy(&decisions);

    assert_eq!(plan.aggregate, OutputBufferAggregate::AllFit);
    assert!(plan.fill_output_buffers);
    assert!(!plan.report_required_sizes);
}

#[test]
fn any_too_small_plan_reports_sizes_without_partial_fills() {
    let decisions = [
        OutputBufferDecision::Fits {
            provided_len: 16,
            required_len: 16,
        },
        OutputBufferDecision::TooSmall {
            provided_len: 4,
            required_len: 32,
        },
        OutputBufferDecision::Fits {
            provided_len: 9,
            required_len: 8,
        },
    ];

    let plan = plan_output_buffer_copy(&decisions);

    assert_eq!(plan.aggregate, OutputBufferAggregate::TooSmall);
    assert!(!plan.fill_output_buffers);
    assert!(plan.report_required_sizes);
}

#[test]
fn multiple_too_small_buffers_share_one_erange_plan() {
    let decisions = [
        validate_output_buffer_required_size(
            OutputBufferRequest {
                buffer_len: 0,
                pointer_present: false,
            },
            12,
        )
        .unwrap(),
        validate_output_buffer_required_size(
            OutputBufferRequest {
                buffer_len: 3,
                pointer_present: true,
            },
            9,
        )
        .unwrap(),
    ];

    let plan = plan_output_buffer_copy(&decisions);

    assert_eq!(plan.aggregate, OutputBufferAggregate::TooSmall);
    assert!(!plan.fill_output_buffers);
    assert!(plan.report_required_sizes);
    assert_eq!(
        decisions,
        [
            OutputBufferDecision::TooSmall {
                provided_len: 0,
                required_len: 12,
            },
            OutputBufferDecision::TooSmall {
                provided_len: 3,
                required_len: 9,
            },
        ]
    );
}
