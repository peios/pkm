use lcs_core::{
    LcsError, OutputBufferAggregate, OutputBufferDecision, OutputBufferRequest, OutputBufferShape,
    aggregate_output_buffer_decisions, classify_output_buffer_request,
    validate_output_buffer_required_size,
};

#[test]
fn zero_length_buffers_are_probes_and_ignore_pointer_value() {
    for pointer_present in [false, true] {
        let request = OutputBufferRequest {
            buffer_len: 0,
            pointer_present,
        };

        assert_eq!(
            classify_output_buffer_request(request),
            Ok(OutputBufferShape::Probe)
        );
    }
}

#[test]
fn non_zero_buffers_require_non_null_pointer() {
    assert_eq!(
        classify_output_buffer_request(OutputBufferRequest {
            buffer_len: 8,
            pointer_present: true,
        }),
        Ok(OutputBufferShape::WritableCandidate { len: 8 })
    );

    assert_eq!(
        classify_output_buffer_request(OutputBufferRequest {
            buffer_len: 8,
            pointer_present: false,
        }),
        Err(LcsError::MissingOutputBufferPointer { len: 8 })
    );
}

#[test]
fn required_size_comparison_drives_erange_decision() {
    assert_eq!(
        validate_output_buffer_required_size(
            OutputBufferRequest {
                buffer_len: 0,
                pointer_present: false,
            },
            32,
        ),
        Ok(OutputBufferDecision::TooSmall {
            provided_len: 0,
            required_len: 32,
        })
    );
    assert_eq!(
        validate_output_buffer_required_size(
            OutputBufferRequest {
                buffer_len: 32,
                pointer_present: true,
            },
            32,
        ),
        Ok(OutputBufferDecision::Fits {
            provided_len: 32,
            required_len: 32,
        })
    );
    assert_eq!(
        validate_output_buffer_required_size(
            OutputBufferRequest {
                buffer_len: 64,
                pointer_present: true,
            },
            32,
        ),
        Ok(OutputBufferDecision::Fits {
            provided_len: 64,
            required_len: 32,
        })
    );
}

#[test]
fn zero_length_probe_fits_when_no_output_bytes_are_required() {
    assert_eq!(
        validate_output_buffer_required_size(
            OutputBufferRequest {
                buffer_len: 0,
                pointer_present: true,
            },
            0,
        ),
        Ok(OutputBufferDecision::Fits {
            provided_len: 0,
            required_len: 0,
        })
    );
}

#[test]
fn aggregate_result_prevents_partial_output_fills() {
    let decisions = [
        OutputBufferDecision::Fits {
            provided_len: 64,
            required_len: 32,
        },
        OutputBufferDecision::TooSmall {
            provided_len: 4,
            required_len: 16,
        },
        OutputBufferDecision::Fits {
            provided_len: 8,
            required_len: 8,
        },
    ];

    assert_eq!(
        aggregate_output_buffer_decisions(&decisions),
        OutputBufferAggregate::TooSmall
    );

    let all_fit = [
        OutputBufferDecision::Fits {
            provided_len: 4,
            required_len: 4,
        },
        OutputBufferDecision::Fits {
            provided_len: 0,
            required_len: 0,
        },
    ];
    assert_eq!(
        aggregate_output_buffer_decisions(&all_fit),
        OutputBufferAggregate::AllFit
    );
}
