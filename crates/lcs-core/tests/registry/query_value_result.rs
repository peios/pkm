use lcs_core::{
    LcsError, OutputBufferAggregate, OutputBufferDecision, OutputBufferRequest, QueryValueOutcome,
    QueryValueOutputBuffers, REG_BINARY, REG_DWORD, RegistryValueType, ResolvedValueEntry,
    ValueResolution, query_value_result_from_resolution, validate_query_value_output_buffers,
};

#[test]
fn query_value_result_exposes_effective_value_metadata() {
    let data = [1, 2, 3, 4];
    let outcome = query_value_result_from_resolution(ValueResolution::Found(ResolvedValueEntry {
        value_type: RegistryValueType::Dword,
        data: &data,
        layer: "policy",
        precedence: 10,
        sequence: 42,
    }));

    let QueryValueOutcome::Found(result) = outcome else {
        panic!("expected found query value");
    };
    assert_eq!(result.value_type.code(), REG_DWORD);
    assert_eq!(result.data, &data);
    assert_eq!(result.data_len, data.len());
    assert_eq!(result.sequence, 42);
    assert_eq!(result.layer, "policy");
    assert_eq!(result.layer_len, "policy".len());
}

#[test]
fn query_value_result_preserves_base_layer_name() {
    let outcome = query_value_result_from_resolution(ValueResolution::Found(ResolvedValueEntry {
        value_type: RegistryValueType::Binary,
        data: &[],
        layer: "base",
        precedence: 0,
        sequence: 7,
    }));

    assert_eq!(
        outcome,
        QueryValueOutcome::Found(lcs_core::QueryValueResult {
            value_type: RegistryValueType::Binary,
            data: &[],
            data_len: 0,
            sequence: 7,
            layer: "base",
            layer_len: "base".len(),
        })
    );
}

#[test]
fn query_value_not_found_represents_absent_or_masked_values() {
    assert_eq!(
        query_value_result_from_resolution(ValueResolution::NotFound),
        QueryValueOutcome::NotFound
    );
}

#[test]
fn query_value_output_buffers_fit_when_both_buffers_are_large_enough() {
    let data = [0xaa, 0xbb, 0xcc];
    let QueryValueOutcome::Found(result) =
        query_value_result_from_resolution(ValueResolution::Found(ResolvedValueEntry {
            value_type: RegistryValueType::Binary,
            data: &data,
            layer: "base",
            precedence: 0,
            sequence: 9,
        }))
    else {
        panic!("expected found query value");
    };

    let decision = validate_query_value_output_buffers(
        &result,
        QueryValueOutputBuffers {
            data: OutputBufferRequest {
                buffer_len: data.len(),
                pointer_present: true,
            },
            layer: OutputBufferRequest {
                buffer_len: "base".len(),
                pointer_present: true,
            },
        },
    )
    .expect("buffer validation should succeed");

    assert_eq!(result.value_type.code(), REG_BINARY);
    assert_eq!(
        decision.data,
        OutputBufferDecision::Fits {
            provided_len: data.len(),
            required_len: data.len(),
        }
    );
    assert_eq!(
        decision.layer,
        OutputBufferDecision::Fits {
            provided_len: "base".len(),
            required_len: "base".len(),
        }
    );
    assert_eq!(decision.aggregate, OutputBufferAggregate::AllFit);
}

#[test]
fn query_value_output_buffers_report_all_known_shortfalls() {
    let data = [0; 16];
    let QueryValueOutcome::Found(result) =
        query_value_result_from_resolution(ValueResolution::Found(ResolvedValueEntry {
            value_type: RegistryValueType::Binary,
            data: &data,
            layer: "policy",
            precedence: 1,
            sequence: 1,
        }))
    else {
        panic!("expected found query value");
    };

    let decision = validate_query_value_output_buffers(
        &result,
        QueryValueOutputBuffers {
            data: OutputBufferRequest {
                buffer_len: 8,
                pointer_present: true,
            },
            layer: OutputBufferRequest {
                buffer_len: 0,
                pointer_present: false,
            },
        },
    )
    .expect("short buffers are ERANGE-class decisions, not structural errors");

    assert_eq!(
        decision.data,
        OutputBufferDecision::TooSmall {
            provided_len: 8,
            required_len: data.len(),
        }
    );
    assert_eq!(
        decision.layer,
        OutputBufferDecision::TooSmall {
            provided_len: 0,
            required_len: "policy".len(),
        }
    );
    assert_eq!(decision.aggregate, OutputBufferAggregate::TooSmall);
}

#[test]
fn query_value_output_buffers_propagate_efault_class_shape_errors() {
    let data = [0; 4];
    let QueryValueOutcome::Found(result) =
        query_value_result_from_resolution(ValueResolution::Found(ResolvedValueEntry {
            value_type: RegistryValueType::Binary,
            data: &data,
            layer: "base",
            precedence: 0,
            sequence: 1,
        }))
    else {
        panic!("expected found query value");
    };

    assert_eq!(
        validate_query_value_output_buffers(
            &result,
            QueryValueOutputBuffers {
                data: OutputBufferRequest {
                    buffer_len: data.len(),
                    pointer_present: false,
                },
                layer: OutputBufferRequest {
                    buffer_len: "base".len(),
                    pointer_present: true,
                },
            },
        ),
        Err(LcsError::MissingOutputBufferPointer { len: data.len() })
    );
}
