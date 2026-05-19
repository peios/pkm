use lcs_core::{
    EnumValueOutcome, EnumValueOutputBuffers, EnumeratedValue, OutputBufferAggregate,
    OutputBufferDecision, OutputBufferRequest, REG_BINARY, REG_DWORD, RegistryValueType,
    ResolvedValueEntry, enum_value_result_at, packed_batch_value_len,
    query_values_batch_required_len, validate_enum_value_output_buffers,
    validate_query_values_batch_output,
};

fn value<'a>(name: &'a str, value_type: RegistryValueType, data: &'a [u8]) -> EnumeratedValue<'a> {
    EnumeratedValue {
        name,
        value: ResolvedValueEntry {
            value_type,
            data,
            layer: "base",
            precedence: 0,
            sequence: 1,
        },
    }
}

#[test]
fn batch_value_packed_size_matches_psd_005_layout() {
    let first_data = [1, 2, 3];
    let second_data = [4, 5];
    let values = [
        value("Alpha", RegistryValueType::Binary, &first_data),
        value("", RegistryValueType::Dword, &second_data),
    ];

    assert_eq!(packed_batch_value_len(&values[0]), Ok(12 + 5 + 3));
    assert_eq!(packed_batch_value_len(&values[1]), Ok(12 + 0 + 2));
    assert_eq!(
        query_values_batch_required_len(&values),
        Ok((12 + 5 + 3) + (12 + 0 + 2))
    );
}

#[test]
fn batch_output_buffer_fit_reports_count_and_required_len() {
    let data = [1, 2, 3];
    let values = [value("Alpha", RegistryValueType::Binary, &data)];
    let required = 12 + "Alpha".len() + data.len();

    let decision = validate_query_values_batch_output(
        &values,
        OutputBufferRequest {
            buffer_len: required,
            pointer_present: true,
        },
    )
    .expect("batch output sizing should validate");

    assert_eq!(decision.count, 1);
    assert_eq!(decision.required_len, required);
    assert_eq!(
        decision.buffer,
        OutputBufferDecision::Fits {
            provided_len: required,
            required_len: required,
        }
    );
    assert_eq!(decision.aggregate, OutputBufferAggregate::AllFit);
}

#[test]
fn batch_output_buffer_too_small_reports_erange_decision() {
    let data = [0; 8];
    let values = [value("Alpha", RegistryValueType::Binary, &data)];
    let required = 12 + "Alpha".len() + data.len();

    let decision = validate_query_values_batch_output(
        &values,
        OutputBufferRequest {
            buffer_len: 4,
            pointer_present: true,
        },
    )
    .expect("short batch buffer should be ERANGE-class");

    assert_eq!(
        decision.buffer,
        OutputBufferDecision::TooSmall {
            provided_len: 4,
            required_len: required,
        }
    );
    assert_eq!(decision.aggregate, OutputBufferAggregate::TooSmall);
}

#[test]
fn enum_value_selects_effective_value_by_index() {
    let first_data = [1];
    let second_data = [2, 3, 4];
    let values = [
        value("First", RegistryValueType::Binary, &first_data),
        value("Second", RegistryValueType::Dword, &second_data),
    ];

    let EnumValueOutcome::Found(result) = enum_value_result_at(&values, 1) else {
        panic!("expected indexed value");
    };

    assert_eq!(result.name, "Second");
    assert_eq!(result.name_len, "Second".len());
    assert_eq!(result.value_type.code(), REG_DWORD);
    assert_eq!(result.data, &second_data);
    assert_eq!(result.data_len, second_data.len());
}

#[test]
fn enum_value_index_past_end_is_not_found() {
    let data = [1];
    let values = [value("First", RegistryValueType::Binary, &data)];

    assert_eq!(enum_value_result_at(&values, 1), EnumValueOutcome::NotFound);
}

#[test]
fn enum_value_output_buffers_are_checked_together() {
    let data = [1, 2, 3, 4];
    let values = [value("Name", RegistryValueType::Binary, &data)];
    let EnumValueOutcome::Found(result) = enum_value_result_at(&values, 0) else {
        panic!("expected indexed value");
    };

    let decision = validate_enum_value_output_buffers(
        &result,
        EnumValueOutputBuffers {
            name: OutputBufferRequest {
                buffer_len: 2,
                pointer_present: true,
            },
            data: OutputBufferRequest {
                buffer_len: data.len(),
                pointer_present: true,
            },
        },
    )
    .expect("short enum buffers should be ERANGE-class");

    assert_eq!(result.value_type.code(), REG_BINARY);
    assert_eq!(
        decision.name,
        OutputBufferDecision::TooSmall {
            provided_len: 2,
            required_len: "Name".len(),
        }
    );
    assert_eq!(
        decision.data,
        OutputBufferDecision::Fits {
            provided_len: data.len(),
            required_len: data.len(),
        }
    );
    assert_eq!(decision.aggregate, OutputBufferAggregate::TooSmall);
}
