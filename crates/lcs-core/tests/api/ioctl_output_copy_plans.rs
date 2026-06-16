use lcs_core::{
    EnumValueOutcome, EnumValueOutputBuffers, EnumeratedSubkey, EnumeratedSubkeyInfo,
    EnumeratedValue, OutputBufferAggregate, OutputBufferRequest, QueryKeyInfoInput,
    QueryValueOutcome, QueryValueOutputBuffers, RegistryValueType, ResolvedPathEntry,
    ResolvedValueEntry, ValueResolution, enum_subkey_result_at, enum_value_result_at,
    query_key_info_result, query_value_result_from_resolution, validate_enum_subkey_output_buffer,
    validate_enum_value_output_buffers, validate_query_key_info_output_buffer,
    validate_query_value_output_buffers, validate_query_values_batch_output,
};

fn value<'a>(name: &'a str, data: &'a [u8]) -> EnumeratedValue<'a> {
    EnumeratedValue {
        name,
        value: ResolvedValueEntry {
            value_type: RegistryValueType::Binary,
            data,
            layer: "base",
            precedence: 0,
            sequence: 1,
        },
    }
}

#[test]
fn query_value_copy_plan_suppresses_both_buffers_on_erange() {
    let data = [0u8; 8];
    let QueryValueOutcome::Found(result) =
        query_value_result_from_resolution(ValueResolution::Found(ResolvedValueEntry {
            value_type: RegistryValueType::Binary,
            data: &data,
            layer: "policy",
            precedence: 1,
            sequence: 9,
        }))
    else {
        panic!("expected found value");
    };

    let decision = validate_query_value_output_buffers(
        &result,
        QueryValueOutputBuffers {
            data: OutputBufferRequest {
                buffer_len: data.len(),
                pointer_present: true,
            },
            layer: OutputBufferRequest {
                buffer_len: 1,
                pointer_present: true,
            },
        },
    )
    .expect("short layer buffer is ERANGE-class");

    assert_eq!(decision.aggregate, OutputBufferAggregate::TooSmall);
    assert!(!decision.copy_plan.fill_output_buffers);
    assert!(decision.copy_plan.report_required_sizes);
}

#[test]
fn value_batch_and_enum_value_decisions_carry_copy_plans() {
    let data = [1u8; 4];
    let values = [value("Name", &data)];

    let batch = validate_query_values_batch_output(
        &values,
        OutputBufferRequest {
            buffer_len: 1,
            pointer_present: true,
        },
    )
    .expect("short batch buffer is ERANGE-class");
    assert_eq!(batch.aggregate, OutputBufferAggregate::TooSmall);
    assert!(!batch.copy_plan.fill_output_buffers);
    assert!(batch.copy_plan.report_required_sizes);

    let EnumValueOutcome::Found(result) = enum_value_result_at(&values, 0) else {
        panic!("expected enum value");
    };
    let enum_value = validate_enum_value_output_buffers(
        &result,
        EnumValueOutputBuffers {
            name: OutputBufferRequest {
                buffer_len: result.name_len,
                pointer_present: true,
            },
            data: OutputBufferRequest {
                buffer_len: result.data_len,
                pointer_present: true,
            },
        },
    )
    .expect("fit enum value buffers should validate");
    assert_eq!(enum_value.aggregate, OutputBufferAggregate::AllFit);
    assert!(enum_value.copy_plan.fill_output_buffers);
    assert!(!enum_value.copy_plan.report_required_sizes);
}

#[test]
fn subkey_and_query_key_info_single_buffer_decisions_use_shared_copy_plan() {
    let subkeys = [EnumeratedSubkeyInfo {
        subkey: EnumeratedSubkey {
            child_name: "Child",
            path: ResolvedPathEntry {
                guid: [1u8; 16],
                layer: "base",
                precedence: 0,
                sequence: 1,
            },
        },
        last_write_time: 7,
        subkey_count: 1,
        value_count: 2,
    }];
    let lcs_core::EnumSubkeyOutcome::Found(subkey) = enum_subkey_result_at(&subkeys, 0) else {
        panic!("expected subkey");
    };
    let subkey_decision = validate_enum_subkey_output_buffer(
        &subkey,
        OutputBufferRequest {
            buffer_len: 0,
            pointer_present: false,
        },
    )
    .expect("zero-length probe is ERANGE-class for non-empty name");
    assert_eq!(subkey_decision.aggregate, OutputBufferAggregate::TooSmall);
    assert!(!subkey_decision.copy_plan.fill_output_buffers);
    assert!(subkey_decision.copy_plan.report_required_sizes);

    let key_info = query_key_info_result(QueryKeyInfoInput {
        name: "Child",
        last_write_time: 0,
        subkey_count: 0,
        value_count: 0,
        max_subkey_name_len: 0,
        max_value_name_len: 0,
        max_value_data_size: 0,
        sd_size: 0,
        volatile: false,
        symlink: false,
        hive_generation: 5,
    });
    let key_info_decision = validate_query_key_info_output_buffer(
        &key_info,
        OutputBufferRequest {
            buffer_len: key_info.name_len,
            pointer_present: true,
        },
    )
    .expect("fit key-info buffer should validate");
    assert_eq!(key_info_decision.aggregate, OutputBufferAggregate::AllFit);
    assert!(key_info_decision.copy_plan.fill_output_buffers);
    assert!(!key_info_decision.copy_plan.report_required_sizes);
}
