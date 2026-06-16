use lcs_core::{
    HiveGenerationCounter, LcsError, OutputBufferAggregate, OutputBufferDecision,
    OutputBufferRequest, QueryKeyInfoInput, query_key_info_result,
    validate_query_key_info_output_buffer,
};

#[test]
fn hive_generation_increments_once_per_committed_mutation() {
    let mut generation = HiveGenerationCounter::new();

    assert_eq!(generation.current(), 0);
    assert_eq!(generation.record_committed_mutation(), Ok(1));
    assert_eq!(generation.current(), 1);
    assert_eq!(generation.record_committed_mutation(), Ok(2));
    assert_eq!(generation.current(), 2);
}

#[test]
fn hive_generation_increments_once_per_affected_transaction() {
    let mut generation = HiveGenerationCounter::from_baseline(40);

    assert_eq!(
        generation.record_committed_transaction_for_affected_hive(),
        Ok(41)
    );
    assert_eq!(generation.current(), 41);
}

#[test]
fn hive_generation_fails_closed_on_overflow() {
    let mut generation = HiveGenerationCounter::from_baseline(u64::MAX);

    assert_eq!(
        generation.record_committed_mutation(),
        Err(LcsError::HiveGenerationOverflow)
    );
    assert_eq!(generation.current(), u64::MAX);
}

#[test]
fn query_key_info_result_shapes_metadata_and_generation() {
    let result = query_key_info_result(QueryKeyInfoInput {
        name: "Child",
        last_write_time: 123,
        subkey_count: 2,
        value_count: 3,
        max_subkey_name_len: 8,
        max_value_name_len: 12,
        max_value_data_size: 64,
        sd_size: 96,
        volatile: true,
        symlink: false,
        hive_generation: 55,
    });

    assert_eq!(result.name, "Child");
    assert_eq!(result.name_len, "Child".len());
    assert_eq!(result.last_write_time, 123);
    assert_eq!(result.subkey_count, 2);
    assert_eq!(result.value_count, 3);
    assert_eq!(result.max_subkey_name_len, 8);
    assert_eq!(result.max_value_name_len, 12);
    assert_eq!(result.max_value_data_size, 64);
    assert_eq!(result.sd_size, 96);
    assert!(result.volatile);
    assert!(!result.symlink);
    assert_eq!(result.hive_generation, 55);
}

#[test]
fn query_key_info_name_buffer_sizing_matches_variable_output_abi() {
    let result = query_key_info_result(QueryKeyInfoInput {
        name: "Child",
        last_write_time: 0,
        subkey_count: 0,
        value_count: 0,
        max_subkey_name_len: 0,
        max_value_name_len: 0,
        max_value_data_size: 0,
        sd_size: 0,
        volatile: false,
        symlink: true,
        hive_generation: 1,
    });

    let fit = validate_query_key_info_output_buffer(
        &result,
        OutputBufferRequest {
            buffer_len: "Child".len(),
            pointer_present: true,
        },
    )
    .expect("name buffer should validate");
    assert_eq!(
        fit.name,
        OutputBufferDecision::Fits {
            provided_len: "Child".len(),
            required_len: "Child".len(),
        }
    );
    assert_eq!(fit.aggregate, OutputBufferAggregate::AllFit);

    let short = validate_query_key_info_output_buffer(
        &result,
        OutputBufferRequest {
            buffer_len: 2,
            pointer_present: true,
        },
    )
    .expect("short name buffer should be ERANGE-class");
    assert_eq!(
        short.name,
        OutputBufferDecision::TooSmall {
            provided_len: 2,
            required_len: "Child".len(),
        }
    );
    assert_eq!(short.aggregate, OutputBufferAggregate::TooSmall);
}
