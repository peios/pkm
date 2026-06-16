use lcs_core::{
    EnumSubkeyOutcome, EnumeratedSubkey, EnumeratedSubkeyInfo, Guid, LcsError,
    OutputBufferAggregate, OutputBufferDecision, OutputBufferRequest, ResolvedPathEntry,
    enum_subkey_result_at, validate_enum_subkey_output_buffer,
};

const CHILD_GUID: Guid = [0x20; 16];

fn subkey<'a>(name: &'a str) -> EnumeratedSubkeyInfo<'a> {
    EnumeratedSubkeyInfo {
        subkey: EnumeratedSubkey {
            child_name: name,
            path: ResolvedPathEntry {
                guid: CHILD_GUID,
                layer: "base",
                precedence: 0,
                sequence: 1,
            },
        },
        last_write_time: 123,
        subkey_count: 2,
        value_count: 3,
    }
}

#[test]
fn enum_subkey_selects_visible_child_and_metadata_by_index() {
    let subkeys = [subkey("First"), subkey("Second")];

    let EnumSubkeyOutcome::Found(result) = enum_subkey_result_at(&subkeys, 1) else {
        panic!("expected indexed subkey");
    };

    assert_eq!(result.name, "Second");
    assert_eq!(result.name_len, "Second".len());
    assert_eq!(result.last_write_time, 123);
    assert_eq!(result.subkey_count, 2);
    assert_eq!(result.value_count, 3);
}

#[test]
fn enum_subkey_index_past_end_is_not_found() {
    let subkeys = [subkey("Only")];

    assert_eq!(
        enum_subkey_result_at(&subkeys, 1),
        EnumSubkeyOutcome::NotFound
    );
}

#[test]
fn enum_subkey_name_buffer_fit_allows_output() {
    let subkeys = [subkey("Child")];
    let EnumSubkeyOutcome::Found(result) = enum_subkey_result_at(&subkeys, 0) else {
        panic!("expected indexed subkey");
    };

    let decision = validate_enum_subkey_output_buffer(
        &result,
        OutputBufferRequest {
            buffer_len: "Child".len(),
            pointer_present: true,
        },
    )
    .expect("name buffer should validate");

    assert_eq!(
        decision.name,
        OutputBufferDecision::Fits {
            provided_len: "Child".len(),
            required_len: "Child".len(),
        }
    );
    assert_eq!(decision.aggregate, OutputBufferAggregate::AllFit);
}

#[test]
fn enum_subkey_name_buffer_shortfall_is_erange_class() {
    let subkeys = [subkey("Child")];
    let EnumSubkeyOutcome::Found(result) = enum_subkey_result_at(&subkeys, 0) else {
        panic!("expected indexed subkey");
    };

    let decision = validate_enum_subkey_output_buffer(
        &result,
        OutputBufferRequest {
            buffer_len: 2,
            pointer_present: true,
        },
    )
    .expect("short name buffer should be ERANGE-class");

    assert_eq!(
        decision.name,
        OutputBufferDecision::TooSmall {
            provided_len: 2,
            required_len: "Child".len(),
        }
    );
    assert_eq!(decision.aggregate, OutputBufferAggregate::TooSmall);
}

#[test]
fn enum_subkey_nonzero_null_name_buffer_is_efault_class() {
    let subkeys = [subkey("Child")];
    let EnumSubkeyOutcome::Found(result) = enum_subkey_result_at(&subkeys, 0) else {
        panic!("expected indexed subkey");
    };

    assert_eq!(
        validate_enum_subkey_output_buffer(
            &result,
            OutputBufferRequest {
                buffer_len: "Child".len(),
                pointer_present: false,
            },
        ),
        Err(LcsError::MissingOutputBufferPointer { len: "Child".len() })
    );
}
