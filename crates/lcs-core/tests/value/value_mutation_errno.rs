use lcs_core::{
    LcsError, LinuxErrno, REG_BINARY, REG_TOMBSTONE, SequenceCounter, ValueDataLenErrno,
    ValueLayerAdmissionErrno, ValueWriteInput, plan_value_write, value_data_len_errno,
    value_data_len_linux_errno, value_layer_admission_errno, value_layer_admission_linux_errno,
    value_type_validation_linux_errno,
};

const KEY_GUID: lcs_core::Guid = [0x65; 16];

fn input<'a>(value_type: u32, data: &'a [u8]) -> ValueWriteInput<'a> {
    ValueWriteInput {
        key_guid: KEY_GUID,
        name: "Setting",
        layer: "base",
        value_type,
        data,
        explicit_tombstone_operation: false,
        expected_sequence: None,
    }
}

#[test]
fn invalid_value_type_and_tombstone_shapes_project_to_linux_einval() {
    let limits = lcs_core::LcsLimits::default();
    let mut counter = SequenceCounter::new(700);

    let unknown = plan_value_write(&limits, &mut counter, &input(0xdead_beef, b"payload"))
        .expect_err("unknown public value type should fail");
    assert_eq!(
        value_type_validation_linux_errno(&unknown),
        Some(LinuxErrno::Einval)
    );
    assert_eq!(counter.next_sequence(), 700);

    let implicit_tombstone = plan_value_write(&limits, &mut counter, &input(REG_TOMBSTONE, b""))
        .expect_err("REG_TOMBSTONE without explicit tombstone op should fail");
    assert_eq!(
        value_type_validation_linux_errno(&implicit_tombstone),
        Some(LinuxErrno::Einval)
    );
    assert_eq!(counter.next_sequence(), 700);

    let mut nonempty_tombstone = input(REG_TOMBSTONE, b"x");
    nonempty_tombstone.explicit_tombstone_operation = true;
    let nonempty_tombstone = plan_value_write(&limits, &mut counter, &nonempty_tombstone)
        .expect_err("non-empty explicit tombstone should fail");
    assert_eq!(
        value_type_validation_linux_errno(&nonempty_tombstone),
        Some(LinuxErrno::Einval)
    );
    assert_eq!(counter.next_sequence(), 700);
}

#[test]
fn value_size_and_layer_capacity_failures_project_to_linux_enospc() {
    let size_error = LcsError::ValueDataTooLarge { len: 5, max: 4 };
    assert_eq!(
        value_data_len_errno(&size_error),
        Some(ValueDataLenErrno::Enospc)
    );
    assert_eq!(
        value_data_len_linux_errno(&size_error),
        Some(LinuxErrno::Enospc)
    );

    let layer_error = LcsError::TooManyLayersPerValue {
        count: 128,
        max: 128,
    };
    assert_eq!(
        value_layer_admission_errno(&layer_error),
        Some(ValueLayerAdmissionErrno::Enospc)
    );
    assert_eq!(
        value_layer_admission_linux_errno(&layer_error),
        Some(LinuxErrno::Enospc)
    );
}

#[test]
fn valid_value_mutation_states_have_no_linux_errno_projection() {
    let limits = lcs_core::LcsLimits::default();
    let mut counter = SequenceCounter::new(700);
    let planned = plan_value_write(&limits, &mut counter, &input(REG_BINARY, b"payload"))
        .expect("valid value write should plan");

    assert_eq!(planned.write.sequence, 700);
    assert_eq!(
        value_type_validation_linux_errno(&LcsError::SequenceOverflow),
        None
    );
    assert_eq!(
        value_data_len_linux_errno(&LcsError::SequenceOverflow),
        None
    );
    assert_eq!(
        value_layer_admission_linux_errno(&LcsError::SequenceOverflow),
        None
    );
}
