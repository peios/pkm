use crate::common::{limits};
use lcs_core::{
    Guid, LcsError, REG_BINARY, REG_TOMBSTONE, SequenceCounter,
    ValueTypeValidationErrno, ValueWriteInput, plan_value_write, value_type_validation_errno,
};

const KEY_GUID: Guid = [0x59; 16];


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
fn unknown_user_visible_value_type_is_einval_before_sequence_allocation() {
    let limits = limits();
    let mut counter = SequenceCounter::new(900);
    let error = plan_value_write(&limits, &mut counter, &input(0xdead_beef, b"payload"))
        .expect_err("unknown value type should fail before planning");

    assert_eq!(error, LcsError::UnknownValueType(0xdead_beef));
    assert_eq!(
        value_type_validation_errno(&error),
        Some(ValueTypeValidationErrno::Einval)
    );
    assert_eq!(counter.next_sequence(), 900);
}

#[test]
fn internal_tombstone_type_misuse_is_einval_before_sequence_allocation() {
    let limits = limits();
    let mut counter = SequenceCounter::new(900);
    let not_explicit = plan_value_write(&limits, &mut counter, &input(REG_TOMBSTONE, b""))
        .expect_err("implicit tombstone type should fail before planning");

    assert_eq!(not_explicit, LcsError::TombstoneNotExplicit);
    assert_eq!(
        value_type_validation_errno(&not_explicit),
        Some(ValueTypeValidationErrno::Einval)
    );
    assert_eq!(counter.next_sequence(), 900);

    let mut nonempty = input(REG_TOMBSTONE, b"x");
    nonempty.explicit_tombstone_operation = true;
    let nonempty_error = plan_value_write(&limits, &mut counter, &nonempty)
        .expect_err("non-empty tombstone should fail before planning");

    assert_eq!(
        nonempty_error,
        LcsError::TombstoneDataMustBeEmpty { len: 1 }
    );
    assert_eq!(
        value_type_validation_errno(&nonempty_error),
        Some(ValueTypeValidationErrno::Einval)
    );
    assert_eq!(counter.next_sequence(), 900);
}

#[test]
fn valid_value_type_has_no_value_type_validation_errno() {
    let limits = limits();
    let mut counter = SequenceCounter::new(900);
    let planned = plan_value_write(&limits, &mut counter, &input(REG_BINARY, b"payload"))
        .expect("normal value type should plan");

    assert_eq!(planned.write.sequence, 900);
    assert_eq!(counter.next_sequence(), 901);
    assert_eq!(
        value_type_validation_errno(&LcsError::SequenceOverflow),
        None
    );
}
