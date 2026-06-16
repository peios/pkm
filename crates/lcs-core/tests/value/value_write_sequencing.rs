use crate::common::{limits};
use lcs_core::{
    Guid, LcsError, REG_BINARY, REG_TOMBSTONE, SequenceCounter, ValidatedValueType,
    ValueWriteInput, plan_value_write,
};

const KEY_GUID: Guid = [0x17; 16];


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
fn value_write_planner_assigns_next_global_sequence() {
    let limits = limits();
    let mut counter = SequenceCounter::new(50);
    let planned = plan_value_write(&limits, &mut counter, &input(REG_BINARY, b"payload"))
        .expect("value write should plan");

    assert_eq!(planned.write.key_guid, KEY_GUID);
    assert_eq!(planned.write.name, "Setting");
    assert_eq!(planned.write.layer, "base");
    assert_eq!(planned.write.sequence, 50);
    assert_eq!(
        planned.write.value_type,
        ValidatedValueType::Normal(lcs_core::RegistryValueType::Binary)
    );
    assert_eq!(planned.write.data, b"payload");
    assert_eq!(planned.write.expected_sequence, None);
    assert!(planned.updates_last_write_time);
    assert_eq!(counter.next_sequence(), 51);
}

#[test]
fn value_write_planner_preserves_source_atomic_cas_sequence() {
    let limits = limits();
    let mut counter = SequenceCounter::new(9);
    let mut request = input(REG_BINARY, b"payload");
    request.expected_sequence = Some(44);

    let planned =
        plan_value_write(&limits, &mut counter, &request).expect("conditional write should plan");

    assert_eq!(planned.write.sequence, 9);
    assert_eq!(planned.write.expected_sequence, Some(44));
    assert_eq!(counter.next_sequence(), 10);
}

#[test]
fn value_write_planner_assigns_sequences_to_explicit_tombstones() {
    let limits = limits();
    let mut counter = SequenceCounter::new(100);
    let mut request = input(REG_TOMBSTONE, b"");
    request.explicit_tombstone_operation = true;

    let planned = plan_value_write(&limits, &mut counter, &request).expect("tombstone should plan");

    assert_eq!(planned.write.sequence, 100);
    assert_eq!(planned.write.value_type, ValidatedValueType::Tombstone);
    assert_eq!(planned.write.data, b"");
    assert_eq!(counter.next_sequence(), 101);
}

#[test]
fn value_write_planner_fails_closed_on_sequence_overflow() {
    let limits = limits();
    let mut counter = SequenceCounter::new(u64::MAX);

    assert_eq!(
        plan_value_write(&limits, &mut counter, &input(REG_BINARY, b"payload")),
        Err(LcsError::SequenceOverflow)
    );
    assert_eq!(counter.next_sequence(), u64::MAX);
}

#[test]
fn malformed_value_writes_do_not_consume_sequence_numbers() {
    let limits = limits();
    let mut counter = SequenceCounter::new(77);
    let request = input(0xdead_beef, b"payload");

    assert_eq!(
        plan_value_write(&limits, &mut counter, &request),
        Err(LcsError::UnknownValueType(0xdead_beef))
    );
    assert_eq!(counter.next_sequence(), 77);

    let mut bad_tombstone = input(REG_TOMBSTONE, b"x");
    bad_tombstone.explicit_tombstone_operation = true;
    assert_eq!(
        plan_value_write(&limits, &mut counter, &bad_tombstone),
        Err(LcsError::TombstoneDataMustBeEmpty { len: 1 })
    );
    assert_eq!(counter.next_sequence(), 77);
}
