use crate::common::{field, limits};
use lcs_core::{
    Guid, LcsError, REG_TOMBSTONE, RSI_REQUEST_HEADER_LEN, RegistryValueType, SequenceCounter, ValueTypeValidationErrno, ValueWriteInput,
    parse_rsi_set_value_request_payload, plan_value_write, value_type_validation_errno,
    write_planned_rsi_set_value_request_frame,
};

const KEY_GUID: Guid = [0x60; 16];



fn tombstone_input(data: &'static [u8], explicit: bool) -> ValueWriteInput<'static> {
    ValueWriteInput {
        key_guid: KEY_GUID,
        name: "Setting",
        layer: "policy",
        value_type: REG_TOMBSTONE,
        data,
        explicit_tombstone_operation: explicit,
        expected_sequence: None,
    }
}

#[test]
fn tombstone_type_is_not_a_user_visible_registry_value_type() {
    assert_eq!(RegistryValueType::from_code(REG_TOMBSTONE), None);
}

#[test]
fn explicit_zero_length_tombstone_is_the_only_planned_write_path() {
    let limits = limits();
    let mut counter = SequenceCounter::new(410);
    let planned = plan_value_write(&limits, &mut counter, &tombstone_input(b"", true))
        .expect("explicit empty tombstone should plan");
    let mut frame = [0u8; 128];

    let built = write_planned_rsi_set_value_request_frame(&mut frame, 1600, 0, &planned)
        .expect("planned tombstone should write");
    let payload = parse_rsi_set_value_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len])
        .expect("payload should parse");

    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.value_name, field(b"Setting"));
    assert_eq!(payload.layer_name, field(b"policy"));
    assert_eq!(payload.value_type, REG_TOMBSTONE);
    assert_eq!(payload.data, field(b""));
    assert_eq!(payload.sequence, 410);
    assert_eq!(counter.next_sequence(), 411);
}

#[test]
fn invalid_tombstone_write_shapes_are_einval_before_sequence_allocation() {
    let limits = limits();
    let mut counter = SequenceCounter::new(410);
    let implicit = plan_value_write(&limits, &mut counter, &tombstone_input(b"", false))
        .expect_err("implicit tombstone should fail");

    assert_eq!(implicit, LcsError::TombstoneNotExplicit);
    assert_eq!(
        value_type_validation_errno(&implicit),
        Some(ValueTypeValidationErrno::Einval)
    );
    assert_eq!(counter.next_sequence(), 410);

    let nonempty = plan_value_write(&limits, &mut counter, &tombstone_input(b"x", true))
        .expect_err("non-empty tombstone should fail");
    assert_eq!(nonempty, LcsError::TombstoneDataMustBeEmpty { len: 1 });
    assert_eq!(
        value_type_validation_errno(&nonempty),
        Some(ValueTypeValidationErrno::Einval)
    );
    assert_eq!(counter.next_sequence(), 410);
}
