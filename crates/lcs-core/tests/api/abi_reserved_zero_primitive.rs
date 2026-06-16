use lcs_core::{LcsError, validate_abi_reserved_zero, validate_notify_reserved, zero_abi_reserved};

#[test]
fn reserved_zero_validation_accepts_empty_and_all_zero_fields() {
    assert_eq!(validate_abi_reserved_zero("empty", &[]), Ok(()));
    assert_eq!(
        validate_abi_reserved_zero("reg_example._pad", &[0, 0, 0, 0]),
        Ok(())
    );
}

#[test]
fn reserved_zero_validation_rejects_any_non_zero_byte_with_field_identity() {
    assert_eq!(
        validate_abi_reserved_zero("reg_example._pad", &[0, 0, 1, 0]),
        Err(LcsError::NonZeroReservedBytes {
            field: "reg_example._pad",
        })
    );
}

#[test]
fn reserved_output_zeroing_clears_every_byte_before_copyout() {
    let mut reserved = [0xaa, 0xbb, 0xcc, 0xdd, 0xee];

    zero_abi_reserved(&mut reserved);

    assert_eq!(reserved, [0, 0, 0, 0, 0]);
}

#[test]
fn notify_reserved_padding_uses_shared_zero_validation() {
    assert_eq!(validate_notify_reserved([0, 0, 0]), Ok(()));
    assert_eq!(
        validate_notify_reserved([0, 1, 0]),
        Err(LcsError::NonZeroReservedBytes {
            field: "reg_notify_args._pad",
        })
    );
}
