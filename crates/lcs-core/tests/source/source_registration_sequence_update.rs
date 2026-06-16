use lcs_core::{
    LcsError, SequenceCounter, SourceRegistrationSequencePlan,
    apply_source_registration_sequence_update, plan_source_registration_sequence_update,
};

#[test]
fn startup_source_registration_initializes_from_reported_max_sequence() {
    assert_eq!(
        plan_source_registration_sequence_update(None, 41),
        Ok(SourceRegistrationSequencePlan {
            previous_next_sequence: None,
            source_next_sequence: 42,
            effective_next_sequence: 42,
            initializes_counter: true,
            advances_existing_counter: false,
            source_may_be_made_active: true,
        })
    );
}

#[test]
fn later_source_registration_preserves_or_advances_existing_counter() {
    assert_eq!(
        plan_source_registration_sequence_update(Some(100), 41),
        Ok(SourceRegistrationSequencePlan {
            previous_next_sequence: Some(100),
            source_next_sequence: 42,
            effective_next_sequence: 100,
            initializes_counter: false,
            advances_existing_counter: false,
            source_may_be_made_active: true,
        })
    );
    assert_eq!(
        plan_source_registration_sequence_update(Some(100), 150),
        Ok(SourceRegistrationSequencePlan {
            previous_next_sequence: Some(100),
            source_next_sequence: 151,
            effective_next_sequence: 151,
            initializes_counter: false,
            advances_existing_counter: true,
            source_may_be_made_active: true,
        })
    );
}

#[test]
fn applying_registration_update_mutates_initialized_counter_to_effective_sequence() {
    let mut counter = SequenceCounter::new(100);

    assert_eq!(
        apply_source_registration_sequence_update(&mut counter, 150),
        Ok(SourceRegistrationSequencePlan {
            previous_next_sequence: Some(100),
            source_next_sequence: 151,
            effective_next_sequence: 151,
            initializes_counter: false,
            advances_existing_counter: true,
            source_may_be_made_active: true,
        })
    );
    assert_eq!(counter.next_sequence(), 151);

    assert_eq!(
        apply_source_registration_sequence_update(&mut counter, 120)
            .unwrap()
            .effective_next_sequence,
        151
    );
    assert_eq!(counter.next_sequence(), 151);
}

#[test]
fn source_registration_sequence_overflow_fails_before_source_activation() {
    let mut counter = SequenceCounter::new(100);

    assert_eq!(
        plan_source_registration_sequence_update(Some(100), u64::MAX),
        Err(LcsError::SequenceOverflow)
    );
    assert_eq!(
        apply_source_registration_sequence_update(&mut counter, u64::MAX),
        Err(LcsError::SequenceOverflow)
    );
    assert_eq!(counter.next_sequence(), 100);
}
