use crate::common::{limits};
use lcs_core::{
    Guid, LcsError, SequenceCounter, TransactionBinding,
    TransactionMutationAcceptanceFailure, TransactionMutationAcceptancePlan,
    TransactionMutationBindingPlan, TransactionState, TransactionUseFailure,
    plan_transaction_mutation_acceptance,
};

const ROOT_GUID: Guid = [0x71; 16];
const OTHER_ROOT_GUID: Guid = [0x72; 16];


fn binding(
    source_id: u32,
    hive_name: &'static str,
    hive_root_guid: Guid,
) -> TransactionBinding<'static> {
    TransactionBinding {
        source_id,
        hive_name,
        hive_root_guid,
    }
}

#[test]
fn accepted_transactional_mutations_allocate_sequence_at_acceptance() {
    let limits = limits();
    let target = binding(7, "Machine", ROOT_GUID);
    let mut counter = SequenceCounter::new(500);

    let first = plan_transaction_mutation_acceptance(
        &limits,
        TransactionState::ActiveUnbound,
        target,
        true,
        0,
        &mut counter,
    )
    .unwrap();
    assert_eq!(
        first,
        TransactionMutationAcceptancePlan {
            binding: TransactionMutationBindingPlan::BindNew(target),
            sequence: 500,
            sequence_assigned_at_acceptance: true,
            commit_reuses_assigned_sequence: true,
            abort_leaves_sequence_gap: true,
        }
    );
    assert_eq!(counter.next_sequence(), 501);

    let second = plan_transaction_mutation_acceptance(
        &limits,
        TransactionState::ActiveBound(target),
        target,
        true,
        1,
        &mut counter,
    )
    .unwrap();
    assert_eq!(
        second,
        TransactionMutationAcceptancePlan {
            binding: TransactionMutationBindingPlan::UseExisting(target),
            sequence: 501,
            sequence_assigned_at_acceptance: true,
            commit_reuses_assigned_sequence: true,
            abort_leaves_sequence_gap: true,
        }
    );
    assert_eq!(counter.next_sequence(), 502);
}

#[test]
fn failed_transaction_acceptance_does_not_consume_sequence() {
    let limits = limits();
    let existing = binding(7, "Machine", ROOT_GUID);
    let other_hive = binding(7, "Users", OTHER_ROOT_GUID);
    let mut counter = SequenceCounter::new(80);

    assert_eq!(
        plan_transaction_mutation_acceptance(
            &limits,
            TransactionState::ActiveBound(existing),
            other_hive,
            true,
            1,
            &mut counter,
        ),
        Err(TransactionMutationAcceptanceFailure::TransactionUse(
            TransactionUseFailure::CrossHive,
        ))
    );
    assert_eq!(counter.next_sequence(), 80);
}

#[test]
fn aborted_transaction_sequences_are_not_reused() {
    let limits = limits();
    let target = binding(7, "Machine", ROOT_GUID);
    let mut counter = SequenceCounter::new(900);

    let aborted = plan_transaction_mutation_acceptance(
        &limits,
        TransactionState::ActiveBound(target),
        target,
        true,
        1,
        &mut counter,
    )
    .unwrap();
    assert!(aborted.abort_leaves_sequence_gap);

    let later = plan_transaction_mutation_acceptance(
        &limits,
        TransactionState::ActiveBound(target),
        target,
        true,
        1,
        &mut counter,
    )
    .unwrap();

    assert_eq!(aborted.sequence, 900);
    assert_eq!(later.sequence, 901);
    assert_eq!(counter.next_sequence(), 902);
}

#[test]
fn sequence_overflow_fails_acceptance_without_advancing_counter() {
    let limits = limits();
    let target = binding(7, "Machine", ROOT_GUID);
    let mut counter = SequenceCounter::new(u64::MAX);

    assert_eq!(
        plan_transaction_mutation_acceptance(
            &limits,
            TransactionState::ActiveBound(target),
            target,
            true,
            1,
            &mut counter,
        ),
        Err(TransactionMutationAcceptanceFailure::Sequence(
            LcsError::SequenceOverflow,
        ))
    );
    assert_eq!(counter.next_sequence(), u64::MAX);
}
