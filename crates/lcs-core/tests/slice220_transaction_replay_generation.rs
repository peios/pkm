use lcs_core::{
    HiveGenerationCounter, LcsError, TransactionMutationReplaySummary,
    TransactionReplayGenerationApplyPlan, record_transaction_replay_generation,
};

fn summary(
    entries: usize,
    increment_hive_generation_once: bool,
) -> TransactionMutationReplaySummary {
    TransactionMutationReplaySummary {
        entries,
        capacity: entries,
        increment_hive_generation_once,
        key_last_write_updates: 0,
        parent_last_write_updates: 0,
        security_watch_mutations: 0,
        effective_value_recomputations: 0,
        effective_subkey_recomputations: 0,
        orphan_evaluations: 0,
        new_key_publications: 0,
    }
}

#[test]
fn transaction_replay_generation_increments_once_for_any_affected_transaction() {
    let mut counter = HiveGenerationCounter::from_baseline(41);
    let mut replay = summary(5, true);
    replay.key_last_write_updates = 2;
    replay.parent_last_write_updates = 1;
    replay.security_watch_mutations = 1;
    replay.effective_value_recomputations = 1;
    replay.effective_subkey_recomputations = 3;
    replay.orphan_evaluations = 1;
    replay.new_key_publications = 1;

    assert_eq!(
        record_transaction_replay_generation(&mut counter, &replay),
        Ok(TransactionReplayGenerationApplyPlan {
            previous_generation: 41,
            current_generation: 42,
            incremented: true,
        })
    );
    assert_eq!(counter.current(), 42);
}

#[test]
fn transaction_replay_without_generation_work_leaves_counter_unchanged() {
    let mut counter = HiveGenerationCounter::from_baseline(7);

    assert_eq!(
        record_transaction_replay_generation(&mut counter, &summary(0, false)),
        Ok(TransactionReplayGenerationApplyPlan {
            previous_generation: 7,
            current_generation: 7,
            incremented: false,
        })
    );
    assert_eq!(counter.current(), 7);
}

#[test]
fn transaction_replay_generation_overflow_fails_without_mutating_counter() {
    let mut counter = HiveGenerationCounter::from_baseline(u64::MAX);

    assert_eq!(
        record_transaction_replay_generation(&mut counter, &summary(1, true)),
        Err(LcsError::HiveGenerationOverflow)
    );
    assert_eq!(counter.current(), u64::MAX);
}

#[test]
fn impossible_replay_summaries_fail_before_counter_mutation() {
    let mut counter = HiveGenerationCounter::from_baseline(9);
    let mut impossible = summary(0, true);
    assert_eq!(
        record_transaction_replay_generation(&mut counter, &impossible),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_summary.generation",
        })
    );
    assert_eq!(counter.current(), 9);

    impossible = summary(1, false);
    impossible.capacity = 0;
    assert_eq!(
        record_transaction_replay_generation(&mut counter, &impossible),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_summary.entries",
        })
    );
    assert_eq!(counter.current(), 9);

    impossible = summary(2, false);
    impossible.key_last_write_updates = 2;
    impossible.parent_last_write_updates = 1;
    assert_eq!(
        record_transaction_replay_generation(&mut counter, &impossible),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_summary.last_write_updates",
        })
    );
    assert_eq!(counter.current(), 9);

    impossible = summary(2, false);
    impossible.security_watch_mutations = 1;
    impossible.effective_value_recomputations = 1;
    impossible.effective_subkey_recomputations = 1;
    assert_eq!(
        record_transaction_replay_generation(&mut counter, &impossible),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_summary.watch_work",
        })
    );
    assert_eq!(counter.current(), 9);

    impossible = summary(2, false);
    impossible.effective_subkey_recomputations = 1;
    impossible.orphan_evaluations = 2;
    assert_eq!(
        record_transaction_replay_generation(&mut counter, &impossible),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_summary.orphan_evaluations",
        })
    );
    assert_eq!(counter.current(), 9);
}
