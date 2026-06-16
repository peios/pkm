use lcs_core::{BackupRestoreSequenceRemapper, LcsError};

#[test]
fn restore_sequence_remapper_offsets_backup_sequences_and_tracks_max() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(remapper.restore_sequence_offset(), 100);
    assert_eq!(remapper.record_dispatched(5), Ok(105));
    assert_eq!(remapper.record_dispatched(1), Ok(101));
    assert_eq!(remapper.record_dispatched(9), Ok(109));
    assert_eq!(remapper.dispatched_count(), 3);
    assert_eq!(remapper.max_dispatched_sequence(), Some(109));
    assert_eq!(remapper.terminal_next_sequence(100), Ok(110));
}

#[test]
fn restore_sequence_terminal_advance_never_decrements_current_next_sequence() {
    let mut remapper = BackupRestoreSequenceRemapper::new(100);
    assert_eq!(remapper.record_dispatched(5), Ok(105));

    assert_eq!(remapper.terminal_next_sequence(200), Ok(200));
}

#[test]
fn restore_sequence_without_dispatch_does_not_require_gate_advancement() {
    let remapper = BackupRestoreSequenceRemapper::new(100);

    assert_eq!(remapper.max_dispatched_sequence(), None);
    assert_eq!(remapper.dispatched_count(), 0);
    assert_eq!(remapper.terminal_next_sequence(100), Ok(100));
}

#[test]
fn restore_sequence_remapper_fails_before_dispatch_on_addition_overflow() {
    let mut remapper = BackupRestoreSequenceRemapper::new(u64::MAX - 4);

    assert_eq!(
        remapper.record_dispatched(5),
        Err(LcsError::SequenceOverflow)
    );
    assert_eq!(remapper.dispatched_count(), 0);
    assert_eq!(remapper.max_dispatched_sequence(), None);
}

#[test]
fn restore_sequence_remapper_fails_before_dispatch_when_terminal_advance_would_overflow() {
    let mut remapper = BackupRestoreSequenceRemapper::new(u64::MAX);

    assert_eq!(
        remapper.record_dispatched(0),
        Err(LcsError::SequenceOverflow)
    );
    assert_eq!(remapper.dispatched_count(), 0);
    assert_eq!(remapper.max_dispatched_sequence(), None);
}
