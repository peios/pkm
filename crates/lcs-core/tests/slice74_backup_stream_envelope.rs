use lcs_core::{
    BACKUP_TRAILER_CHECKSUM_LEN, BackupRecordKind, BackupStreamEnvelopeState,
    BackupStreamEnvelopeSummary, BackupTrailerPayload, LcsError,
};

const CHECKSUM: [u8; BACKUP_TRAILER_CHECKSUM_LEN] = [0x42; BACKUP_TRAILER_CHECKSUM_LEN];

fn observe_all(kinds: &[BackupRecordKind]) -> Result<BackupStreamEnvelopeState, LcsError> {
    let mut state = BackupStreamEnvelopeState::new();
    for kind in kinds {
        state.observe_record(*kind)?;
    }
    Ok(state)
}

#[test]
fn backup_stream_envelope_accepts_header_unknown_records_and_final_trailer() {
    let state = observe_all(&[
        BackupRecordKind::Header,
        BackupRecordKind::Unknown(0x8000),
        BackupRecordKind::LayerManifest,
        BackupRecordKind::Key,
        BackupRecordKind::Trailer,
    ])
    .unwrap();

    assert_eq!(state.records_seen(), 5);
    assert!(state.header_seen());
    assert!(state.trailer_seen());
    assert_eq!(
        state.finish(
            BackupTrailerPayload {
                record_count: 5,
                checksum: CHECKSUM,
            },
            CHECKSUM,
        ),
        Ok(BackupStreamEnvelopeSummary { record_count: 5 })
    );
}

#[test]
fn backup_stream_envelope_rejects_non_header_first_record() {
    let mut state = BackupStreamEnvelopeState::new();
    assert_eq!(
        state.observe_record(BackupRecordKind::Unknown(0x8000)),
        Err(LcsError::BackupStreamFirstRecordNotHeader { actual: 0x8000 })
    );
    assert_eq!(state.records_seen(), 0);
    assert!(!state.header_seen());
}

#[test]
fn backup_stream_envelope_rejects_duplicate_header_records() {
    let mut state = BackupStreamEnvelopeState::new();
    state.observe_record(BackupRecordKind::Header).unwrap();
    state
        .observe_record(BackupRecordKind::LayerManifest)
        .unwrap();

    assert_eq!(
        state.observe_record(BackupRecordKind::Header),
        Err(LcsError::BackupStreamDuplicateHeader { index: 2 })
    );
    assert_eq!(state.records_seen(), 2);
}

#[test]
fn backup_stream_envelope_rejects_records_after_trailer() {
    let mut state = BackupStreamEnvelopeState::new();
    state.observe_record(BackupRecordKind::Header).unwrap();
    state.observe_record(BackupRecordKind::Trailer).unwrap();

    assert_eq!(
        state.observe_record(BackupRecordKind::Value),
        Err(LcsError::BackupStreamRecordAfterTrailer {
            index: 2,
            record_type: BackupRecordKind::Value.code(),
        })
    );
    assert_eq!(state.records_seen(), 2);
}

#[test]
fn backup_stream_envelope_finish_requires_header_and_trailer() {
    let empty = BackupStreamEnvelopeState::new();
    assert_eq!(
        empty.finish(
            BackupTrailerPayload {
                record_count: 2,
                checksum: CHECKSUM,
            },
            CHECKSUM,
        ),
        Err(LcsError::BackupStreamMissingHeader)
    );

    let state = observe_all(&[BackupRecordKind::Header, BackupRecordKind::Key]).unwrap();
    assert_eq!(
        state.finish(
            BackupTrailerPayload {
                record_count: 2,
                checksum: CHECKSUM,
            },
            CHECKSUM,
        ),
        Err(LcsError::BackupStreamMissingTrailer)
    );
}

#[test]
fn backup_stream_envelope_finish_checks_record_count_and_checksum() {
    let state = observe_all(&[
        BackupRecordKind::Header,
        BackupRecordKind::Key,
        BackupRecordKind::Trailer,
    ])
    .unwrap();

    assert_eq!(
        state.finish(
            BackupTrailerPayload {
                record_count: 4,
                checksum: CHECKSUM,
            },
            CHECKSUM,
        ),
        Err(LcsError::BackupStreamRecordCountMismatch {
            declared: 4,
            observed: 3,
        })
    );

    let computed = [0x24; BACKUP_TRAILER_CHECKSUM_LEN];
    assert_eq!(
        state.finish(
            BackupTrailerPayload {
                record_count: 3,
                checksum: CHECKSUM,
            },
            computed,
        ),
        Err(LcsError::BackupStreamChecksumMismatch {
            declared: CHECKSUM,
            computed,
        })
    );
}
