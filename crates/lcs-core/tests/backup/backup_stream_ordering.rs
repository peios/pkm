use lcs_core::{
    BackupRecordKind, BackupStreamOrderingPhase, BackupStreamOrderingState,
    BackupStreamOrderingSummary, LcsError,
};

fn observe_all(kinds: &[BackupRecordKind]) -> Result<BackupStreamOrderingState, LcsError> {
    let mut state = BackupStreamOrderingState::new();
    for kind in kinds {
        state.observe_record(*kind)?;
    }
    Ok(state)
}

#[test]
fn stream_ordering_accepts_manifest_then_ordered_key_sections() {
    let state = observe_all(&[
        BackupRecordKind::Header,
        BackupRecordKind::LayerManifest,
        BackupRecordKind::Unknown(0x9000),
        BackupRecordKind::Key,
        BackupRecordKind::PathEntry,
        BackupRecordKind::Unknown(0x9001),
        BackupRecordKind::Value,
        BackupRecordKind::BlanketTombstone,
        BackupRecordKind::Unknown(0x9002),
        BackupRecordKind::Key,
        BackupRecordKind::PathEntry,
        BackupRecordKind::Value,
        BackupRecordKind::Trailer,
    ])
    .unwrap();

    assert_eq!(state.phase(), BackupStreamOrderingPhase::Values);
    assert_eq!(
        state.summary(),
        BackupStreamOrderingSummary {
            record_count: 13,
            layer_manifest_count: 1,
            key_count: 2,
            path_entry_count: 2,
            value_count: 2,
            blanket_tombstone_count: 1,
            unknown_count: 3,
        }
    );
}

#[test]
fn stream_ordering_rejects_layer_manifest_after_key_data_starts() {
    assert_eq!(
        observe_all(&[
            BackupRecordKind::Header,
            BackupRecordKind::LayerManifest,
            BackupRecordKind::Key,
            BackupRecordKind::Unknown(0x9000),
            BackupRecordKind::LayerManifest,
        ]),
        Err(LcsError::BackupStreamLayerManifestAfterKeyData { index: 4 })
    );
}

#[test]
fn stream_ordering_rejects_section_records_before_first_key() {
    assert_eq!(
        observe_all(&[
            BackupRecordKind::Header,
            BackupRecordKind::Unknown(0x9000),
            BackupRecordKind::PathEntry,
        ]),
        Err(LcsError::BackupStreamRecordOutsideKeySection {
            index: 2,
            record_type: BackupRecordKind::PathEntry.code(),
        })
    );

    assert_eq!(
        observe_all(&[BackupRecordKind::Header, BackupRecordKind::Value]),
        Err(LcsError::BackupStreamRecordOutsideKeySection {
            index: 1,
            record_type: BackupRecordKind::Value.code(),
        })
    );

    assert_eq!(
        observe_all(&[BackupRecordKind::Header, BackupRecordKind::BlanketTombstone]),
        Err(LcsError::BackupStreamRecordOutsideKeySection {
            index: 1,
            record_type: BackupRecordKind::BlanketTombstone.code(),
        })
    );
}

#[test]
fn stream_ordering_rejects_path_entries_after_value_or_blanket_data() {
    assert_eq!(
        observe_all(&[
            BackupRecordKind::Key,
            BackupRecordKind::Value,
            BackupRecordKind::Unknown(0x9000),
            BackupRecordKind::PathEntry,
        ]),
        Err(LcsError::BackupStreamPathEntryAfterValueData { index: 3 })
    );

    assert_eq!(
        observe_all(&[
            BackupRecordKind::Key,
            BackupRecordKind::BlanketTombstone,
            BackupRecordKind::PathEntry,
        ]),
        Err(LcsError::BackupStreamPathEntryAfterValueData { index: 2 })
    );
}

#[test]
fn stream_ordering_rejects_values_after_blanket_data() {
    assert_eq!(
        observe_all(&[
            BackupRecordKind::Key,
            BackupRecordKind::BlanketTombstone,
            BackupRecordKind::Unknown(0x9000),
            BackupRecordKind::Value,
        ]),
        Err(LcsError::BackupStreamValueAfterBlanketData { index: 3 })
    );
}

#[test]
fn stream_ordering_key_starts_a_fresh_section_after_prior_data() {
    let state = observe_all(&[
        BackupRecordKind::Key,
        BackupRecordKind::Value,
        BackupRecordKind::BlanketTombstone,
        BackupRecordKind::Key,
        BackupRecordKind::PathEntry,
        BackupRecordKind::Value,
    ])
    .unwrap();

    assert_eq!(state.phase(), BackupStreamOrderingPhase::Values);
    assert_eq!(state.summary().key_count, 2);
    assert_eq!(state.summary().path_entry_count, 1);
    assert_eq!(state.summary().value_count, 2);
    assert_eq!(state.summary().blanket_tombstone_count, 1);
}
