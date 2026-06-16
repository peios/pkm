use lcs_core::{BackupRestoreProcessedKeySet, Guid, LcsError, NIL_GUID};

const TARGET_ROOT: Guid = [0x60; 16];
const CHILD: Guid = [0x61; 16];
const GRANDCHILD: Guid = [0x62; 16];
const EXTRA: Guid = [0x63; 16];

#[test]
fn processed_key_set_starts_empty_and_preserves_stream_order() {
    let mut storage = [[0u8; 16]; 3];
    let mut processed = BackupRestoreProcessedKeySet::new(&mut storage);

    assert!(processed.is_empty());
    assert_eq!(processed.len(), 0);
    assert_eq!(processed.capacity(), 3);

    assert_eq!(
        processed.mark_non_root_key_processed(TARGET_ROOT, CHILD),
        Ok(())
    );
    assert_eq!(
        processed.mark_non_root_key_processed(TARGET_ROOT, GRANDCHILD),
        Ok(())
    );

    assert_eq!(processed.as_slice(), &[CHILD, GRANDCHILD]);
    assert!(processed.contains(CHILD));
    assert!(processed.contains(GRANDCHILD));
    assert!(!processed.contains(EXTRA));
}

#[test]
fn processed_key_set_rejects_nil_root_or_key() {
    let mut storage = [[0u8; 16]; 1];
    let mut processed = BackupRestoreProcessedKeySet::new(&mut storage);

    assert_eq!(
        processed.mark_non_root_key_processed(NIL_GUID, CHILD),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        processed.mark_non_root_key_processed(TARGET_ROOT, NIL_GUID),
        Err(LcsError::NilKeyGuid)
    );
    assert!(processed.is_empty());
}

#[test]
fn processed_key_set_rejects_target_root_as_non_root_key() {
    let mut storage = [[0u8; 16]; 1];
    let mut processed = BackupRestoreProcessedKeySet::new(&mut storage);

    assert_eq!(
        processed.mark_non_root_key_processed(TARGET_ROOT, TARGET_ROOT),
        Err(LcsError::BackupRestoreRootKeyCreateNotAllowed { guid: TARGET_ROOT })
    );
    assert!(processed.is_empty());
}

#[test]
fn processed_key_set_rejects_duplicate_keys_without_mutating_order() {
    let mut storage = [[0u8; 16]; 2];
    let mut processed = BackupRestoreProcessedKeySet::new(&mut storage);

    assert_eq!(
        processed.mark_non_root_key_processed(TARGET_ROOT, CHILD),
        Ok(())
    );
    assert_eq!(
        processed.mark_non_root_key_processed(TARGET_ROOT, CHILD),
        Err(LcsError::DuplicateBackupKeyGuid { guid: CHILD })
    );
    assert_eq!(processed.as_slice(), &[CHILD]);
}

#[test]
fn processed_key_set_fails_closed_when_storage_is_full() {
    let mut storage = [[0u8; 16]; 1];
    let mut processed = BackupRestoreProcessedKeySet::new(&mut storage);

    assert_eq!(
        processed.mark_non_root_key_processed(TARGET_ROOT, CHILD),
        Ok(())
    );
    assert_eq!(
        processed.mark_non_root_key_processed(TARGET_ROOT, GRANDCHILD),
        Err(LcsError::BackupRestoreProcessedKeySetFull { capacity: 1 })
    );
    assert_eq!(processed.as_slice(), &[CHILD]);
}
