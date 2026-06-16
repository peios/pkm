use crate::common::{system_sid};
use lcs_core::{
    BackupKeyPayload, BackupPathEntryPayload, BackupRestoreNonRootKeyCreatePlan,
    BackupRestoreTopologyKeySectionPlan, BackupRestoreTopologyState, Guid, LcsError, NIL_GUID,
    PathTarget,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const CHILD: Guid = [0x31; 16];
const GRANDCHILD: Guid = [0x32; 16];
const OUTSIDE: Guid = [0x40; 16];


fn owner_only_sd() -> Vec<u8> {
    let owner = system_sid();
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd
}

fn key<'a>(guid: Guid, sd: &'a [u8]) -> BackupKeyPayload<'a> {
    BackupKeyPayload {
        guid,
        volatile: false,
        symlink: false,
        security_descriptor: sd,
        last_write_time_ns: 100,
    }
}

fn path_entry(
    parent_guid: Guid,
    child_name: &'static str,
    target: PathTarget,
) -> BackupPathEntryPayload<'static> {
    BackupPathEntryPayload {
        parent_guid,
        child_name,
        target,
        layer_name: "base",
        sequence: 10,
    }
}

#[test]
fn topology_accepts_root_then_parent_before_child_sections() {
    let sd = owner_only_sd();
    let mut storage = [[0u8; 16]; 2];
    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();

    assert_eq!(
        topology.observe_key_section(key(HEADER_ROOT, &sd), &[]),
        Ok(BackupRestoreTopologyKeySectionPlan::Root {
            header_root_guid: HEADER_ROOT,
            target_root_guid: TARGET_ROOT,
            security_descriptor: sd.as_slice(),
            last_write_time_ns: 100,
        })
    );
    assert!(topology.root_seen());
    assert!(topology.processed_non_root_key_guids().is_empty());

    let child_entries = [path_entry(HEADER_ROOT, "child", PathTarget::Guid(CHILD))];
    assert_eq!(
        topology.observe_key_section(key(CHILD, &sd), &child_entries),
        Ok(BackupRestoreTopologyKeySectionPlan::NonRoot(
            BackupRestoreNonRootKeyCreatePlan {
                guid: CHILD,
                parent_guid: TARGET_ROOT,
                child_name: "child",
                security_descriptor: sd.as_slice(),
                volatile: false,
                symlink: false,
                anchor_path_entry_index: 0,
            }
        ))
    );
    assert_eq!(topology.processed_non_root_key_guids(), &[CHILD]);

    let grandchild_entries = [path_entry(
        CHILD,
        "grandchild",
        PathTarget::Guid(GRANDCHILD),
    )];
    assert_eq!(
        topology.observe_key_section(key(GRANDCHILD, &sd), &grandchild_entries),
        Ok(BackupRestoreTopologyKeySectionPlan::NonRoot(
            BackupRestoreNonRootKeyCreatePlan {
                guid: GRANDCHILD,
                parent_guid: CHILD,
                child_name: "grandchild",
                security_descriptor: sd.as_slice(),
                volatile: false,
                symlink: false,
                anchor_path_entry_index: 0,
            }
        ))
    );
    assert_eq!(
        topology.processed_non_root_key_guids(),
        &[CHILD, GRANDCHILD]
    );
}

#[test]
fn topology_rejects_non_root_key_before_root_without_mutating_state() {
    let sd = owner_only_sd();
    let mut storage = [[0u8; 16]; 1];
    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();
    let entries = [path_entry(HEADER_ROOT, "child", PathTarget::Guid(CHILD))];

    assert_eq!(
        topology.observe_key_section(key(CHILD, &sd), &entries),
        Err(LcsError::BackupRestoreFirstKeyNotRoot { key_guid: CHILD })
    );
    assert!(!topology.root_seen());
    assert!(topology.processed_non_root_key_guids().is_empty());

    assert!(
        topology
            .observe_key_section(key(HEADER_ROOT, &sd), &[])
            .is_ok()
    );
    assert!(topology.root_seen());
}

#[test]
fn topology_rejects_duplicate_root_after_root_section() {
    let sd = owner_only_sd();
    let mut storage = [[0u8; 16]; 1];
    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();

    assert!(
        topology
            .observe_key_section(key(HEADER_ROOT, &sd), &[])
            .is_ok()
    );
    assert_eq!(
        topology.observe_key_section(key(HEADER_ROOT, &sd), &[]),
        Err(LcsError::BackupRestoreRootKeyDuplicate)
    );
    assert!(topology.processed_non_root_key_guids().is_empty());
}

#[test]
fn topology_rejects_child_before_parent_is_processed() {
    let sd = owner_only_sd();
    let mut storage = [[0u8; 16]; 2];
    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();
    let entries = [path_entry(
        CHILD,
        "grandchild",
        PathTarget::Guid(GRANDCHILD),
    )];

    assert!(
        topology
            .observe_key_section(key(HEADER_ROOT, &sd), &[])
            .is_ok()
    );
    assert_eq!(
        topology.observe_key_section(key(GRANDCHILD, &sd), &entries),
        Err(LcsError::BackupRestoreParentGuidOutsideSubtree { parent_guid: CHILD })
    );
    assert!(topology.processed_non_root_key_guids().is_empty());
}

#[test]
fn topology_rejects_duplicate_non_root_without_reprocessing_section() {
    let sd = owner_only_sd();
    let mut storage = [[0u8; 16]; 2];
    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();
    let entries = [path_entry(HEADER_ROOT, "child", PathTarget::Guid(CHILD))];

    assert!(
        topology
            .observe_key_section(key(HEADER_ROOT, &sd), &[])
            .is_ok()
    );
    assert!(
        topology
            .observe_key_section(key(CHILD, &sd), &entries)
            .is_ok()
    );

    assert_eq!(
        topology.observe_key_section(key(CHILD, &sd), &entries),
        Err(LcsError::DuplicateBackupKeyGuid { guid: CHILD })
    );
    assert_eq!(topology.processed_non_root_key_guids(), &[CHILD]);
}

#[test]
fn topology_fails_closed_when_processed_key_storage_is_full() {
    let sd = owner_only_sd();
    let mut storage = [[0u8; 16]; 1];
    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();
    let child_entries = [path_entry(HEADER_ROOT, "child", PathTarget::Guid(CHILD))];
    let grandchild_entries = [path_entry(
        CHILD,
        "grandchild",
        PathTarget::Guid(GRANDCHILD),
    )];

    assert!(
        topology
            .observe_key_section(key(HEADER_ROOT, &sd), &[])
            .is_ok()
    );
    assert!(
        topology
            .observe_key_section(key(CHILD, &sd), &child_entries)
            .is_ok()
    );
    assert_eq!(
        topology.observe_key_section(key(GRANDCHILD, &sd), &grandchild_entries),
        Err(LcsError::BackupRestoreProcessedKeySetFull { capacity: 1 })
    );
    assert_eq!(topology.processed_non_root_key_guids(), &[CHILD]);
}

#[test]
fn topology_rejects_nil_roots_and_nil_key_sections() {
    let sd = owner_only_sd();
    let mut storage = [[0u8; 16]; 1];

    assert_eq!(
        BackupRestoreTopologyState::new(NIL_GUID, TARGET_ROOT, &mut storage).unwrap_err(),
        LcsError::NilKeyGuid
    );
    assert_eq!(
        BackupRestoreTopologyState::new(HEADER_ROOT, NIL_GUID, &mut storage).unwrap_err(),
        LcsError::NilKeyGuid
    );

    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();
    assert_eq!(
        topology.observe_key_section(key(NIL_GUID, &sd), &[]),
        Err(LcsError::NilKeyGuid)
    );
    assert!(!topology.root_seen());
}

#[test]
fn topology_rejects_malformed_root_sd_without_marking_root_seen() {
    let mut storage = [[0u8; 16]; 1];
    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();

    assert_eq!(
        topology.observe_key_section(key(HEADER_ROOT, b"bad"), &[]),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "backup_key.sd",
        })
    );
    assert!(!topology.root_seen());
}

#[test]
fn topology_rejects_outside_parent_without_marking_key_processed() {
    let sd = owner_only_sd();
    let mut storage = [[0u8; 16]; 1];
    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();
    let entries = [path_entry(OUTSIDE, "child", PathTarget::Guid(CHILD))];

    assert!(
        topology
            .observe_key_section(key(HEADER_ROOT, &sd), &[])
            .is_ok()
    );
    assert_eq!(
        topology.observe_key_section(key(CHILD, &sd), &entries),
        Err(LcsError::BackupRestoreParentGuidOutsideSubtree {
            parent_guid: OUTSIDE,
        })
    );
    assert!(topology.processed_non_root_key_guids().is_empty());
}
