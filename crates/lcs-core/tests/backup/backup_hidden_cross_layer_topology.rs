use crate::common::{limits, system_sid};
use lcs_core::{
    BackupKeyPayload, BackupPathEntryPayload, BackupRestoreNonRootKeyCreatePlan,
    BackupRestoreTopologyKeySectionPlan, BackupRestoreTopologyState, Guid, LcsError,
    NIL_GUID, PathTarget, parse_backup_path_entry_record, write_backup_key_record_frame,
    write_backup_path_entry_record_frame,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const HEADER_ROOT: Guid = [0x10; 16];
const TARGET_ROOT: Guid = [0x20; 16];
const PARENT: Guid = [0x31; 16];
const CHILD: Guid = [0x32; 16];



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
    layer_name: &'static str,
) -> BackupPathEntryPayload<'static> {
    BackupPathEntryPayload {
        parent_guid,
        child_name,
        target,
        layer_name,
        sequence: 10,
    }
}

#[test]
fn hidden_path_entry_round_trips_but_nil_guid_key_record_is_rejected() {
    let mut frame = [0u8; 128];
    let len = write_backup_path_entry_record_frame(
        &limits(),
        &mut frame,
        HEADER_ROOT,
        "masked",
        PathTarget::Hidden,
        "overlay",
        0x0102_0304_0506_0708,
    )
    .unwrap();
    let hidden = parse_backup_path_entry_record(&limits(), &frame[..len]).unwrap();

    assert_eq!(hidden.parent_guid, HEADER_ROOT);
    assert_eq!(hidden.child_name, "masked");
    assert_eq!(hidden.target, PathTarget::Hidden);
    assert_eq!(hidden.layer_name, "overlay");
    assert_eq!(hidden.sequence, 0x0102_0304_0506_0708);

    let sd = owner_only_sd();
    let mut key_frame = [0xaa; 128];
    assert_eq!(
        write_backup_key_record_frame(&mut key_frame, NIL_GUID, false, false, &sd, 100),
        Err(LcsError::NilKeyGuid)
    );
    assert!(key_frame.iter().all(|byte| *byte == 0xaa));
}

#[test]
fn restore_topology_accepts_parent_named_in_different_layer() {
    let sd = owner_only_sd();
    let mut storage = [[0u8; 16]; 2];
    let mut topology =
        BackupRestoreTopologyState::new(HEADER_ROOT, TARGET_ROOT, &mut storage).unwrap();

    assert!(
        topology
            .observe_key_section(key(HEADER_ROOT, &sd), &[])
            .is_ok()
    );

    let parent_entries = [path_entry(
        HEADER_ROOT,
        "parent",
        PathTarget::Guid(PARENT),
        "base",
    )];
    assert!(
        topology
            .observe_key_section(key(PARENT, &sd), &parent_entries)
            .is_ok()
    );

    let child_entries = [path_entry(
        PARENT,
        "child",
        PathTarget::Guid(CHILD),
        "policy",
    )];
    assert_eq!(
        topology.observe_key_section(key(CHILD, &sd), &child_entries),
        Ok(BackupRestoreTopologyKeySectionPlan::NonRoot(
            BackupRestoreNonRootKeyCreatePlan {
                guid: CHILD,
                parent_guid: PARENT,
                child_name: "child",
                security_descriptor: sd.as_slice(),
                volatile: false,
                symlink: false,
                anchor_path_entry_index: 0,
            }
        ))
    );
    assert_eq!(topology.processed_non_root_key_guids(), &[PARENT, CHILD]);
}
