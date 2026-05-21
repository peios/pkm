// KACS file-open ABI surface for libp-files: the `kacs_open_how` /
// `kacs_mount_policy_args` structs, create dispositions, create options,
// open flags, file/directory access rights, the file generic mapping, mount
// policy values, and the open-status words.
//
// Constant *values* and struct layouts come from the generated `peios-uapi`
// crate; this module re-exposes them under the historical names libp-files'
// wrappers use. `FILE_GENERIC_MAPPING` is hand-written on
// `libp_sd::GenericMapping` (it composes file rights with the standard
// rights from libp-sd).

use libp_sd::GenericMapping;
use libp_sd::consts::{DELETE, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER};

/// On-wire layout of `struct kacs_open_how` (32 bytes). `sd_ptr` / `sd_len`
/// describe an optional self-relative security descriptor applied to a
/// newly-created file (ignored for plain opens). `__pad` must be zero.
pub use peios_uapi::kacs_open_how as KacsOpenHow;
/// On-wire layout of `struct kacs_mount_policy_args` (32 bytes).
pub use peios_uapi::kacs_mount_policy_args as KacsMountPolicyArgs;

/// Minimum `howsize` the kernel accepts for `kacs_open`.
pub const KACS_OPEN_HOW_MIN_SIZE: usize = peios_uapi::KACS_OPEN_HOW_MIN_SIZE as usize;
/// Minimum `argsize` the kernel accepts for mount-policy syscalls.
pub const KACS_MOUNT_POLICY_ARGS_MIN_SIZE: usize =
    peios_uapi::KACS_MOUNT_POLICY_ARGS_MIN_SIZE as usize;

// ---------------------------------------------------------------------------
// Create dispositions (`kacs_open_how.create_disposition`).
// ---------------------------------------------------------------------------

/// Overwrite if it exists, create if it doesn't (replacing all state).
pub const KACS_FILE_SUPERSEDE: u32 = peios_uapi::KACS_DISPOSITION_SUPERSEDE;
/// Open an existing file; fail if absent.
pub const KACS_FILE_OPEN: u32 = peios_uapi::KACS_DISPOSITION_OPEN;
/// Create a new file; fail if it already exists.
pub const KACS_FILE_CREATE: u32 = peios_uapi::KACS_DISPOSITION_CREATE;
/// Open if it exists, create if it doesn't.
pub const KACS_FILE_OPEN_IF: u32 = peios_uapi::KACS_DISPOSITION_OPEN_IF;
/// Open and truncate an existing file; fail if absent.
pub const KACS_FILE_OVERWRITE: u32 = peios_uapi::KACS_DISPOSITION_OVERWRITE;
/// Open+truncate if it exists, create if it doesn't.
pub const KACS_FILE_OVERWRITE_IF: u32 = peios_uapi::KACS_DISPOSITION_OVERWRITE_IF;

// ---------------------------------------------------------------------------
// File and directory object-specific access rights.
// ---------------------------------------------------------------------------

pub const FILE_READ_DATA: u32 = peios_uapi::KACS_FILE_READ_DATA;
pub const FILE_WRITE_DATA: u32 = peios_uapi::KACS_FILE_WRITE_DATA;
pub const FILE_APPEND_DATA: u32 = peios_uapi::KACS_FILE_APPEND_DATA;
pub const FILE_READ_EA: u32 = peios_uapi::KACS_FILE_READ_EA;
pub const FILE_WRITE_EA: u32 = peios_uapi::KACS_FILE_WRITE_EA;
pub const FILE_EXECUTE: u32 = peios_uapi::KACS_FILE_EXECUTE;
pub const FILE_DELETE_CHILD: u32 = peios_uapi::KACS_FILE_DELETE_CHILD;
pub const FILE_READ_ATTRIBUTES: u32 = peios_uapi::KACS_FILE_READ_ATTRIBUTES;
pub const FILE_WRITE_ATTRIBUTES: u32 = peios_uapi::KACS_FILE_WRITE_ATTRIBUTES;

pub const FILE_LIST_DIRECTORY: u32 = peios_uapi::KACS_FILE_LIST_DIRECTORY;
pub const FILE_ADD_FILE: u32 = peios_uapi::KACS_FILE_ADD_FILE;
pub const FILE_ADD_SUBDIRECTORY: u32 = peios_uapi::KACS_FILE_ADD_SUBDIRECTORY;
pub const FILE_TRAVERSE: u32 = peios_uapi::KACS_FILE_TRAVERSE;

/// PSD-004 file/directory mapping from generic rights to concrete rights.
pub const FILE_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
    write: FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_ATTRIBUTES
        | FILE_WRITE_EA
        | READ_CONTROL
        | SYNCHRONIZE,
    execute: FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    all: FILE_READ_DATA
        | FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_READ_EA
        | FILE_WRITE_EA
        | FILE_EXECUTE
        | FILE_DELETE_CHILD
        | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | SYNCHRONIZE,
};

// ---------------------------------------------------------------------------
// Create options (`kacs_open_how.create_options`).
// ---------------------------------------------------------------------------

/// The target must be / will be created as a directory.
pub const KACS_CREATE_OPT_DIRECTORY: u32 = peios_uapi::KACS_CREATE_OPT_DIRECTORY;
/// Delete the file when the last handle closes.
pub const KACS_CREATE_OPT_DELETE_ON_CLOSE: u32 = peios_uapi::KACS_CREATE_OPT_DELETE_ON_CLOSE;

// ---------------------------------------------------------------------------
// Flags (`kacs_open_how.flags`).
// ---------------------------------------------------------------------------

/// Open with backup intent (bypass normal access for backup operations).
pub const KACS_BACKUP_INTENT: u32 = peios_uapi::KACS_BACKUP_INTENT;
/// Open with restore intent.
pub const KACS_RESTORE_INTENT: u32 = peios_uapi::KACS_RESTORE_INTENT;

// ---------------------------------------------------------------------------
// Mount policy values (`kacs_mount_policy_args.policy`).
// ---------------------------------------------------------------------------

pub const KACS_MOUNT_POLICY_UNMANAGED: u32 = peios_uapi::KACS_MOUNT_POLICY_UNMANAGED;
pub const KACS_MOUNT_POLICY_DENY_MISSING: u32 = peios_uapi::KACS_MOUNT_POLICY_DENY_MISSING;
pub const KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL: u32 =
    peios_uapi::KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
pub const KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT: u32 =
    peios_uapi::KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT;

// ---------------------------------------------------------------------------
// Status word written to `status_out` by `kacs_open`.
// ---------------------------------------------------------------------------

/// An existing file was opened.
pub const KACS_STATUS_OPENED: u32 = peios_uapi::KACS_STATUS_OPENED;
/// A new file was created.
pub const KACS_STATUS_CREATED: u32 = peios_uapi::KACS_STATUS_CREATED;
/// An existing file was opened and truncated.
pub const KACS_STATUS_OVERWRITTEN: u32 = peios_uapi::KACS_STATUS_OVERWRITTEN;
/// An existing file was replaced wholesale.
pub const KACS_STATUS_SUPERSEDED: u32 = peios_uapi::KACS_STATUS_SUPERSEDED;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_how_is_32_bytes() {
        assert_eq!(core::mem::size_of::<KacsOpenHow>(), 32);
    }

    #[test]
    fn open_how_offsets_match_psd_004() {
        assert_eq!(core::mem::offset_of!(KacsOpenHow, desired_access), 0);
        assert_eq!(core::mem::offset_of!(KacsOpenHow, create_disposition), 4);
        assert_eq!(core::mem::offset_of!(KacsOpenHow, create_options), 8);
        assert_eq!(core::mem::offset_of!(KacsOpenHow, flags), 12);
        assert_eq!(core::mem::offset_of!(KacsOpenHow, sd_ptr), 16);
        assert_eq!(core::mem::offset_of!(KacsOpenHow, sd_len), 24);
        assert_eq!(core::mem::offset_of!(KacsOpenHow, __pad), 28);
    }

    #[test]
    fn mount_policy_args_is_32_bytes() {
        assert_eq!(core::mem::size_of::<KacsMountPolicyArgs>(), 32);
    }

    #[test]
    fn mount_policy_args_offsets_match_psd_004() {
        assert_eq!(core::mem::offset_of!(KacsMountPolicyArgs, policy), 0);
        assert_eq!(core::mem::offset_of!(KacsMountPolicyArgs, flags), 4);
        assert_eq!(core::mem::offset_of!(KacsMountPolicyArgs, generation), 8);
        assert_eq!(
            core::mem::offset_of!(KacsMountPolicyArgs, template_sd_ptr),
            16
        );
        assert_eq!(
            core::mem::offset_of!(KacsMountPolicyArgs, template_sd_len),
            24
        );
        assert_eq!(core::mem::offset_of!(KacsMountPolicyArgs, __pad0), 12);
        assert_eq!(core::mem::offset_of!(KacsMountPolicyArgs, __pad1), 28);
    }

    #[test]
    fn file_rights_match_psd_004() {
        assert_eq!(FILE_READ_DATA, 0x0001);
        assert_eq!(FILE_WRITE_DATA, 0x0002);
        assert_eq!(FILE_APPEND_DATA, 0x0004);
        assert_eq!(FILE_READ_EA, 0x0008);
        assert_eq!(FILE_WRITE_EA, 0x0010);
        assert_eq!(FILE_EXECUTE, 0x0020);
        assert_eq!(FILE_DELETE_CHILD, 0x0040);
        assert_eq!(FILE_READ_ATTRIBUTES, 0x0080);
        assert_eq!(FILE_WRITE_ATTRIBUTES, 0x0100);
    }

    #[test]
    fn directory_aliases_match_file_right_bits() {
        assert_eq!(FILE_LIST_DIRECTORY, FILE_READ_DATA);
        assert_eq!(FILE_ADD_FILE, FILE_WRITE_DATA);
        assert_eq!(FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA);
        assert_eq!(FILE_TRAVERSE, FILE_EXECUTE);
    }

    #[test]
    fn file_generic_mapping_matches_psd_004() {
        assert_eq!(
            FILE_GENERIC_MAPPING.read,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE
        );
        assert_eq!(
            FILE_GENERIC_MAPPING.write,
            FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_ATTRIBUTES
                | FILE_WRITE_EA
                | READ_CONTROL
                | SYNCHRONIZE
        );
        assert_eq!(
            FILE_GENERIC_MAPPING.execute,
            FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
        );
        assert_eq!(
            FILE_GENERIC_MAPPING.all,
            FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_READ_EA
                | FILE_WRITE_EA
                | FILE_EXECUTE
                | FILE_DELETE_CHILD
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | READ_CONTROL
                | WRITE_DAC
                | WRITE_OWNER
                | SYNCHRONIZE
        );
    }

    #[test]
    fn mount_policy_constants_match_psd_004() {
        assert_eq!(KACS_MOUNT_POLICY_UNMANAGED, 1);
        assert_eq!(KACS_MOUNT_POLICY_DENY_MISSING, 2);
        assert_eq!(KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL, 3);
        assert_eq!(KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT, 4);
    }
}
