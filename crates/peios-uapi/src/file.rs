// KACS file open ABI — `kacs_open` (syscall 1020).
//
// `kacs_open` is the NtCreateFile-shaped native open: it takes a
// `kacs_open_how` describing the desired access, create disposition,
// create options, and an optional security descriptor for newly-created
// files. It returns a file descriptor and writes a status word telling
// the caller whether the file was opened, created, overwritten, or
// superseded.

use crate::sd::{DELETE, GenericMapping, READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER};

/// On-wire layout of `struct kacs_open_how` (32 bytes).
///
/// `sd_ptr` / `sd_len` describe an optional self-relative security
/// descriptor applied to a newly-created file (ignored for plain
/// opens). `__pad` must be zero.
#[repr(C)]
#[derive(Default)]
pub struct KacsOpenHow {
    /// Desired access mask (MS-DTYP access bits).
    pub desired_access: u32,
    /// One of `KACS_FILE_*`.
    pub create_disposition: u32,
    /// Bitmask of `KACS_CREATE_OPT_*`.
    pub create_options: u32,
    /// Bitmask of `KACS_*_INTENT`.
    pub flags: u32,
    /// Pointer to a self-relative SD for newly-created files (0 = none).
    pub sd_ptr: u64,
    /// Length of the SD (0 = none).
    pub sd_len: u32,
    /// Reserved — must be zero.
    pub __pad: u32,
}

/// On-wire layout of `struct kacs_mount_policy_args` (32 bytes).
#[repr(C)]
#[derive(Default)]
pub struct KacsMountPolicyArgs {
    /// One of `KACS_MOUNT_POLICY_*`.
    pub policy: u32,
    /// Reserved — must be zero.
    pub flags: u32,
    /// Kernel-maintained generation. Must be zero on set.
    pub generation: u32,
    /// Reserved — must be zero.
    pub __pad0: u32,
    /// Userspace pointer to a mount template SD buffer, or 0.
    pub template_sd_ptr: u64,
    /// Input buffer size on get, input template length on set.
    pub template_sd_len: u32,
    /// Reserved — must be zero.
    pub __pad1: u32,
}

/// Minimum `howsize` the kernel accepts for `kacs_open`.
pub const KACS_OPEN_HOW_MIN_SIZE: usize = 16;

/// Minimum `argsize` the kernel accepts for mount-policy syscalls.
pub const KACS_MOUNT_POLICY_ARGS_MIN_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// Create dispositions (`kacs_open_how.create_disposition`).
// ---------------------------------------------------------------------------

/// Overwrite if it exists, create if it doesn't (replacing all state).
pub const KACS_FILE_SUPERSEDE: u32 = 0;
/// Open an existing file; fail if absent.
pub const KACS_FILE_OPEN: u32 = 1;
/// Create a new file; fail if it already exists.
pub const KACS_FILE_CREATE: u32 = 2;
/// Open if it exists, create if it doesn't.
pub const KACS_FILE_OPEN_IF: u32 = 3;
/// Open and truncate an existing file; fail if absent.
pub const KACS_FILE_OVERWRITE: u32 = 4;
/// Open+truncate if it exists, create if it doesn't.
pub const KACS_FILE_OVERWRITE_IF: u32 = 5;

// ---------------------------------------------------------------------------
// File and directory object-specific access rights.
// ---------------------------------------------------------------------------

pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_READ_EA: u32 = 0x0000_0008;
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
pub const FILE_EXECUTE: u32 = 0x0000_0020;
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

pub const FILE_LIST_DIRECTORY: u32 = FILE_READ_DATA;
pub const FILE_ADD_FILE: u32 = FILE_WRITE_DATA;
pub const FILE_ADD_SUBDIRECTORY: u32 = FILE_APPEND_DATA;
pub const FILE_TRAVERSE: u32 = FILE_EXECUTE;

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
pub const KACS_CREATE_OPT_DIRECTORY: u32 = 0x0001;
/// Delete the file when the last handle closes.
pub const KACS_CREATE_OPT_DELETE_ON_CLOSE: u32 = 0x0002;

// ---------------------------------------------------------------------------
// Flags (`kacs_open_how.flags`).
// ---------------------------------------------------------------------------

/// Open with backup intent (bypass normal access for backup operations).
pub const KACS_BACKUP_INTENT: u32 = 0x0000_0001;
/// Open with restore intent.
pub const KACS_RESTORE_INTENT: u32 = 0x0000_0002;

// ---------------------------------------------------------------------------
// Mount policy values (`kacs_mount_policy_args.policy`).
// ---------------------------------------------------------------------------

pub const KACS_MOUNT_POLICY_UNMANAGED: u32 = 1;
pub const KACS_MOUNT_POLICY_DENY_MISSING: u32 = 2;
pub const KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL: u32 = 3;
pub const KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT: u32 = 4;

// ---------------------------------------------------------------------------
// Status word written to `status_out` by `kacs_open`.
// ---------------------------------------------------------------------------

/// An existing file was opened.
pub const KACS_STATUS_OPENED: u32 = 1;
/// A new file was created.
pub const KACS_STATUS_CREATED: u32 = 2;
/// An existing file was opened and truncated.
pub const KACS_STATUS_OVERWRITTEN: u32 = 3;
/// An existing file was replaced wholesale.
pub const KACS_STATUS_SUPERSEDED: u32 = 4;

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
        assert_eq!(core::mem::offset_of!(KacsMountPolicyArgs, __pad0), 12);
        assert_eq!(
            core::mem::offset_of!(KacsMountPolicyArgs, template_sd_ptr),
            16
        );
        assert_eq!(
            core::mem::offset_of!(KacsMountPolicyArgs, template_sd_len),
            24
        );
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
