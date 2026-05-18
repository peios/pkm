// KACS token-handle access mask bits, token-info classes, ioctl numbers,
// and the privilege bit ↔ name table.
//
// Sourced from pkm-new/kacs/token_fd.h and pkm-new/kacs/lsm.c.

use crate::sd::{GenericMapping, READ_CONTROL, WRITE_DAC};

// ---------------------------------------------------------------------------
// Token-handle access mask (per-handle rights, MS-DTYP-style).
// ---------------------------------------------------------------------------

pub const KACS_TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
pub const KACS_TOKEN_DUPLICATE: u32 = 0x0002;
pub const KACS_TOKEN_IMPERSONATE: u32 = 0x0004;
pub const KACS_TOKEN_QUERY: u32 = 0x0008;
pub const KACS_TOKEN_QUERY_SOURCE: u32 = 0x0010;
pub const KACS_TOKEN_ADJUST_PRIVS: u32 = 0x0020;
pub const KACS_TOKEN_ADJUST_GROUPS: u32 = 0x0040;
pub const KACS_TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
pub const KACS_TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
pub const KACS_TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;

/// PSD-004 token-SD mapping from generic rights to token-handle rights.
pub const KACS_TOKEN_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: KACS_TOKEN_QUERY | READ_CONTROL,
    write: KACS_TOKEN_ADJUST_PRIVS
        | KACS_TOKEN_ADJUST_GROUPS
        | KACS_TOKEN_ADJUST_DEFAULT
        | WRITE_DAC,
    execute: KACS_TOKEN_IMPERSONATE,
    all: KACS_TOKEN_ALL_ACCESS,
};

// ---------------------------------------------------------------------------
// kacs_open_self_token flags (syscall 1000 first arg).
// ---------------------------------------------------------------------------

/// Open the calling task's real (primary) token rather than its effective
/// (impersonation) token, when the two differ.
pub const KACS_REAL_TOKEN: u32 = 0x01;

// ---------------------------------------------------------------------------
// Token ioctl ABI (KACS_IOC_MAGIC = 'K' = 0x4B).
//
// Struct shadows come first; ioctl numbers below derive sizes from
// `core::mem::size_of::<...>()` so the Rust types are the single source
// of truth. If a struct layout drifts from the kernel header, the
// kernel will reject the call with -ENOTTY (size mismatch) — easier to
// diagnose than silent breakage.
// ---------------------------------------------------------------------------

pub const KACS_IOC_MAGIC: u32 = 0x4B;

// _IOC(dir, type, nr, size):
//   dir << 30 | size << 16 | type << 8 | nr
// where dir is 3 (READ|WRITE) for _IOWR.
const fn iowr(nr: u32, size_bytes: u32) -> u64 {
    ((3u64) << 30) | ((size_bytes as u64) << 16) | ((KACS_IOC_MAGIC as u64) << 8) | (nr as u64)
}
const fn iow(nr: u32, size_bytes: u32) -> u64 {
    ((1u64) << 30) | ((size_bytes as u64) << 16) | ((KACS_IOC_MAGIC as u64) << 8) | (nr as u64)
}
const fn io_(nr: u32) -> u64 {
    ((KACS_IOC_MAGIC as u64) << 8) | (nr as u64)
}

/// On-wire layout of struct kacs_query_args. Pass &KacsQueryArgs as the
/// ioctl arg; the kernel fills `buf_len` on probe and writes payload bytes
/// into `buf_ptr` on fetch.
#[repr(C)]
#[derive(Default)]
pub struct KacsQueryArgs {
    pub token_class: u32,
    pub buf_len: u32,
    pub buf_ptr: u64,
}

/// `sizeof(struct kacs_query_args)` — kept for callers that already use
/// this constant. Equivalent to `core::mem::size_of::<KacsQueryArgs>() as u32`.
pub const KACS_QUERY_ARGS_SIZE: u32 = core::mem::size_of::<KacsQueryArgs>() as u32;

/// On-wire layout of struct kacs_adjust_privs_args.
#[repr(C)]
#[derive(Default)]
pub struct KacsAdjustPrivsArgs {
    pub count: u32,
    pub _pad: u32,
    pub data_ptr: u64,
    pub previous_enabled: u64,
}

/// On-wire layout of struct kacs_priv_entry — one element of the array
/// `kacs_adjust_privs_args.data_ptr` points at.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct KacsPrivEntry {
    pub luid: u32,
    pub attributes: u32,
}

/// On-wire layout of struct kacs_duplicate_args. Kernel writes the new
/// fd into `result_fd` on success.
#[repr(C)]
#[derive(Default)]
pub struct KacsDuplicateArgs {
    pub access_mask: u32,
    pub token_type: u32,
    pub impersonation_level: u32,
    pub result_fd: i32,
}

/// On-wire layout of struct kacs_adjust_groups_args.
#[repr(C)]
#[derive(Default)]
pub struct KacsAdjustGroupsArgs {
    pub count: u32,
    pub _pad: u32,
    pub data_ptr: u64,
    pub previous_state: u64,
}

/// On-wire layout of struct kacs_group_entry — one element of the array
/// `kacs_adjust_groups_args.data_ptr` points at.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct KacsGroupEntry {
    pub index: u32,
    pub enable: u32,
}

/// On-wire layout of struct kacs_adjust_default_args.
#[repr(C)]
#[derive(Default)]
pub struct KacsAdjustDefaultArgs {
    pub dacl_ptr: u64,
    pub dacl_len: u32,
    pub owner_index: u16,
    pub group_index: u16,
}

/// On-wire layout of struct kacs_restrict_args. Kernel writes the new
/// fd into `result_fd` on success.
#[repr(C)]
#[derive(Default)]
pub struct KacsRestrictArgs {
    pub privs_to_delete: u64,
    pub num_deny_indices: u32,
    pub num_restrict_sids: u32,
    pub data_len: u32,
    pub flags: u32,
    pub data_ptr: u64,
    pub result_fd: i32,
}

/// On-wire layout of struct kacs_link_tokens_args.
#[repr(C)]
#[derive(Default)]
pub struct KacsLinkTokensArgs {
    pub elevated_fd: i32,
    pub filtered_fd: i32,
    pub session_id: u64,
}

/// On-wire layout of struct kacs_get_linked_token_args. Kernel writes
/// the linked fd into `result_fd` on success.
#[repr(C)]
#[derive(Default)]
pub struct KacsGetLinkedTokenArgs {
    pub result_fd: i32,
}

/// Flags bit accepted in `kacs_restrict_args.flags`.
pub const KACS_RESTRICT_WRITE_RESTRICTED: u32 = 0x0000_0001;

// ---------------------------------------------------------------------------
// ioctl numbers, derived from the struct layouts above.
// ---------------------------------------------------------------------------

pub const KACS_IOC_QUERY: u64 = iowr(0, core::mem::size_of::<KacsQueryArgs>() as u32);
pub const KACS_IOC_ADJUST_PRIVS: u64 = iow(1, core::mem::size_of::<KacsAdjustPrivsArgs>() as u32);
pub const KACS_IOC_DUPLICATE: u64 = iowr(2, core::mem::size_of::<KacsDuplicateArgs>() as u32);
pub const KACS_IOC_INSTALL: u64 = io_(3);
pub const KACS_IOC_RESTRICT: u64 = iowr(4, core::mem::size_of::<KacsRestrictArgs>() as u32);
pub const KACS_IOC_LINK_TOKENS: u64 = iow(5, core::mem::size_of::<KacsLinkTokensArgs>() as u32);
pub const KACS_IOC_GET_LINKED_TOKEN: u64 =
    iowr(6, core::mem::size_of::<KacsGetLinkedTokenArgs>() as u32);
pub const KACS_IOC_ADJUST_GROUPS: u64 = iow(7, core::mem::size_of::<KacsAdjustGroupsArgs>() as u32);
pub const KACS_IOC_IMPERSONATE: u64 = io_(8);
pub const KACS_IOC_ADJUST_DEFAULT: u64 =
    iow(9, core::mem::size_of::<KacsAdjustDefaultArgs>() as u32);
pub const KACS_IOC_ADJUST_SESSIONID: u64 = iow(10, core::mem::size_of::<u32>() as u32);

// ---------------------------------------------------------------------------
// Token information classes (struct kacs_query_args.token_class).
// ---------------------------------------------------------------------------

pub const TOKEN_CLASS_USER: u32 = 0x01;
pub const TOKEN_CLASS_GROUPS: u32 = 0x02;
pub const TOKEN_CLASS_PRIVILEGES: u32 = 0x03;
pub const TOKEN_CLASS_TYPE: u32 = 0x04;
pub const TOKEN_CLASS_INTEGRITY_LEVEL: u32 = 0x05;
pub const TOKEN_CLASS_OWNER: u32 = 0x06;
pub const TOKEN_CLASS_PRIMARY_GROUP: u32 = 0x07;
pub const TOKEN_CLASS_SESSION_ID: u32 = 0x08;
pub const TOKEN_CLASS_RESTRICTED_SIDS: u32 = 0x09;
pub const TOKEN_CLASS_SOURCE: u32 = 0x0A;
pub const TOKEN_CLASS_STATISTICS: u32 = 0x0B;
pub const TOKEN_CLASS_ORIGIN: u32 = 0x0C;
pub const TOKEN_CLASS_ELEVATION_TYPE: u32 = 0x0D;
pub const TOKEN_CLASS_DEVICE_GROUPS: u32 = 0x0E;
pub const TOKEN_CLASS_APPCONTAINER_SID: u32 = 0x0F;
pub const TOKEN_CLASS_CAPABILITIES: u32 = 0x10;
pub const TOKEN_CLASS_MANDATORY_POLICY: u32 = 0x11;
pub const TOKEN_CLASS_LOGON_TYPE: u32 = 0x12;
pub const TOKEN_CLASS_LOGON_SID: u32 = 0x13;
pub const TOKEN_CLASS_DEFAULT_DACL: u32 = 0x14;
pub const TOKEN_CLASS_IMPERSONATION_LEVEL: u32 = 0x15;
pub const TOKEN_CLASS_USER_CLAIMS: u32 = 0x16;
pub const TOKEN_CLASS_DEVICE_CLAIMS: u32 = 0x17;
pub const TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS: u32 = 0x18;

// ---------------------------------------------------------------------------
// Token type / impersonation level / elevation type — discriminant values.
// ---------------------------------------------------------------------------

pub const KACS_TOKEN_TYPE_PRIMARY: u32 = 0x01;
pub const KACS_TOKEN_TYPE_IMPERSONATION: u32 = 0x02;

pub const KACS_LEVEL_ANONYMOUS: u32 = 0x00;
pub const KACS_LEVEL_IDENTIFICATION: u32 = 0x01;
pub const KACS_LEVEL_IMPERSONATION: u32 = 0x02;
pub const KACS_LEVEL_DELEGATION: u32 = 0x03;

pub const KACS_ELEVATION_DEFAULT: u32 = 0x01;
pub const KACS_ELEVATION_FULL: u32 = 0x02;
pub const KACS_ELEVATION_LIMITED: u32 = 0x03;

pub const TOKEN_MANDATORY_POLICY_NO_WRITE_UP: u32 = 0x0000_0001;
pub const TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN: u32 = 0x0000_0002;

pub const KACS_LOGON_TYPE_INTERACTIVE: u32 = 2;
pub const KACS_LOGON_TYPE_NETWORK: u32 = 3;
pub const KACS_LOGON_TYPE_BATCH: u32 = 4;
pub const KACS_LOGON_TYPE_SERVICE: u32 = 5;
pub const KACS_LOGON_TYPE_NETWORK_CLEARTEXT: u32 = 8;
pub const KACS_LOGON_TYPE_NEW_CREDENTIALS: u32 = 9;

pub fn token_type_name(v: u32) -> &'static str {
    match v {
        KACS_TOKEN_TYPE_PRIMARY => "primary",
        KACS_TOKEN_TYPE_IMPERSONATION => "impersonation",
        _ => "?",
    }
}
pub fn impersonation_level_name(v: u32) -> &'static str {
    match v {
        KACS_LEVEL_ANONYMOUS => "anonymous",
        KACS_LEVEL_IDENTIFICATION => "identification",
        KACS_LEVEL_IMPERSONATION => "impersonation",
        KACS_LEVEL_DELEGATION => "delegation",
        _ => "?",
    }
}
pub fn elevation_type_name(v: u32) -> &'static str {
    match v {
        KACS_ELEVATION_DEFAULT => "default",
        KACS_ELEVATION_FULL => "full",
        KACS_ELEVATION_LIMITED => "limited",
        _ => "?",
    }
}

// ---------------------------------------------------------------------------
// Privilege bits and names. Bit index → privilege name.
// ---------------------------------------------------------------------------

/// (bit_index, name) table. The kernel stores privilege presence/enabled/etc.
/// as a 64-bit mask, one bit per privilege.
pub const PRIVILEGES: &[(u32, &str)] = &[
    (2, "SeCreateToken"),
    (3, "SeAssignPrimaryToken"),
    (4, "SeLockMemory"),
    (5, "SeIncreaseQuota"),
    (7, "SeTcb"),
    (8, "SeSecurity"),
    (10, "SeLoadDriver"),
    (12, "SeSystemTime"),
    (13, "SeProfileSingleProcess"),
    (14, "SeIncreaseBasePriority"),
    (18, "SeRestore"),
    (19, "SeShutdown"),
    (20, "SeDebug"),
    (21, "SeAudit"),
    (23, "SeChangeNotify"),
    (29, "SeImpersonate"),
    (35, "SeCreateSymbolicLink"),
    (63, "SeBindPrivilegedPort"),
];

/// Privilege adjust-bit flags (struct kacs_priv_entry.attributes).
pub const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
pub const SE_PRIVILEGE_REMOVED: u32 = 0x0000_0004;
pub const KACS_PRIV_RESET_ALL_DEFAULTS: u32 = 0x8000_0000;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn ioc_query_matches_legacy_constant() {
        // The hand-encoded value previously used in the three tools.
        assert_eq!(KACS_IOC_QUERY, 0xC010_4B00);
    }

    /// Cross-check: every ioctl number's size field equals the size of
    /// the struct it encodes. Regression guard against a struct layout
    /// being updated without the ioctl number following along (the
    /// kernel would reject these with -ENOTTY, but a fast unit test
    /// catches it before we hit a VM).
    #[test]
    fn ioctl_sizes_match_struct_sizes() {
        use core::mem::size_of;
        let size_field = |ioc: u64| ((ioc >> 16) & 0x3FFF) as usize;
        assert_eq!(size_field(KACS_IOC_QUERY), size_of::<KacsQueryArgs>());
        assert_eq!(
            size_field(KACS_IOC_ADJUST_PRIVS),
            size_of::<KacsAdjustPrivsArgs>()
        );
        assert_eq!(
            size_field(KACS_IOC_DUPLICATE),
            size_of::<KacsDuplicateArgs>()
        );
        assert_eq!(size_field(KACS_IOC_RESTRICT), size_of::<KacsRestrictArgs>());
        assert_eq!(
            size_field(KACS_IOC_LINK_TOKENS),
            size_of::<KacsLinkTokensArgs>()
        );
        assert_eq!(
            size_field(KACS_IOC_GET_LINKED_TOKEN),
            size_of::<KacsGetLinkedTokenArgs>()
        );
        assert_eq!(
            size_field(KACS_IOC_ADJUST_GROUPS),
            size_of::<KacsAdjustGroupsArgs>()
        );
        assert_eq!(
            size_field(KACS_IOC_ADJUST_DEFAULT),
            size_of::<KacsAdjustDefaultArgs>()
        );
        assert_eq!(size_field(KACS_IOC_ADJUST_SESSIONID), size_of::<u32>());
    }

    #[test]
    fn token_ioctl_struct_layouts_match_psd_004() {
        use core::mem::{offset_of, size_of};

        assert_eq!(size_of::<KacsQueryArgs>(), 16);
        assert_eq!(offset_of!(KacsQueryArgs, token_class), 0);
        assert_eq!(offset_of!(KacsQueryArgs, buf_len), 4);
        assert_eq!(offset_of!(KacsQueryArgs, buf_ptr), 8);

        assert_eq!(size_of::<KacsAdjustPrivsArgs>(), 24);
        assert_eq!(offset_of!(KacsAdjustPrivsArgs, count), 0);
        assert_eq!(offset_of!(KacsAdjustPrivsArgs, _pad), 4);
        assert_eq!(offset_of!(KacsAdjustPrivsArgs, data_ptr), 8);
        assert_eq!(offset_of!(KacsAdjustPrivsArgs, previous_enabled), 16);

        assert_eq!(size_of::<KacsPrivEntry>(), 8);
        assert_eq!(offset_of!(KacsPrivEntry, luid), 0);
        assert_eq!(offset_of!(KacsPrivEntry, attributes), 4);

        assert_eq!(size_of::<KacsDuplicateArgs>(), 16);
        assert_eq!(offset_of!(KacsDuplicateArgs, access_mask), 0);
        assert_eq!(offset_of!(KacsDuplicateArgs, token_type), 4);
        assert_eq!(offset_of!(KacsDuplicateArgs, impersonation_level), 8);
        assert_eq!(offset_of!(KacsDuplicateArgs, result_fd), 12);

        assert_eq!(size_of::<KacsRestrictArgs>(), 40);
        assert_eq!(offset_of!(KacsRestrictArgs, privs_to_delete), 0);
        assert_eq!(offset_of!(KacsRestrictArgs, num_deny_indices), 8);
        assert_eq!(offset_of!(KacsRestrictArgs, num_restrict_sids), 12);
        assert_eq!(offset_of!(KacsRestrictArgs, data_len), 16);
        assert_eq!(offset_of!(KacsRestrictArgs, flags), 20);
        assert_eq!(offset_of!(KacsRestrictArgs, data_ptr), 24);
        assert_eq!(offset_of!(KacsRestrictArgs, result_fd), 32);

        assert_eq!(size_of::<KacsLinkTokensArgs>(), 16);
        assert_eq!(offset_of!(KacsLinkTokensArgs, elevated_fd), 0);
        assert_eq!(offset_of!(KacsLinkTokensArgs, filtered_fd), 4);
        assert_eq!(offset_of!(KacsLinkTokensArgs, session_id), 8);

        assert_eq!(size_of::<KacsGetLinkedTokenArgs>(), 4);
        assert_eq!(offset_of!(KacsGetLinkedTokenArgs, result_fd), 0);

        assert_eq!(size_of::<KacsAdjustGroupsArgs>(), 24);
        assert_eq!(offset_of!(KacsAdjustGroupsArgs, count), 0);
        assert_eq!(offset_of!(KacsAdjustGroupsArgs, _pad), 4);
        assert_eq!(offset_of!(KacsAdjustGroupsArgs, data_ptr), 8);
        assert_eq!(offset_of!(KacsAdjustGroupsArgs, previous_state), 16);

        assert_eq!(size_of::<KacsGroupEntry>(), 8);
        assert_eq!(offset_of!(KacsGroupEntry, index), 0);
        assert_eq!(offset_of!(KacsGroupEntry, enable), 4);

        assert_eq!(size_of::<KacsAdjustDefaultArgs>(), 16);
        assert_eq!(offset_of!(KacsAdjustDefaultArgs, dacl_ptr), 0);
        assert_eq!(offset_of!(KacsAdjustDefaultArgs, dacl_len), 8);
        assert_eq!(offset_of!(KacsAdjustDefaultArgs, owner_index), 12);
        assert_eq!(offset_of!(KacsAdjustDefaultArgs, group_index), 14);
    }

    #[test]
    fn privilege_table_covers_known_bits() {
        let names: Vec<&'static str> = PRIVILEGES.iter().map(|(_, n)| *n).collect();
        assert!(names.contains(&"SeTcb"));
        assert!(names.contains(&"SeChangeNotify"));
        assert!(names.contains(&"SeBindPrivilegedPort"));
        assert_eq!(PRIVILEGES.len(), 18);
    }

    #[test]
    fn token_scalar_constants_match_psd_004() {
        assert_eq!(KACS_REAL_TOKEN, 0x01);
        assert_eq!(KACS_TOKEN_ASSIGN_PRIMARY, 0x0001);
        assert_eq!(KACS_TOKEN_DUPLICATE, 0x0002);
        assert_eq!(KACS_TOKEN_IMPERSONATE, 0x0004);
        assert_eq!(KACS_TOKEN_QUERY, 0x0008);
        assert_eq!(KACS_TOKEN_QUERY_SOURCE, 0x0010);
        assert_eq!(KACS_TOKEN_ADJUST_PRIVS, 0x0020);
        assert_eq!(KACS_TOKEN_ADJUST_GROUPS, 0x0040);
        assert_eq!(KACS_TOKEN_ADJUST_DEFAULT, 0x0080);
        assert_eq!(KACS_TOKEN_ADJUST_SESSIONID, 0x0100);
        assert_eq!(KACS_TOKEN_ALL_ACCESS, 0x000F_01FF);
        assert_eq!(KACS_LEVEL_ANONYMOUS, 0);
        assert_eq!(KACS_LEVEL_IDENTIFICATION, 1);
        assert_eq!(KACS_LEVEL_IMPERSONATION, 2);
        assert_eq!(KACS_LEVEL_DELEGATION, 3);
        assert_eq!(TOKEN_MANDATORY_POLICY_NO_WRITE_UP, 0x0000_0001);
        assert_eq!(TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN, 0x0000_0002);
    }

    #[test]
    fn token_generic_mapping_matches_psd_004() {
        assert_eq!(
            KACS_TOKEN_GENERIC_MAPPING.read,
            KACS_TOKEN_QUERY | READ_CONTROL
        );
        assert_eq!(
            KACS_TOKEN_GENERIC_MAPPING.write,
            KACS_TOKEN_ADJUST_PRIVS
                | KACS_TOKEN_ADJUST_GROUPS
                | KACS_TOKEN_ADJUST_DEFAULT
                | WRITE_DAC
        );
        assert_eq!(KACS_TOKEN_GENERIC_MAPPING.execute, KACS_TOKEN_IMPERSONATE);
        assert_eq!(KACS_TOKEN_GENERIC_MAPPING.all, KACS_TOKEN_ALL_ACCESS);
    }

    #[test]
    fn logon_type_values_match_psd_004() {
        assert_eq!(KACS_LOGON_TYPE_INTERACTIVE, 2);
        assert_eq!(KACS_LOGON_TYPE_NETWORK, 3);
        assert_eq!(KACS_LOGON_TYPE_BATCH, 4);
        assert_eq!(KACS_LOGON_TYPE_SERVICE, 5);
        assert_eq!(KACS_LOGON_TYPE_NETWORK_CLEARTEXT, 8);
        assert_eq!(KACS_LOGON_TYPE_NEW_CREDENTIALS, 9);
    }
}
