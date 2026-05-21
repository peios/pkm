// KACS token ABI surface for libp-token: token-handle access mask bits,
// token-info classes, ioctl numbers, the ioctl arg structs, and the
// privilege bit ↔ name table.
//
// Constant *values* and struct layouts come from the generated `peios-uapi`
// crate (the kernel ABI's single source of truth); this module re-exposes
// them under the historical names libp-token's wrappers use, plus the
// hand-written pieces that are not part of the raw ABI mirror: the
// `PRIVILEGES` table, the `*_name` decode helpers, and the token
// `GenericMapping`.

use libp_sd::GenericMapping;
use libp_sd::consts::{READ_CONTROL, WRITE_DAC};

// ---------------------------------------------------------------------------
// Token-handle access mask (per-handle rights, MS-DTYP-style).
// ---------------------------------------------------------------------------

pub const KACS_TOKEN_ASSIGN_PRIMARY: u32 = peios_uapi::KACS_TOKEN_ASSIGN_PRIMARY;
pub const KACS_TOKEN_DUPLICATE: u32 = peios_uapi::KACS_TOKEN_DUPLICATE;
pub const KACS_TOKEN_IMPERSONATE: u32 = peios_uapi::KACS_TOKEN_IMPERSONATE;
pub const KACS_TOKEN_QUERY: u32 = peios_uapi::KACS_TOKEN_QUERY;
pub const KACS_TOKEN_QUERY_SOURCE: u32 = peios_uapi::KACS_TOKEN_QUERY_SOURCE;
pub const KACS_TOKEN_ADJUST_PRIVS: u32 = peios_uapi::KACS_TOKEN_ADJUST_PRIVS;
pub const KACS_TOKEN_ADJUST_GROUPS: u32 = peios_uapi::KACS_TOKEN_ADJUST_GROUPS;
pub const KACS_TOKEN_ADJUST_DEFAULT: u32 = peios_uapi::KACS_TOKEN_ADJUST_DEFAULT;
pub const KACS_TOKEN_ADJUST_SESSIONID: u32 = peios_uapi::KACS_TOKEN_ADJUST_SESSIONID;
pub const KACS_TOKEN_ALL_ACCESS: u32 = peios_uapi::KACS_TOKEN_ALL_ACCESS;

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
pub const KACS_REAL_TOKEN: u32 = peios_uapi::KACS_TOKEN_OPEN_REAL;

// ---------------------------------------------------------------------------
// Token ioctl ABI (KACS_IOC_MAGIC = 'K' = 0x4B). The ioctl numbers come
// from the generated mirror; the kernel's `_IOWR`/`_IOW`/`_IO` macros
// produce some values above 2^31 (typed u64 in the mirror) and some below
// (u32), so each is normalised to u64 for `libp_sys::ioctl`.
// ---------------------------------------------------------------------------

pub const KACS_IOC_MAGIC: u32 = peios_uapi::KACS_IOC_MAGIC;

/// On-wire layout of struct kacs_query_args. Pass `&KacsQueryArgs` as the
/// ioctl arg; the kernel fills `buf_len` on probe and writes payload bytes
/// into `buf_ptr` on fetch.
pub use peios_uapi::kacs_query_args as KacsQueryArgs;
/// On-wire layout of struct kacs_adjust_privs_args.
pub use peios_uapi::kacs_adjust_privs_args as KacsAdjustPrivsArgs;
/// On-wire layout of struct kacs_priv_entry — one element of the array
/// `kacs_adjust_privs_args.data_ptr` points at.
pub use peios_uapi::kacs_priv_entry as KacsPrivEntry;
/// On-wire layout of struct kacs_duplicate_args. Kernel writes the new fd
/// into `result_fd` on success.
pub use peios_uapi::kacs_duplicate_args as KacsDuplicateArgs;
/// On-wire layout of struct kacs_adjust_groups_args.
pub use peios_uapi::kacs_adjust_groups_args as KacsAdjustGroupsArgs;
/// On-wire layout of struct kacs_group_entry — one element of the array
/// `kacs_adjust_groups_args.data_ptr` points at.
pub use peios_uapi::kacs_group_entry as KacsGroupEntry;
/// On-wire layout of struct kacs_adjust_default_args.
pub use peios_uapi::kacs_adjust_default_args as KacsAdjustDefaultArgs;
/// On-wire layout of struct kacs_restrict_args. Kernel writes the new fd
/// into `result_fd` on success.
pub use peios_uapi::kacs_restrict_args as KacsRestrictArgs;
/// On-wire layout of struct kacs_link_tokens_args.
pub use peios_uapi::kacs_link_tokens_args as KacsLinkTokensArgs;
/// On-wire layout of struct kacs_get_linked_token_args. Kernel writes the
/// linked fd into `result_fd` on success.
pub use peios_uapi::kacs_get_linked_token_args as KacsGetLinkedTokenArgs;

/// `sizeof(struct kacs_query_args)`, for callers that need it directly.
pub const KACS_QUERY_ARGS_SIZE: u32 = core::mem::size_of::<KacsQueryArgs>() as u32;

/// Flags bit accepted in `kacs_restrict_args.flags`.
pub const KACS_RESTRICT_WRITE_RESTRICTED: u32 = peios_uapi::KACS_TOKEN_RESTRICT_WRITE_RESTRICTED;

// ioctl numbers for `libp_sys::ioctl` (which takes a u64 request). The
// generated mirror types the `_IOWR`/`_IOW` numbers as u64 already and the
// argument-less `_IO` numbers (INSTALL, IMPERSONATE) as u32 — the latter
// are widened here.
pub const KACS_IOC_QUERY: u64 = peios_uapi::KACS_IOC_QUERY;
pub const KACS_IOC_ADJUST_PRIVS: u64 = peios_uapi::KACS_IOC_ADJUST_PRIVS;
pub const KACS_IOC_DUPLICATE: u64 = peios_uapi::KACS_IOC_DUPLICATE;
pub const KACS_IOC_INSTALL: u64 = peios_uapi::KACS_IOC_INSTALL as u64;
pub const KACS_IOC_RESTRICT: u64 = peios_uapi::KACS_IOC_RESTRICT;
pub const KACS_IOC_LINK_TOKENS: u64 = peios_uapi::KACS_IOC_LINK_TOKENS;
pub const KACS_IOC_GET_LINKED_TOKEN: u64 = peios_uapi::KACS_IOC_GET_LINKED_TOKEN;
pub const KACS_IOC_ADJUST_GROUPS: u64 = peios_uapi::KACS_IOC_ADJUST_GROUPS;
pub const KACS_IOC_IMPERSONATE: u64 = peios_uapi::KACS_IOC_IMPERSONATE as u64;
pub const KACS_IOC_ADJUST_DEFAULT: u64 = peios_uapi::KACS_IOC_ADJUST_DEFAULT;
pub const KACS_IOC_ADJUST_SESSIONID: u64 = peios_uapi::KACS_IOC_ADJUST_SESSIONID;

// ---------------------------------------------------------------------------
// Token information classes (struct kacs_query_args.token_class).
// ---------------------------------------------------------------------------

pub const TOKEN_CLASS_USER: u32 = peios_uapi::KACS_TOKEN_CLASS_USER;
pub const TOKEN_CLASS_GROUPS: u32 = peios_uapi::KACS_TOKEN_CLASS_GROUPS;
pub const TOKEN_CLASS_PRIVILEGES: u32 = peios_uapi::KACS_TOKEN_CLASS_PRIVILEGES;
pub const TOKEN_CLASS_TYPE: u32 = peios_uapi::KACS_TOKEN_CLASS_TYPE;
pub const TOKEN_CLASS_INTEGRITY_LEVEL: u32 = peios_uapi::KACS_TOKEN_CLASS_INTEGRITY_LEVEL;
pub const TOKEN_CLASS_OWNER: u32 = peios_uapi::KACS_TOKEN_CLASS_OWNER;
pub const TOKEN_CLASS_PRIMARY_GROUP: u32 = peios_uapi::KACS_TOKEN_CLASS_PRIMARY_GROUP;
pub const TOKEN_CLASS_SESSION_ID: u32 = peios_uapi::KACS_TOKEN_CLASS_SESSION_ID;
pub const TOKEN_CLASS_RESTRICTED_SIDS: u32 = peios_uapi::KACS_TOKEN_CLASS_RESTRICTED_SIDS;
pub const TOKEN_CLASS_SOURCE: u32 = peios_uapi::KACS_TOKEN_CLASS_SOURCE;
pub const TOKEN_CLASS_STATISTICS: u32 = peios_uapi::KACS_TOKEN_CLASS_STATISTICS;
pub const TOKEN_CLASS_ORIGIN: u32 = peios_uapi::KACS_TOKEN_CLASS_ORIGIN;
pub const TOKEN_CLASS_ELEVATION_TYPE: u32 = peios_uapi::KACS_TOKEN_CLASS_ELEVATION_TYPE;
pub const TOKEN_CLASS_DEVICE_GROUPS: u32 = peios_uapi::KACS_TOKEN_CLASS_DEVICE_GROUPS;
pub const TOKEN_CLASS_APPCONTAINER_SID: u32 = peios_uapi::KACS_TOKEN_CLASS_APPCONTAINER_SID;
pub const TOKEN_CLASS_CAPABILITIES: u32 = peios_uapi::KACS_TOKEN_CLASS_CAPABILITIES;
pub const TOKEN_CLASS_MANDATORY_POLICY: u32 = peios_uapi::KACS_TOKEN_CLASS_MANDATORY_POLICY;
pub const TOKEN_CLASS_LOGON_TYPE: u32 = peios_uapi::KACS_TOKEN_CLASS_LOGON_TYPE;
pub const TOKEN_CLASS_LOGON_SID: u32 = peios_uapi::KACS_TOKEN_CLASS_LOGON_SID;
pub const TOKEN_CLASS_DEFAULT_DACL: u32 = peios_uapi::KACS_TOKEN_CLASS_DEFAULT_DACL;
pub const TOKEN_CLASS_IMPERSONATION_LEVEL: u32 = peios_uapi::KACS_TOKEN_CLASS_IMPERSONATION_LEVEL;
pub const TOKEN_CLASS_USER_CLAIMS: u32 = peios_uapi::KACS_TOKEN_CLASS_USER_CLAIMS;
pub const TOKEN_CLASS_DEVICE_CLAIMS: u32 = peios_uapi::KACS_TOKEN_CLASS_DEVICE_CLAIMS;
pub const TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS: u32 =
    peios_uapi::KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS;

// ---------------------------------------------------------------------------
// Token type / impersonation level / elevation type — discriminant values.
// ---------------------------------------------------------------------------

pub const KACS_TOKEN_TYPE_PRIMARY: u32 = peios_uapi::KACS_TOKEN_TYPE_PRIMARY;
pub const KACS_TOKEN_TYPE_IMPERSONATION: u32 = peios_uapi::KACS_TOKEN_TYPE_IMPERSONATION;

pub const KACS_LEVEL_ANONYMOUS: u32 = peios_uapi::KACS_IMLEVEL_ANONYMOUS;
pub const KACS_LEVEL_IDENTIFICATION: u32 = peios_uapi::KACS_IMLEVEL_IDENTIFICATION;
pub const KACS_LEVEL_IMPERSONATION: u32 = peios_uapi::KACS_IMLEVEL_IMPERSONATION;
pub const KACS_LEVEL_DELEGATION: u32 = peios_uapi::KACS_IMLEVEL_DELEGATION;

pub const KACS_ELEVATION_DEFAULT: u32 = peios_uapi::KACS_ELEVATION_DEFAULT;
pub const KACS_ELEVATION_FULL: u32 = peios_uapi::KACS_ELEVATION_FULL;
pub const KACS_ELEVATION_LIMITED: u32 = peios_uapi::KACS_ELEVATION_LIMITED;

pub const TOKEN_MANDATORY_POLICY_NO_WRITE_UP: u32 =
    peios_uapi::KACS_TOKEN_MANDATORY_POLICY_NO_WRITE_UP;
pub const TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN: u32 =
    peios_uapi::KACS_TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN;

pub const KACS_LOGON_TYPE_INTERACTIVE: u32 = peios_uapi::KACS_LOGON_TYPE_INTERACTIVE;
pub const KACS_LOGON_TYPE_NETWORK: u32 = peios_uapi::KACS_LOGON_TYPE_NETWORK;
pub const KACS_LOGON_TYPE_BATCH: u32 = peios_uapi::KACS_LOGON_TYPE_BATCH;
pub const KACS_LOGON_TYPE_SERVICE: u32 = peios_uapi::KACS_LOGON_TYPE_SERVICE;
pub const KACS_LOGON_TYPE_NETWORK_CLEARTEXT: u32 = peios_uapi::KACS_LOGON_TYPE_NETWORK_CLEARTEXT;
pub const KACS_LOGON_TYPE_NEW_CREDENTIALS: u32 = peios_uapi::KACS_LOGON_TYPE_NEW_CREDENTIALS;

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
// Privilege bits and names. Bit index → privilege name. (Hand-written: the
// kernel stores privilege presence/enabled state as a 64-bit mask, one bit
// per privilege; this table is the userspace name mapping.)
// ---------------------------------------------------------------------------

/// (bit_index, name) table.
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
pub const SE_PRIVILEGE_ENABLED: u32 = peios_uapi::KACS_PRIVILEGE_ATTR_ENABLED;
pub const SE_PRIVILEGE_REMOVED: u32 = peios_uapi::KACS_PRIVILEGE_ATTR_REMOVED;
pub const KACS_PRIV_RESET_ALL_DEFAULTS: u32 = peios_uapi::KACS_PRIVILEGE_RESET_ALL_DEFAULTS;

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
