// KACS token-handle access mask bits, token-info classes, ioctl numbers,
// and the privilege bit ↔ name table.
//
// Sourced from pkm-new/kacs/token_fd.h and pkm-new/kacs/lsm.c.

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

// ---------------------------------------------------------------------------
// kacs_open_self_token flags (syscall 1000 first arg).
// ---------------------------------------------------------------------------

/// Open the calling task's real (primary) token rather than its effective
/// (impersonation) token, when the two differ.
pub const KACS_REAL_TOKEN: u32 = 0x01;

// ---------------------------------------------------------------------------
// Token ioctl ABI (KACS_IOC_MAGIC = 'K' = 0x4B).
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

/// sizeof(struct kacs_query_args) = u32 + u32 + u64.
pub const KACS_QUERY_ARGS_SIZE: u32 = 16;

pub const KACS_IOC_QUERY: u64 = iowr(0, KACS_QUERY_ARGS_SIZE);
pub const KACS_IOC_ADJUST_PRIVS: u64 = iow(1, 32);
pub const KACS_IOC_DUPLICATE: u64 = iowr(2, 16);
pub const KACS_IOC_INSTALL: u64 = io_(3);
pub const KACS_IOC_RESTRICT: u64 = iowr(4, 40);
pub const KACS_IOC_LINK_TOKENS: u64 = iow(5, 24);
pub const KACS_IOC_GET_LINKED_TOKEN: u64 = iowr(6, 4);
pub const KACS_IOC_ADJUST_GROUPS: u64 = iow(7, 24);
pub const KACS_IOC_IMPERSONATE: u64 = io_(8);
pub const KACS_IOC_ADJUST_DEFAULT: u64 = iow(9, 24);
pub const KACS_IOC_ADJUST_SESSIONID: u64 = iow(10, 4);

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

    #[test]
    fn ioc_query_matches_legacy_constant() {
        // The hand-encoded value previously used in the three tools.
        assert_eq!(KACS_IOC_QUERY, 0xC010_4B00);
    }

    #[test]
    fn privilege_table_covers_known_bits() {
        let names: Vec<&'static str> = PRIVILEGES.iter().map(|(_, n)| *n).collect();
        assert!(names.contains(&"SeTcb"));
        assert!(names.contains(&"SeChangeNotify"));
        assert!(names.contains(&"SeBindPrivilegedPort"));
        assert_eq!(PRIVILEGES.len(), 18);
    }
}
