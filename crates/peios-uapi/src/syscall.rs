// Peios kernel syscall numbers.
//
// Sourced from pkm-new/kernel/install-pkm-subtree.sh and verify-scaffold.sh.
// Keep in sync with the kernel patch that registers these numbers in
// syscall_64.tbl.

// ---------------------------------------------------------------------------
// KACS — tokens, sessions, impersonation.
// ---------------------------------------------------------------------------

pub const SYS_KACS_OPEN_SELF_TOKEN: i64 = 1000;
pub const SYS_KACS_OPEN_PROCESS_TOKEN: i64 = 1001;
pub const SYS_KACS_OPEN_THREAD_TOKEN: i64 = 1002;
pub const SYS_KACS_CREATE_TOKEN: i64 = 1003;
pub const SYS_KACS_CREATE_SESSION: i64 = 1004;
pub const SYS_KACS_SET_PSB: i64 = 1005;
pub const SYS_KACS_DESTROY_EMPTY_SESSION: i64 = 1006;

pub const SYS_KACS_OPEN_PEER_TOKEN: i64 = 1010;
pub const SYS_KACS_IMPERSONATE_PEER: i64 = 1011;
pub const SYS_KACS_REVERT: i64 = 1012;
pub const SYS_KACS_SET_IMPERSONATION_LEVEL: i64 = 1013;

// ---------------------------------------------------------------------------
// KACS — files, security descriptors, access checks, mount policies.
// ---------------------------------------------------------------------------

pub const SYS_KACS_OPEN: i64 = 1020;
pub const SYS_KACS_GET_SD: i64 = 1021;
pub const SYS_KACS_SET_SD: i64 = 1022;
pub const SYS_KACS_ACCESS_CHECK: i64 = 1023;
pub const SYS_KACS_ACCESS_CHECK_LIST: i64 = 1024;
pub const SYS_KACS_SET_CAAP: i64 = 1025;
pub const SYS_KACS_GET_MOUNT_POLICY: i64 = 1026;
pub const SYS_KACS_SET_MOUNT_POLICY: i64 = 1027;

// ---------------------------------------------------------------------------
// KMES — kernel-mediated event stream.
// ---------------------------------------------------------------------------

pub const SYS_KMES_EMIT: i64 = 1090;
pub const SYS_KMES_ATTACH: i64 = 1091;
pub const SYS_KMES_EMIT_BATCH: i64 = 1092;

// ---------------------------------------------------------------------------
// LCS — registry.
// ---------------------------------------------------------------------------

pub const SYS_REG_OPEN_KEY: i64 = 1100;
pub const SYS_REG_CREATE_KEY: i64 = 1101;
pub const SYS_REG_BEGIN_TRANSACTION: i64 = 1102;

// ---------------------------------------------------------------------------
// Generic dirfd convenience.
// ---------------------------------------------------------------------------

/// AT_FDCWD: dirfd value meaning "current working directory" for path-based
/// *at-family syscalls. Defined by Linux UAPI as -100.
pub const AT_FDCWD: i32 = -100;

/// Do not follow the terminal symlink.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// Operate on the supplied fd itself when the path is empty.
pub const AT_EMPTY_PATH: i32 = 0x1000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_constants_match_linux_uapi_and_psd_004() {
        assert_eq!(AT_FDCWD, -100);
        assert_eq!(AT_SYMLINK_NOFOLLOW, 0x100);
        assert_eq!(AT_EMPTY_PATH, 0x1000);
    }

    #[test]
    fn lcs_syscall_numbers_match_psd_005() {
        assert_eq!(SYS_REG_OPEN_KEY, 1100);
        assert_eq!(SYS_REG_CREATE_KEY, 1101);
        assert_eq!(SYS_REG_BEGIN_TRANSACTION, 1102);
    }
}
