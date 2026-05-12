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

// ---------------------------------------------------------------------------
// Generic dirfd convenience.
// ---------------------------------------------------------------------------

/// AT_FDCWD: dirfd value meaning "current working directory" for path-based
/// *at-family syscalls. Defined by Linux UAPI as -100.
pub const AT_FDCWD: i32 = -100;
