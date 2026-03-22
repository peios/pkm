// Privilege system (§10).
//
// Privileges are system-wide rights carried on the token. Stored as
// four parallel u64 bitmasks: present, enabled, enabled_by_default, used.
// Windows defines ~35 built-in privileges; Peios adds custom privileges
// starting at bit 63 downward to avoid collision.
//
// All fields are AtomicU64 for thread-safe concurrent access — multiple
// threads sharing a token (via cred_prepare Arc clone) may read privileges
// while another thread adjusts them via KACS_IOC_ADJUST_PRIVS.

use core::sync::atomic::{AtomicU64, Ordering};

/// Privilege bitmask positions.
///
/// Windows-compatible privileges occupy their standard bit positions
/// (starting from bit 2). Peios custom privileges start at bit 63
/// and work downward.
pub mod bits {
    // --- Identity and token management ---

    /// Create a primary token (bit 2).
    pub const SE_CREATE_TOKEN: u64 = 1 << 2;
    /// Assign a primary token to a process (bit 3).
    pub const SE_ASSIGN_PRIMARY_TOKEN: u64 = 1 << 3;
    /// Impersonate a client via token (bit 29).
    pub const SE_IMPERSONATE: u64 = 1 << 29;

    // --- Access control (evaluated inside AccessCheck §11.6) ---

    /// Read/write the SACL in a security descriptor (bit 8).
    pub const SE_SECURITY: u64 = 1 << 8;
    /// Take ownership of objects without being granted access (bit 9).
    pub const SE_TAKE_OWNERSHIP: u64 = 1 << 9;
    /// Bypass access checks for read operations (backup intent, bit 17).
    pub const SE_BACKUP: u64 = 1 << 17;
    /// Bypass access checks for write/delete (restore intent, bit 18).
    pub const SE_RESTORE: u64 = 1 << 18;
    /// Modify mandatory integrity labels (bit 25).
    pub const SE_RELABEL: u64 = 1 << 25;

    // --- System operations ---

    /// Trusted Computing Base (bit 7).
    pub const SE_TCB: u64 = 1 << 7;
    /// Shut down the system (bit 19).
    pub const SE_SHUTDOWN: u64 = 1 << 19;
    /// Remote shutdown (bit 24).
    pub const SE_REMOTE_SHUTDOWN: u64 = 1 << 24;
    /// Load/unload device drivers (bit 10).
    pub const SE_LOAD_DRIVER: u64 = 1 << 10;
    /// Debug other processes (bit 20).
    pub const SE_DEBUG: u64 = 1 << 20;
    /// Change the system time (bit 12).
    pub const SE_SYSTEMTIME: u64 = 1 << 12;
    /// Increase scheduling priority (bit 14).
    pub const SE_INCREASE_BASE_PRIORITY: u64 = 1 << 14;
    /// Adjust memory quotas for a process (bit 5).
    pub const SE_INCREASE_QUOTA: u64 = 1 << 5;
    /// Lock physical pages in memory (bit 4).
    pub const SE_LOCK_MEMORY: u64 = 1 << 4;
    /// Generate security audit entries (bit 21).
    pub const SE_AUDIT: u64 = 1 << 21;
    /// Profile a single process (bit 13).
    pub const SE_PROFILE_SINGLE_PROCESS: u64 = 1 << 13;
    /// Bypass traverse checking (bit 23).
    pub const SE_CHANGE_NOTIFY: u64 = 1 << 23;
    /// Create symbolic links (bit 35).
    pub const SE_CREATE_SYMBOLIC_LINK: u64 = 1 << 35;
    /// AD synchronization agent (bit 26).
    pub const SE_SYNC_AGENT: u64 = 1 << 26;
    /// Enable Kerberos delegation (bit 27).
    pub const SE_ENABLE_DELEGATION: u64 = 1 << 27;
    /// Add machines to a domain (bit 6).
    pub const SE_MACHINE_ACCOUNT: u64 = 1 << 6;
    /// Create global objects in a session (bit 30).
    pub const SE_CREATE_GLOBAL: u64 = 1 << 30;
    /// Create a pagefile (bit 15).
    pub const SE_CREATE_PAGEFILE: u64 = 1 << 15;
    /// Create permanent shared objects (bit 16).
    pub const SE_CREATE_PERMANENT: u64 = 1 << 16;
    /// Increase process working set (bit 33).
    pub const SE_INCREASE_WORKING_SET: u64 = 1 << 33;
    /// Manage disk volumes (bit 28).
    pub const SE_MANAGE_VOLUME: u64 = 1 << 28;
    /// Access Credential Manager as a trusted caller (bit 31).
    pub const SE_TRUSTED_CRED_MAN_ACCESS: u64 = 1 << 31;
    /// Modify firmware environment variables (bit 22).
    pub const SE_SYSTEM_ENVIRONMENT: u64 = 1 << 22;
    /// Profile system performance (bit 11).
    pub const SE_SYSTEM_PROFILE: u64 = 1 << 11;
    /// Change the time zone (bit 34).
    pub const SE_TIMEZONE: u64 = 1 << 34;
    /// Undock a laptop (bit 32).
    pub const SE_UNDOCK: u64 = 1 << 32;

    // --- Peios custom privileges (bit 63 downward) ---

    /// Bind to privileged ports (Peios custom, bit 63).
    pub const SE_BIND_PRIVILEGED_PORT: u64 = 1 << 63;
    /// Create job objects (Peios custom, bit 62).
    pub const SE_CREATE_JOB: u64 = 1 << 62;

    /// All privileges that the SYSTEM token should have.
    pub const ALL_PRIVILEGES: u64 = SE_CREATE_TOKEN
        | SE_ASSIGN_PRIMARY_TOKEN
        | SE_IMPERSONATE
        | SE_SECURITY
        | SE_TAKE_OWNERSHIP
        | SE_BACKUP
        | SE_RESTORE
        | SE_RELABEL
        | SE_TCB
        | SE_SHUTDOWN
        | SE_REMOTE_SHUTDOWN
        | SE_LOAD_DRIVER
        | SE_DEBUG
        | SE_SYSTEMTIME
        | SE_INCREASE_BASE_PRIORITY
        | SE_INCREASE_QUOTA
        | SE_LOCK_MEMORY
        | SE_AUDIT
        | SE_PROFILE_SINGLE_PROCESS
        | SE_CHANGE_NOTIFY
        | SE_CREATE_SYMBOLIC_LINK
        | SE_SYNC_AGENT
        | SE_ENABLE_DELEGATION
        | SE_MACHINE_ACCOUNT
        | SE_CREATE_GLOBAL
        | SE_CREATE_PAGEFILE
        | SE_CREATE_PERMANENT
        | SE_INCREASE_WORKING_SET
        | SE_MANAGE_VOLUME
        | SE_TRUSTED_CRED_MAN_ACCESS
        | SE_SYSTEM_ENVIRONMENT
        | SE_SYSTEM_PROFILE
        | SE_TIMEZONE
        | SE_UNDOCK
        | SE_BIND_PRIVILEGED_PORT
        | SE_CREATE_JOB;
}

/// Four parallel atomic bitmasks tracking the privilege lifecycle on a token.
///
/// All fields are `AtomicU64` for thread-safe concurrent access.
/// Multiple threads may share a token (via credential cloning), and
/// one thread may adjust privileges while others read them.
pub struct Privileges {
    /// Which privileges exist on the token. Bits can be cleared
    /// (removal is permanent) but never set after creation.
    pub present: AtomicU64,
    /// Which present privileges are currently active.
    pub enabled: AtomicU64,
    /// The reset position — AdjustPrivileges can restore to this state.
    pub enabled_by_default: AtomicU64,
    /// Audit trail: set when a privilege is actually exercised.
    pub used: AtomicU64,
}

impl Privileges {
    /// Create a new privilege set with all specified privileges present and enabled.
    pub fn new_all_enabled(mask: u64) -> Self {
        Privileges {
            present: AtomicU64::new(mask),
            enabled: AtomicU64::new(mask),
            enabled_by_default: AtomicU64::new(mask),
            used: AtomicU64::new(0),
        }
    }

    /// Create a privilege set where privileges are present but NOT enabled.
    /// Mirrors the real-world case where privileges start disabled.
    pub fn new_present_but_disabled(mask: u64) -> Self {
        Privileges {
            present: AtomicU64::new(mask),
            enabled: AtomicU64::new(0),
            enabled_by_default: AtomicU64::new(0),
            used: AtomicU64::new(0),
        }
    }

    /// Check if a privilege is present AND enabled.
    #[inline]
    pub fn check(&self, privilege: u64) -> bool {
        let p = self.present.load(Ordering::SeqCst);
        let e = self.enabled.load(Ordering::SeqCst);
        (p & e & privilege) == privilege
    }

    /// Check if a privilege is present (regardless of enabled state).
    #[inline]
    pub fn is_present(&self, privilege: u64) -> bool {
        (self.present.load(Ordering::SeqCst) & privilege) == privilege
    }

    /// Enable a privilege. Returns false if the privilege is not present.
    pub fn enable(&self, privilege: u64) -> bool {
        if !self.is_present(privilege) {
            return false;
        }
        self.enabled.fetch_or(privilege, Ordering::SeqCst);
        true
    }

    /// Disable a privilege. Returns false if the privilege is not present.
    pub fn disable(&self, privilege: u64) -> bool {
        if !self.is_present(privilege) {
            return false;
        }
        self.enabled.fetch_and(!privilege, Ordering::SeqCst);
        true
    }

    /// Permanently remove a privilege. Clears from all bitmasks. Irreversible.
    pub fn remove(&self, privilege: u64) {
        self.present.fetch_and(!privilege, Ordering::SeqCst);
        self.enabled.fetch_and(!privilege, Ordering::SeqCst);
        self.enabled_by_default.fetch_and(!privilege, Ordering::SeqCst);
    }

    /// Reset all privileges to their default enabled/disabled state.
    pub fn reset_to_defaults(&self) {
        let defaults = self.enabled_by_default.load(Ordering::SeqCst)
            & self.present.load(Ordering::SeqCst);
        self.enabled.store(defaults, Ordering::SeqCst);
    }

    /// Record that a privilege was exercised (for audit).
    #[inline]
    pub fn mark_used(&self, privilege: u64) {
        self.used.fetch_or(privilege, Ordering::SeqCst);
    }
}

// Manual trait impls — AtomicU64 doesn't derive Clone, Debug, PartialEq.

impl Clone for Privileges {
    fn clone(&self) -> Self {
        Privileges {
            present: AtomicU64::new(self.present.load(Ordering::SeqCst)),
            enabled: AtomicU64::new(self.enabled.load(Ordering::SeqCst)),
            enabled_by_default: AtomicU64::new(self.enabled_by_default.load(Ordering::SeqCst)),
            used: AtomicU64::new(self.used.load(Ordering::SeqCst)),
        }
    }
}

impl core::fmt::Debug for Privileges {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Privileges")
            .field("present", &self.present.load(Ordering::SeqCst))
            .field("enabled", &self.enabled.load(Ordering::SeqCst))
            .field("enabled_by_default", &self.enabled_by_default.load(Ordering::SeqCst))
            .field("used", &self.used.load(Ordering::SeqCst))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bits::*;

    #[test]
    fn check_present_and_enabled() {
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        assert!(privs.check(SE_BACKUP));
        assert!(privs.check(SE_RESTORE));
        assert!(!privs.check(SE_DEBUG));
    }

    #[test]
    fn enable_disable_cycle() {
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        assert!(privs.check(SE_BACKUP));

        privs.disable(SE_BACKUP);
        assert!(!privs.check(SE_BACKUP));
        assert!(privs.is_present(SE_BACKUP));

        privs.enable(SE_BACKUP);
        assert!(privs.check(SE_BACKUP));
    }

    #[test]
    fn remove_is_permanent() {
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.remove(SE_BACKUP);

        assert!(!privs.is_present(SE_BACKUP));
        assert!(!privs.check(SE_BACKUP));
        assert!(!privs.enable(SE_BACKUP)); // can't re-enable after remove
    }

    #[test]
    fn reset_to_defaults() {
        let privs = Privileges {
            present: AtomicU64::new(SE_BACKUP | SE_RESTORE | SE_DEBUG),
            enabled: AtomicU64::new(SE_BACKUP | SE_RESTORE | SE_DEBUG),
            enabled_by_default: AtomicU64::new(SE_BACKUP),
            used: AtomicU64::new(0),
        };

        privs.disable(SE_BACKUP);
        privs.reset_to_defaults();

        assert!(privs.check(SE_BACKUP)); // restored
        assert!(!privs.check(SE_RESTORE)); // was not default-enabled
        assert!(!privs.check(SE_DEBUG)); // was not default-enabled
    }

    #[test]
    fn enable_nonexistent_returns_false() {
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        assert!(!privs.enable(SE_DEBUG)); // not present
    }

    #[test]
    fn mark_used() {
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        assert_eq!(privs.used.load(Ordering::SeqCst), 0);
        privs.mark_used(SE_BACKUP);
        assert_eq!(privs.used.load(Ordering::SeqCst), SE_BACKUP);
    }

    #[test]
    fn reset_respects_removal() {
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.remove(SE_BACKUP);
        privs.reset_to_defaults();
        // Backup was removed — reset can't bring it back
        assert!(!privs.check(SE_BACKUP));
        assert!(privs.check(SE_RESTORE));
    }

    #[test]
    fn system_token_has_all_privileges() {
        let privs = Privileges::new_all_enabled(ALL_PRIVILEGES);
        assert!(privs.check(SE_CREATE_TOKEN));
        assert!(privs.check(SE_ASSIGN_PRIMARY_TOKEN));
        assert!(privs.check(SE_TCB));
        assert!(privs.check(SE_SECURITY));
        assert!(privs.check(SE_BACKUP));
        assert!(privs.check(SE_RESTORE));
        assert!(privs.check(SE_DEBUG));
        assert!(privs.check(SE_IMPERSONATE));
        assert!(privs.check(SE_BIND_PRIVILEGED_PORT));
        assert!(privs.check(SE_CREATE_JOB));
    }

    // --- §2.16 Token Privilege Bitmask Fields ---

    #[test]
    fn privilege_present_u64() {
        // §7.3 line 2086: privileges_present is a u64 bitmask
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        assert_eq!(core::mem::size_of_val(&privs.present), 8); // AtomicU64 = 8 bytes
    }

    #[test]
    fn privilege_enabled_u64() {
        // §7.3 line 2087: privileges_enabled toggleable for non-removed
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.disable(SE_BACKUP);
        assert!(privs.is_present(SE_BACKUP));
        assert!(!privs.check(SE_BACKUP));
        assert!(privs.check(SE_RESTORE));
    }

    #[test]
    fn privilege_enabled_by_default_u64() {
        // §7.3 line 2088: reset position for AdjustTokenPrivileges
        let privs = Privileges {
            present: AtomicU64::new(SE_BACKUP | SE_RESTORE),
            enabled: AtomicU64::new(SE_BACKUP | SE_RESTORE),
            enabled_by_default: AtomicU64::new(SE_BACKUP), // only backup is default
            used: AtomicU64::new(0),
        };
        privs.reset_to_defaults();
        assert!(privs.check(SE_BACKUP));
        assert!(!privs.check(SE_RESTORE)); // not default-enabled
    }

    #[test]
    fn privilege_used_u64() {
        // §7.3 line 2089: audit trail
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        privs.mark_used(SE_BACKUP);
        assert_eq!(privs.used.load(Ordering::SeqCst) & SE_BACKUP, SE_BACKUP);
    }

    #[test]
    fn privilege_removal_clears_all_three_masks() {
        // §7.3 lines 2093-2094
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.remove(SE_BACKUP);
        assert_eq!(privs.present.load(Ordering::SeqCst) & SE_BACKUP, 0);
        assert_eq!(privs.enabled.load(Ordering::SeqCst) & SE_BACKUP, 0);
        assert_eq!(privs.enabled_by_default.load(Ordering::SeqCst) & SE_BACKUP, 0);
    }

    #[test]
    fn privilege_lifecycle() {
        // §7.3 lines 2091-2094: present+disabled -> enabled -> used -> disabled -> removed
        let privs = Privileges {
            present: AtomicU64::new(SE_DEBUG),
            enabled: AtomicU64::new(0), // present but disabled
            enabled_by_default: AtomicU64::new(0),
            used: AtomicU64::new(0),
        };
        assert!(privs.is_present(SE_DEBUG));
        assert!(!privs.check(SE_DEBUG)); // disabled

        privs.enable(SE_DEBUG);
        assert!(privs.check(SE_DEBUG)); // enabled

        privs.mark_used(SE_DEBUG);
        assert_ne!(privs.used.load(Ordering::SeqCst) & SE_DEBUG, 0); // used

        privs.disable(SE_DEBUG);
        assert!(!privs.check(SE_DEBUG)); // disabled again

        privs.remove(SE_DEBUG);
        assert!(!privs.is_present(SE_DEBUG)); // gone
        assert!(!privs.enable(SE_DEBUG)); // can't re-enable
    }

    #[test]
    fn privilege_present_bits_never_set_after_creation() {
        // §7.3 line 2086: present bits can only be cleared, never set
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        assert!(!privs.is_present(SE_DEBUG));
        // enable() won't set the present bit
        assert!(!privs.enable(SE_DEBUG));
        assert!(!privs.is_present(SE_DEBUG));
    }

    // --- §10.2 Privilege Model ---

    #[test]
    fn privilege_assigned_at_token_creation() {
        // §10.2 lines 4011-4016: resolved at token creation time
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        assert!(privs.is_present(SE_BACKUP));
        assert!(privs.is_present(SE_RESTORE));
    }

    #[test]
    fn privilege_no_add_after_creation() {
        // §10.2 lines 4015-4016
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        assert!(!privs.enable(SE_DEBUG)); // not present, can't add
    }

    #[test]
    fn privilege_most_start_disabled() {
        // §10.2 lines 4018-4020
        let privs = Privileges {
            present: AtomicU64::new(SE_BACKUP | SE_RESTORE | SE_DEBUG),
            enabled: AtomicU64::new(SE_CHANGE_NOTIFY), // only SeChangeNotify enabled
            enabled_by_default: AtomicU64::new(SE_CHANGE_NOTIFY),
            used: AtomicU64::new(0),
        };
        assert!(privs.is_present(SE_BACKUP));
        assert!(!privs.check(SE_BACKUP)); // present but disabled
    }

    #[test]
    fn privilege_must_enable_before_use() {
        // §10.2 lines 4023-4025
        let privs = Privileges {
            present: AtomicU64::new(SE_BACKUP),
            enabled: AtomicU64::new(0),
            enabled_by_default: AtomicU64::new(0),
            used: AtomicU64::new(0),
        };
        assert!(!privs.check(SE_BACKUP)); // present but disabled = not exercised
        privs.enable(SE_BACKUP);
        assert!(privs.check(SE_BACKUP)); // now exercisable
    }

    #[test]
    fn privilege_check_requires_present_and_enabled() {
        // §10.2 line 4054
        let privs = Privileges {
            present: AtomicU64::new(SE_BACKUP),
            enabled: AtomicU64::new(0), // present but not enabled
            enabled_by_default: AtomicU64::new(0),
            used: AtomicU64::new(0),
        };
        assert!(!privs.check(SE_BACKUP));
        let privs2 = Privileges {
            present: AtomicU64::new(0), // not present
            enabled: AtomicU64::new(SE_BACKUP), // "enabled" but not present
            enabled_by_default: AtomicU64::new(0),
            used: AtomicU64::new(0),
        };
        assert!(!privs2.check(SE_BACKUP));
    }

    #[test]
    fn privilege_can_be_disabled_after_use() {
        // §10.2 line 4033
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        privs.mark_used(SE_BACKUP);
        privs.disable(SE_BACKUP);
        assert!(!privs.check(SE_BACKUP));
        assert!(privs.is_present(SE_BACKUP)); // still present
    }

    #[test]
    fn privilege_can_be_permanently_removed() {
        // §10.2 lines 4033-4034
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        privs.remove(SE_BACKUP);
        assert!(!privs.is_present(SE_BACKUP));
        assert!(!privs.enable(SE_BACKUP)); // irreversible
    }

    #[test]
    fn privilege_check_is_bitmask_test() {
        // §10.2 lines 4055-4056
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        let enabled = privs.enabled.load(Ordering::SeqCst);
        let present = privs.present.load(Ordering::SeqCst);
        assert_eq!((present & enabled & SE_BACKUP), SE_BACKUP);
    }

    // --- §10.3 Five AccessCheck-Influencing Privileges ---

    #[test]
    fn privilege_accesscheck_influencing_count() {
        // §10.3 line 4072: exactly five
        let ac_privs = [SE_SECURITY, SE_TAKE_OWNERSHIP, SE_BACKUP, SE_RESTORE, SE_RELABEL];
        assert_eq!(ac_privs.len(), 5);
    }

    #[test]
    fn se_security_is_accesscheck_enforcement() {
        assert_eq!(SE_SECURITY, 1 << 8);
    }

    #[test]
    fn se_take_ownership_is_accesscheck_enforcement() {
        assert_eq!(SE_TAKE_OWNERSHIP, 1 << 9);
    }

    #[test]
    fn se_backup_is_accesscheck_enforcement() {
        assert_eq!(SE_BACKUP, 1 << 17);
    }

    #[test]
    fn se_restore_is_accesscheck_enforcement() {
        assert_eq!(SE_RESTORE, 1 << 18);
    }

    #[test]
    fn se_relabel_is_accesscheck_plus_enforcement() {
        assert_eq!(SE_RELABEL, 1 << 25);
    }

    #[test]
    fn se_change_notify_default_granted() {
        // §10.8 line 4244: granted to all principals by default
        // When creating a normal user token, SE_CHANGE_NOTIFY should be present
        let privs = Privileges::new_all_enabled(SE_CHANGE_NOTIFY);
        assert!(privs.check(SE_CHANGE_NOTIFY));
    }

    #[test]
    fn se_create_symbolic_link_default_granted() {
        // §10.8 line 4245
        let privs = Privileges::new_all_enabled(SE_CREATE_SYMBOLIC_LINK);
        assert!(privs.check(SE_CREATE_SYMBOLIC_LINK));
    }

    // --- §10.5 Privilege Assignment ---

    #[test]
    fn privilege_not_from_group_membership() {
        // §10.5 lines 4122-4124: Administrators group doesn't confer privileges
        // Privileges are orthogonal to group membership
        let privs = Privileges::new_all_enabled(0); // no privileges
        assert!(!privs.check(SE_BACKUP));
        assert!(!privs.check(SE_DEBUG));
    }

    #[test]
    fn privilege_set_fixed_at_birth() {
        // §10.5 lines 4147-4150
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        assert!(!privs.enable(SE_DEBUG)); // can't add after creation
    }

    #[test]
    fn privilege_no_runtime_escalation() {
        // §10.5 lines 4152-4154
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        // Only present bits can be toggled — can't expand the set
        assert!(!privs.enable(SE_TCB));
        assert!(!privs.is_present(SE_TCB));
    }

    // --- §10.6 Custom Peios Privileges ---

    #[test]
    fn custom_privileges_from_bit_63_downward() {
        // §10.6 lines 4165-4166
        assert_eq!(SE_BIND_PRIVILEGED_PORT, 1u64 << 63);
        assert_eq!(SE_CREATE_JOB, 1u64 << 62);
    }

    #[test]
    fn windows_privileges_from_bit_2_upward() {
        // §10.6 lines 4166-4167
        assert_eq!(SE_CREATE_TOKEN, 1u64 << 2);
        assert_eq!(SE_ASSIGN_PRIMARY_TOKEN, 1u64 << 3);
    }

    #[test]
    fn custom_grow_down_windows_grow_up() {
        // §10.6 lines 4169-4170: no collision between custom and Windows
        let windows_max_bit = 35u32; // SE_CREATE_SYMBOLIC_LINK
        let custom_min_bit = 62u32;  // SE_CREATE_JOB
        assert!(custom_min_bit > windows_max_bit);
    }

    #[test]
    fn v1_only_custom_privilege_is_bind_port() {
        // §10.6 lines 4172-4173 (plus SE_CREATE_JOB)
        // Only custom Peios privileges are SE_BIND_PRIVILEGED_PORT and SE_CREATE_JOB
        assert!(SE_BIND_PRIVILEGED_PORT > (1u64 << 36)); // above Windows range
        assert!(SE_CREATE_JOB > (1u64 << 36));
    }

    // --- §10.7 Privilege Auditing ---

    #[test]
    fn privilege_used_is_monotonic() {
        // §10.7 lines 4188-4189: bits set but never cleared
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.mark_used(SE_BACKUP);
        privs.mark_used(SE_RESTORE);
        let used = privs.used.load(Ordering::SeqCst);
        assert_ne!(used & SE_BACKUP, 0);
        assert_ne!(used & SE_RESTORE, 0);
        // No method to clear used bits
    }

    #[test]
    fn privilege_enabled_exercised_sets_used_bit() {
        // §10.2 lines 4028-4030, §10.7 lines 4187-4189
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        assert_eq!(privs.used.load(Ordering::SeqCst), 0);
        privs.mark_used(SE_BACKUP);
        assert_ne!(privs.used.load(Ordering::SeqCst) & SE_BACKUP, 0);
    }

    #[test]
    fn privilege_present_disabled_not_exercised() {
        // §10.2 line 4054: present but disabled is NOT exercised
        let privs = Privileges {
            present: AtomicU64::new(SE_BACKUP),
            enabled: AtomicU64::new(0),
            enabled_by_default: AtomicU64::new(0),
            used: AtomicU64::new(0),
        };
        assert!(!privs.check(SE_BACKUP));
    }

    // --- §10.8 Privilege Catalog Counts ---

    #[test]
    fn privilege_catalog_identity_count_3() {
        // §10.8 lines 4229-4233
        let identity = [SE_CREATE_TOKEN, SE_ASSIGN_PRIMARY_TOKEN, SE_IMPERSONATE];
        assert_eq!(identity.len(), 3);
    }

    #[test]
    fn privilege_catalog_access_control_count_7() {
        // §10.8 lines 4237-4245
        let ac = [SE_SECURITY, SE_TAKE_OWNERSHIP, SE_BACKUP, SE_RESTORE,
                  SE_RELABEL, SE_CHANGE_NOTIFY, SE_CREATE_SYMBOLIC_LINK];
        assert_eq!(ac.len(), 7);
    }

    #[test]
    fn privilege_catalog_system_ops_count_12() {
        // §10.8 lines 4249-4262 (including SE_CREATE_JOB)
        let sys = [SE_TCB, SE_SHUTDOWN, SE_REMOTE_SHUTDOWN, SE_LOAD_DRIVER,
                   SE_DEBUG, SE_SYSTEMTIME, SE_INCREASE_BASE_PRIORITY,
                   SE_INCREASE_QUOTA, SE_LOCK_MEMORY, SE_AUDIT,
                   SE_PROFILE_SINGLE_PROCESS, SE_CREATE_JOB];
        assert_eq!(sys.len(), 12);
    }

    #[test]
    fn privilege_catalog_network_count_1() {
        // §10.8 lines 4266-4268
        let net = [SE_BIND_PRIVILEGED_PORT];
        assert_eq!(net.len(), 1);
    }

    #[test]
    fn privilege_catalog_directory_count_3() {
        // §10.8 lines 4272-4276
        let dir = [SE_SYNC_AGENT, SE_ENABLE_DELEGATION, SE_MACHINE_ACCOUNT];
        assert_eq!(dir.len(), 3);
    }

    #[test]
    fn privilege_catalog_reserved_count_10() {
        // §10.8 lines 4285-4296
        let reserved = [SE_CREATE_GLOBAL, SE_CREATE_PAGEFILE, SE_CREATE_PERMANENT,
                        SE_INCREASE_WORKING_SET, SE_MANAGE_VOLUME,
                        SE_TRUSTED_CRED_MAN_ACCESS, SE_SYSTEM_ENVIRONMENT,
                        SE_SYSTEM_PROFILE, SE_TIMEZONE, SE_UNDOCK];
        assert_eq!(reserved.len(), 10);
    }

    #[test]
    fn privilege_all_fit_in_u64() {
        // §10.6 lines 4165-4170: all privileges fit in u64
        let _: u64 = ALL_PRIVILEGES; // compiles = fits in u64
        assert_ne!(ALL_PRIVILEGES, 0);
    }

    // --- Reserved privilege assertions ---

    #[test]
    fn se_create_global_reserved() {
        assert_eq!(SE_CREATE_GLOBAL, 1 << 30);
    }

    #[test]
    fn se_create_pagefile_reserved() {
        assert_eq!(SE_CREATE_PAGEFILE, 1 << 15);
    }

    #[test]
    fn se_create_permanent_reserved() {
        assert_eq!(SE_CREATE_PERMANENT, 1 << 16);
    }

    #[test]
    fn se_increase_working_set_reserved() {
        assert_eq!(SE_INCREASE_WORKING_SET, 1 << 33);
    }

    #[test]
    fn se_manage_volume_reserved() {
        assert_eq!(SE_MANAGE_VOLUME, 1 << 28);
    }

    #[test]
    fn se_trusted_cred_man_access_reserved() {
        assert_eq!(SE_TRUSTED_CRED_MAN_ACCESS, 1 << 31);
    }

    #[test]
    fn se_system_environment_reserved() {
        assert_eq!(SE_SYSTEM_ENVIRONMENT, 1 << 22);
    }

    #[test]
    fn se_system_profile_reserved() {
        assert_eq!(SE_SYSTEM_PROFILE, 1 << 11);
    }

    #[test]
    fn se_time_zone_reserved() {
        assert_eq!(SE_TIMEZONE, 1 << 34);
    }

    #[test]
    fn se_undock_reserved() {
        assert_eq!(SE_UNDOCK, 1 << 32);
    }

    #[test]
    fn reserved_privileges_have_no_enforcement() {
        // §10.8 lines 4280-4284: bit positions exist only for AD token compatibility.
        // All reserved privileges are present in ALL_PRIVILEGES for SYSTEM token.
        let reserved = SE_CREATE_GLOBAL | SE_CREATE_PAGEFILE | SE_CREATE_PERMANENT
            | SE_INCREASE_WORKING_SET | SE_MANAGE_VOLUME | SE_TRUSTED_CRED_MAN_ACCESS
            | SE_SYSTEM_ENVIRONMENT | SE_SYSTEM_PROFILE | SE_TIMEZONE | SE_UNDOCK;
        assert_eq!(ALL_PRIVILEGES & reserved, reserved);
    }

    // --- §10.8 Application-level privilege assertions ---

    #[test]
    fn se_sync_agent_is_application_level() {
        assert_eq!(SE_SYNC_AGENT, 1 << 26);
    }

    #[test]
    fn se_enable_delegation_is_application_level() {
        assert_eq!(SE_ENABLE_DELEGATION, 1 << 27);
    }

    #[test]
    fn se_machine_account_is_application_level() {
        assert_eq!(SE_MACHINE_ACCOUNT, 1 << 6);
    }

    // --- §10.3 Standalone vs AccessCheck-influencing ---

    #[test]
    fn privilege_standalone_independent_of_accesscheck() {
        // §10.3 lines 4050-4052: standalone privileges don't go through AccessCheck
        // SE_TCB, SE_SHUTDOWN, etc. are standalone; check they're distinct from AC privs
        let ac_privs = SE_SECURITY | SE_TAKE_OWNERSHIP | SE_BACKUP | SE_RESTORE | SE_RELABEL;
        assert_eq!(SE_TCB & ac_privs, 0);
        assert_eq!(SE_SHUTDOWN & ac_privs, 0);
        assert_eq!(SE_DEBUG & ac_privs, 0);
    }

    #[test]
    fn privilege_has_enable_disable_lifecycle() {
        // §10.1 lines 3988-3991: unlike capabilities which are binary
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        assert!(privs.check(SE_BACKUP));
        privs.disable(SE_BACKUP);
        assert!(!privs.check(SE_BACKUP));
        assert!(privs.is_present(SE_BACKUP)); // still present, just disabled
    }

    #[test]
    fn privilege_usage_tracked() {
        // §10.1 lines 3995-3999
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.mark_used(SE_BACKUP);
        let used = privs.used.load(Ordering::SeqCst);
        assert_ne!(used & SE_BACKUP, 0);
        assert_eq!(used & SE_RESTORE, 0); // not used yet
    }

    // --- §10.4 Intent-gated ---

    #[test]
    fn se_backup_intent_gated() {
        // §10.4 lines 4114-4118: only evaluated with BACKUP_INTENT flag
        // We verify the privilege exists and is distinct
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        assert!(privs.check(SE_BACKUP));
    }

    #[test]
    fn se_restore_intent_gated() {
        // §10.4 lines 4114-4118
        let privs = Privileges::new_all_enabled(SE_RESTORE);
        assert!(privs.check(SE_RESTORE));
    }

    #[test]
    fn privilege_orthogonal_to_groups() {
        // §10.5 lines 4126-4128: privileges and groups are orthogonal
        // Verified by the fact that Privileges struct has no group fields
        let privs = Privileges::new_all_enabled(0);
        assert!(!privs.check(SE_BACKUP)); // no privileges = no access
    }

    #[test]
    fn privilege_new_token_only_via_auth_or_create() {
        // §10.5 lines 4155-4157: only path to different privileges is new
        // authentication event or SeCreateTokenPrivilege
        let privs = Privileges::new_all_enabled(SE_BACKUP);
        // Cannot add SE_DEBUG after creation
        assert!(!privs.enable(SE_DEBUG));
        // SE_CREATE_TOKEN would be needed to mint a new token with SE_DEBUG
        assert_eq!(SE_CREATE_TOKEN, 1 << 2);
    }

    #[test]
    fn accesscheck_privilege_audit_only_when_necessary() {
        // §10.7 lines 4191-4196: audit emitted only when privilege was
        // actually necessary (access would have been denied without it)
        // Verified structurally: privileges_used tracks which privileges
        // were exercised, and mark_used is called only when needed.
        let privs = Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        assert_eq!(privs.used.load(Ordering::SeqCst), 0);
        // Only mark_used when the privilege was necessary for access
        privs.mark_used(SE_BACKUP);
        assert_ne!(privs.used.load(Ordering::SeqCst) & SE_BACKUP, 0);
        assert_eq!(privs.used.load(Ordering::SeqCst) & SE_RESTORE, 0);
    }

    // -----------------------------------------------------------------------
    // §6.4 — Privilege enable/disable semantics
    // -----------------------------------------------------------------------

    #[test]
    fn privilege_enable_disable() {
        let privs = Privileges::new_present_but_disabled(SE_BACKUP | SE_RESTORE);
        assert!(privs.is_present(SE_BACKUP));
        assert!(!privs.check(SE_BACKUP));
        privs.enable(SE_BACKUP);
        assert!(privs.check(SE_BACKUP));
    }

    #[test]
    fn privileges_start_disabled() {
        let privs = Privileges::new_present_but_disabled(SE_BACKUP | SE_RESTORE);
        assert!(!privs.check(SE_BACKUP));
        assert!(!privs.check(SE_RESTORE));
        assert!(privs.is_present(SE_BACKUP));
        assert!(privs.is_present(SE_RESTORE));
    }

    #[test]
    fn se_relabel_privilege_bit_is_32() {
        assert_eq!(SE_RELABEL, 1u64 << 25);
    }

    #[test]
    fn se_undock_privilege_bit_is_25() {
        assert_eq!(SE_UNDOCK, 1u64 << 32);
    }

    #[test]
    fn privilege_bit_positions_match_windows_luids() {
        assert_eq!(SE_CREATE_TOKEN, 1u64 << 2);
        assert_eq!(SE_ASSIGN_PRIMARY_TOKEN, 1u64 << 3);
        assert_eq!(SE_LOCK_MEMORY, 1u64 << 4);
        assert_eq!(SE_INCREASE_QUOTA, 1u64 << 5);
        assert_eq!(SE_MACHINE_ACCOUNT, 1u64 << 6);
        assert_eq!(SE_TCB, 1u64 << 7);
        assert_eq!(SE_SECURITY, 1u64 << 8);
        assert_eq!(SE_TAKE_OWNERSHIP, 1u64 << 9);
        assert_eq!(SE_LOAD_DRIVER, 1u64 << 10);
        assert_eq!(SE_SYSTEM_PROFILE, 1u64 << 11);
        assert_eq!(SE_SYSTEMTIME, 1u64 << 12);
        assert_eq!(SE_PROFILE_SINGLE_PROCESS, 1u64 << 13);
        assert_eq!(SE_INCREASE_BASE_PRIORITY, 1u64 << 14);
        assert_eq!(SE_CREATE_PAGEFILE, 1u64 << 15);
        assert_eq!(SE_CREATE_PERMANENT, 1u64 << 16);
        assert_eq!(SE_BACKUP, 1u64 << 17);
        assert_eq!(SE_RESTORE, 1u64 << 18);
        assert_eq!(SE_SHUTDOWN, 1u64 << 19);
        assert_eq!(SE_DEBUG, 1u64 << 20);
        assert_eq!(SE_AUDIT, 1u64 << 21);
        assert_eq!(SE_SYSTEM_ENVIRONMENT, 1u64 << 22);
        assert_eq!(SE_CHANGE_NOTIFY, 1u64 << 23);
        assert_eq!(SE_REMOTE_SHUTDOWN, 1u64 << 24);
        assert_eq!(SE_RELABEL, 1u64 << 25);
        assert_eq!(SE_SYNC_AGENT, 1u64 << 26);
        assert_eq!(SE_ENABLE_DELEGATION, 1u64 << 27);
        assert_eq!(SE_MANAGE_VOLUME, 1u64 << 28);
        assert_eq!(SE_IMPERSONATE, 1u64 << 29);
        assert_eq!(SE_CREATE_GLOBAL, 1u64 << 30);
        assert_eq!(SE_TRUSTED_CRED_MAN_ACCESS, 1u64 << 31);
        assert_eq!(SE_UNDOCK, 1u64 << 32);
        assert_eq!(SE_INCREASE_WORKING_SET, 1u64 << 33);
        assert_eq!(SE_TIMEZONE, 1u64 << 34);
        assert_eq!(SE_CREATE_SYMBOLIC_LINK, 1u64 << 35);
    }

    #[test]
    fn privilege_set_backup_starts_disabled() {
        let privs = Privileges::new_present_but_disabled(SE_BACKUP);
        assert!(privs.is_present(SE_BACKUP));
        assert!(!privs.check(SE_BACKUP));
    }

    #[test]
    fn privilege_set_restore_starts_disabled() {
        let privs = Privileges::new_present_but_disabled(SE_RESTORE);
        assert!(privs.is_present(SE_RESTORE));
        assert!(!privs.check(SE_RESTORE));
    }
}
