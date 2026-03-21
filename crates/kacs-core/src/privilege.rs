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
}
