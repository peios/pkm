//! Logon sessions — one per authentication event.
//!
//! A session represents "user X authenticated via method Y at time Z."
//! Each session gets a unique logon SID (S-1-5-5-{high}-{low}) derived
//! from the session ID. Tokens reference their session, and the logon
//! SID is injected into the token's group list.

use crate::compat::{self, AllocError, TryClone, Vec};
use crate::sid::Sid;

/// Logon type — how the user authenticated. Matches Windows values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogonType {
    /// Console or GUI login.
    Interactive = 2,
    /// Network authentication (SMB, HTTP, etc.).
    Network = 3,
    /// Batch job (scheduled task).
    Batch = 4,
    /// System service.
    Service = 5,
    /// Network cleartext (FTP, HTTP Basic).
    NetworkCleartext = 8,
    /// New credentials (runas-style).
    NewCredentials = 9,
}

impl LogonType {
    /// Parse from wire format byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            2 => Some(LogonType::Interactive),
            3 => Some(LogonType::Network),
            4 => Some(LogonType::Batch),
            5 => Some(LogonType::Service),
            8 => Some(LogonType::NetworkCleartext),
            9 => Some(LogonType::NewCredentials),
            _ => None,
        }
    }
}

/// A logon session.
pub struct LogonSession {
    /// Unique session ID. The logon SID is derived from this:
    /// S-1-5-5-{id >> 32}-{id & 0xFFFFFFFF}.
    pub session_id: u64,
    /// How the user authenticated.
    pub logon_type: LogonType,
    /// Who authenticated.
    pub user_sid: Sid,
    /// Reference count from tokens. Session is removed when this hits zero.
    pub refcount: core::sync::atomic::AtomicU32,
}

impl LogonSession {
    /// Derive the logon SID from the session ID.
    pub fn logon_sid(&self) -> Result<Sid, AllocError> {
        logon_sid_from_id(self.session_id)
    }
}

/// Derive a logon SID from a session ID.
pub fn logon_sid_from_id(session_id: u64) -> Result<Sid, AllocError> {
    let high = (session_id >> 32) as u32;
    let low = (session_id & 0xFFFF_FFFF) as u32;
    Sid::new(5, &[5, high, low])
}

/// Session table — stores all active logon sessions.
/// In the kernel, this is a global protected by a lock.
pub struct SessionTable {
    sessions: Vec<LogonSession>,
    next_id: u64,
}

impl SessionTable {
    /// Create an empty session table. Session IDs start at 1
    /// (session 0 is the SYSTEM session, created at boot).
    pub fn new() -> Self {
        SessionTable {
            sessions: Vec::new(),
            next_id: 0,
        }
    }

    /// Create the SYSTEM session (session 0). Called at boot.
    pub fn create_system_session(
        &mut self,
        system_sid: Sid,
    ) -> Result<u64, AllocError> {
        self.create(LogonType::Service, system_sid)
    }

    /// Create a new session. Returns the session ID.
    pub fn create(
        &mut self,
        logon_type: LogonType,
        user_sid: Sid,
    ) -> Result<u64, AllocError> {
        let id = self.next_id;
        self.next_id += 1;

        compat::vec_push(&mut self.sessions, LogonSession {
            session_id: id,
            logon_type,
            user_sid,
            refcount: core::sync::atomic::AtomicU32::new(0),
        })?;

        Ok(id)
    }

    /// Increment a session's refcount (called when a token is created).
    pub fn addref(&self, session_id: u64) {
        if let Some(s) = self.sessions.iter().find(|s| s.session_id == session_id) {
            s.refcount.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Decrement a session's refcount. Returns true if refcount hit zero.
    pub fn release(&self, session_id: u64) -> bool {
        if let Some(s) = self.sessions.iter().find(|s| s.session_id == session_id) {
            s.refcount.fetch_sub(1, core::sync::atomic::Ordering::SeqCst) == 1
        } else {
            false
        }
    }

    /// Remove a session by ID. Returns true if found and removed.
    /// Remove a session by ID. Returns true if found and removed.
    /// Uses linear scan + shift — fine for small tables (O(hundreds)).
    pub fn remove(&mut self, session_id: u64) -> bool {
        let len = self.sessions.len();
        let mut found = false;
        let mut write = 0;
        for read in 0..len {
            if self.sessions[read].session_id == session_id && !found {
                found = true;
                continue; // skip this element
            }
            if write != read {
                // Shift element left — we can't move AtomicU32, so
                // reconstruct the entry. Session removal is rare.
                let s = &self.sessions[read];
                self.sessions[write] = LogonSession {
                    session_id: s.session_id,
                    logon_type: s.logon_type,
                    user_sid: s.user_sid.try_clone().unwrap_or_else(|_| {
                        crate::sid::Sid::new(0, &[]).unwrap()
                    }),
                    refcount: core::sync::atomic::AtomicU32::new(
                        s.refcount.load(core::sync::atomic::Ordering::SeqCst)
                    ),
                };
            }
            write += 1;
        }
        if found {
            self.sessions.truncate(write);
        }
        found
    }

    /// Look up a session by ID.
    pub fn get(&self, session_id: u64) -> Option<&LogonSession> {
        self.sessions.iter().find(|s| s.session_id == session_id)
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// True if no sessions exist.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Iterate over all sessions.
    pub fn iter_sessions(&self) -> impl Iterator<Item = &LogonSession> {
        self.sessions.iter()
    }
}

/// Session spec wire format for kacs_create_session.
///
/// Layout: [logon_type:u8] [user_sid_len:u32le] [user_sid bytes]
pub fn parse_session_spec(data: &[u8]) -> Option<(LogonType, Sid)> {
    if data.len() < 5 {
        return None;
    }

    let logon_type = LogonType::from_u8(data[0])?;
    let sid_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;

    if data.len() < 5 + sid_len {
        return None;
    }

    let user_sid = Sid::from_bytes(&data[5..5 + sid_len])?;
    Some((logon_type, user_sid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::well_known;

    #[test]
    fn create_system_session() {
        let mut table = SessionTable::new();
        let id = table.create_system_session(well_known::system().unwrap()).unwrap();
        assert_eq!(id, 0);
        assert_eq!(table.len(), 1);

        let session = table.get(0).unwrap();
        assert_eq!(session.logon_type, LogonType::Service);
        assert_eq!(session.user_sid, well_known::system().unwrap());

        let sid = session.logon_sid().unwrap();
        assert_eq!(sid, Sid::new(5, &[5, 0, 0]).unwrap());
    }

    #[test]
    fn create_user_session() {
        let mut table = SessionTable::new();
        let _ = table.create_system_session(well_known::system().unwrap()).unwrap();

        let user = Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let id = table.create(LogonType::Interactive, user.clone()).unwrap();
        assert_eq!(id, 1);

        let session = table.get(1).unwrap();
        assert_eq!(session.logon_type, LogonType::Interactive);

        // Logon SID for session 1: S-1-5-5-0-1
        let sid = session.logon_sid().unwrap();
        assert_eq!(sid, Sid::new(5, &[5, 0, 1]).unwrap());
    }

    #[test]
    fn parse_spec() {
        let system = well_known::system().unwrap();
        let sid_bytes = system.to_bytes().unwrap();

        let mut spec = alloc::vec![5u8]; // Service
        spec.extend_from_slice(&(sid_bytes.len() as u32).to_le_bytes());
        spec.extend_from_slice(&sid_bytes);

        let (logon_type, user_sid) = parse_session_spec(&spec).unwrap();
        assert_eq!(logon_type, LogonType::Service);
        assert_eq!(user_sid, system);
    }
}
