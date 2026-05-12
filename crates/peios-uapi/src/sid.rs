// Security Identifier (SID) — Peios uses the Windows binary SID layout
// verbatim (MS-DTYP § 2.4.2 / 2.4.2.2).
//
// Binary layout (variable length):
//   u8  Revision               (always 1)
//   u8  SubAuthorityCount      (0..=15)
//   u8[6] IdentifierAuthority  (big-endian 48-bit)
//   u32 SubAuthority[count]    (little-endian, one per subauthority)
//
// Text form: "S-<rev>-<authority>-<sub1>-<sub2>-...".

/// A parsed/owned Security Identifier.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    pub revision: u8,
    pub authority: u64, // 48-bit value
    pub sub_authorities: Vec<u32>,
}

/// Length-in-bytes of a SID structure given its subauthority count.
pub fn sid_byte_len(sub_authority_count: u8) -> usize {
    8 + 4 * (sub_authority_count as usize)
}

impl Sid {
    /// Parse the leading SID from `bytes`. Returns (sid, bytes_consumed).
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), &'static str> {
        if bytes.len() < 8 {
            return Err("SID too short for header");
        }
        let revision = bytes[0];
        let count = bytes[1] as usize;
        let need = 8 + 4 * count;
        if bytes.len() < need {
            return Err("SID truncated");
        }
        let mut authority: u64 = 0;
        for &b in &bytes[2..8] {
            authority = (authority << 8) | b as u64;
        }
        let mut subs = Vec::with_capacity(count);
        for i in 0..count {
            let off = 8 + 4 * i;
            subs.push(u32::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ]));
        }
        Ok((
            Self {
                revision,
                authority,
                sub_authorities: subs,
            },
            need,
        ))
    }

    /// Number of bytes this SID occupies on the wire.
    pub fn encoded_len(&self) -> usize {
        sid_byte_len(self.sub_authorities.len() as u8)
    }

    /// Render in the canonical text form "S-<rev>-<authority>-<sub>...".
    pub fn to_string(&self) -> String {
        let mut s = format!("S-{}-{}", self.revision, self.authority);
        for sa in &self.sub_authorities {
            s.push('-');
            s.push_str(&sa.to_string());
        }
        s
    }

    /// Return a human-readable label for well-known SIDs, or an empty string
    /// for unknown SIDs. Suitable for parenthetical annotation:
    ///   format!("{}{}", sid.to_string(), sid.well_known_label())
    /// (the labels include leading " (" themselves).
    pub fn well_known_label(&self) -> &'static str {
        well_known_label(&self.to_string())
    }
}

impl core::fmt::Display for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl core::fmt::Debug for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sid({})", self.to_string())
    }
}

/// Look up a label for a canonical-form SID string. Returns "" for unknown.
/// Labels are formatted with leading " (" and trailing ")" so they can be
/// concatenated directly after the SID text.
pub fn well_known_label(sid: &str) -> &'static str {
    match sid {
        "S-1-0-0" => " (Null)",
        "S-1-1-0" => " (World/Everyone)",
        "S-1-5-7" => " (Anonymous)",
        "S-1-5-11" => " (Authenticated Users)",
        "S-1-5-18" => " (LocalSystem)",
        "S-1-5-19" => " (LocalService)",
        "S-1-5-20" => " (NetworkService)",
        "S-1-5-32-544" => " (BUILTIN\\Administrators)",
        "S-1-5-32-545" => " (BUILTIN\\Users)",
        "S-1-16-0" => " (Untrusted IL)",
        "S-1-16-4096" => " (Low IL)",
        "S-1-16-8192" => " (Medium IL)",
        "S-1-16-8448" => " (Medium-Plus IL)",
        "S-1-16-12288" => " (High IL)",
        "S-1-16-16384" => " (System IL)",
        "S-1-16-20480" => " (Protected-Process IL)",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // S-1-5-18 (LocalSystem): rev=1, count=1, auth=5, sub=[18].
    const LOCAL_SYSTEM_BYTES: &[u8] = &[
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parse_local_system() {
        let (sid, used) = Sid::parse(LOCAL_SYSTEM_BYTES).unwrap();
        assert_eq!(used, 12);
        assert_eq!(sid.revision, 1);
        assert_eq!(sid.authority, 5);
        assert_eq!(sid.sub_authorities, vec![18]);
        assert_eq!(sid.to_string(), "S-1-5-18");
        assert_eq!(sid.well_known_label(), " (LocalSystem)");
    }

    #[test]
    fn builtin_admins_label() {
        assert_eq!(well_known_label("S-1-5-32-544"), " (BUILTIN\\Administrators)");
    }

    #[test]
    fn unknown_sid_has_no_label() {
        assert_eq!(well_known_label("S-1-5-21-1234-5678"), "");
    }

    #[test]
    fn rejects_truncated() {
        assert!(Sid::parse(&[0x01, 0x01]).is_err());
        assert!(Sid::parse(&LOCAL_SYSTEM_BYTES[..10]).is_err());
    }
}
