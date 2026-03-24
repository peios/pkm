//! Token specification wire format for `kacs_create_token`.
//!
//! Binary layout: fixed 96-byte header + variable-length sections for
//! the user SID, group memberships, and optional default DACL.
//! Offsets in the header point to the variable sections.
//!
//! This is the format authd sends to the kernel to mint a new token.

use core::sync::atomic::AtomicU64;

use crate::compat::{self, AllocError, Vec};
use crate::group::GroupEntry;
use crate::luid::Luid;
use crate::privilege::Privileges;
use crate::sid::Sid;
use crate::token::*;

/// Current wire format version.
pub const TOKEN_SPEC_VERSION: u32 = 1;

/// Minimum spec size (header only, no variable data).
/// Header: 96 bytes.
const HEADER_SIZE: usize = 96;

/// Parse a token specification from its binary representation.
///
/// Returns `Ok(Some(token))` on success, `Ok(None)` if the spec is
/// malformed, `Err(AllocError)` if allocation fails during parsing.
pub fn parse_token_spec(data: &[u8]) -> Result<Option<Token>, AllocError> {
    if data.len() < HEADER_SIZE {
        return Ok(None);
    }

    // ── Header ────────────────────────────────────────────────────────

    let version = u32_at(data, 0);
    if version != TOKEN_SPEC_VERSION {
        return Ok(None);
    }

    let token_type = match data[4] {
        1 => TokenType::Primary,
        2 => TokenType::Impersonation,
        _ => return Ok(None),
    };

    let impersonation_level = match data[5] {
        0 => ImpersonationLevel::Anonymous,
        1 => ImpersonationLevel::Identification,
        2 => ImpersonationLevel::Impersonation,
        3 => ImpersonationLevel::Delegation,
        _ => return Ok(None),
    };

    let integrity_rid = u32_at(data, 8);
    let integrity_level = match IntegrityLevel::from_rid(integrity_rid) {
        Some(il) => il,
        None => return Ok(None),
    };

    let mandatory_policy = u32_at(data, 12);
    let privs_present = u64_at(data, 16);
    let privs_enabled = u64_at(data, 24);
    let elevation_type = match u32_at(data, 32) {
        1 => ElevationType::Default,
        2 => ElevationType::Full,
        3 => ElevationType::Limited,
        _ => return Ok(None),
    };

    let projected_uid = u32_at(data, 36);
    let projected_gid = u32_at(data, 40);
    let user_sid_offset = u32_at(data, 44) as usize;
    let groups_offset = u32_at(data, 48) as usize;
    let groups_count = u32_at(data, 52) as usize;
    let session_id = u64_at(data, 56);
    let owner_sid_index = u32_at(data, 64) as u16;
    let primary_group_index = u32_at(data, 68) as u16;
    let default_dacl_offset = u32_at(data, 72) as usize;
    let default_dacl_len = u32_at(data, 76) as usize;
    let mut source_name = [0u8; 8];
    source_name.copy_from_slice(&data[80..88]);
    let source_id = u64_at(data, 88);

    // ── User SID ──────────────────────────────────────────────────────

    if user_sid_offset >= data.len() {
        return Ok(None);
    }
    let user_sid = match Sid::from_bytes(&data[user_sid_offset..]) {
        Some(sid) => sid,
        None => return Ok(None),
    };

    // ── Groups ────────────────────────────────────────────────────────

    // Cap groups_count to prevent excessive allocation before validation.
    // 64KB spec / 12-byte minimum group entry ≈ 5000 max; 16384 is generous.
    if groups_count > 16384 {
        return Ok(None);
    }
    let mut groups = compat::vec_with_capacity(groups_count)?;
    let mut pos = groups_offset;
    for _ in 0..groups_count {
        if pos + 4 > data.len() {
            return Ok(None);
        }
        let sid_len = u32_at(data, pos) as usize;
        pos += 4;

        if pos + sid_len + 4 > data.len() {
            return Ok(None);
        }
        let sid = match Sid::from_bytes(&data[pos..pos + sid_len]) {
            Some(sid) => sid,
            None => return Ok(None),
        };
        pos += sid_len;

        let attrs = u32_at(data, pos);
        pos += 4;

        compat::vec_push(&mut groups, GroupEntry::new(sid, attrs))?;
    }

    // ── Default DACL (optional) ───────────────────────────────────────

    let default_dacl = if default_dacl_offset != 0 && default_dacl_len != 0 {
        if default_dacl_offset + default_dacl_len > data.len() {
            return Ok(None);
        }
        match crate::acl::Acl::from_bytes(&data[default_dacl_offset..default_dacl_offset + default_dacl_len]) {
            Ok(Some(acl)) => Some(acl),
            _ => return Ok(None),
        }
    } else {
        None
    };

    // ── Build token ───────────────────────────────────────────────────

    Ok(Some(Token {
        user_sid,
        user_deny_only: false,
        groups,
        logon_sid: crate::session::logon_sid_from_id(session_id)?,
        restricted_sids: None,
        write_restricted: false,

        token_type,
        impersonation_level,
        integrity_level,
        mandatory_policy,

        privileges: Privileges {
            present: AtomicU64::new(privs_present),
            enabled: AtomicU64::new(privs_enabled),
            enabled_by_default: AtomicU64::new(privs_enabled),
            used: AtomicU64::new(0),
        },

        elevation_type,
        owner_sid_index,
        primary_group_index,
        default_dacl,
        security_descriptor: None, // kernel generates after creation

        token_id: Luid(0), // kernel assigns real IDs
        auth_id: Luid(session_id), // links token to its auth session
        source: TokenSource {
            name: source_name,
            source_id: Luid(source_id),
        },
        origin: Luid(0),
        created_at: 0, // kernel stamps real value after construction
        expiration: 0, // default: never expires
        interactive_session_id: 0,

        user_claims: Vec::new(),
        device_claims: Vec::new(),
        device_groups: None,
        restricted_device_groups: None,
        confinement_sid: None,
        confinement_capabilities: Vec::new(),
        isolation_boundary: false,
        confinement_exempt: false,

        projected_uid,
        projected_gid,
        projected_supplementary_gids: Vec::new(),
        audit_policy: 0,
        modified_id: 0,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::well_known;
    use crate::privilege::bits;

    fn build_spec(user_sid: &Sid, groups: &[(Sid, u32)],
                  privs: u64, integrity: u32) -> alloc::vec::Vec<u8> {
        let user_bytes = user_sid.to_bytes().unwrap();

        // Calculate offsets
        let user_sid_offset = HEADER_SIZE;
        let groups_offset = user_sid_offset + user_bytes.len();

        // Build groups section
        let mut groups_section = alloc::vec::Vec::new();
        for (sid, attrs) in groups {
            let sid_bytes = sid.to_bytes().unwrap();
            groups_section.extend_from_slice(&(sid_bytes.len() as u32).to_le_bytes());
            groups_section.extend_from_slice(&sid_bytes);
            groups_section.extend_from_slice(&attrs.to_le_bytes());
        }

        // Build header
        let mut spec = alloc::vec::Vec::with_capacity(
            HEADER_SIZE + user_bytes.len() + groups_section.len()
        );

        // version(4) + token_type(1) + imp_level(1) + reserved(2)
        spec.extend_from_slice(&TOKEN_SPEC_VERSION.to_le_bytes());
        spec.push(1); // Primary
        spec.push(2); // Impersonation level
        spec.extend_from_slice(&[0, 0]); // reserved

        // integrity(4) + mandatory_policy(4) + privs_present(8) + privs_enabled(8)
        spec.extend_from_slice(&integrity.to_le_bytes());
        spec.extend_from_slice(&1u32.to_le_bytes()); // NO_WRITE_UP
        spec.extend_from_slice(&privs.to_le_bytes()); // present
        spec.extend_from_slice(&privs.to_le_bytes()); // enabled

        // elevation(4) + uid(4) + gid(4)
        spec.extend_from_slice(&1u32.to_le_bytes()); // Default
        spec.extend_from_slice(&1000u32.to_le_bytes()); // uid
        spec.extend_from_slice(&1000u32.to_le_bytes()); // gid

        // user_sid_offset(4) + groups_offset(4) + groups_count(4)
        spec.extend_from_slice(&(user_sid_offset as u32).to_le_bytes());
        spec.extend_from_slice(&(groups_offset as u32).to_le_bytes());
        spec.extend_from_slice(&(groups.len() as u32).to_le_bytes());

        // session_id(8) — session 0 = SYSTEM
        spec.extend_from_slice(&0u64.to_le_bytes());

        // owner_sid_index(4) + primary_group_sid_index(4)
        spec.extend_from_slice(&0u32.to_le_bytes()); // 0 = user_sid is owner
        spec.extend_from_slice(&0u32.to_le_bytes()); // 0 = first group

        // default_dacl_offset(4) + default_dacl_len(4)
        spec.extend_from_slice(&0u32.to_le_bytes()); // 0 = no default DACL
        spec.extend_from_slice(&0u32.to_le_bytes());

        // source_name(8) + source_id(8)
        spec.extend_from_slice(b"authd\0\0\0");
        spec.extend_from_slice(&0u64.to_le_bytes());

        // Variable sections
        spec.extend_from_slice(&user_bytes);
        spec.extend_from_slice(&groups_section);

        spec
    }

    #[test]
    fn parse_system_token() {
        let system = well_known::system().unwrap();
        let admins = well_known::administrators().unwrap();
        let spec = build_spec(&system, &[(admins, 0x07)],
                              bits::ALL_PRIVILEGES, 16384);

        let token = parse_token_spec(&spec).unwrap().unwrap();
        assert_eq!(token.user_sid, well_known::system().unwrap());
        assert_eq!(token.groups.len(), 1);
        assert_eq!(token.integrity_level, IntegrityLevel::System);
        assert_eq!(token.projected_uid, 1000);
    }

    #[test]
    fn reject_short() {
        assert!(parse_token_spec(&[0; 10]).unwrap().is_none());
    }

    #[test]
    fn reject_bad_version() {
        let mut spec = alloc::vec![0u8; HEADER_SIZE];
        spec[0] = 99; // bad version
        assert!(parse_token_spec(&spec).unwrap().is_none());
    }

    // --- §7.5 Token Creation corpus tests ---

    #[test]
    fn create_token_wire_format_version() {
        assert_eq!(TOKEN_SPEC_VERSION, 1);
    }

    #[test]
    fn create_token_wire_format_header_size() {
        assert_eq!(HEADER_SIZE, 96);
    }

    #[test]
    fn parse_token_preserves_all_fields() {
        let system = well_known::system().unwrap();
        let admins = well_known::administrators().unwrap();
        let spec = build_spec(&system, &[(admins.clone(), 0x07)],
                              bits::SE_BACKUP | bits::SE_RESTORE, 8192);
        let token = parse_token_spec(&spec).unwrap().unwrap();
        assert_eq!(token.user_sid, system);
        assert_eq!(token.token_type, TokenType::Primary);
        assert_eq!(token.integrity_level, IntegrityLevel::Medium);
        assert_eq!(token.groups.len(), 1);
        assert_eq!(token.groups[0].sid, admins);
        assert!(token.privileges.check(bits::SE_BACKUP));
        assert!(token.privileges.check(bits::SE_RESTORE));
        assert!(!token.privileges.check(bits::SE_DEBUG));
        assert_eq!(token.elevation_type, ElevationType::Default);
        assert_eq!(token.projected_uid, 1000);
        assert_eq!(token.projected_gid, 1000);
        assert_eq!(&token.source.name, b"authd\0\0\0");
    }

    #[test]
    fn reject_bad_token_type() {
        let system = well_known::system().unwrap();
        let mut spec = build_spec(&system, &[], 0, 8192);
        spec[4] = 99; // invalid token type
        assert!(parse_token_spec(&spec).unwrap().is_none());
    }

    #[test]
    fn reject_bad_impersonation_level() {
        let system = well_known::system().unwrap();
        let mut spec = build_spec(&system, &[], 0, 8192);
        spec[5] = 99; // invalid impersonation level
        assert!(parse_token_spec(&spec).unwrap().is_none());
    }

    #[test]
    fn reject_bad_integrity_level() {
        let system = well_known::system().unwrap();
        let spec = build_spec(&system, &[], 0, 9999); // invalid RID
        assert!(parse_token_spec(&spec).unwrap().is_none());
    }

    #[test]
    fn reject_bad_elevation_type() {
        let system = well_known::system().unwrap();
        let mut spec = build_spec(&system, &[], 0, 8192);
        // elevation_type is at offset 32
        spec[32] = 99;
        spec[33] = 0;
        spec[34] = 0;
        spec[35] = 0;
        assert!(parse_token_spec(&spec).unwrap().is_none());
    }

    #[test]
    fn reject_user_sid_offset_out_of_bounds() {
        let system = well_known::system().unwrap();
        let mut spec = build_spec(&system, &[], 0, 8192);
        // user_sid_offset at bytes 44-47, set to very large value
        spec[44] = 0xFF;
        spec[45] = 0xFF;
        spec[46] = 0xFF;
        spec[47] = 0x7F;
        assert!(parse_token_spec(&spec).unwrap().is_none());
    }

    #[test]
    fn parse_with_multiple_groups() {
        let alice = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let eng = crate::sid::Sid::new(5, &[21, 100, 200, 300, 2001]).unwrap();
        let mgrs = crate::sid::Sid::new(5, &[21, 100, 200, 300, 2002]).unwrap();
        let spec = build_spec(&alice, &[
            (eng, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED),
            (mgrs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED),
        ], bits::SE_CHANGE_NOTIFY, 8192);
        let token = parse_token_spec(&spec).unwrap().unwrap();
        assert_eq!(token.groups.len(), 2);
        assert!(token.groups[0].is_enabled());
        assert!(token.groups[1].is_enabled());
    }

    #[test]
    fn parse_all_integrity_levels() {
        let system = well_known::system().unwrap();
        for &(rid, expected) in &[
            (0, IntegrityLevel::Untrusted),
            (4096, IntegrityLevel::Low),
            (8192, IntegrityLevel::Medium),
            (12288, IntegrityLevel::High),
            (16384, IntegrityLevel::System),
        ] {
            let spec = build_spec(&system, &[], 0, rid);
            let token = parse_token_spec(&spec).unwrap().unwrap();
            assert_eq!(token.integrity_level, expected);
        }
    }
}
