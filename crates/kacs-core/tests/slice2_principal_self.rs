use kacs_core::{
    evaluate_dacl_with_self_sid, GenericMapping, SecurityDescriptor, Sid, TokenView,
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, DELETE, READ_CONTROL, SE_DACL_PRESENT,
    SE_SELF_RELATIVE, WRITE_DAC,
};

fn sid_bytes(authority: [u8; 6], sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + (sub_authorities.len() * 4));
    bytes.push(1);
    bytes.push(sub_authorities.len() as u8);
    bytes.extend_from_slice(&authority);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(&sub_authority.to_le_bytes());
    }
    bytes
}

fn parse_sid(bytes: &[u8]) -> Sid<'_> {
    Sid::parse(bytes).expect("sid should parse")
}

fn basic_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl_bytes(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(2);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    bytes
}

fn sd_with_dacl(owner: &[u8], dacl: Option<&[u8]>) -> Vec<u8> {
    let control = SE_SELF_RELATIVE | if dacl.is_some() { SE_DACL_PRESENT } else { 0 };
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(owner);
    if let Some(dacl) = dacl {
        let dacl_offset = bytes.len() as u32;
        bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
        bytes.extend_from_slice(dacl);
    }
    bytes
}

fn mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL | 0x0000_0001,
        write: WRITE_DAC | 0x0000_0002,
        execute: 0x0000_0004,
        all: DELETE | READ_CONTROL | WRITE_DAC | 0x0000_0007,
    }
}

fn principal_self_sid() -> Vec<u8> {
    sid_bytes([0, 0, 0, 0, 0, 5], &[10])
}

#[test]
fn principal_self_allow_matches_when_self_sid_matches_user() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 3000]);
    let principal_self = principal_self_sid();
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL,
        &principal_self,
    )]);
    let sd_bytes = sd_with_dacl(&user, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl_with_self_sid(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        Some(parse_sid(&user)),
    )
    .expect("principal-self evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn principal_self_matches_nothing_when_self_sid_is_null() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 3001]);
    let principal_self = principal_self_sid();
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL,
        &principal_self,
    )]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl_with_self_sid(&sd, &token, READ_CONTROL, &mapping(), false, None)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn principal_self_obeys_deny_only_polarity_rules() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 3002]);
    let principal_self = principal_self_sid();
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_DENIED_ACE_TYPE, 0, READ_CONTROL, &principal_self),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &principal_self),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: true,
        groups: &[],
    };

    let result = evaluate_dacl_with_self_sid(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        Some(parse_sid(&user)),
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}
