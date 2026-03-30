use kacs_core::{
    AceKind, Acl, KacsError, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT,
};

fn sid_bytes(sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + (sub_authorities.len() * 4));
    bytes.push(1);
    bytes.push(sub_authorities.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(&sub_authority.to_le_bytes());
    }
    bytes
}

fn basic_allow_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ACCESS_ALLOWED_ACE_TYPE);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn object_allow_ace(mask: u32, flags: u32, object_type: Option<[u8; 16]>, sid: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    if let Some(guid) = object_type {
        body.extend_from_slice(&guid);
    }
    body.extend_from_slice(sid);

    let size = 4 + body.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ACCESS_ALLOWED_OBJECT_ACE_TYPE);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

fn callback_allow_ace(mask: u32, sid: &[u8], application_data: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len() + application_data.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ACCESS_ALLOWED_CALLBACK_ACE_TYPE);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(application_data);
    bytes
}

fn acl_bytes(revision: u8, aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(revision);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    bytes
}

#[test]
fn parses_acl_with_basic_allow_ace() {
    let sid = sid_bytes(&[21, 32, 544]);
    let ace = basic_allow_ace(0x0002_0001, &sid);
    let bytes = acl_bytes(2, &[ace]);
    let acl = Acl::parse(&bytes).expect("acl should parse");

    assert_eq!(acl.revision(), 2);
    assert_eq!(acl.ace_count(), 1);

    let entries: Vec<_> = acl.entries().collect();
    assert_eq!(entries.len(), 1);

    let entry = entries[0].as_ref().expect("entry should parse");
    match entry.kind() {
        AceKind::SingleSid {
            mask,
            sid: parsed_sid,
        } => {
            assert_eq!(mask, 0x0002_0001);
            assert_eq!(parsed_sid.as_bytes(), sid.as_slice());
        }
        other => panic!("unexpected ace kind: {other:?}"),
    }
}

#[test]
fn parses_object_ace_without_guid_as_object_family_with_no_guids() {
    let sid = sid_bytes(&[18]);
    let ace = object_allow_ace(0x0002_0001, 0, None, &sid);
    let bytes = acl_bytes(4, &[ace]);
    let acl = Acl::parse(&bytes).expect("acl should parse");
    let entry = acl
        .entries()
        .next()
        .expect("entry expected")
        .expect("entry should parse");

    match entry.kind() {
        AceKind::Object {
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid: parsed_sid,
        } => {
            assert_eq!(mask, 0x0002_0001);
            assert_eq!(flags, 0);
            assert!(object_type.is_none());
            assert!(inherited_object_type.is_none());
            assert_eq!(parsed_sid.as_bytes(), sid.as_slice());
        }
        other => panic!("unexpected ace kind: {other:?}"),
    }
}

#[test]
fn parses_object_ace_with_object_type_guid() {
    let sid = sid_bytes(&[18]);
    let guid = [0x11; 16];
    let ace = object_allow_ace(0x0000_0001, ACE_OBJECT_TYPE_PRESENT, Some(guid), &sid);
    let bytes = acl_bytes(4, &[ace]);
    let acl = Acl::parse(&bytes).expect("acl should parse");
    let entry = acl
        .entries()
        .next()
        .expect("entry expected")
        .expect("entry should parse");

    match entry.kind() {
        AceKind::Object { object_type, .. } => {
            assert_eq!(object_type, Some(&guid));
        }
        other => panic!("unexpected ace kind: {other:?}"),
    }
}

#[test]
fn parses_callback_ace_and_exposes_application_data() {
    let sid = sid_bytes(&[18]);
    let app_data = *b"artx";
    let ace = callback_allow_ace(0x0000_0001, &sid, &app_data);
    let bytes = acl_bytes(4, &[ace]);
    let acl = Acl::parse(&bytes).expect("acl should parse");
    let entry = acl
        .entries()
        .next()
        .expect("entry expected")
        .expect("entry should parse");

    match entry.kind() {
        AceKind::Callback {
            mask,
            sid: parsed_sid,
            application_data,
        } => {
            assert_eq!(mask, 0x0000_0001);
            assert_eq!(parsed_sid.as_bytes(), sid.as_slice());
            assert_eq!(application_data, app_data);
        }
        other => panic!("unexpected ace kind: {other:?}"),
    }
}

#[test]
fn rejects_acl_smaller_than_header() {
    let err = Acl::parse(&[2, 0, 7, 0, 0, 0, 0, 0]).expect_err("small acl must fail");
    assert_eq!(err, KacsError::InvalidAclSize(7));
}

#[test]
fn rejects_acl_with_invalid_ace_size_alignment() {
    let sid = sid_bytes(&[18]);
    let mut ace = basic_allow_ace(0x0000_0001, &sid);
    ace[2..4].copy_from_slice(&18u16.to_le_bytes());

    let err = Acl::parse(&acl_bytes(2, &[ace])).expect_err("misaligned ace must fail");
    assert_eq!(err, KacsError::InvalidAceSize(18));
}

#[test]
fn rejects_acl_with_trailing_bytes_inside_acl_size() {
    let sid = sid_bytes(&[18]);
    let mut bytes = acl_bytes(2, &[basic_allow_ace(0x0000_0001, &sid)]);
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());

    let err = Acl::parse(&bytes).expect_err("trailing bytes must fail");
    assert_eq!(err, KacsError::AclTrailingBytes { remaining: 4 });
}
