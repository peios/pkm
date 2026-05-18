use kacs_core::{
    minimum_acl_revision_for_ace_slices, minimum_acl_revision_with_source_floor_for_opaque,
    AceKind, Acl, KacsError, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT,
    ACL_REVISION, ACL_REVISION_DS, MAXIMUM_ALLOWED, SYSTEM_ALARM_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_ACE_TYPE, SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
};

const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 0x04;

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

fn everyone_sid_bytes() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.push(1);
    bytes.push(1);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

fn utf16_cstr(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn int64_claim(name: &str, value: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let values_start = 20usize;
    let name_offset = 28usize;

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(values_start as u32).to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn single_sid_ace(ace_type: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
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

fn object_ace(
    ace_type: u8,
    mask: u32,
    flags: u32,
    object_type: Option<[u8; 16]>,
    sid: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    if let Some(guid) = object_type {
        body.extend_from_slice(&guid);
    }
    body.extend_from_slice(sid);

    let size = 4 + body.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&body);
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

fn callback_ace(ace_type: u8, mask: u32, sid: &[u8], application_data: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len() + application_data.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(application_data);
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

fn callback_object_ace(
    ace_type: u8,
    mask: u32,
    flags: u32,
    object_type: [u8; 16],
    sid: &[u8],
    application_data: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&object_type);
    body.extend_from_slice(sid);
    body.extend_from_slice(application_data);

    let size = 4 + body.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

fn resource_attribute_ace(mask: u32, application_data: &[u8]) -> Vec<u8> {
    let everyone = everyone_sid_bytes();
    let size = 8 + everyone.len() + application_data.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&everyone);
    bytes.extend_from_slice(application_data);
    bytes
}

fn opaque_ace(ace_type: u8, body: &[u8]) -> Vec<u8> {
    let size = 4 + body.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(body);
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
fn parses_resource_attribute_ace_and_exposes_mask() {
    let app_data = int64_claim("Level", 3);
    let ace = resource_attribute_ace(0x0000_0001, &app_data);
    let bytes = acl_bytes(4, &[ace]);
    let acl = Acl::parse(&bytes).expect("acl should parse");
    let entry = acl
        .entries()
        .next()
        .expect("entry expected")
        .expect("entry should parse");

    match entry.kind() {
        AceKind::ResourceAttribute {
            mask,
            sid,
            application_data,
        } => {
            assert_eq!(mask, 0x0000_0001);
            assert_eq!(sid.as_bytes(), everyone_sid_bytes().as_slice());
            assert_eq!(application_data, app_data.as_slice());
        }
        other => panic!("unexpected ace kind: {other:?}"),
    }
}

#[test]
fn rejects_malformed_resource_attribute_application_data() {
    let ace = resource_attribute_ace(0, &[1, 2, 3, 4]);
    let err = Acl::parse(&acl_bytes(4, &[ace]))
        .expect_err("resource attribute application data must be one claim entry");

    assert_eq!(err, KacsError::InvalidClaimFormat("claim entry header"));
}

#[test]
fn rejects_maximum_allowed_in_resource_attribute_ace_mask() {
    let ace = resource_attribute_ace(MAXIMUM_ALLOWED, b"attr");
    let err = Acl::parse(&acl_bytes(4, &[ace]))
        .expect_err("resource attribute ACE mask must reject maximum allowed");

    assert_eq!(err, KacsError::MaximumAllowedInAce(MAXIMUM_ALLOWED));
}

#[test]
fn preserves_opaque_ace_payload_without_access_mask_validation() {
    let ace = opaque_ace(0x7f, &MAXIMUM_ALLOWED.to_le_bytes());
    let bytes = acl_bytes(4, &[ace.clone()]);
    let acl = Acl::parse(&bytes).expect("opaque ace should parse");
    let entry = acl
        .entries()
        .next()
        .expect("entry expected")
        .expect("opaque entry should parse");

    assert_eq!(entry.kind(), AceKind::Opaque);
    assert_eq!(entry.bytes(), ace.as_slice());
}

#[test]
fn acl_parser_accepts_revision_type_mismatch_permissively() {
    let sid = sid_bytes(&[18]);
    let object = object_allow_ace(0x0002_0001, 0, None, &sid);
    let bytes = acl_bytes(ACL_REVISION, &[object]);

    let acl = Acl::parse(&bytes).expect("revision mismatch should parse permissively");

    assert_eq!(acl.revision(), ACL_REVISION);
    assert!(matches!(
        acl.entries()
            .next()
            .expect("entry expected")
            .expect("object ace should parse")
            .kind(),
        AceKind::Object { .. }
    ));
}

#[test]
fn minimum_acl_revision_tracks_known_ace_families() {
    let sid = sid_bytes(&[18]);
    let basic = basic_allow_ace(0x0002_0001, &sid);
    let mut label = basic_allow_ace(0x0002_0001, &sid);
    label[0] = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    let object = object_allow_ace(0x0002_0001, 0, None, &sid);
    let callback = callback_allow_ace(0x0002_0001, &sid, b"expr");

    assert_eq!(
        minimum_acl_revision_for_ace_slices(&[basic.as_slice(), label.as_slice()])
            .expect("known basic families compute"),
        ACL_REVISION
    );
    assert_eq!(
        minimum_acl_revision_for_ace_slices(&[basic.as_slice(), object.as_slice()])
            .expect("object family computes"),
        ACL_REVISION_DS
    );
    assert_eq!(
        minimum_acl_revision_for_ace_slices(&[callback.as_slice()])
            .expect("callback family computes"),
        ACL_REVISION_DS
    );
}

#[test]
fn opaque_ace_revision_floor_applies_only_when_opaque_is_preserved() {
    let sid = sid_bytes(&[18]);
    let basic = basic_allow_ace(0x0002_0001, &sid);
    let opaque = opaque_ace(0x7f, &[0, 0, 0, 0]);

    assert_eq!(
        minimum_acl_revision_with_source_floor_for_opaque(ACL_REVISION_DS, &[basic.as_slice()])
            .expect("known-only rewrite computes"),
        ACL_REVISION
    );
    assert_eq!(
        minimum_acl_revision_with_source_floor_for_opaque(
            ACL_REVISION_DS,
            &[basic.as_slice(), opaque.as_slice()],
        )
        .expect("opaque-preserving rewrite computes"),
        ACL_REVISION_DS
    );
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
fn parses_known_system_audit_single_sid_ace_layout() {
    let sid = sid_bytes(&[18]);
    let ace = basic_allow_ace(0x0000_0001, &sid);
    let mut audit_ace = ace;
    audit_ace[0] = SYSTEM_AUDIT_ACE_TYPE;
    let bytes = acl_bytes(2, &[audit_ace]);
    let acl = Acl::parse(&bytes).expect("acl should parse");
    let entry = acl
        .entries()
        .next()
        .expect("entry expected")
        .expect("entry should parse");

    match entry.kind() {
        AceKind::SingleSid {
            mask,
            sid: parsed_sid,
        } => {
            assert_eq!(mask, 0x0000_0001);
            assert_eq!(parsed_sid.as_bytes(), sid.as_slice());
        }
        other => panic!("unexpected ace kind: {other:?}"),
    }
}

#[test]
fn parses_known_system_audit_callback_object_ace_layout() {
    let sid = sid_bytes(&[18]);
    let guid = [0x22; 16];
    let app_data = *b"artx";
    let ace = callback_object_ace(
        SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
        0x0000_0001,
        ACE_OBJECT_TYPE_PRESENT,
        guid,
        &sid,
        &app_data,
    );
    let bytes = acl_bytes(4, &[ace]);
    let acl = Acl::parse(&bytes).expect("acl should parse");
    let entry = acl
        .entries()
        .next()
        .expect("entry expected")
        .expect("entry should parse");

    match entry.kind() {
        AceKind::CallbackObject {
            mask,
            object_type,
            sid: parsed_sid,
            application_data,
            ..
        } => {
            assert_eq!(mask, 0x0000_0001);
            assert_eq!(object_type, Some(&guid));
            assert_eq!(parsed_sid.as_bytes(), sid.as_slice());
            assert_eq!(application_data, app_data);
        }
        other => panic!("unexpected ace kind: {other:?}"),
    }
}

#[test]
fn parses_every_listed_single_sid_ace_type() {
    let sid = sid_bytes(&[18]);
    let single_sid_types = [
        ACCESS_ALLOWED_ACE_TYPE,
        ACCESS_DENIED_ACE_TYPE,
        SYSTEM_AUDIT_ACE_TYPE,
        SYSTEM_ALARM_ACE_TYPE,
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
    ];

    for ace_type in single_sid_types {
        let ace = single_sid_ace(ace_type, 0x0000_0001, &sid);
        let bytes = acl_bytes(ACL_REVISION, &[ace]);
        let acl = Acl::parse(&bytes).expect("listed single-SID ACE type should parse");
        let entry = acl
            .entries()
            .next()
            .expect("entry expected")
            .expect("entry should parse");

        assert_eq!(entry.ace_type(), ace_type);
        match entry.kind() {
            AceKind::SingleSid {
                mask,
                sid: parsed_sid,
            } => {
                assert_eq!(mask, 0x0000_0001);
                assert_eq!(parsed_sid.as_bytes(), sid.as_slice());
            }
            other => panic!("unexpected ace kind for {ace_type:#x}: {other:?}"),
        }
    }
}

#[test]
fn parses_every_listed_object_ace_type() {
    let sid = sid_bytes(&[18]);
    let guid = [0x33; 16];
    let object_types = [
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        ACCESS_DENIED_OBJECT_ACE_TYPE,
        SYSTEM_AUDIT_OBJECT_ACE_TYPE,
        SYSTEM_ALARM_OBJECT_ACE_TYPE,
    ];

    for ace_type in object_types {
        let ace = object_ace(
            ace_type,
            0x0000_0001,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid),
            &sid,
        );
        let bytes = acl_bytes(ACL_REVISION_DS, &[ace]);
        let acl = Acl::parse(&bytes).expect("listed object ACE should parse");
        let entry = acl
            .entries()
            .next()
            .expect("entry expected")
            .expect("entry should parse");

        assert_eq!(entry.ace_type(), ace_type);
        match entry.kind() {
            AceKind::Object {
                mask,
                flags,
                object_type,
                sid: parsed_sid,
                ..
            } => {
                assert_eq!(mask, 0x0000_0001);
                assert_eq!(flags, ACE_OBJECT_TYPE_PRESENT);
                assert_eq!(object_type, Some(&guid));
                assert_eq!(parsed_sid.as_bytes(), sid.as_slice());
            }
            other => panic!("unexpected ace kind for {ace_type:#x}: {other:?}"),
        }
    }
}

#[test]
fn parses_every_listed_callback_ace_type() {
    let sid = sid_bytes(&[18]);
    let app_data = *b"artx";
    let callback_types = [
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_DENIED_CALLBACK_ACE_TYPE,
        SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
        SYSTEM_ALARM_CALLBACK_ACE_TYPE,
    ];

    for ace_type in callback_types {
        let ace = callback_ace(ace_type, 0x0000_0001, &sid, &app_data);
        let bytes = acl_bytes(ACL_REVISION_DS, &[ace]);
        let acl = Acl::parse(&bytes).expect("listed callback ACE should parse");
        let entry = acl
            .entries()
            .next()
            .expect("entry expected")
            .expect("entry should parse");

        assert_eq!(entry.ace_type(), ace_type);
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
            other => panic!("unexpected ace kind for {ace_type:#x}: {other:?}"),
        }
    }
}

#[test]
fn parses_every_listed_callback_object_ace_type() {
    let sid = sid_bytes(&[18]);
    let guid = [0x44; 16];
    let app_data = *b"artx";
    let callback_object_types = [
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
        SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
        SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    ];

    for ace_type in callback_object_types {
        let ace = callback_object_ace(
            ace_type,
            0x0000_0001,
            ACE_OBJECT_TYPE_PRESENT,
            guid,
            &sid,
            &app_data,
        );
        let bytes = acl_bytes(ACL_REVISION_DS, &[ace]);
        let acl = Acl::parse(&bytes).expect("listed callback-object ACE should parse");
        let entry = acl
            .entries()
            .next()
            .expect("entry expected")
            .expect("entry should parse");

        assert_eq!(entry.ace_type(), ace_type);
        match entry.kind() {
            AceKind::CallbackObject {
                mask,
                flags,
                object_type,
                sid: parsed_sid,
                application_data,
                ..
            } => {
                assert_eq!(mask, 0x0000_0001);
                assert_eq!(flags, ACE_OBJECT_TYPE_PRESENT);
                assert_eq!(object_type, Some(&guid));
                assert_eq!(parsed_sid.as_bytes(), sid.as_slice());
                assert_eq!(application_data, app_data);
            }
            other => panic!("unexpected ace kind for {ace_type:#x}: {other:?}"),
        }
    }
}

#[test]
fn parses_listed_resource_attribute_ace_type() {
    let app_data = int64_claim("Level", 3);
    let ace = resource_attribute_ace(0x0000_0001, &app_data);
    let bytes = acl_bytes(ACL_REVISION, &[ace]);
    let acl = Acl::parse(&bytes).expect("listed resource-attribute ACE should parse");
    let entry = acl
        .entries()
        .next()
        .expect("entry expected")
        .expect("entry should parse");

    assert_eq!(entry.ace_type(), SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);
    match entry.kind() {
        AceKind::ResourceAttribute {
            mask,
            sid,
            application_data,
        } => {
            assert_eq!(mask, 0x0000_0001);
            assert_eq!(sid.as_bytes(), everyone_sid_bytes().as_slice());
            assert_eq!(application_data, app_data.as_slice());
        }
        other => panic!("unexpected resource-attribute ace kind: {other:?}"),
    }
}

#[test]
fn reserved_compound_ace_type_parses_as_opaque() {
    let ace = opaque_ace(ACCESS_ALLOWED_COMPOUND_ACE_TYPE, &[0, 0, 0, 0]);
    let bytes = acl_bytes(ACL_REVISION, &[ace.clone()]);
    let acl = Acl::parse(&bytes).expect("reserved compound ACE should parse opaquely");
    let entry = acl
        .entries()
        .next()
        .expect("entry expected")
        .expect("entry should parse");

    assert_eq!(entry.ace_type(), ACCESS_ALLOWED_COMPOUND_ACE_TYPE);
    assert_eq!(entry.kind(), AceKind::Opaque);
    assert_eq!(entry.bytes(), ace.as_slice());
}

#[test]
fn rejects_truncated_acl_header() {
    let err = Acl::parse(&[2, 0, 8]).expect_err("truncated acl header must fail");
    assert_eq!(err, KacsError::Truncated("acl"));
}

#[test]
fn rejects_acl_smaller_than_header() {
    let err = Acl::parse(&[2, 0, 7, 0, 0, 0, 0, 0]).expect_err("small acl must fail");
    assert_eq!(err, KacsError::InvalidAclSize(7));
}

#[test]
fn rejects_acl_size_larger_than_buffer() {
    let err = Acl::parse(&[2, 0, 12, 0, 0, 0, 0, 0]).expect_err("oversized acl must fail");
    assert_eq!(
        err,
        KacsError::AclSizeExceedsBuffer {
            size: 12,
            buffer_len: 8,
        }
    );
}

#[test]
fn rejects_acl_with_too_high_ace_count() {
    let err = Acl::parse(&[2, 0, 8, 0, 1, 0, 0, 0]).expect_err("missing ace must fail");
    assert_eq!(
        err,
        KacsError::AclAceCountMismatch {
            expected: 1,
            actual: 0,
        }
    );
}

#[test]
fn rejects_acl_with_truncated_ace_header() {
    let err = Acl::parse(&[2, 0, 10, 0, 1, 0, 0, 0, 0, 0]).expect_err("truncated ace must fail");
    assert_eq!(err, KacsError::Truncated("ace"));
}

#[test]
fn rejects_acl_with_ace_overrun() {
    let err =
        Acl::parse(&[2, 0, 12, 0, 1, 0, 0, 0, 0, 0, 16, 0]).expect_err("ace overrun must fail");
    assert_eq!(err, KacsError::Truncated("ace"));
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

#[test]
fn accepts_largest_aligned_acl_below_u16_maximum() {
    let ace_body = vec![0u8; 65_520];
    let ace = opaque_ace(0x87, &ace_body);
    let bytes = acl_bytes(ACL_REVISION, &[ace]);

    assert_eq!(bytes.len(), 65_532);

    let acl = Acl::parse(&bytes).expect("largest aligned acl should parse");

    assert_eq!(acl.bytes().len(), 65_532);
    assert_eq!(acl.ace_count(), 1);
}

#[test]
fn rejects_declared_u16_max_acl_with_alignment_leftover() {
    let ace_body = vec![0u8; 65_520];
    let ace = opaque_ace(0x87, &ace_body);
    let mut bytes = vec![0u8; u16::MAX as usize];

    bytes[0] = ACL_REVISION;
    bytes[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[8..8 + ace.len()].copy_from_slice(&ace);

    let err = Acl::parse(&bytes).expect_err("u16 max acl with leftover bytes must fail");

    assert_eq!(err, KacsError::AclTrailingBytes { remaining: 3 });
}
