use kacs_core::{
    KacsError, SecurityDescriptor, MAX_SECURITY_DESCRIPTOR_BYTES, SE_DACL_AUTO_INHERITED,
    SE_DACL_AUTO_INHERIT_REQ, SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SE_DACL_TRUSTED, SE_GROUP_DEFAULTED, SE_OWNER_DEFAULTED, SE_RM_CONTROL_VALID,
    SE_SACL_AUTO_INHERITED, SE_SACL_AUTO_INHERIT_REQ, SE_SACL_DEFAULTED, SE_SACL_PRESENT,
    SE_SACL_PROTECTED, SE_SELF_RELATIVE, SE_SERVER_SECURITY,
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
    bytes.push(0x00);
    bytes.push(0);
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

fn sd_bytes(owner: &[u8], dacl: &[u8], control: u16, dacl_offset: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes.extend_from_slice(owner);
    if dacl_offset as usize > bytes.len() {
        bytes.resize(dacl_offset as usize, 0);
    }
    bytes.extend_from_slice(dacl);
    bytes
}

#[test]
fn exposes_security_descriptor_control_flag_catalog() {
    assert_eq!(SE_OWNER_DEFAULTED, 0x0001);
    assert_eq!(SE_GROUP_DEFAULTED, 0x0002);
    assert_eq!(SE_DACL_PRESENT, 0x0004);
    assert_eq!(SE_DACL_DEFAULTED, 0x0008);
    assert_eq!(SE_SACL_PRESENT, 0x0010);
    assert_eq!(SE_SACL_DEFAULTED, 0x0020);
    assert_eq!(SE_DACL_TRUSTED, 0x0040);
    assert_eq!(SE_SERVER_SECURITY, 0x0080);
    assert_eq!(SE_DACL_AUTO_INHERIT_REQ, 0x0100);
    assert_eq!(SE_SACL_AUTO_INHERIT_REQ, 0x0200);
    assert_eq!(SE_DACL_AUTO_INHERITED, 0x0400);
    assert_eq!(SE_SACL_AUTO_INHERITED, 0x0800);
    assert_eq!(SE_DACL_PROTECTED, 0x1000);
    assert_eq!(SE_SACL_PROTECTED, 0x2000);
    assert_eq!(SE_RM_CONTROL_VALID, 0x4000);
    assert_eq!(SE_SELF_RELATIVE, 0x8000);
}

#[test]
fn accepts_security_descriptor_at_architectural_maximum_size() {
    let mut bytes = vec![0u8; MAX_SECURITY_DESCRIPTOR_BYTES];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());

    let sd = SecurityDescriptor::parse(&bytes).expect("maximum-sized sd should parse");

    assert_eq!(sd.bytes().len(), MAX_SECURITY_DESCRIPTOR_BYTES);
}

#[test]
fn rejects_security_descriptor_above_architectural_maximum_size() {
    let bytes = vec![0u8; MAX_SECURITY_DESCRIPTOR_BYTES + 1];

    let err = SecurityDescriptor::parse(&bytes).expect_err("oversized sd must fail");

    assert_eq!(
        err,
        KacsError::SecurityDescriptorTooLarge {
            len: MAX_SECURITY_DESCRIPTOR_BYTES + 1,
            max: MAX_SECURITY_DESCRIPTOR_BYTES,
        }
    );
}

#[test]
fn parses_self_relative_sd_with_owner_and_dacl() {
    let owner = sid_bytes(&[18]);
    let dacl = acl_bytes(&[basic_allow_ace(0x0002_0001, &owner)]);
    let bytes = sd_bytes(
        &owner,
        &dacl,
        SE_SELF_RELATIVE | SE_DACL_PRESENT,
        20 + owner.len() as u32,
    );

    let sd = SecurityDescriptor::parse(&bytes).expect("sd should parse");

    assert_eq!(
        sd.owner().expect("owner expected").as_bytes(),
        owner.as_slice()
    );
    assert!(sd.group().is_none());
    assert!(sd.sacl().is_none());
    assert_eq!(sd.dacl().expect("dacl expected").ace_count(), 1);
}

#[test]
fn cached_layout_reconstructs_same_descriptor_views() {
    let owner = sid_bytes(&[18]);
    let group = sid_bytes(&[32, 544]);
    let dacl = acl_bytes(&[basic_allow_ace(0x0002_0001, &owner)]);
    let mut bytes = sd_bytes(
        &owner,
        &dacl,
        SE_SELF_RELATIVE | SE_DACL_PRESENT,
        20 + owner.len() as u32 + group.len() as u32,
    );
    bytes[8..12].copy_from_slice(&(20 + owner.len() as u32).to_le_bytes());
    bytes.truncate(20 + owner.len());
    bytes.extend_from_slice(&group);
    bytes.extend_from_slice(&dacl);

    let layout = SecurityDescriptor::parse_layout(&bytes).expect("layout should parse");
    let parsed = SecurityDescriptor::parse(&bytes).expect("sd should parse");
    let cached =
        SecurityDescriptor::from_cached_layout(&bytes, &layout).expect("layout should rebuild");

    assert_eq!(cached.control(), parsed.control());
    assert_eq!(
        cached.resource_manager_control(),
        parsed.resource_manager_control()
    );
    assert_eq!(cached.owner(), parsed.owner());
    assert_eq!(cached.group(), parsed.group());
    assert_eq!(
        cached.dacl().map(|acl| acl.bytes()),
        parsed.dacl().map(|acl| acl.bytes())
    );
}

#[test]
fn preserves_resource_manager_control_byte() {
    let owner = sid_bytes(&[18]);
    let dacl = acl_bytes(&[]);
    let mut bytes = sd_bytes(
        &owner,
        &dacl,
        SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_RM_CONTROL_VALID,
        20 + owner.len() as u32,
    );
    bytes[1] = 0x5a;

    let sd = SecurityDescriptor::parse(&bytes).expect("sd should parse");

    assert_eq!(sd.resource_manager_control(), 0x5a);
    assert_eq!(sd.bytes()[1], 0x5a);
}

#[test]
fn rejects_missing_self_relative_flag() {
    let owner = sid_bytes(&[18]);
    let dacl = acl_bytes(&[]);
    let bytes = sd_bytes(&owner, &dacl, SE_DACL_PRESENT, 20 + owner.len() as u32);

    let err = SecurityDescriptor::parse(&bytes).expect_err("missing self relative must fail");
    assert_eq!(err, KacsError::MissingSelfRelativeControl(SE_DACL_PRESENT));
}

#[test]
fn rejects_dacl_present_with_zero_offset() {
    let owner = sid_bytes(&[18]);
    let dacl = acl_bytes(&[]);
    let bytes = sd_bytes(&owner, &dacl, SE_SELF_RELATIVE | SE_DACL_PRESENT, 0);

    let err = SecurityDescriptor::parse(&bytes).expect_err("zero dacl offset must fail");
    assert_eq!(
        err,
        KacsError::InconsistentSecurityDescriptorField {
            field: "dacl",
            present: true,
            offset: 0,
        }
    );
}

#[test]
fn rejects_dacl_offset_beyond_buffer() {
    let owner = sid_bytes(&[18]);
    let dacl = acl_bytes(&[]);
    let mut bytes = sd_bytes(
        &owner,
        &dacl,
        SE_SELF_RELATIVE | SE_DACL_PRESENT,
        20 + owner.len() as u32,
    );
    bytes[16..20].copy_from_slice(&4096u32.to_le_bytes());

    let err = SecurityDescriptor::parse(&bytes).expect_err("oob dacl offset must fail");
    assert_eq!(
        err,
        KacsError::SecurityDescriptorOffsetOutOfBounds {
            field: "dacl",
            offset: 4096,
            buffer_len: bytes.len(),
        }
    );
}

#[test]
fn rejects_nonzero_dacl_offset_when_dacl_not_present() {
    let owner = sid_bytes(&[18]);
    let dacl = acl_bytes(&[]);
    let bytes = sd_bytes(&owner, &dacl, SE_SELF_RELATIVE, 20 + owner.len() as u32);

    let err = SecurityDescriptor::parse(&bytes).expect_err("nonzero absent dacl offset must fail");
    assert_eq!(
        err,
        KacsError::InconsistentSecurityDescriptorField {
            field: "dacl",
            present: false,
            offset: 32,
        }
    );
}

#[test]
fn rejects_sacl_present_with_zero_offset() {
    let owner = sid_bytes(&[18]);
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&(SE_SELF_RELATIVE | SE_SACL_PRESENT).to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(&owner);

    let err = SecurityDescriptor::parse(&bytes).expect_err("zero sacl offset must fail");
    assert_eq!(
        err,
        KacsError::InconsistentSecurityDescriptorField {
            field: "sacl",
            present: true,
            offset: 0,
        }
    );
}

#[test]
fn rejects_sacl_offset_beyond_buffer() {
    let owner = sid_bytes(&[18]);
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&(SE_SELF_RELATIVE | SE_SACL_PRESENT).to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&4096u32.to_le_bytes());
    bytes.extend_from_slice(&owner);

    let err = SecurityDescriptor::parse(&bytes).expect_err("oob sacl offset must fail");
    assert_eq!(
        err,
        KacsError::SecurityDescriptorOffsetOutOfBounds {
            field: "sacl",
            offset: 4096,
            buffer_len: bytes.len(),
        }
    );
}

#[test]
fn rejects_nonzero_sacl_offset_when_sacl_not_present() {
    let owner = sid_bytes(&[18]);
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&(20 + owner.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&owner);

    let err = SecurityDescriptor::parse(&bytes).expect_err("nonzero absent sacl offset must fail");
    assert_eq!(
        err,
        KacsError::InconsistentSecurityDescriptorField {
            field: "sacl",
            present: false,
            offset: 32,
        }
    );
}

#[test]
fn rejects_component_offsets_inside_header() {
    let owner = sid_bytes(&[18]);
    let dacl = acl_bytes(&[]);
    let mut bytes = sd_bytes(
        &owner,
        &dacl,
        SE_SELF_RELATIVE | SE_DACL_PRESENT,
        20 + owner.len() as u32,
    );
    bytes[4..8].copy_from_slice(&4u32.to_le_bytes());

    let err =
        SecurityDescriptor::parse(&bytes).expect_err("header-relative owner offset must fail");
    assert_eq!(
        err,
        KacsError::SecurityDescriptorOffsetInsideHeader {
            field: "owner",
            offset: 4,
            header_len: 20,
        }
    );
}

#[test]
fn rejects_overlapping_components() {
    let owner = sid_bytes(&[18]);
    let dacl = acl_bytes(&[basic_allow_ace(0x0002_0001, &owner)]);
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&(SE_SELF_RELATIVE | SE_DACL_PRESENT).to_le_bytes());
    bytes[4..8].copy_from_slice(&36u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(&dacl);

    let err = SecurityDescriptor::parse(&bytes).expect_err("overlapping owner and dacl must fail");
    assert_eq!(
        err,
        KacsError::SecurityDescriptorComponentsOverlap {
            first: "owner",
            second: "dacl",
        }
    );
}

#[test]
fn rejects_overlapping_sacl_and_dacl_components() {
    let sacl = acl_bytes(&[]);
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4]
        .copy_from_slice(&(SE_SELF_RELATIVE | SE_SACL_PRESENT | SE_DACL_PRESENT).to_le_bytes());
    bytes[12..16].copy_from_slice(&20u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(&sacl);

    let err = SecurityDescriptor::parse(&bytes).expect_err("overlapping sacl and dacl must fail");
    assert_eq!(
        err,
        KacsError::SecurityDescriptorComponentsOverlap {
            first: "sacl",
            second: "dacl",
        }
    );
}
