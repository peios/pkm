use kacs_core::{KacsError, SecurityDescriptor, SE_DACL_PRESENT, SE_SELF_RELATIVE};

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
