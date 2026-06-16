use kacs_core::{AceKind, CONTAINER_INHERIT_ACE, GENERIC_READ, INHERITED_ACE, SecurityDescriptor};
use lcs_core::{
    KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_QUERY_VALUE, LcsError, READ_CONTROL,
    RegistryKeyInitialSecurityDescriptorInput, compute_registry_key_initial_security_descriptor,
};

const KEY_READ: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL;

fn sid(authority: u8, subauths: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(1);
    bytes.push(subauths.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, authority]);
    for subauth in subauths {
        bytes.extend_from_slice(&subauth.to_le_bytes());
    }
    bytes
}

fn basic_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let ace_size = 8 + sid.len();
    let mut bytes = Vec::new();
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(ace_size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::new();
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

fn sd(owner: &[u8], group: &[u8], dacl: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    let owner_offset = bytes.len() as u32;
    bytes.extend_from_slice(owner);
    let group_offset = bytes.len() as u32;
    bytes.extend_from_slice(group);
    let dacl_offset = if let Some(dacl) = dacl {
        let offset = bytes.len() as u32;
        bytes.extend_from_slice(dacl);
        offset
    } else {
        0
    };

    let control = kacs_core::SE_SELF_RELATIVE
        | if dacl.is_some() {
            kacs_core::SE_DACL_PRESENT
        } else {
            0
        };
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes
}

#[test]
fn lcs_registry_key_initial_sd_delegates_to_kacs_inheritance() {
    let parent_owner = sid(5, &[18]);
    let parent_group = sid(5, &[32, 544]);
    let token_owner = sid(5, &[21, 1000]);
    let token_group = sid(5, &[21, 513]);
    let creator_owner = sid(3, &[0]);
    let parent_dacl = acl(&[basic_ace(
        kacs_core::ACCESS_ALLOWED_ACE_TYPE,
        CONTAINER_INHERIT_ACE,
        GENERIC_READ,
        &creator_owner,
    )]);
    let parent_sd = sd(&parent_owner, &parent_group, Some(&parent_dacl));

    let child_sd = compute_registry_key_initial_security_descriptor(
        RegistryKeyInitialSecurityDescriptorInput {
            parent_sd: &parent_sd,
            token_owner_sid: &token_owner,
            token_primary_group_sid: &token_group,
            token_default_dacl: None,
        },
    )
    .unwrap();
    let child = SecurityDescriptor::parse(child_sd.as_slice()).unwrap();

    assert_eq!(child.owner().unwrap().as_bytes(), token_owner.as_slice());
    assert_eq!(child.group().unwrap().as_bytes(), token_group.as_slice());
    assert_ne!(child.control() & kacs_core::SE_DACL_AUTO_INHERITED, 0);

    let entries: Vec<_> = child
        .dacl()
        .unwrap()
        .entries()
        .map(Result::unwrap)
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].ace_flags(),
        CONTAINER_INHERIT_ACE | INHERITED_ACE
    );
    match entries[0].kind() {
        AceKind::SingleSid { mask, sid } => {
            assert_eq!(mask, KEY_READ);
            assert_eq!(sid.as_bytes(), token_owner.as_slice());
        }
        other => panic!("unexpected ACE kind: {other:?}"),
    }
}

#[test]
fn lcs_registry_key_initial_sd_rejects_malformed_inputs_before_delegation() {
    let owner = sid(5, &[21, 1000]);
    let group = sid(5, &[21, 513]);
    let parent_sd = sd(&owner, &group, None);

    assert_eq!(
        compute_registry_key_initial_security_descriptor(
            RegistryKeyInitialSecurityDescriptorInput {
                parent_sd: b"bad",
                token_owner_sid: &owner,
                token_primary_group_sid: &group,
                token_default_dacl: None,
            }
        ),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "reg_create_key.parent_sd"
        })
    );

    assert_eq!(
        compute_registry_key_initial_security_descriptor(
            RegistryKeyInitialSecurityDescriptorInput {
                parent_sd: &parent_sd,
                token_owner_sid: b"bad",
                token_primary_group_sid: &group,
                token_default_dacl: None,
            }
        ),
        Err(LcsError::MalformedTokenSid {
            field: "token.owner_sid"
        })
    );

    assert_eq!(
        compute_registry_key_initial_security_descriptor(
            RegistryKeyInitialSecurityDescriptorInput {
                parent_sd: &parent_sd,
                token_owner_sid: &owner,
                token_primary_group_sid: &group,
                token_default_dacl: Some(b"bad"),
            }
        ),
        Err(LcsError::MalformedTokenDefaultDacl)
    );
}
