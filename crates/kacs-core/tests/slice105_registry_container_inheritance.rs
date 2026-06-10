use kacs_core::{
    inherit_registry_container_child_sd, AceKind, GenericMapping, KacsError,
    RegistryContainerChildInheritance, SecurityDescriptor, ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE, CONTAINER_INHERIT_ACE, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE,
    INHERITED_ACE, INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE,
    SE_DACL_AUTO_INHERITED,
    SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_GROUP_DEFAULTED, SE_OWNER_DEFAULTED,
    SE_SACL_AUTO_INHERITED, SE_SACL_PRESENT, SE_SELF_RELATIVE, SYNCHRONIZE, SYSTEM_AUDIT_ACE_TYPE,
};

const KEY_QUERY_VALUE: u32 = 0x0000_0001;
const KEY_SET_VALUE: u32 = 0x0000_0002;
const KEY_CREATE_SUB_KEY: u32 = 0x0000_0004;
const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0000_0008;
const KEY_NOTIFY: u32 = 0x0000_0010;
const KEY_CREATE_LINK: u32 = 0x0000_0020;
const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const KEY_READ: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL;
const KEY_WRITE: u32 = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL;
const KEY_ALL_ACCESS: u32 = KEY_QUERY_VALUE
    | KEY_SET_VALUE
    | KEY_CREATE_SUB_KEY
    | KEY_ENUMERATE_SUB_KEYS
    | KEY_NOTIFY
    | KEY_CREATE_LINK
    | DELETE
    | READ_CONTROL
    | WRITE_DAC
    | WRITE_OWNER;
const REG_VALID_MAPPED_ACCESS_MASK: u32 = KEY_QUERY_VALUE
    | KEY_SET_VALUE
    | KEY_CREATE_SUB_KEY
    | KEY_ENUMERATE_SUB_KEYS
    | KEY_NOTIFY
    | KEY_CREATE_LINK
    | DELETE
    | READ_CONTROL
    | WRITE_DAC
    | WRITE_OWNER
    | 0x0100_0000;

fn registry_mapping() -> GenericMapping {
    GenericMapping {
        read: KEY_READ,
        write: KEY_WRITE,
        execute: 0,
        all: KEY_ALL_ACCESS,
    }
}

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

fn opaque_ace(flags: u8) -> Vec<u8> {
    vec![0x7f, flags, 4, 0]
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

fn sd(owner: &[u8], group: &[u8], sacl: Option<&[u8]>, dacl: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    let owner_offset = bytes.len() as u32;
    bytes.extend_from_slice(owner);
    let group_offset = bytes.len() as u32;
    bytes.extend_from_slice(group);
    let sacl_offset = if let Some(sacl) = sacl {
        let offset = bytes.len() as u32;
        bytes.extend_from_slice(sacl);
        offset
    } else {
        0
    };
    let dacl_offset = if let Some(dacl) = dacl {
        let offset = bytes.len() as u32;
        bytes.extend_from_slice(dacl);
        offset
    } else {
        0
    };

    let mut control = SE_SELF_RELATIVE;
    if sacl.is_some() {
        control |= SE_SACL_PRESENT;
    }
    if dacl.is_some() {
        control |= SE_DACL_PRESENT;
    }
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes
}

#[test]
fn registry_container_inheritance_uses_ci_marks_inherited_and_maps_generics() {
    let parent_owner = sid(5, &[18]);
    let parent_group = sid(5, &[32, 544]);
    let owner = sid(5, &[21, 1000]);
    let group = sid(5, &[21, 513]);
    let other = sid(5, &[11]);
    let creator_owner = sid(3, &[0]);
    let creator_group = sid(3, &[1]);
    let parent_dacl = acl(&[
        basic_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            CONTAINER_INHERIT_ACE,
            GENERIC_READ,
            &creator_owner,
        ),
        basic_ace(
            ACCESS_DENIED_ACE_TYPE,
            OBJECT_INHERIT_ACE,
            GENERIC_WRITE,
            &other,
        ),
        basic_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            GENERIC_WRITE,
            &creator_group,
        ),
    ]);
    let parent_sacl = acl(&[basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        CONTAINER_INHERIT_ACE,
        GENERIC_READ,
        &other,
    )]);
    let parent_sd_bytes = sd(
        &parent_owner,
        &parent_group,
        Some(&parent_sacl),
        Some(&parent_dacl),
    );
    let parent_sd = SecurityDescriptor::parse(&parent_sd_bytes).unwrap();

    let child_bytes = inherit_registry_container_child_sd(RegistryContainerChildInheritance {
        parent_sd,
        token_owner: kacs_core::Sid::parse(&owner).unwrap(),
        token_primary_group: kacs_core::Sid::parse(&group).unwrap(),
        token_default_dacl: None,
        generic_mapping: registry_mapping(),
        valid_mapped_access_mask: REG_VALID_MAPPED_ACCESS_MASK,
    })
    .unwrap();
    let child = SecurityDescriptor::parse(child_bytes.as_slice()).unwrap();

    assert_eq!(child.owner().unwrap().as_bytes(), owner.as_slice());
    assert_eq!(child.group().unwrap().as_bytes(), group.as_slice());
    assert_eq!(
        child.control()
            & (SE_OWNER_DEFAULTED
                | SE_GROUP_DEFAULTED
                | SE_DACL_PRESENT
                | SE_DACL_AUTO_INHERITED
                | SE_SACL_PRESENT
                | SE_SACL_AUTO_INHERITED),
        SE_OWNER_DEFAULTED
            | SE_GROUP_DEFAULTED
            | SE_DACL_PRESENT
            | SE_DACL_AUTO_INHERITED
            | SE_SACL_PRESENT
            | SE_SACL_AUTO_INHERITED
    );

    let dacl = child.dacl().unwrap();
    let entries: Vec<_> = dacl.entries().map(Result::unwrap).collect();
    assert_eq!(entries.len(), 2);

    match entries[0].kind() {
        AceKind::SingleSid { mask, sid } => {
            assert_eq!(mask, KEY_READ);
            assert_eq!(sid.as_bytes(), owner.as_slice());
        }
        other => panic!("unexpected ACE kind: {other:?}"),
    }
    assert_eq!(
        entries[0].ace_flags(),
        CONTAINER_INHERIT_ACE | INHERITED_ACE
    );

    match entries[1].kind() {
        AceKind::SingleSid { mask, sid } => {
            assert_eq!(mask, KEY_WRITE);
            assert_eq!(sid.as_bytes(), group.as_slice());
        }
        other => panic!("unexpected ACE kind: {other:?}"),
    }
    assert_ne!(entries[1].ace_flags() & INHERITED_ACE, 0);
    assert_eq!(
        entries[1].ace_flags() & (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE),
        0
    );

    let sacl = child.sacl().unwrap();
    let sacl_entries: Vec<_> = sacl.entries().map(Result::unwrap).collect();
    assert_eq!(sacl_entries.len(), 1);
    assert_eq!(
        sacl_entries[0].ace_flags(),
        CONTAINER_INHERIT_ACE | INHERITED_ACE
    );
    match sacl_entries[0].kind() {
        AceKind::SingleSid { mask, sid } => {
            assert_eq!(mask, KEY_READ);
            assert_eq!(sid.as_bytes(), other.as_slice());
        }
        other => panic!("unexpected ACE kind: {other:?}"),
    }
}

#[test]
fn registry_container_inheritance_falls_back_to_token_default_or_null_dacl() {
    let parent_owner = sid(5, &[18]);
    let parent_group = sid(5, &[32, 544]);
    let owner = sid(5, &[21, 1000]);
    let group = sid(5, &[21, 513]);
    let parent_dacl = acl(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        OBJECT_INHERIT_ACE,
        GENERIC_READ,
        &owner,
    )]);
    let parent_sd_bytes = sd(&parent_owner, &parent_group, None, Some(&parent_dacl));
    let parent_sd = SecurityDescriptor::parse(&parent_sd_bytes).unwrap();
    let default_dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL, &owner)]);

    let defaulted = inherit_registry_container_child_sd(RegistryContainerChildInheritance {
        parent_sd,
        token_owner: kacs_core::Sid::parse(&owner).unwrap(),
        token_primary_group: kacs_core::Sid::parse(&group).unwrap(),
        token_default_dacl: Some(kacs_core::Acl::parse(&default_dacl).unwrap()),
        generic_mapping: registry_mapping(),
        valid_mapped_access_mask: REG_VALID_MAPPED_ACCESS_MASK,
    })
    .unwrap();
    let defaulted = SecurityDescriptor::parse(defaulted.as_slice()).unwrap();
    assert_eq!(
        defaulted.control() & (SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_DACL_AUTO_INHERITED),
        SE_DACL_PRESENT | SE_DACL_DEFAULTED
    );
    let entries: Vec<_> = defaulted
        .dacl()
        .unwrap()
        .entries()
        .map(Result::unwrap)
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].ace_flags() & INHERITED_ACE, 0);
    match entries[0].kind() {
        AceKind::SingleSid { mask, sid } => {
            assert_eq!(mask, KEY_ALL_ACCESS);
            assert_eq!(sid.as_bytes(), owner.as_slice());
        }
        other => panic!("unexpected ACE kind: {other:?}"),
    }

    let null_dacl = inherit_registry_container_child_sd(RegistryContainerChildInheritance {
        parent_sd,
        token_owner: kacs_core::Sid::parse(&owner).unwrap(),
        token_primary_group: kacs_core::Sid::parse(&group).unwrap(),
        token_default_dacl: None,
        generic_mapping: registry_mapping(),
        valid_mapped_access_mask: REG_VALID_MAPPED_ACCESS_MASK,
    })
    .unwrap();
    let null_dacl = SecurityDescriptor::parse(null_dacl.as_slice()).unwrap();
    assert_eq!(null_dacl.control() & SE_DACL_PRESENT, 0);
    assert!(null_dacl.dacl().is_none());
}

#[test]
fn registry_container_inheritance_rejects_opaque_inheritable_aces() {
    let owner = sid(5, &[21, 1000]);
    let group = sid(5, &[21, 513]);
    let parent_dacl = acl(&[opaque_ace(CONTAINER_INHERIT_ACE)]);
    let parent_sd_bytes = sd(&owner, &group, None, Some(&parent_dacl));
    let parent_sd = SecurityDescriptor::parse(&parent_sd_bytes).unwrap();

    let err = inherit_registry_container_child_sd(RegistryContainerChildInheritance {
        parent_sd,
        token_owner: kacs_core::Sid::parse(&owner).unwrap(),
        token_primary_group: kacs_core::Sid::parse(&group).unwrap(),
        token_default_dacl: None,
        generic_mapping: registry_mapping(),
        valid_mapped_access_mask: REG_VALID_MAPPED_ACCESS_MASK,
    })
    .unwrap_err();

    assert_eq!(
        err,
        KacsError::UnsupportedAceInDacl {
            ace_type: 0x7f,
            reason: "inheritance requires rewritable ACE masks and SIDs"
        }
    );
}

#[test]
fn registry_container_inheritance_rejects_mapped_masks_outside_registry_rights() {
    let owner = sid(5, &[21, 1000]);
    let group = sid(5, &[21, 513]);
    let parent_dacl = acl(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        CONTAINER_INHERIT_ACE,
        SYNCHRONIZE,
        &owner,
    )]);
    let parent_sd_bytes = sd(&owner, &group, None, Some(&parent_dacl));
    let parent_sd = SecurityDescriptor::parse(&parent_sd_bytes).unwrap();

    assert_eq!(
        inherit_registry_container_child_sd(RegistryContainerChildInheritance {
            parent_sd,
            token_owner: kacs_core::Sid::parse(&owner).unwrap(),
            token_primary_group: kacs_core::Sid::parse(&group).unwrap(),
            token_default_dacl: None,
            generic_mapping: registry_mapping(),
            valid_mapped_access_mask: REG_VALID_MAPPED_ACCESS_MASK,
        }),
        Err(KacsError::MappedAccessMaskOutsideObjectRights(SYNCHRONIZE))
    );
}

#[test]
fn registry_container_inheritance_clears_inherit_only_on_child() {
    // Regression for KC-26: a CONTAINER_INHERIT | INHERIT_ONLY DENY ACE on the
    // parent key must produce an inherited copy on the created subkey with
    // INHERIT_ONLY CLEARED, so the DENY is actually enforced on the subkey.
    // Previously the registry path retained INHERIT_ONLY, and the access-check
    // walk skips INHERIT_ONLY ACEs, silently dropping the DENY (fail-open).
    let parent_owner = sid(5, &[18]);
    let parent_group = sid(5, &[32, 544]);
    let owner = sid(5, &[21, 1000]);
    let group = sid(5, &[21, 513]);
    let other = sid(5, &[11]);
    let parent_dacl = acl(&[basic_ace(
        ACCESS_DENIED_ACE_TYPE,
        CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
        GENERIC_WRITE,
        &other,
    )]);
    let parent_sd_bytes = sd(&parent_owner, &parent_group, None, Some(&parent_dacl));
    let parent_sd = SecurityDescriptor::parse(&parent_sd_bytes).unwrap();

    let child_bytes = inherit_registry_container_child_sd(RegistryContainerChildInheritance {
        parent_sd,
        token_owner: kacs_core::Sid::parse(&owner).unwrap(),
        token_primary_group: kacs_core::Sid::parse(&group).unwrap(),
        token_default_dacl: None,
        generic_mapping: registry_mapping(),
        valid_mapped_access_mask: REG_VALID_MAPPED_ACCESS_MASK,
    })
    .unwrap();
    let child = SecurityDescriptor::parse(child_bytes.as_slice()).unwrap();

    let dacl = child.dacl().unwrap();
    let entries: Vec<_> = dacl.entries().map(Result::unwrap).collect();
    assert_eq!(entries.len(), 1);

    // INHERIT_ONLY cleared; CONTAINER_INHERIT retained for further propagation;
    // INHERITED marked. The DENY now applies to the subkey itself.
    assert_eq!(entries[0].ace_flags() & INHERIT_ONLY_ACE, 0);
    assert_eq!(
        entries[0].ace_flags(),
        CONTAINER_INHERIT_ACE | INHERITED_ACE
    );
    match entries[0].kind() {
        AceKind::SingleSid { mask, sid } => {
            assert_eq!(mask, KEY_WRITE);
            assert_eq!(sid.as_bytes(), other.as_slice());
        }
        other => panic!("unexpected ACE kind: {other:?}"),
    }
}
