use crate::access_mask::GenericMapping;
use crate::ace::{
    minimum_acl_revision_for_ace_type, Ace, AceKind, ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, SYSTEM_ALARM_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_ACE_TYPE, SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
};
use crate::acl::Acl;
use crate::error::{KacsError, KacsResult};
use crate::pkm_alloc::Vec as PkmVec;
use crate::security_descriptor::{
    SecurityDescriptor, MAX_SECURITY_DESCRIPTOR_BYTES, SE_DACL_AUTO_INHERITED, SE_DACL_DEFAULTED,
    SE_DACL_PRESENT, SE_GROUP_DEFAULTED, SE_OWNER_DEFAULTED, SE_SACL_AUTO_INHERITED,
    SE_SACL_PRESENT, SE_SELF_RELATIVE,
};
use crate::sid::Sid;

/// ACE flag: inherit to non-container children.
pub const OBJECT_INHERIT_ACE: u8 = peios_uapi::KACS_ACE_FLAG_OBJECT_INHERIT as u8;
/// ACE flag: inherit to container children.
pub const CONTAINER_INHERIT_ACE: u8 = peios_uapi::KACS_ACE_FLAG_CONTAINER_INHERIT as u8;
/// ACE flag: clear object/container propagation flags on the inherited copy.
pub const NO_PROPAGATE_INHERIT_ACE: u8 = peios_uapi::KACS_ACE_FLAG_NO_PROPAGATE_INHERIT as u8;
/// ACE flag: ACE exists only for inheritance and does not apply locally.
pub const INHERIT_ONLY_ACE: u8 = peios_uapi::KACS_ACE_FLAG_INHERIT_ONLY as u8;
/// ACE flag: ACE was produced by inheritance.
pub const INHERITED_ACE: u8 = peios_uapi::KACS_ACE_FLAG_INHERITED as u8;

const CREATOR_OWNER_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
const CREATOR_GROUP_SID: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0];

/// Inputs for the registry-key subset of KACS SD inheritance.
///
/// LCS `reg_create_key` does not accept a caller-supplied creator SD. Registry
/// keys are containers, so only `CONTAINER_INHERIT_ACE` parent ACEs propagate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryContainerChildInheritance<'a> {
    /// Parent key's security descriptor; its DACL and SACL supply the
    /// inheritable ACEs propagated to the child.
    pub parent_sd: SecurityDescriptor<'a>,
    /// Creating token's owner SID; becomes the child owner and substitutes
    /// `CREATOR_OWNER` placeholders in inherited ACEs.
    pub token_owner: Sid<'a>,
    /// Creating token's primary group SID; becomes the child group and
    /// substitutes `CREATOR_GROUP` placeholders in inherited ACEs.
    pub token_primary_group: Sid<'a>,
    /// Token's default DACL, applied only when the parent yields no
    /// inheritable DACL (the defaulted-DACL fallback).
    pub token_default_dacl: Option<Acl<'a>>,
    /// Generic-to-specific access-rights mapping for registry keys, used to
    /// resolve generic rights in inherited ACE masks.
    pub generic_mapping: GenericMapping,
    /// Mask of access bits valid for a registry key; mapped ACE masks are
    /// constrained to these bits.
    pub valid_mapped_access_mask: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaclSource {
    Inherited,
    Defaulted,
}

#[derive(Debug, Eq, PartialEq)]
struct BuiltAcl {
    bytes: PkmVec<u8>,
    ace_count: u16,
}

#[derive(Debug, Eq, PartialEq)]
struct BuiltDacl {
    acl: BuiltAcl,
    source: DaclSource,
}

/// Computes the child SD for a newly created registry key.
pub fn inherit_registry_container_child_sd(
    input: RegistryContainerChildInheritance<'_>,
) -> KacsResult<PkmVec<u8>> {
    let inherited_dacl = build_inherited_acl(
        input.parent_sd.dacl(),
        input.token_owner,
        input.token_primary_group,
        input.generic_mapping,
        input.valid_mapped_access_mask,
    )?;
    let dacl = match inherited_dacl {
        Some(acl) => Some(BuiltDacl {
            acl,
            source: DaclSource::Inherited,
        }),
        None => input
            .token_default_dacl
            .map(|acl| {
                build_default_acl(
                    acl,
                    input.token_owner,
                    input.token_primary_group,
                    input.generic_mapping,
                    input.valid_mapped_access_mask,
                )
                .map(|acl| BuiltDacl {
                    acl,
                    source: DaclSource::Defaulted,
                })
            })
            .transpose()?,
    };

    let sacl = build_inherited_acl(
        input.parent_sd.sacl(),
        input.token_owner,
        input.token_primary_group,
        input.generic_mapping,
        input.valid_mapped_access_mask,
    )?;

    build_child_sd(input.token_owner, input.token_primary_group, sacl, dacl)
}

fn build_inherited_acl(
    acl: Option<Acl<'_>>,
    owner: Sid<'_>,
    group: Sid<'_>,
    mapping: GenericMapping,
    valid_mapped_mask: u32,
) -> KacsResult<Option<BuiltAcl>> {
    let Some(acl) = acl else {
        return Ok(None);
    };

    let mut builder = AclBuilder::new(acl.revision())?;
    for ace in acl.entries() {
        let ace = ace?;
        if (ace.ace_flags() & CONTAINER_INHERIT_ACE) == 0 {
            continue;
        }
        let rewritten = rewrite_ace(
            ace,
            inherited_ace_flags(ace.ace_flags()),
            owner,
            group,
            mapping,
            valid_mapped_mask,
        )?;
        builder.push_ace(ace.ace_type(), rewritten.as_slice())?;
    }

    if builder.ace_count == 0 {
        Ok(None)
    } else {
        Ok(Some(builder.finish()?))
    }
}

fn build_default_acl(
    acl: Acl<'_>,
    owner: Sid<'_>,
    group: Sid<'_>,
    mapping: GenericMapping,
    valid_mapped_mask: u32,
) -> KacsResult<BuiltAcl> {
    let mut builder = AclBuilder::new(acl.revision())?;
    for ace in acl.entries() {
        let ace = ace?;
        let rewritten = rewrite_ace(
            ace,
            ace.ace_flags(),
            owner,
            group,
            mapping,
            valid_mapped_mask,
        )?;
        builder.push_ace(ace.ace_type(), rewritten.as_slice())?;
    }
    builder.finish()
}

fn inherited_ace_flags(parent_flags: u8) -> u8 {
    // Registry keys are always containers and only CONTAINER_INHERIT ACEs reach
    // this path (see build_inherited_acl), so the inherited copy always applies
    // to the created subkey itself. Clear INHERIT_ONLY (mirroring the file path
    // in token_runtime.rs) so a CONTAINER_INHERIT|INHERIT_ONLY DENY/ALLOW ACE is
    // actually enforced on subkeys instead of being skipped by the DACL walk.
    let mut flags = (parent_flags | INHERITED_ACE) & !INHERIT_ONLY_ACE;
    if (parent_flags & NO_PROPAGATE_INHERIT_ACE) != 0 {
        flags &= !(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
    }
    flags
}

struct AclBuilder {
    bytes: PkmVec<u8>,
    revision: u8,
    ace_count: u16,
}

impl AclBuilder {
    fn new(revision_floor: u8) -> KacsResult<Self> {
        let mut bytes = PkmVec::with_capacity(Acl::HEADER_SIZE)?;
        for _ in 0..Acl::HEADER_SIZE {
            bytes.push(0)?;
        }
        Ok(Self {
            bytes,
            revision: revision_floor,
            ace_count: 0,
        })
    }

    fn push_ace(&mut self, ace_type: u8, ace: &[u8]) -> KacsResult<()> {
        if self.ace_count == u16::MAX {
            return Err(KacsError::InvariantViolation("acl ace count overflow"));
        }
        self.revision = core::cmp::max(self.revision, minimum_acl_revision_for_ace_type(ace_type));
        self.bytes.extend_from_slice(ace)?;
        self.ace_count += 1;
        Ok(())
    }

    fn finish(mut self) -> KacsResult<BuiltAcl> {
        let acl_len = self.bytes.len();
        if acl_len > u16::MAX as usize {
            return Err(KacsError::SecurityDescriptorTooLarge {
                len: acl_len,
                max: u16::MAX as usize,
            });
        }

        self.bytes[0] = self.revision;
        self.bytes[1] = 0;
        write_u16_at(&mut self.bytes, 2, acl_len as u16);
        write_u16_at(&mut self.bytes, 4, self.ace_count);
        write_u16_at(&mut self.bytes, 6, 0);

        Ok(BuiltAcl {
            bytes: self.bytes,
            ace_count: self.ace_count,
        })
    }
}

fn rewrite_ace(
    ace: Ace<'_>,
    ace_flags: u8,
    owner: Sid<'_>,
    group: Sid<'_>,
    mapping: GenericMapping,
    valid_mapped_mask: u32,
) -> KacsResult<PkmVec<u8>> {
    match ace.kind() {
        AceKind::SingleSid { mask, sid } => write_single_sid_ace(
            ace.ace_type(),
            ace_flags,
            mask,
            sid,
            owner,
            group,
            mapping,
            valid_mapped_mask,
        ),
        AceKind::Object {
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
        } => write_object_ace(
            ace.ace_type(),
            ace_flags,
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
            owner,
            group,
            mapping,
            valid_mapped_mask,
        ),
        AceKind::Callback {
            mask,
            sid,
            application_data,
        } => write_callback_ace(
            ace.ace_type(),
            ace_flags,
            mask,
            sid,
            application_data,
            owner,
            group,
            mapping,
            valid_mapped_mask,
        ),
        AceKind::CallbackObject {
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
            application_data,
        } => write_callback_object_ace(
            ace.ace_type(),
            ace_flags,
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
            application_data,
            owner,
            group,
            mapping,
            valid_mapped_mask,
        ),
        AceKind::ResourceAttribute {
            mask,
            sid,
            application_data,
        } => write_callback_ace(
            ace.ace_type(),
            ace_flags,
            mask,
            sid,
            application_data,
            owner,
            group,
            mapping,
            valid_mapped_mask,
        ),
        AceKind::Opaque => Err(KacsError::UnsupportedAceInDacl {
            ace_type: ace.ace_type(),
            reason: "inheritance requires rewritable ACE masks and SIDs",
        }),
    }
}

fn write_single_sid_ace(
    ace_type: u8,
    ace_flags: u8,
    mask: u32,
    sid: Sid<'_>,
    owner: Sid<'_>,
    group: Sid<'_>,
    mapping: GenericMapping,
    valid_mapped_mask: u32,
) -> KacsResult<PkmVec<u8>> {
    let mut payload = PkmVec::new();
    push_u32(
        &mut payload,
        map_ace_mask(mask, mapping, valid_mapped_mask)?,
    )?;
    push_substituted_sid(&mut payload, sid, owner, group)?;
    write_ace(ace_type, ace_flags, payload.as_slice())
}

#[allow(clippy::too_many_arguments)]
fn write_object_ace(
    ace_type: u8,
    ace_flags: u8,
    mask: u32,
    object_flags: u32,
    object_type: Option<&[u8; 16]>,
    inherited_object_type: Option<&[u8; 16]>,
    sid: Sid<'_>,
    owner: Sid<'_>,
    group: Sid<'_>,
    mapping: GenericMapping,
    valid_mapped_mask: u32,
) -> KacsResult<PkmVec<u8>> {
    let mut payload = PkmVec::new();
    push_u32(
        &mut payload,
        map_ace_mask(mask, mapping, valid_mapped_mask)?,
    )?;
    push_u32(&mut payload, object_flags)?;
    if let Some(guid) = object_type {
        payload.extend_from_slice(guid)?;
    }
    if let Some(guid) = inherited_object_type {
        payload.extend_from_slice(guid)?;
    }
    push_substituted_sid(&mut payload, sid, owner, group)?;
    write_ace(ace_type, ace_flags, payload.as_slice())
}

#[allow(clippy::too_many_arguments)]
fn write_callback_ace(
    ace_type: u8,
    ace_flags: u8,
    mask: u32,
    sid: Sid<'_>,
    application_data: &[u8],
    owner: Sid<'_>,
    group: Sid<'_>,
    mapping: GenericMapping,
    valid_mapped_mask: u32,
) -> KacsResult<PkmVec<u8>> {
    let mut payload = PkmVec::new();
    push_u32(
        &mut payload,
        map_ace_mask(mask, mapping, valid_mapped_mask)?,
    )?;
    push_substituted_sid(&mut payload, sid, owner, group)?;
    payload.extend_from_slice(application_data)?;
    write_ace(ace_type, ace_flags, payload.as_slice())
}

#[allow(clippy::too_many_arguments)]
fn write_callback_object_ace(
    ace_type: u8,
    ace_flags: u8,
    mask: u32,
    object_flags: u32,
    object_type: Option<&[u8; 16]>,
    inherited_object_type: Option<&[u8; 16]>,
    sid: Sid<'_>,
    application_data: &[u8],
    owner: Sid<'_>,
    group: Sid<'_>,
    mapping: GenericMapping,
    valid_mapped_mask: u32,
) -> KacsResult<PkmVec<u8>> {
    let mut payload = PkmVec::new();
    push_u32(
        &mut payload,
        map_ace_mask(mask, mapping, valid_mapped_mask)?,
    )?;
    push_u32(&mut payload, object_flags)?;
    if let Some(guid) = object_type {
        payload.extend_from_slice(guid)?;
    }
    if let Some(guid) = inherited_object_type {
        payload.extend_from_slice(guid)?;
    }
    push_substituted_sid(&mut payload, sid, owner, group)?;
    payload.extend_from_slice(application_data)?;
    write_ace(ace_type, ace_flags, payload.as_slice())
}

fn map_ace_mask(mask: u32, mapping: GenericMapping, valid_mapped_mask: u32) -> KacsResult<u32> {
    let mapped = mapping.map_mask(mask)?;
    let invalid = mapped & !valid_mapped_mask;
    if invalid != 0 {
        return Err(KacsError::MappedAccessMaskOutsideObjectRights(invalid));
    }
    Ok(mapped)
}

fn write_ace(ace_type: u8, ace_flags: u8, payload: &[u8]) -> KacsResult<PkmVec<u8>> {
    let ace_size = 4usize
        .checked_add(payload.len())
        .ok_or(KacsError::InvariantViolation("ace size overflow"))?;
    if ace_size > u16::MAX as usize || (ace_size % 4) != 0 {
        return Err(KacsError::InvalidAceSize(
            u16::try_from(ace_size).unwrap_or(u16::MAX),
        ));
    }

    let mut bytes = PkmVec::with_capacity(ace_size)?;
    bytes.push(ace_type)?;
    bytes.push(ace_flags)?;
    push_u16(&mut bytes, ace_size as u16)?;
    bytes.extend_from_slice(payload)?;

    debug_assert_eq!(bytes.len(), ace_size);
    Ok(bytes)
}

fn push_substituted_sid(
    dst: &mut PkmVec<u8>,
    sid: Sid<'_>,
    owner: Sid<'_>,
    group: Sid<'_>,
) -> KacsResult<()> {
    if sid.as_bytes() == CREATOR_OWNER_SID {
        dst.extend_from_slice(owner.as_bytes())?;
    } else if sid.as_bytes() == CREATOR_GROUP_SID {
        dst.extend_from_slice(group.as_bytes())?;
    } else {
        dst.extend_from_slice(sid.as_bytes())?;
    }
    Ok(())
}

fn build_child_sd(
    owner: Sid<'_>,
    group: Sid<'_>,
    sacl: Option<BuiltAcl>,
    dacl: Option<BuiltDacl>,
) -> KacsResult<PkmVec<u8>> {
    let mut bytes = PkmVec::with_capacity(SecurityDescriptor::HEADER_SIZE)?;
    for _ in 0..SecurityDescriptor::HEADER_SIZE {
        bytes.push(0)?;
    }

    let owner_offset = append_component(&mut bytes, owner.as_bytes())?;
    let group_offset = append_component(&mut bytes, group.as_bytes())?;
    let sacl_offset = if let Some(sacl) = &sacl {
        append_component(&mut bytes, sacl.bytes.as_slice())?
    } else {
        0
    };
    let dacl_offset = if let Some(dacl) = &dacl {
        append_component(&mut bytes, dacl.acl.bytes.as_slice())?
    } else {
        0
    };

    if bytes.len() > MAX_SECURITY_DESCRIPTOR_BYTES {
        return Err(KacsError::SecurityDescriptorTooLarge {
            len: bytes.len(),
            max: MAX_SECURITY_DESCRIPTOR_BYTES,
        });
    }

    let mut control = SE_SELF_RELATIVE | SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED;
    if sacl.is_some() {
        control |= SE_SACL_PRESENT | SE_SACL_AUTO_INHERITED;
    }
    if let Some(dacl) = &dacl {
        control |= SE_DACL_PRESENT;
        match dacl.source {
            DaclSource::Inherited => control |= SE_DACL_AUTO_INHERITED,
            DaclSource::Defaulted => control |= SE_DACL_DEFAULTED,
        }
    }

    bytes[0] = 1;
    bytes[1] = 0;
    write_u16_at(&mut bytes, 2, control);
    write_u32_at(&mut bytes, 4, owner_offset);
    write_u32_at(&mut bytes, 8, group_offset);
    write_u32_at(&mut bytes, 12, sacl_offset);
    write_u32_at(&mut bytes, 16, dacl_offset);

    SecurityDescriptor::parse(bytes.as_slice())?;
    Ok(bytes)
}

fn append_component(dst: &mut PkmVec<u8>, component: &[u8]) -> KacsResult<u32> {
    let offset = u32::try_from(dst.len()).map_err(|_| KacsError::SecurityDescriptorTooLarge {
        len: dst.len(),
        max: MAX_SECURITY_DESCRIPTOR_BYTES,
    })?;
    dst.extend_from_slice(component)?;
    Ok(offset)
}

fn push_u16(dst: &mut PkmVec<u8>, value: u16) -> KacsResult<()> {
    dst.extend_from_slice(&value.to_le_bytes())?;
    Ok(())
}

fn push_u32(dst: &mut PkmVec<u8>, value: u32) -> KacsResult<()> {
    dst.extend_from_slice(&value.to_le_bytes())?;
    Ok(())
}

fn write_u16_at(dst: &mut [u8], offset: usize, value: u16) {
    dst[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(dst: &mut [u8], offset: usize, value: u32) {
    dst[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

const _: () = {
    assert!(ACCESS_ALLOWED_ACE_TYPE == 0x00);
    assert!(ACCESS_DENIED_ACE_TYPE == 0x01);
    assert!(SYSTEM_AUDIT_ACE_TYPE == 0x02);
    assert!(SYSTEM_ALARM_ACE_TYPE == 0x03);
    assert!(ACCESS_ALLOWED_OBJECT_ACE_TYPE == 0x05);
    assert!(ACCESS_DENIED_OBJECT_ACE_TYPE == 0x06);
    assert!(SYSTEM_AUDIT_OBJECT_ACE_TYPE == 0x07);
    assert!(SYSTEM_ALARM_OBJECT_ACE_TYPE == 0x08);
    assert!(ACCESS_ALLOWED_CALLBACK_ACE_TYPE == 0x09);
    assert!(ACCESS_DENIED_CALLBACK_ACE_TYPE == 0x0a);
    assert!(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE == 0x0b);
    assert!(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE == 0x0c);
    assert!(SYSTEM_AUDIT_CALLBACK_ACE_TYPE == 0x0d);
    assert!(SYSTEM_ALARM_CALLBACK_ACE_TYPE == 0x0e);
    assert!(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE == 0x0f);
    assert!(SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE == 0x10);
    assert!(SYSTEM_MANDATORY_LABEL_ACE_TYPE == 0x11);
    assert!(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE == 0x12);
    assert!(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE == 0x13);
    assert!(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE == 0x14);
};
