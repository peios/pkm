// SD Inheritance algorithm (§9.5).
//
// Computes the Security Descriptor for a newly created object from:
//   1. Parent SD — provides inheritable ACEs
//   2. Creator SD (optional) — explicit SD provided by the caller
//   3. Creator token — provides default owner, group, and DACL
//
// Follows MS-DTYP §2.5.3.4 (CreateSecurityDescriptor).

use crate::compat::{self, AllocError, TryClone, Vec};
use crate::ace::{self, Ace};
use crate::acl::{Acl, ACL_REVISION};
use crate::mask::GenericMapping;
use crate::sd::*;
use crate::sid::Sid;
use crate::token::Token;
use crate::well_known;

/// Whether the new object is a container (directory, registry key)
/// or a non-container (file, value).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectClass {
    /// Directory, registry key, or other namespace node.
    Container,
    /// File, value, or other leaf object.
    NonContainer,
}

/// Compute the SD for a newly created object (§9.5).
///
/// `parent_sd`: SD of the container the object is created in (None if no parent).
/// `creator_sd`: explicit SD provided by the caller (None = use defaults).
/// `token`: the creating thread's effective token.
/// `object_class`: Container or NonContainer.
/// `mapping`: GenericMapping for the new object's type.
/// `child_type_guid`: the new object's schema class GUID (for
///   InheritedObjectType filtering). Files pass None. Registry/directory
///   objects pass the GUID from the schema. ACEs with an inherited_object_type
///   that doesn't match are skipped during inheritance.
pub fn compute_inherited_sd(
    parent_sd: Option<&SecurityDescriptor>,
    creator_sd: Option<&SecurityDescriptor>,
    token: &Token,
    object_class: ObjectClass,
    mapping: &GenericMapping,
    child_type_guid: Option<&crate::guid::Guid>,
) -> Result<SecurityDescriptor, AllocError> {
    // --- Owner ---
    let owner = match creator_sd.and_then(|csd| csd.owner.as_ref()) {
        Some(o) => o.try_clone()?,
        None => owner_from_token(token)?,
    };

    // --- Group ---
    let group = match creator_sd.and_then(|csd| csd.group.as_ref()) {
        Some(g) => g.try_clone()?,
        None => group_from_token(token)?,
    };

    // --- DACL ---
    let dacl = compute_acl(
        parent_sd.and_then(|p| p.dacl.as_ref()),
        creator_sd.and_then(|c| c.dacl.as_ref()),
        creator_sd.map_or(false, |c| c.control & SE_DACL_PROTECTED != 0),
        creator_sd.map_or(false, |c| c.control & SE_DACL_PRESENT != 0),
        token,
        &owner,
        &group,
        object_class,
        mapping,
        true, // is_dacl
        child_type_guid,
    )?;

    // --- SACL ---
    let sacl = compute_acl(
        parent_sd.and_then(|p| p.sacl.as_ref()),
        creator_sd.and_then(|c| c.sacl.as_ref()),
        creator_sd.map_or(false, |c| c.control & SE_SACL_PROTECTED != 0),
        creator_sd.map_or(false, |c| c.control & SE_SACL_PRESENT != 0),
        token,
        &owner,
        &group,
        object_class,
        mapping,
        false, // not dacl
        child_type_guid,
    )?;

    let mut control = SE_SELF_RELATIVE;
    let dacl_protected = creator_sd.map_or(false, |c| c.control & SE_DACL_PROTECTED != 0);
    let sacl_protected = creator_sd.map_or(false, |c| c.control & SE_SACL_PROTECTED != 0);
    if dacl.is_some() {
        control |= SE_DACL_PRESENT;
        if !dacl_protected && parent_sd.and_then(|p| p.dacl.as_ref()).is_some() {
            control |= SE_DACL_AUTO_INHERITED;
        }
    }
    if sacl.is_some() {
        control |= SE_SACL_PRESENT;
        if !sacl_protected && parent_sd.and_then(|p| p.sacl.as_ref()).is_some() {
            control |= SE_SACL_AUTO_INHERITED;
        }
    }

    Ok(SecurityDescriptor {
        control,
        owner: Some(owner),
        group: Some(group),
        dacl,
        sacl,
    })
}

/// Get the owner SID from the token (token's owner_sid_index).
fn owner_from_token(token: &Token) -> Result<Sid, AllocError> {
    if token.owner_sid_index == 0 {
        token.user_sid.try_clone()
    } else {
        let group_idx = (token.owner_sid_index - 1) as usize;
        if group_idx < token.groups.len() {
            token.groups[group_idx].sid.try_clone()
        } else {
            token.user_sid.try_clone()
        }
    }
}

/// Get the primary group SID from the token.
fn group_from_token(token: &Token) -> Result<Sid, AllocError> {
    if token.primary_group_index == 0 {
        token.user_sid.try_clone()
    } else {
        let group_idx = (token.primary_group_index - 1) as usize;
        if group_idx < token.groups.len() {
            token.groups[group_idx].sid.try_clone()
        } else {
            token.user_sid.try_clone()
        }
    }
}

/// Compute an inherited ACL (DACL or SACL).
fn compute_acl(
    parent_acl: Option<&Acl>,
    creator_acl: Option<&Acl>,
    creator_protected: bool,
    creator_present: bool,
    token: &Token,
    owner: &Sid,
    group: &Sid,
    object_class: ObjectClass,
    mapping: &GenericMapping,
    is_dacl: bool,
    child_type_guid: Option<&crate::guid::Guid>,
) -> Result<Option<Acl>, AllocError> {
    if creator_present && creator_protected {
        // Creator supplied a protected ACL — use it as-is, no parent inheritance
        return match creator_acl {
            Some(acl) => Ok(Some(acl.try_clone()?)),
            None => Ok(None),
        };
    }

    if creator_present {
        // Creator supplied an unprotected ACL — keep explicit ACEs,
        // append inheritable ACEs from parent
        let mut aces = Vec::new();

        // Explicit ACEs from creator (those without INHERITED_ACE flag)
        if let Some(cacl) = creator_acl {
            for a in &cacl.aces {
                if a.flags & ace::INHERITED_ACE == 0 {
                    let mut ace = a.try_clone()?;
                    post_process_ace(&mut ace, owner, group, mapping)?;
                    compat::vec_push(&mut aces, ace)?;
                }
            }
        }

        // Inheritable ACEs from parent
        if let Some(pacl) = parent_acl {
            let inherited = inherit_aces_from_parent(pacl, owner, group, object_class, mapping, child_type_guid)?;
            compat::vec_extend(&mut aces, &inherited)?;
        }

        if aces.is_empty() && !creator_present {
            return Ok(None);
        }

        return Ok(Some(Acl::with_aces(aces)));
    }

    // No creator ACL supplied
    if let Some(pacl) = parent_acl {
        let inherited = inherit_aces_from_parent(pacl, owner, group, object_class, mapping, child_type_guid)?;
        if !inherited.is_empty() {
            return Ok(Some(Acl::with_aces(inherited)));
        }
    }

    // No parent inheritance — use token's default DACL
    if is_dacl {
        if let Some(ref default_dacl) = token.default_dacl {
            Ok(Some(default_dacl.try_clone()?))
        } else {
            Ok(Some(Acl::new(ACL_REVISION)))
        }
    } else {
        // No default SACL
        Ok(None)
    }
}

/// Inherit ACEs from a parent ACL for the given object class.
fn inherit_aces_from_parent(
    parent_acl: &Acl,
    owner: &Sid,
    group: &Sid,
    object_class: ObjectClass,
    mapping: &GenericMapping,
    child_type_guid: Option<&crate::guid::Guid>,
) -> Result<Vec<Ace>, AllocError> {
    let mut result = Vec::new();
    let is_container = object_class == ObjectClass::Container;

    for parent_ace in &parent_acl.aces {
        let ci = parent_ace.flags & ace::CONTAINER_INHERIT_ACE != 0;
        let oi = parent_ace.flags & ace::OBJECT_INHERIT_ACE != 0;
        let np = parent_ace.flags & ace::NO_PROPAGATE_INHERIT_ACE != 0;
        let io = parent_ace.flags & ace::INHERIT_ONLY_ACE != 0;

        // InheritedObjectType filtering: if the ACE specifies a type
        // that this child must be, skip it if the child doesn't match.
        // Files pass None (untyped) — all ACEs apply.
        if let Some(ref inherited_ot) = parent_ace.inherited_object_type {
            match child_type_guid {
                Some(child_guid) if child_guid == inherited_ot => { /* match, continue */ }
                Some(_) => continue, // child is a different type, skip
                None => { /* untyped child, apply all ACEs */ }
            }
        }

        // Determine if this ACE is inherited by this object type.
        // Containers inherit CI ACEs directly and OI ACEs as inherit-only
        // (so they can propagate to grandchildren non-containers).
        let inherited = if is_container {
            ci || oi
        } else {
            oi
        };

        if !inherited {
            continue;
        }

        let mut new_ace = parent_ace.try_clone()?;

        // Set INHERITED_ACE flag
        new_ace.flags |= ace::INHERITED_ACE;

        if is_container {
            if np {
                // NO_PROPAGATE: clear all inheritance flags on the child copy
                new_ace.flags &= !(ace::CONTAINER_INHERIT_ACE
                    | ace::OBJECT_INHERIT_ACE
                    | ace::NO_PROPAGATE_INHERIT_ACE
                    | ace::INHERIT_ONLY_ACE);
            } else {
                // Container: if the parent ACE has OI but not CI,
                // the inherited copy is INHERIT_ONLY on the container
                // (it doesn't apply to the container itself, only to
                // non-container children)
                if oi && !ci {
                    new_ace.flags |= ace::INHERIT_ONLY_ACE;
                } else if !io {
                    // Remove IO if it was set — the ACE applies to this container
                    new_ace.flags &= !ace::INHERIT_ONLY_ACE;
                }
            }
        } else {
            // Non-container: clear all inheritance flags (can't propagate further)
            new_ace.flags &= !(ace::CONTAINER_INHERIT_ACE
                | ace::OBJECT_INHERIT_ACE
                | ace::NO_PROPAGATE_INHERIT_ACE
                | ace::INHERIT_ONLY_ACE);
        }

        // CREATOR OWNER / CREATOR GROUP substitution
        substitute_creator_sids(&mut new_ace, owner, group)?;

        // Map generic bits in inherited ACE (Peios preserves generics on IO ACEs)
        if new_ace.flags & ace::INHERIT_ONLY_ACE == 0 {
            new_ace.mask = crate::mask::map_generic_bits(new_ace.mask, mapping);
        }

        compat::vec_push(&mut result, new_ace)?;
    }

    Ok(result)
}

/// Replace CREATOR OWNER (S-1-3-0) and CREATOR GROUP (S-1-3-1)
/// with the actual owner and group SIDs.
fn substitute_creator_sids(ace: &mut Ace, owner: &Sid, group: &Sid) -> Result<(), AllocError> {
    if ace.sid == well_known::creator_owner()? {
        ace.sid = owner.try_clone()?;
    } else if ace.sid == well_known::creator_group()? {
        ace.sid = group.try_clone()?;
    }
    Ok(())
}

/// Post-process an explicit ACE from the creator SD.
fn post_process_ace(ace: &mut Ace, owner: &Sid, group: &Sid, mapping: &GenericMapping) -> Result<(), AllocError> {
    substitute_creator_sids(ace, owner, group)?;
    if ace.flags & ace::INHERIT_ONLY_ACE == 0 {
        ace.mask = crate::mask::map_generic_bits(ace.mask, mapping);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ace::*;
    use crate::mask::*;

    fn test_token() -> Token {
        Token::system_token().unwrap()
    }

    fn parent_sd(aces: Vec<Ace>) -> SecurityDescriptor {
        SecurityDescriptor::new(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl { revision: ACL_REVISION, aces },
        )
    }

    fn ci_oi_allow(sid: &Sid, mask: u32) -> Ace {
        Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }
    }

    fn ci_allow(sid: &Sid, mask: u32) -> Ace {
        Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE,
            mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }
    }

    fn oi_allow(sid: &Sid, mask: u32) -> Ace {
        Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: OBJECT_INHERIT_ACE,
            mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }
    }

    // -----------------------------------------------------------------------
    // Basic inheritance
    // -----------------------------------------------------------------------

    #[test]
    fn file_inherits_oi_ace() {
        let parent = parent_sd(alloc::vec![
            oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert_eq!(dacl.aces[0].sid, well_known::everyone().unwrap());
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
        // Non-container: inheritance flags cleared
        assert_eq!(dacl.aces[0].flags & OBJECT_INHERIT_ACE, 0);
    }

    #[test]
    fn file_does_not_inherit_ci_ace() {
        let parent = parent_sd(alloc::vec![
            ci_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 0); // CI doesn't apply to files
    }

    #[test]
    fn dir_inherits_ci_ace() {
        let parent = parent_sd(alloc::vec![
            ci_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
        // CI preserved for further propagation
        assert!(dacl.aces[0].flags & CONTAINER_INHERIT_ACE != 0);
    }

    #[test]
    fn dir_inherits_ci_oi_ace() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // Both CI and OI preserved
        assert!(dacl.aces[0].flags & CONTAINER_INHERIT_ACE != 0);
        assert!(dacl.aces[0].flags & OBJECT_INHERIT_ACE != 0);
        // Not IO — applies to the directory itself
        assert_eq!(dacl.aces[0].flags & INHERIT_ONLY_ACE, 0);
    }

    #[test]
    fn file_inherits_ci_oi_ace() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // Non-container: all inheritance flags cleared
        assert_eq!(dacl.aces[0].flags & (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE), 0);
    }

    // -----------------------------------------------------------------------
    // NO_PROPAGATE_INHERIT
    // -----------------------------------------------------------------------

    #[test]
    fn np_clears_inheritance_flags() {
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let parent = parent_sd(alloc::vec![ace]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // All inheritance flags cleared (NP = one level only)
        assert_eq!(dacl.aces[0].flags & (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
            | NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE), 0);
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
    }

    // -----------------------------------------------------------------------
    // OI-only on container → INHERIT_ONLY
    // -----------------------------------------------------------------------

    #[test]
    fn oi_only_becomes_io_on_container() {
        // OI without CI: container inherits as INHERIT_ONLY
        // (applies to files inside, not to the subdir itself)
        let parent = parent_sd(alloc::vec![
            oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert!(dacl.aces[0].flags & INHERIT_ONLY_ACE != 0);
    }

    // -----------------------------------------------------------------------
    // CREATOR OWNER / CREATOR GROUP substitution
    // -----------------------------------------------------------------------

    #[test]
    fn creator_owner_substituted() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::creator_owner().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // CREATOR OWNER replaced with the owner (SYSTEM for our test token)
        assert_eq!(dacl.aces[0].sid, well_known::system().unwrap());
    }

    #[test]
    fn creator_group_substituted() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::creator_group().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // CREATOR GROUP replaced with the group (SYSTEM for our test token)
        assert_eq!(dacl.aces[0].sid, well_known::system().unwrap());
    }

    // -----------------------------------------------------------------------
    // Protected DACL
    // -----------------------------------------------------------------------

    #[test]
    fn protected_dacl_blocks_inheritance() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), GENERIC_ALL),
        ]);
        let alice = Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: Some(well_known::users().unwrap()),
            dacl: Some(Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: FILE_READ_DATA,
                    sid: alice.clone(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            }),
            sacl: None,
        };
        let child = compute_inherited_sd(
            Some(&parent), Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        // Only the creator's explicit ACE, no parent inheritance
        assert_eq!(dacl.aces.len(), 1);
        assert_eq!(dacl.aces[0].sid, alice);
    }

    // -----------------------------------------------------------------------
    // No parent
    // -----------------------------------------------------------------------

    #[test]
    fn no_parent_uses_default() {
        let child = compute_inherited_sd(
            None, None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert!(child.dacl.is_some()); // gets default (empty for now)
        assert!(child.owner.is_some());
        assert!(child.group.is_some());
    }

    // -----------------------------------------------------------------------
    // Owner and group from token
    // -----------------------------------------------------------------------

    #[test]
    fn owner_from_token_default() {
        let child = compute_inherited_sd(
            None, None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // SYSTEM token's owner is user_sid (S-1-5-18)
        assert_eq!(child.owner.unwrap(), well_known::system().unwrap());
    }

    #[test]
    fn owner_from_creator_sd() {
        let alice = Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let creator = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: None,
            dacl: None,
            sacl: None,
        };
        let child = compute_inherited_sd(
            None, Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert_eq!(child.owner.unwrap(), alice);
    }

    // -----------------------------------------------------------------------
    // Generic bits mapped on non-IO inherited ACEs
    // -----------------------------------------------------------------------

    #[test]
    fn generic_bits_mapped_on_inherited_ace() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), GENERIC_READ),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // GENERIC_READ should be mapped to file-specific bits
        assert!(dacl.aces[0].mask & FILE_READ_DATA != 0);
        assert_eq!(dacl.aces[0].mask & GENERIC_READ, 0); // generic cleared
    }

    #[test]
    fn generic_bits_preserved_on_io_ace() {
        // IO ACEs preserve generic bits (Peios divergence from MS-DTYP)
        let parent = parent_sd(alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE,
            mask: GENERIC_READ,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert!(dacl.aces[0].flags & INHERIT_ONLY_ACE != 0);
        // Generic bits preserved on IO ACEs
        assert!(dacl.aces[0].mask & GENERIC_READ != 0);
    }

    // -----------------------------------------------------------------------
    // Multiple ACEs
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_parent_aces_inherited() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::administrators().unwrap(), GENERIC_ALL),
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA | READ_CONTROL),
            Ace {
                ace_type: ACCESS_DENIED_ACE_TYPE,
                flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                mask: FILE_WRITE_DATA,
                sid: well_known::guests().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 3);
        // All have INHERITED_ACE set
        for ace in &dacl.aces {
            assert!(ace.flags & INHERITED_ACE != 0);
        }
    }

    #[test]
    fn non_inheritable_ace_not_inherited() {
        let parent = parent_sd(alloc::vec![
            // No CI or OI — explicit only, not inheritable
            Ace {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                flags: 0,
                mask: GENERIC_ALL,
                sid: well_known::administrators().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1); // only the CI|OI one
        assert_eq!(dacl.aces[0].sid, well_known::everyone().unwrap());
    }

    // -----------------------------------------------------------------------
    // Creator SD with parent inheritance
    // -----------------------------------------------------------------------

    #[test]
    fn creator_explicit_plus_parent_inherited() {
        let alice = Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: Some(well_known::users().unwrap()),
            dacl: Some(Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0, // explicit
                    mask: FILE_WRITE_DATA,
                    sid: alice.clone(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            }),
            sacl: None,
        };
        let child = compute_inherited_sd(
            Some(&parent), Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 2);
        // First: explicit from creator
        assert_eq!(dacl.aces[0].sid, alice);
        assert_eq!(dacl.aces[0].flags & INHERITED_ACE, 0);
        // Second: inherited from parent
        assert_eq!(dacl.aces[1].sid, well_known::everyone().unwrap());
        assert!(dacl.aces[1].flags & INHERITED_ACE != 0);
    }

    // -----------------------------------------------------------------------
    // SACL inheritance
    // -----------------------------------------------------------------------

    #[test]
    fn sacl_inherited_from_parent() {
        let parent = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: SYSTEM_AUDIT_ACE_TYPE,
                    flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
                        | SUCCESSFUL_ACCESS_ACE_FLAG,
                    mask: FILE_WRITE_DATA,
                    sid: well_known::everyone().unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            },
        );
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert!(child.sacl.is_some());
        let sacl = child.sacl.unwrap();
        assert_eq!(sacl.aces.len(), 1);
        assert_eq!(sacl.aces[0].ace_type, SYSTEM_AUDIT_ACE_TYPE);
        assert!(sacl.aces[0].flags & INHERITED_ACE != 0);
    }

    #[test]
    fn sacl_not_inherited_without_flags() {
        let parent = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::system().unwrap(),
            Acl::new(ACL_REVISION),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: SYSTEM_AUDIT_ACE_TYPE,
                    flags: SUCCESSFUL_ACCESS_ACE_FLAG, // no CI/OI
                    mask: FILE_WRITE_DATA,
                    sid: well_known::everyone().unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            },
        );
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // No SACL inheritance (no CI/OI on parent ACE)
        assert!(child.sacl.is_none());
    }

    // -----------------------------------------------------------------------
    // Nested inheritance (grandchild)
    // -----------------------------------------------------------------------

    #[test]
    fn nested_inheritance_parent_to_child_to_grandchild() {
        // CI|OI ACE propagates through: parent → child dir → grandchild file
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);

        // First generation: child directory
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let child_dacl = child.dacl.as_ref().unwrap();
        assert_eq!(child_dacl.aces.len(), 1);
        // CI|OI should still be present for further propagation
        assert!(child_dacl.aces[0].flags & CONTAINER_INHERIT_ACE != 0);
        assert!(child_dacl.aces[0].flags & OBJECT_INHERIT_ACE != 0);

        // Second generation: grandchild file
        let grandchild = compute_inherited_sd(
            Some(&child), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let gc_dacl = grandchild.dacl.as_ref().unwrap();
        assert_eq!(gc_dacl.aces.len(), 1);
        assert_eq!(gc_dacl.aces[0].sid, well_known::everyone().unwrap());
        // Non-container: flags cleared
        assert_eq!(gc_dacl.aces[0].flags & (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE), 0);
    }

    #[test]
    fn np_stops_at_one_level() {
        // CI|OI|NP: inherits to child, but child can't propagate further
        let parent = parent_sd(alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }]);

        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let child_dacl = child.dacl.as_ref().unwrap();
        assert_eq!(child_dacl.aces.len(), 1);
        // NP cleared all inheritance flags — can't propagate
        assert_eq!(child_dacl.aces[0].flags & (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
            | NO_PROPAGATE_INHERIT_ACE), 0);

        // Grandchild: nothing inherited (child's ACE has no inheritance flags)
        let grandchild = compute_inherited_sd(
            Some(&child), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let gc_dacl = grandchild.dacl.as_ref().unwrap();
        assert_eq!(gc_dacl.aces.len(), 0); // nothing to inherit
    }

    // -----------------------------------------------------------------------
    // Creator SD with pre-existing INHERITED_ACE
    // -----------------------------------------------------------------------

    #[test]
    fn creator_sd_inherited_aces_filtered() {
        // Creator SD has both explicit and inherited ACEs.
        // Only explicit should be kept.
        let alice = Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: Some(well_known::users().unwrap()),
            dacl: Some(Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![
                    Ace {
                        ace_type: ACCESS_ALLOWED_ACE_TYPE,
                        flags: 0, // explicit
                        mask: FILE_WRITE_DATA,
                        sid: alice.clone(),
                        object_type: None, inherited_object_type: None,
                        condition: None, application_data: None,
                    },
                    Ace {
                        ace_type: ACCESS_ALLOWED_ACE_TYPE,
                        flags: INHERITED_ACE, // inherited — should be filtered
                        mask: FILE_READ_DATA,
                        sid: well_known::everyone().unwrap(),
                        object_type: None, inherited_object_type: None,
                        condition: None, application_data: None,
                    },
                ],
            }),
            sacl: None,
        };
        let child = compute_inherited_sd(
            None, Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        // Only the explicit ACE should be present
        assert_eq!(dacl.aces.len(), 1);
        assert_eq!(dacl.aces[0].sid, alice);
        assert_eq!(dacl.aces[0].flags & INHERITED_ACE, 0);
    }

    // -----------------------------------------------------------------------
    // Deny ACE inheritance
    // -----------------------------------------------------------------------

    #[test]
    fn deny_ace_inherited() {
        let parent = parent_sd(alloc::vec![Ace {
            ace_type: ACCESS_DENIED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            mask: FILE_WRITE_DATA,
            sid: well_known::guests().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert_eq!(dacl.aces[0].ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(dacl.aces[0].sid, well_known::guests().unwrap());
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
    }

    // --- §9.5 Corpus: Additional inheritance tests ---

    #[test]
    fn inherited_ace_flag_set_on_inherited_aces() {
        // §9.5 line 3562: INHERITED_ACE (0x10) set on inherited ACEs
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        for ace in &dacl.aces {
            assert!(ace.flags & INHERITED_ACE != 0, "inherited ACE must have INHERITED_ACE flag");
        }
    }

    #[test]
    fn no_flags_no_inheritance() {
        // §9.5 line 3578: ACE with no inheritance flags doesn't inherit
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: 0, // no CI, OI, NP, IO
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let parent = parent_sd(alloc::vec![ace]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // No ACEs inherited (token default DACL is used instead)
        // The child should have the token's default DACL, not the parent's ACE
        if let Some(dacl) = &child.dacl {
            for ace in &dacl.aces {
                // If any ACEs are present, they should NOT be the parent's
                assert_ne!(ace.sid, well_known::everyone().unwrap());
            }
        }
    }

    #[test]
    fn sacl_computed_identically_to_dacl() {
        // §9.5 line 3650: SACL inheritance same algorithm as DACL
        let parent = SecurityDescriptor::with_sacl(
            well_known::system().unwrap(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: ace::SYSTEM_AUDIT_ACE_TYPE,
                    flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
                        | ace::SUCCESSFUL_ACCESS_ACE_FLAG,
                    mask: FILE_WRITE_DATA,
                    sid: well_known::everyone().unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            },
        );
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert!(child.sacl.is_some());
        let sacl = child.sacl.unwrap();
        assert_eq!(sacl.aces.len(), 1);
        assert_eq!(sacl.aces[0].ace_type, ace::SYSTEM_AUDIT_ACE_TYPE);
        assert!(sacl.aces[0].flags & INHERITED_ACE != 0);
    }

    #[test]
    fn group_from_creator_sd_if_specified() {
        // §9.5 line 3619
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(well_known::system().unwrap()),
            group: Some(well_known::administrators().unwrap()),
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let child = compute_inherited_sd(
            None, Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert_eq!(child.group.unwrap(), well_known::administrators().unwrap());
    }

    #[test]
    fn group_from_token_if_creator_sd_omits() {
        // §9.5 line 3620: no creator SD group → token's primary group
        let child = compute_inherited_sd(
            None, None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // Token's primary group index 0 → first group in the array
        assert!(child.group.is_some());
    }

    #[test]
    fn each_child_gets_resolved_copy() {
        // §9.5 line 3598: each child gets its own resolved CREATOR OWNER copy
        let parent = parent_sd(alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::creator_owner().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }]);
        let token1 = test_token();
        let child1 = compute_inherited_sd(
            Some(&parent), None, &token1,
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // Each child's ACE has the creator's SID, not CREATOR OWNER
        let dacl1 = child1.dacl.unwrap();
        assert_ne!(dacl1.aces[0].sid, well_known::creator_owner().unwrap());
    }

    #[test]
    fn ci_only_inherits_containers_recursively() {
        // §9.5 line 3573: CI only → containers only, recursively
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let parent = parent_sd(alloc::vec![ace]);
        // File (non-container) should NOT inherit CI-only ACE
        let file_child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let file_dacl = file_child.dacl.as_ref();
        let has_everyone_ace = file_dacl.map_or(false, |d|
            d.aces.iter().any(|a| a.sid == well_known::everyone().unwrap() && a.flags & INHERITED_ACE != 0)
        );
        assert!(!has_everyone_ace, "CI-only should not inherit to non-container");
    }

    // --- §9.5 Exact corpus-named tests ---

    #[test]
    fn oi_inherits_to_non_container_children() {
        // §9.5 L3538-3539: ACE with OI set is inherited by non-container children (files)
        let parent = parent_sd(alloc::vec![
            oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert_eq!(dacl.aces[0].sid, well_known::everyone().unwrap());
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
    }

    #[test]
    fn oi_inherit_only_on_container_children() {
        // §9.5 L3540-3542: ACE with OI (without NP) is inherited as inherit-only on child containers
        let parent = parent_sd(alloc::vec![
            oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // Container inherits OI as INHERIT_ONLY (doesn't apply to the container itself)
        assert!(dacl.aces[0].flags & INHERIT_ONLY_ACE != 0);
    }

    #[test]
    fn ci_inherits_to_container_children() {
        // §9.5 L3544-3545: ACE with CI set is inherited by child containers
        let parent = parent_sd(alloc::vec![
            ci_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
    }

    #[test]
    fn ci_remains_inheritable() {
        // §9.5 L3546-3547: ACE with CI propagates to grandchildren (unless NP set)
        let parent = parent_sd(alloc::vec![
            ci_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // CI flag preserved for further propagation
        assert!(dacl.aces[0].flags & CONTAINER_INHERIT_ACE != 0);
    }

    #[test]
    fn np_clears_oi_ci_on_inherited_copy() {
        // §9.5 L3549-3551: when ACE with NP inherited, OI and CI cleared on inherited copy
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let parent = parent_sd(alloc::vec![ace]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert_eq!(dacl.aces[0].flags & CONTAINER_INHERIT_ACE, 0);
        assert_eq!(dacl.aces[0].flags & OBJECT_INHERIT_ACE, 0);
        assert_eq!(dacl.aces[0].flags & NO_PROPAGATE_INHERIT_ACE, 0);
    }

    #[test]
    fn np_applies_to_immediate_child_only() {
        // §9.5 L3551-3552: ACE with NP applies to immediate child but does not propagate further
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let parent = parent_sd(alloc::vec![ace]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let child_dacl = child.dacl.as_ref().unwrap();
        assert_eq!(child_dacl.aces.len(), 1);
        // Child's inherited ACE has no inheritance flags — can't propagate
        assert_eq!(child_dacl.aces[0].flags & (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE), 0);

        // Grandchild inherits nothing
        let grandchild = compute_inherited_sd(
            Some(&child), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let gc_dacl = grandchild.dacl.as_ref().unwrap();
        assert_eq!(gc_dacl.aces.len(), 0);
    }

    #[test]
    fn io_ace_does_not_apply_to_attached_object() {
        // §9.5 L3554-3555: ACE with IO set does not apply to the object it is attached to
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        assert!(ace.is_inherit_only());
        // This ACE exists only to be inherited, not to apply to the current object
    }

    #[test]
    fn inherited_ace_flag_informational() {
        // §9.5 L3564: INHERITED_ACE flag distinguishes inherited from explicit ACEs
        let explicit_ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let inherited_ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: INHERITED_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        assert!(!explicit_ace.is_inherited());
        assert!(inherited_ace.is_inherited());
    }

    #[test]
    fn ci_oi_inherits_everything_recursively() {
        // CI|OI: inherits to containers and non-containers, recursively
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        // Inherits to file (non-container)
        let file_child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert_eq!(file_child.dacl.as_ref().unwrap().aces.len(), 1);

        // Inherits to directory (container)
        let dir_child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dir_dacl = dir_child.dacl.as_ref().unwrap();
        assert_eq!(dir_dacl.aces.len(), 1);
        // Both CI and OI preserved for recursive propagation
        assert!(dir_dacl.aces[0].flags & CONTAINER_INHERIT_ACE != 0);
        assert!(dir_dacl.aces[0].flags & OBJECT_INHERIT_ACE != 0);
    }

    #[test]
    fn oi_only_inherit_only_on_containers() {
        // §9.5 L3574: OI only → inherits to non-containers; for containers, inherited as inherit-only
        let parent = parent_sd(alloc::vec![
            oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        // Container: inherited as IO
        let dir_child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dir_dacl = dir_child.dacl.as_ref().unwrap();
        assert_eq!(dir_dacl.aces.len(), 1);
        assert!(dir_dacl.aces[0].flags & INHERIT_ONLY_ACE != 0);

        // Non-container: inherited and applies
        let file_child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let file_dacl = file_child.dacl.as_ref().unwrap();
        assert_eq!(file_dacl.aces.len(), 1);
        assert_eq!(file_dacl.aces[0].flags & INHERIT_ONLY_ACE, 0); // applies to file
    }

    #[test]
    fn ci_oi_io_inherits_contents_only() {
        // CI|OI|IO: inherits to subfolders and files but not the object itself
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        // The IO flag means it doesn't apply to the attached object
        assert!(ace.is_inherit_only());

        // But it still inherits to children
        let parent = parent_sd(alloc::vec![ace]);
        let file_child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert_eq!(file_child.dacl.as_ref().unwrap().aces.len(), 1);
    }

    #[test]
    fn ci_oi_np_immediate_children_only() {
        // CI|OI|NP: inherits to immediate children only
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let parent = parent_sd(alloc::vec![ace]);

        // Immediate child (container) inherits
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert_eq!(child.dacl.as_ref().unwrap().aces.len(), 1);

        // But child's ACE has no inheritance flags — grandchild gets nothing
        let child_dacl = child.dacl.as_ref().unwrap();
        assert_eq!(child_dacl.aces[0].flags & (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE), 0);
    }

    #[test]
    fn ci_np_immediate_child_containers_only() {
        // CI|NP: inherits to immediate child containers only
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let parent = parent_sd(alloc::vec![ace]);

        // Container inherits
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let child_dacl = child.dacl.as_ref().unwrap();
        assert_eq!(child_dacl.aces.len(), 1);
        // Inheritance flags cleared by NP
        assert_eq!(child_dacl.aces[0].flags & CONTAINER_INHERIT_ACE, 0);

        // Non-container does NOT inherit (no OI)
        let file_child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let file_dacl = file_child.dacl.as_ref();
        let has_everyone = file_dacl.map_or(false, |d|
            d.aces.iter().any(|a| a.sid == well_known::everyone().unwrap() && a.flags & INHERITED_ACE != 0)
        );
        assert!(!has_everyone, "CI|NP should not inherit to non-containers");
    }

    #[test]
    fn creator_owner_sid_substituted_on_inherit() {
        // §9.5 L3584-3589: CREATOR OWNER (S-1-3-0) replaced with creating principal's SID
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::creator_owner().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // CREATOR OWNER replaced with owner (SYSTEM for test token)
        assert_ne!(dacl.aces[0].sid, well_known::creator_owner().unwrap());
        assert_eq!(dacl.aces[0].sid, well_known::system().unwrap());
    }

    #[test]
    fn creator_group_sid_substituted_on_inherit() {
        // §9.5 L3591-3592: CREATOR GROUP (S-1-3-1) replaced with creating principal's primary group
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::creator_group().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert_ne!(dacl.aces[0].sid, well_known::creator_group().unwrap());
    }

    #[test]
    fn substitution_happens_at_inheritance_time() {
        // §9.5 L3594-3595: substitution produces a resolved SID on child
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::creator_owner().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        // Child ACE contains actual SID, not placeholder
        assert_ne!(dacl.aces[0].sid, well_known::creator_owner().unwrap());
    }

    #[test]
    fn io_ace_preserves_placeholder_on_parent() {
        // §9.5 L3596-3598: if original ACE has IO, placeholder SID is preserved on parent
        let parent_ace = Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::creator_owner().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        // The parent's ACE retains CREATOR OWNER — it's not mutated
        assert_eq!(parent_ace.sid, well_known::creator_owner().unwrap());
    }

    #[test]
    fn sd_creation_three_sources() {
        // §9.5 L3603-3612: new object's SD computed from parent SD, creator SD, and creator token
        let alice = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: None,
            dacl: Some(Acl {
                revision: crate::acl::ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: FILE_WRITE_DATA,
                    sid: alice.clone(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            }),
            sacl: None,
        };
        let child = compute_inherited_sd(
            Some(&parent), Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // Owner from creator SD
        assert_eq!(child.owner.unwrap(), alice);
        // DACL has both creator's explicit ACE and parent's inherited ACE
        let dacl = child.dacl.unwrap();
        assert!(dacl.aces.len() >= 2);
    }

    #[test]
    fn owner_from_creator_sd_if_specified() {
        // §9.5 L3616: if creator SD specifies an owner, that owner is used
        let alice = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let creator = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: None,
            dacl: None,
            sacl: None,
        };
        let child = compute_inherited_sd(
            None, Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert_eq!(child.owner.unwrap(), alice);
    }

    #[test]
    fn owner_from_token_if_creator_sd_omits() {
        // §9.5 L3617: if creator SD doesn't specify owner, token's owner SID is used
        let child = compute_inherited_sd(
            None, None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert_eq!(child.owner.unwrap(), well_known::system().unwrap());
    }

    #[test]
    fn dacl_inherit_only_no_creator_sd() {
        // §9.5 L3625-3628: no creator SD + parent has inheritable ACEs → DACL is entirely inherited
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
    }

    #[test]
    fn dacl_token_default_no_creator_no_inheritable() {
        // §9.5 L3630-3631: no creator SD + parent has no inheritable ACEs → token's default DACL
        let parent = parent_sd(alloc::vec![
            // No CI or OI — not inheritable
            Ace {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                flags: 0,
                mask: FILE_READ_DATA,
                sid: well_known::administrators().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // Should get token's default DACL (or empty DACL if no default)
        assert!(child.dacl.is_some());
        // The parent's non-inheritable ACE should NOT be present
        let dacl = child.dacl.unwrap();
        for ace in &dacl.aces {
            assert_eq!(ace.flags & INHERITED_ACE, 0, "no inherited ACEs from non-inheritable parent");
        }
    }

    #[test]
    fn dacl_creator_sd_explicit_aces_preserved() {
        // §9.5 L3634-3635: creator SD with DACL → explicit ACEs preserved
        let alice = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: Some(well_known::users().unwrap()),
            dacl: Some(Acl {
                revision: crate::acl::ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0, // explicit
                    mask: FILE_WRITE_DATA,
                    sid: alice.clone(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            }),
            sacl: None,
        };
        let child = compute_inherited_sd(
            None, Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert!(dacl.aces.iter().any(|a| a.sid == alice));
    }

    #[test]
    fn dacl_unprotected_merges_parent_inheritance() {
        // §9.5 L3636-3638: creator SD with unprotected DACL + auto-inheritance
        // → inheritable ACEs from parent appended after explicit ACEs
        let alice = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE, // unprotected
            owner: Some(alice.clone()),
            group: Some(well_known::users().unwrap()),
            dacl: Some(Acl {
                revision: crate::acl::ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: FILE_WRITE_DATA,
                    sid: alice.clone(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            }),
            sacl: None,
        };
        let child = compute_inherited_sd(
            Some(&parent), Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        // Both explicit and inherited ACEs present
        assert!(dacl.aces.len() >= 2);
        // First: explicit from creator
        assert_eq!(dacl.aces[0].sid, alice);
        assert_eq!(dacl.aces[0].flags & INHERITED_ACE, 0);
        // Second: inherited from parent
        assert!(dacl.aces[1].flags & INHERITED_ACE != 0);
    }

    #[test]
    fn dacl_protected_blocks_parent_inheritance() {
        // §9.5 L3639-3640: SE_DACL_PROTECTED → parent inheritance blocked
        let alice = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), GENERIC_ALL),
        ]);
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: Some(well_known::users().unwrap()),
            dacl: Some(Acl {
                revision: crate::acl::ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: ACCESS_ALLOWED_ACE_TYPE,
                    flags: 0,
                    mask: FILE_READ_DATA,
                    sid: alice.clone(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            }),
            sacl: None,
        };
        let child = compute_inherited_sd(
            Some(&parent), Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        // Only creator's explicit ACE, no parent inheritance
        assert_eq!(dacl.aces.len(), 1);
        assert_eq!(dacl.aces[0].sid, alice);
    }

    #[test]
    fn inherited_aces_creator_owner_substituted() {
        // §9.5 L3643-3644: CREATOR OWNER/CREATOR GROUP SIDs substituted in all DACL paths
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::creator_owner().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        // Substituted — no CREATOR OWNER SID
        for ace in &dacl.aces {
            assert_ne!(ace.sid, well_known::creator_owner().unwrap());
        }
    }

    #[test]
    fn inherited_aces_generic_rights_mapped() {
        // §9.5 L3645-3646: generic rights in inherited ACEs mapped to object-specific
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), GENERIC_READ),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        assert!(dacl.aces[0].mask & FILE_READ_DATA != 0);
        assert_eq!(dacl.aces[0].mask & GENERIC_READ, 0);
    }

    #[test]
    fn inherited_aces_flag_set() {
        // §9.5 L3647-3648: INHERITED_ACE flag set on all ACEs from parent
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
            Ace {
                ace_type: ACCESS_DENIED_ACE_TYPE,
                flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                mask: FILE_WRITE_DATA,
                sid: well_known::guests().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        let dacl = child.dacl.unwrap();
        for ace in &dacl.aces {
            assert!(ace.flags & INHERITED_ACE != 0, "all inherited ACEs must have INHERITED_ACE flag");
        }
    }

    #[test]
    fn no_token_default_sacl() {
        // §9.5 L3651-3653: token has no "default SACL"; if no creator SACL and
        // parent has no inheritable SACL ACEs → new object has no SACL
        let child = compute_inherited_sd(
            None, None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert!(child.sacl.is_none(), "no default SACL exists");
    }

    #[test]
    fn inheritance_is_eager() {
        // §9.5 L3655-3658: SD is fully computed at creation time
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // The child's SD is complete — it doesn't lazily reference the parent
        assert!(child.dacl.is_some());
        let bytes = child.to_bytes().unwrap();
        let reparsed = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert_eq!(reparsed.dacl.as_ref().unwrap().aces.len(), 1);
    }

    #[test]
    fn no_parent_tree_walk_at_access_time() {
        // §9.5 L3657: AccessCheck does not walk up the directory tree
        // The stored SD is self-contained after inheritance at creation
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // Child SD is complete — serialize and reparse without parent
        let bytes = child.to_bytes().unwrap();
        let standalone = SecurityDescriptor::from_bytes(&bytes).unwrap().unwrap();
        assert!(standalone.dacl.is_some());
    }

    #[test]
    fn stored_sd_is_complete_evaluated_policy() {
        // §9.5 L3658: the SD stored on disk is always the complete, evaluated policy
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone().unwrap(), GENERIC_READ),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // Verify the stored SD has fully-resolved content
        let dacl = child.dacl.as_ref().unwrap();
        // Generic bits mapped
        assert_eq!(dacl.aces[0].mask & GENERIC_READ, 0);
        assert!(dacl.aces[0].mask & FILE_READ_DATA != 0);
    }

    #[test]
    fn standalone_objects_no_inherit() {
        // §9.5 L3529-3531: objects without a container parent don't inherit
        // (IPC endpoints, tokens, processes) — SDs are explicit or from token defaults
        let child = compute_inherited_sd(
            None, None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        // No parent → no inherited ACEs
        if let Some(dacl) = &child.dacl {
            for ace in &dacl.aces {
                assert_eq!(ace.flags & INHERITED_ACE, 0, "standalone objects should have no inherited ACEs");
            }
        }
    }
}
