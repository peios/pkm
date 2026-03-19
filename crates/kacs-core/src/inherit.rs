// SD Inheritance algorithm (§9.5).
//
// Computes the Security Descriptor for a newly created object from:
//   1. Parent SD — provides inheritable ACEs
//   2. Creator SD (optional) — explicit SD provided by the caller
//   3. Creator token — provides default owner, group, and DACL
//
// Follows MS-DTYP §2.5.3.4 (CreateSecurityDescriptor).

use alloc::vec::Vec;
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
    Container,
    NonContainer,
}

/// Compute the SD for a newly created object (§9.5).
///
/// `parent_sd`: SD of the container the object is created in (None if no parent).
/// `creator_sd`: explicit SD provided by the caller (None = use defaults).
/// `token`: the creating thread's effective token.
/// `object_class`: Container or NonContainer.
/// `mapping`: GenericMapping for the new object's type.
pub fn compute_inherited_sd(
    parent_sd: Option<&SecurityDescriptor>,
    creator_sd: Option<&SecurityDescriptor>,
    token: &Token,
    object_class: ObjectClass,
    mapping: &GenericMapping,
) -> SecurityDescriptor {
    // --- Owner ---
    let owner = if let Some(ref csd) = creator_sd {
        csd.owner.clone()
    } else {
        None
    }
    .unwrap_or_else(|| owner_from_token(token));

    // --- Group ---
    let group = if let Some(ref csd) = creator_sd {
        csd.group.clone()
    } else {
        None
    }
    .unwrap_or_else(|| group_from_token(token));

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
    );

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
    );

    let mut control = SE_SELF_RELATIVE;
    if dacl.is_some() {
        control |= SE_DACL_PRESENT;
    }
    if sacl.is_some() {
        control |= SE_SACL_PRESENT;
    }

    SecurityDescriptor {
        control,
        owner: Some(owner),
        group: Some(group),
        dacl,
        sacl,
    }
}

/// Get the owner SID from the token (token's owner_sid_index).
fn owner_from_token(token: &Token) -> Sid {
    if token.owner_sid_index == 0 {
        token.user_sid.clone()
    } else {
        let group_idx = (token.owner_sid_index - 1) as usize;
        if group_idx < token.groups.len() {
            token.groups[group_idx].sid.clone()
        } else {
            token.user_sid.clone()
        }
    }
}

/// Get the primary group SID from the token.
fn group_from_token(token: &Token) -> Sid {
    if token.primary_group_index == 0 {
        token.user_sid.clone()
    } else {
        let group_idx = (token.primary_group_index - 1) as usize;
        if group_idx < token.groups.len() {
            token.groups[group_idx].sid.clone()
        } else {
            token.user_sid.clone()
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
) -> Option<Acl> {
    if creator_present && creator_protected {
        // Creator supplied a protected ACL — use it as-is, no parent inheritance
        return creator_acl.cloned();
    }

    if creator_present {
        // Creator supplied an unprotected ACL — keep explicit ACEs,
        // append inheritable ACEs from parent
        let mut aces = Vec::new();

        // Explicit ACEs from creator (those without INHERITED_ACE flag)
        if let Some(cacl) = creator_acl {
            for a in &cacl.aces {
                if a.flags & ace::INHERITED_ACE == 0 {
                    let mut ace = a.clone();
                    post_process_ace(&mut ace, owner, group, mapping);
                    aces.push(ace);
                }
            }
        }

        // Inheritable ACEs from parent
        if let Some(pacl) = parent_acl {
            let inherited = inherit_aces_from_parent(pacl, owner, group, object_class, mapping);
            aces.extend(inherited);
        }

        if aces.is_empty() && !creator_present {
            return None;
        }

        return Some(Acl::with_aces(aces));
    }

    // No creator ACL supplied
    if let Some(pacl) = parent_acl {
        let inherited = inherit_aces_from_parent(pacl, owner, group, object_class, mapping);
        if !inherited.is_empty() {
            return Some(Acl::with_aces(inherited));
        }
    }

    // No parent inheritance — use token's default DACL
    if is_dacl {
        // Token's default_dacl would go here. For now, return an empty DACL.
        // TODO: use token.default_dacl when it's modeled
        Some(Acl::new(ACL_REVISION))
    } else {
        // No default SACL
        None
    }
}

/// Inherit ACEs from a parent ACL for the given object class.
fn inherit_aces_from_parent(
    parent_acl: &Acl,
    owner: &Sid,
    group: &Sid,
    object_class: ObjectClass,
    mapping: &GenericMapping,
) -> Vec<Ace> {
    let mut result = Vec::new();
    let is_container = object_class == ObjectClass::Container;

    for parent_ace in &parent_acl.aces {
        let ci = parent_ace.flags & ace::CONTAINER_INHERIT_ACE != 0;
        let oi = parent_ace.flags & ace::OBJECT_INHERIT_ACE != 0;
        let np = parent_ace.flags & ace::NO_PROPAGATE_INHERIT_ACE != 0;
        let io = parent_ace.flags & ace::INHERIT_ONLY_ACE != 0;

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

        let mut new_ace = parent_ace.clone();

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
        substitute_creator_sids(&mut new_ace, owner, group);

        // Map generic bits in inherited ACE (Peios preserves generics on IO ACEs)
        if new_ace.flags & ace::INHERIT_ONLY_ACE == 0 {
            new_ace.mask = crate::mask::map_generic_bits(new_ace.mask, mapping);
        }

        result.push(new_ace);
    }

    result
}

/// Replace CREATOR OWNER (S-1-3-0) and CREATOR GROUP (S-1-3-1)
/// with the actual owner and group SIDs.
fn substitute_creator_sids(ace: &mut Ace, owner: &Sid, group: &Sid) {
    if ace.sid == well_known::creator_owner() {
        ace.sid = owner.clone();
    } else if ace.sid == well_known::creator_group() {
        ace.sid = group.clone();
    }
}

/// Post-process an explicit ACE from the creator SD.
fn post_process_ace(ace: &mut Ace, owner: &Sid, group: &Sid, mapping: &GenericMapping) {
    substitute_creator_sids(ace, owner, group);
    if ace.flags & ace::INHERIT_ONLY_ACE == 0 {
        ace.mask = crate::mask::map_generic_bits(ace.mask, mapping);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ace::*;
    use crate::mask::*;

    fn test_token() -> Token {
        Token::system_token()
    }

    fn parent_sd(aces: Vec<Ace>) -> SecurityDescriptor {
        SecurityDescriptor::new(
            well_known::system(),
            well_known::system(),
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
            oi_allow(&well_known::everyone(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert_eq!(dacl.aces[0].sid, well_known::everyone());
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
        // Non-container: inheritance flags cleared
        assert_eq!(dacl.aces[0].flags & OBJECT_INHERIT_ACE, 0);
    }

    #[test]
    fn file_does_not_inherit_ci_ace() {
        let parent = parent_sd(alloc::vec![
            ci_allow(&well_known::everyone(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 0); // CI doesn't apply to files
    }

    #[test]
    fn dir_inherits_ci_ace() {
        let parent = parent_sd(alloc::vec![
            ci_allow(&well_known::everyone(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING,
        );
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
        // CI preserved for further propagation
        assert!(dacl.aces[0].flags & CONTAINER_INHERIT_ACE != 0);
    }

    #[test]
    fn dir_inherits_ci_oi_ace() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING,
        );
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
            ci_oi_allow(&well_known::everyone(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
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
            sid: well_known::everyone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        };
        let parent = parent_sd(alloc::vec![ace]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING,
        );
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
            oi_allow(&well_known::everyone(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING,
        );
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
            ci_oi_allow(&well_known::creator_owner(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // CREATOR OWNER replaced with the owner (SYSTEM for our test token)
        assert_eq!(dacl.aces[0].sid, well_known::system());
    }

    #[test]
    fn creator_group_substituted() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::creator_group(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        // CREATOR GROUP replaced with the group (SYSTEM for our test token)
        assert_eq!(dacl.aces[0].sid, well_known::system());
    }

    // -----------------------------------------------------------------------
    // Protected DACL
    // -----------------------------------------------------------------------

    #[test]
    fn protected_dacl_blocks_inheritance() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone(), GENERIC_ALL),
        ]);
        let alice = Sid::new(5, &[21, 100, 200, 300, 1001]);
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: Some(well_known::users()),
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
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
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
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
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
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        // SYSTEM token's owner is user_sid (S-1-5-18)
        assert_eq!(child.owner.unwrap(), well_known::system());
    }

    #[test]
    fn owner_from_creator_sd() {
        let alice = Sid::new(5, &[21, 100, 200, 300, 1001]);
        let creator = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: None,
            dacl: None,
            sacl: None,
        };
        let child = compute_inherited_sd(
            None, Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        assert_eq!(child.owner.unwrap(), alice);
    }

    // -----------------------------------------------------------------------
    // Generic bits mapped on non-IO inherited ACEs
    // -----------------------------------------------------------------------

    #[test]
    fn generic_bits_mapped_on_inherited_ace() {
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone(), GENERIC_READ),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
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
            sid: well_known::everyone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING,
        );
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
            ci_oi_allow(&well_known::administrators(), GENERIC_ALL),
            ci_oi_allow(&well_known::everyone(), FILE_READ_DATA | READ_CONTROL),
            Ace {
                ace_type: ACCESS_DENIED_ACE_TYPE,
                flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                mask: FILE_WRITE_DATA,
                sid: well_known::guests(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
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
                sid: well_known::administrators(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
            ci_oi_allow(&well_known::everyone(), FILE_READ_DATA),
        ]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1); // only the CI|OI one
        assert_eq!(dacl.aces[0].sid, well_known::everyone());
    }

    // -----------------------------------------------------------------------
    // Creator SD with parent inheritance
    // -----------------------------------------------------------------------

    #[test]
    fn creator_explicit_plus_parent_inherited() {
        let alice = Sid::new(5, &[21, 100, 200, 300, 1001]);
        let parent = parent_sd(alloc::vec![
            ci_oi_allow(&well_known::everyone(), FILE_READ_DATA),
        ]);
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: Some(well_known::users()),
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
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 2);
        // First: explicit from creator
        assert_eq!(dacl.aces[0].sid, alice);
        assert_eq!(dacl.aces[0].flags & INHERITED_ACE, 0);
        // Second: inherited from parent
        assert_eq!(dacl.aces[1].sid, well_known::everyone());
        assert!(dacl.aces[1].flags & INHERITED_ACE != 0);
    }

    // -----------------------------------------------------------------------
    // SACL inheritance
    // -----------------------------------------------------------------------

    #[test]
    fn sacl_inherited_from_parent() {
        let parent = SecurityDescriptor::with_sacl(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: SYSTEM_AUDIT_ACE_TYPE,
                    flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
                        | SUCCESSFUL_ACCESS_ACE_FLAG,
                    mask: FILE_WRITE_DATA,
                    sid: well_known::everyone(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            },
        );
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        assert!(child.sacl.is_some());
        let sacl = child.sacl.unwrap();
        assert_eq!(sacl.aces.len(), 1);
        assert_eq!(sacl.aces[0].ace_type, SYSTEM_AUDIT_ACE_TYPE);
        assert!(sacl.aces[0].flags & INHERITED_ACE != 0);
    }

    #[test]
    fn sacl_not_inherited_without_flags() {
        let parent = SecurityDescriptor::with_sacl(
            well_known::system(),
            well_known::system(),
            Acl::new(ACL_REVISION),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![Ace {
                    ace_type: SYSTEM_AUDIT_ACE_TYPE,
                    flags: SUCCESSFUL_ACCESS_ACE_FLAG, // no CI/OI
                    mask: FILE_WRITE_DATA,
                    sid: well_known::everyone(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                }],
            },
        );
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
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
            ci_oi_allow(&well_known::everyone(), FILE_READ_DATA),
        ]);

        // First generation: child directory
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING,
        );
        let child_dacl = child.dacl.as_ref().unwrap();
        assert_eq!(child_dacl.aces.len(), 1);
        // CI|OI should still be present for further propagation
        assert!(child_dacl.aces[0].flags & CONTAINER_INHERIT_ACE != 0);
        assert!(child_dacl.aces[0].flags & OBJECT_INHERIT_ACE != 0);

        // Second generation: grandchild file
        let grandchild = compute_inherited_sd(
            Some(&child), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        let gc_dacl = grandchild.dacl.as_ref().unwrap();
        assert_eq!(gc_dacl.aces.len(), 1);
        assert_eq!(gc_dacl.aces[0].sid, well_known::everyone());
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
            sid: well_known::everyone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }]);

        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::Container, &FILE_GENERIC_MAPPING,
        );
        let child_dacl = child.dacl.as_ref().unwrap();
        assert_eq!(child_dacl.aces.len(), 1);
        // NP cleared all inheritance flags — can't propagate
        assert_eq!(child_dacl.aces[0].flags & (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
            | NO_PROPAGATE_INHERIT_ACE), 0);

        // Grandchild: nothing inherited (child's ACE has no inheritance flags)
        let grandchild = compute_inherited_sd(
            Some(&child), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
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
        let alice = Sid::new(5, &[21, 100, 200, 300, 1001]);
        let creator = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(alice.clone()),
            group: Some(well_known::users()),
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
                        sid: well_known::everyone(),
                        object_type: None, inherited_object_type: None,
                        condition: None, application_data: None,
                    },
                ],
            }),
            sacl: None,
        };
        let child = compute_inherited_sd(
            None, Some(&creator), &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
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
            sid: well_known::guests(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }]);
        let child = compute_inherited_sd(
            Some(&parent), None, &test_token(),
            ObjectClass::NonContainer, &FILE_GENERIC_MAPPING,
        );
        let dacl = child.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 1);
        assert_eq!(dacl.aces[0].ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(dacl.aces[0].sid, well_known::guests());
        assert!(dacl.aces[0].flags & INHERITED_ACE != 0);
    }
}
