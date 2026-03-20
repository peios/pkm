// Central Access Policy (§11.16).
//
// Policies are defined centrally and referenced by objects via
// SYSTEM_SCOPED_POLICY_ID_ACEs in their SACL. AccessCheck evaluates
// each referenced policy's rules and AND-intersects with the normal
// DACL result. CAP can only further restrict — never expand.

use crate::compat::{self, AllocError, Vec};
use crate::acl::Acl;
use crate::sid::Sid;

/// A single rule within a Central Access Policy.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct CentralAccessRule {
    /// Conditional expression that determines which objects this rule
    /// governs, based on resource attributes. None = applies to all.
    pub applies_to: Option<Vec<u8>>,
    /// The mandatory access rules. A real DACL evaluated by the full pipeline.
    pub effective_dacl: Acl,
    /// Optional proposed replacement for testing (§11.16 staging).
    pub staged_dacl: Option<Acl>,
}

/// A Central Access Policy — a named collection of rules.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct CentralAccessPolicy {
    /// The policy SID (matches the SYSTEM_SCOPED_POLICY_ID_ACE in the SACL).
    pub policy_sid: Sid,
    /// The rules in this policy.
    pub rules: Vec<CentralAccessRule>,
}

/// Recovery policy: used when a scoped policy SID is not found in the cache.
/// Grants GENERIC_ALL to owner (via OWNER RIGHTS), Administrators, and SYSTEM.
/// Safe because CAP is an AND-intersection — recovery policy does not widen
/// access beyond the object's own DACL.
pub fn recovery_policy() -> Result<Acl, AllocError> {
    use crate::ace::*;
    use crate::mask::*;
    use crate::well_known;

    let mut aces = Vec::new();
    compat::vec_push(&mut aces, Ace {
        ace_type: ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: GENERIC_ALL,
        sid: well_known::administrators()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;
    compat::vec_push(&mut aces, Ace {
        ace_type: ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: GENERIC_ALL,
        sid: well_known::system()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;
    compat::vec_push(&mut aces, Ace {
        ace_type: ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: GENERIC_ALL,
        sid: well_known::owner_rights()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;

    Ok(Acl {
        revision: crate::acl::ACL_REVISION,
        aces,
    })
}
