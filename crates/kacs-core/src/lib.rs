//! Fresh slow-track KACS semantic core.
//!
//! The previous fast-track implementation was intentionally removed from this
//! worktree. New modules should be added slice by slice against the ratified
//! spec baseline.

#![cfg_attr(feature = "kernel", no_std)]

extern crate alloc;

mod access_mask;
mod ace;
mod acl;
mod claims;
mod condition;
mod dacl;
mod error;
mod mic;
mod object_tree;
mod privilege;
mod security_descriptor;
mod sid;
mod token;

pub use access_mask::{
    validate_ace_mask, GenericMapping, NormalizedDesiredAccess, ACCESS_SYSTEM_SECURITY, DELETE,
    GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, MAXIMUM_ALLOWED, READ_CONTROL,
    SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
pub use ace::{
    Ace, AceKind, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
    ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
};
pub use acl::Acl;
pub use claims::{
    ClaimAttribute, ClaimValue, CLAIM_SECURITY_ATTRIBUTE_DISABLED,
    CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY, CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE,
};
pub use condition::{evaluate_conditional_expression, ConditionalContext, ConditionalResult};
pub use dacl::{
    evaluate_dacl, evaluate_dacl_result_list, evaluate_dacl_result_list_with_confinement_context,
    evaluate_dacl_result_list_with_context, evaluate_dacl_result_list_with_restricted_context,
    evaluate_dacl_with_confinement_context, evaluate_dacl_with_context,
    evaluate_dacl_with_object_tree, evaluate_dacl_with_object_tree_and_context,
    evaluate_dacl_with_restricted_context, evaluate_dacl_with_self_sid, AccessStatus,
    DaclEvaluation, ObjectDaclResultList,
};
pub use error::{KacsError, KacsResult};
pub use mic::{
    apply_mic, resolve_mandatory_label, IntegrityLevel, MandatoryLabel, MicEnforcementState,
    SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, SYSTEM_MANDATORY_LABEL_NO_READ_UP,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
};
pub use object_tree::{ObjectTypeList, ObjectTypeNode};
pub use privilege::{
    apply_take_ownership_fallback, seed_access_check_privileges, AccessDecisionState,
    PrivilegeGrantState, PrivilegeProvenance, TokenPrivileges, BACKUP_INTENT, RESTORE_INTENT,
    SE_BACKUP_PRIVILEGE, SE_RELABEL_PRIVILEGE, SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE,
    SE_TAKE_OWNERSHIP_PRIVILEGE,
};
pub use security_descriptor::{
    SecurityDescriptor, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
};
pub use sid::{Sid, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};
pub use token::{
    ConfinementTokenContext, IdentityView, RestrictedTokenContext, SidAndAttributes, TokenView,
};
