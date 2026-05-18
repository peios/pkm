//! Fresh slow-track KACS semantic core.
//!
//! The previous fast-track implementation was intentionally removed from this
//! worktree. New modules should be added slice by slice against the ratified
//! spec baseline.

#![cfg_attr(feature = "kernel", no_std)]
#![allow(unreachable_pub)]

/// AccessCheck orchestration, wrappers, and privilege-use audit accounting.
pub mod access_check;
/// Pure ABI parsing and execution shaping for AccessCheck entrypoints.
pub mod access_check_abi;
/// Access-mask constants and generic mapping helpers.
pub mod access_mask;
/// ACE type parsing and typed ACE representations.
pub mod ace;
/// ACL parsing and entry iteration.
pub mod acl;
/// SACL audit/alarm evaluation helpers.
pub mod audit;
/// Central Access Policy parsing, cache, and evaluation.
pub mod caap;
/// Claim attribute parsing and in-memory representations.
pub mod claims;
/// Conditional ACE bytecode evaluation.
pub mod condition;
/// DACL evaluation for scalar and object-tree modes.
pub mod dacl;
/// Shared error types for the slow-track semantic core.
pub mod error;
/// End-to-end security descriptor evaluation.
pub mod evaluate_sd;
/// Mandatory Integrity Control helpers.
pub mod mic;
/// Object-type tree parsing and traversal helpers.
pub mod object_tree;
/// Process trust label resolution and PIP enforcement.
pub mod pip;
/// PKM-owned fallible allocation wrappers.
pub mod pkm_alloc;
/// Pre-SACL orchestration for MIC, PIP, claims, and policy IDs.
pub mod pre_sacl;
/// Privilege seeding, provenance, and fallback helpers.
pub mod privilege;
/// SACL metadata extraction helpers.
pub mod sacl;
/// Self-relative security descriptor parsing.
pub mod security_descriptor;
/// SID parsing and SID attribute constants.
pub mod sid;
/// Token, restricted-token, and confinement-token views.
pub mod token;

/// Returns a stable value from the staged crate so kernel bring-up can prove the
/// real `kacs-core` module graph compiled and linked.
pub fn kernel_compile_probe() -> usize {
    access_check_abi::KACS_ACCESS_CHECK_ARGS_V1_SIZE as usize
}

pub use access_check::{
    access_check, access_check_core, access_check_result_list, AccessCheckCoreState,
    AccessCheckMode, AccessCheckResult, AccessCheckResultListState, CaapDiagnosticEvent,
    CaapDiagnosticKind, PrivilegeUseEvent,
};
pub use access_check_abi::{
    execute_access_check_abi, execute_access_check_list_abi, parse_access_check_abi_request,
    AccessCheckAbiExecution, AccessCheckAbiMemory, AccessCheckAbiRequest, AccessCheckAbiResolved,
    AccessCheckAbiReturn, KacsNodeResultAbi, OwnedAuditEvent, U32Writeback, KACS_ABI_EACCES,
    KACS_ACCESS_CHECK_ARGS_SIZE, KACS_ACCESS_CHECK_ARGS_V1_SIZE,
    KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN, KACS_OBJECT_TYPE_ENTRY_SIZE,
};
pub use access_mask::{
    validate_ace_mask, GenericMapping, NormalizedDesiredAccess, ACCESS_SYSTEM_SECURITY, DELETE,
    FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_EXECUTE, FILE_GENERIC_MAPPING, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_READ_EA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, MAXIMUM_ALLOWED, READ_CONTROL,
    SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
pub use ace::{
    minimum_acl_revision_for_ace_bytes, minimum_acl_revision_for_ace_slices,
    minimum_acl_revision_for_ace_type, minimum_acl_revision_with_source_floor_for_opaque, Ace,
    AceKind, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
    ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL_REVISION, ACL_REVISION_DS,
    SYSTEM_ALARM_ACE_TYPE, SYSTEM_ALARM_CALLBACK_ACE_TYPE, SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
};
pub use acl::Acl;
pub use audit::{evaluate_sacl, AuditEvent, EvaluateSaclState};
pub use caap::{
    evaluate_caap, parse_caap_policy_spec, CaapEvaluationState, CaapPolicy, CaapPolicyCache,
    CaapPolicyEntry, CaapRule, CaapSaclContribution, CaapSaclPhase, OwnedCaapPolicy,
    OwnedCaapPolicyEntry, OwnedCaapRule,
};
pub use claims::{
    parse_claim_attribute_array, parse_claim_attribute_entry, ClaimAttribute, ClaimValue,
    CLAIM_SECURITY_ATTRIBUTE_DISABLED, CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY,
    CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE, CLAIM_TYPE_BOOLEAN, CLAIM_TYPE_INT64,
    CLAIM_TYPE_OCTET, CLAIM_TYPE_SID, CLAIM_TYPE_STRING, CLAIM_TYPE_UINT64,
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
pub use evaluate_sd::{evaluate_security_descriptor, EvaluateSecurityDescriptorState};
pub use mic::{
    apply_mic, resolve_mandatory_label, IntegrityLevel, MandatoryLabel, MicEnforcementState,
    SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, SYSTEM_MANDATORY_LABEL_NO_READ_UP,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
};
pub use object_tree::{ObjectTypeList, ObjectTypeNode};
pub use pip::{
    apply_pip, resolve_process_trust_label, PipContext, PipEnforcementState, ProcessTrustLabel,
};
pub use pkm_alloc::{
    slice_to_vec, vec_collect, AllocError, String as PkmString, TryClone, Vec as PkmVec,
};
pub use pre_sacl::{pre_sacl_walk, PreSaclWalkState};
pub use privilege::{
    apply_take_ownership_fallback, seed_access_check_privileges, AccessDecisionState,
    PrivilegeGrantState, PrivilegeProvenance, TokenPrivileges, BACKUP_INTENT, RESTORE_INTENT,
    SE_BACKUP_PRIVILEGE, SE_RELABEL_PRIVILEGE, SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE,
    SE_TAKE_OWNERSHIP_PRIVILEGE,
};
pub use sacl::{extract_sacl_metadata, SaclMetadata};
pub use security_descriptor::{
    SecurityDescriptor, MAX_SECURITY_DESCRIPTOR_BYTES, SE_DACL_AUTO_INHERITED,
    SE_DACL_AUTO_INHERIT_REQ, SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SE_DACL_TRUSTED, SE_GROUP_DEFAULTED, SE_OWNER_DEFAULTED, SE_RM_CONTROL_VALID,
    SE_SACL_AUTO_INHERITED, SE_SACL_AUTO_INHERIT_REQ, SE_SACL_DEFAULTED, SE_SACL_PRESENT,
    SE_SACL_PROTECTED, SE_SELF_RELATIVE, SE_SERVER_SECURITY,
};
pub use sid::{
    Sid, SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_INTEGRITY,
    SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_LOGON_ID, SE_GROUP_MANDATORY, SE_GROUP_OWNER,
    SE_GROUP_RESOURCE, SE_GROUP_USE_FOR_DENY_ONLY,
};
pub use token::{
    AccessCheckToken, ConfinementTokenContext, IdentityView, ImpersonationLevel,
    RestrictedTokenContext, SidAndAttributes, TokenType, TokenView,
    AUDIT_POLICY_OBJECT_ACCESS_FAILURE, AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
    AUDIT_POLICY_PRIVILEGE_USE_FAILURE, AUDIT_POLICY_PRIVILEGE_USE_SUCCESS,
};
