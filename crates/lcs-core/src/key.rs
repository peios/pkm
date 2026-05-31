use crate::access::{REGISTRY_GENERIC_MAPPING, registry_fd_has_right};
use crate::config::LcsLimits;
use crate::constants::{
    KEY_CREATE_LINK, KEY_CREATE_SUB_KEY, REG_CREATED_NEW, REG_OPENED_EXISTING,
    REG_OPTION_CREATE_LINK, REG_OPTION_VOLATILE, REG_VALID_MAPPED_ACCESS_MASK,
};
use crate::error::{LcsError, LcsResult};
use crate::key_path::{
    DerivedKeyPathMutation, TransactionKeyPathMutationLogEntry, validate_derived_key_path_mutation,
    validate_parent_watch_context_for_log,
};
use crate::path::{validate_key_component_bytes, validate_layer_name_bytes};
use crate::resolution::{
    Guid, PathEntryWriteRequest, PathTarget, ValidatedPathEntryWrite,
    validate_path_entry_write_request,
};
use crate::rsi::RsiStatus;
use crate::sequence::SequenceCounter;
use crate::source::NIL_GUID;
use crate::transaction::{TransactionMutationLogKind, TransactionOperationIndexCounter};
use crate::watch::WatchAncestryContext;

const REG_CREATE_KEY_KNOWN_FLAGS: u32 = REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK;

/// Parent identity recorded on a key object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyParent {
    HiveRoot,
    Parent(Guid),
}

/// Source-returned key record metadata after RSI copy-in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyRecordView<'a> {
    pub guid: Guid,
    pub name: &'a str,
    pub parent: KeyParent,
    pub volatile: bool,
    pub symlink: bool,
}

/// Parsed reg_create_key creation options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCreateOptions {
    pub volatile: bool,
    pub symlink: bool,
}

/// Pure key creation inputs after path resolution and parent AccessCheck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCreateRequest<'a> {
    pub parent_guid: Guid,
    pub parent_is_volatile: bool,
    pub parent_granted_access: u32,
    pub child_name: &'a str,
    pub child_guid: Guid,
    pub flags: u32,
    pub caller_has_tcb_or_admin: bool,
}

/// Candidate GUID and currently-active tracker for a new key before source dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyGuidAssignmentRequest<'a> {
    pub candidate_guid: Guid,
    pub active_key_guids: &'a [Guid],
}

/// LCS-assigned immutable GUID plan for a new key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyGuidAssignmentPlan {
    pub guid: Guid,
    pub assigned_by_lcs: bool,
    pub persist_in_key_record: bool,
}

/// Canonical path location for one non-root key GUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCanonicalPathLocation<'a> {
    pub guid: Guid,
    pub parent_guid: Guid,
    pub child_name: &'a str,
}

/// Validated immutable key record fields for a new child key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCreatePlan<'a> {
    pub guid: Guid,
    pub name: &'a str,
    pub parent_guid: Guid,
    pub volatile: bool,
    pub symlink: bool,
}

/// Inputs for planning all source records created by `reg_create_key`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCreateRecordsRequest<'a> {
    pub parent_guid: Guid,
    pub parent_is_volatile: bool,
    pub parent_granted_access: u32,
    pub child_name: &'a str,
    pub candidate_guid: Guid,
    pub active_key_guids: &'a [Guid],
    pub layer: &'a str,
    pub flags: u32,
    pub caller_has_tcb_or_admin: bool,
}

/// Source-record plan for creating a missing registry key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCreateRecordsPlan<'a> {
    pub guid_assignment: KeyGuidAssignmentPlan,
    pub key_record: KeyCreatePlan<'a>,
    pub path_entry: ValidatedPathEntryWrite<'a>,
}

/// Inputs required to compute a new registry key's initial SD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryKeyInitialSecurityDescriptorInput<'a> {
    pub parent_sd: &'a [u8],
    pub token_owner_sid: &'a [u8],
    pub token_primary_group_sid: &'a [u8],
    pub token_default_dacl: Option<&'a [u8]>,
}

/// Result of resolving a `reg_create_key` target path before creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegCreateKeyTarget {
    Exists,
    Missing,
}

/// High-level `reg_create_key` behavior selected after target resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegCreateKeyResolutionPlan {
    OpenExisting {
        disposition: u32,
        ignore_layer_parameter: bool,
    },
    CreateMissing {
        disposition: u32,
        use_layer_parameter: bool,
    },
}

/// Source create result handling for `reg_create_key`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegCreateKeySourceOperation {
    CreateEntry,
    CreateKey,
}

/// Source create result handling for `reg_create_key`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegCreateKeySourceResultPlan {
    ContinueCreateKey,
    CreatedNew { disposition: u32 },
    RetryOpenExisting { disposition: u32 },
    PropagateSourceStatus(RsiStatus),
    SourceInconsistency,
}

/// Validates immutable source-returned key record metadata.
pub fn validate_key_record<'a>(
    limits: &LcsLimits,
    record: &KeyRecordView<'a>,
) -> LcsResult<KeyRecordView<'a>> {
    validate_key_guid(record.guid)?;
    validate_key_component_bytes(record.name.as_bytes(), limits)?;
    validate_key_parent(record.parent)?;
    Ok(*record)
}

/// Parses and validates reg_create_key REG_OPTION_* flags.
pub fn validate_key_create_flags(flags: u32) -> LcsResult<KeyCreateOptions> {
    let unknown = flags & !REG_CREATE_KEY_KNOWN_FLAGS;
    if unknown != 0 {
        return Err(LcsError::UnknownCreateFlags { flags, unknown });
    }

    Ok(KeyCreateOptions {
        volatile: (flags & REG_OPTION_VOLATILE) != 0,
        symlink: (flags & REG_OPTION_CREATE_LINK) != 0,
    })
}

/// Validates that a candidate key GUID is a new LCS-assigned identity.
pub fn plan_key_guid_assignment(
    request: KeyGuidAssignmentRequest<'_>,
) -> LcsResult<KeyGuidAssignmentPlan> {
    validate_key_guid(request.candidate_guid)?;
    validate_guid_tracker("active_key_guids", request.active_key_guids)?;

    if guid_slice_contains(request.active_key_guids, request.candidate_guid) {
        return Err(LcsError::KeyGuidAlreadyExists {
            guid: request.candidate_guid,
        });
    }

    Ok(KeyGuidAssignmentPlan {
        guid: request.candidate_guid,
        assigned_by_lcs: true,
        persist_in_key_record: true,
    })
}

/// Validates a new child key's immutable metadata and creation gates.
pub fn validate_key_create_request<'a>(
    limits: &LcsLimits,
    request: &KeyCreateRequest<'a>,
) -> LcsResult<KeyCreatePlan<'a>> {
    let options = validate_key_create_flags(request.flags)?;
    validate_parent_guid(request.parent_guid)?;
    validate_key_guid(request.child_guid)?;
    let name = validate_key_component_bytes(request.child_name.as_bytes(), limits)?;

    if !registry_fd_has_right(request.parent_granted_access, KEY_CREATE_SUB_KEY) {
        return Err(LcsError::MissingKeyCreateSubKey);
    }

    if request.parent_is_volatile && !options.volatile {
        return Err(LcsError::NonVolatileChildUnderVolatile);
    }

    if options.symlink {
        validate_symlink_create_authority(
            request.parent_granted_access,
            request.caller_has_tcb_or_admin,
        )?;
    }

    Ok(KeyCreatePlan {
        guid: request.child_guid,
        name,
        parent_guid: request.parent_guid,
        volatile: options.volatile,
        symlink: options.symlink,
    })
}

/// Validates that no key GUID appears at multiple canonical path locations.
pub fn validate_key_canonical_path_locations(
    limits: &LcsLimits,
    locations: &[KeyCanonicalPathLocation<'_>],
) -> LcsResult<()> {
    for (index, location) in locations.iter().enumerate() {
        validate_key_guid(location.guid)?;
        validate_parent_guid(location.parent_guid)?;
        validate_key_component_bytes(location.child_name.as_bytes(), limits)?;

        if locations[..index]
            .iter()
            .any(|previous| previous.guid == location.guid)
        {
            return Err(LcsError::DuplicateTrackedKeyGuid {
                field: "canonical_key_locations",
                index,
            });
        }
    }

    Ok(())
}

/// Plans the key record and path entry that `reg_create_key` must create.
pub fn plan_key_create_records<'a>(
    limits: &LcsLimits,
    sequence_counter: &mut SequenceCounter,
    request: &KeyCreateRecordsRequest<'a>,
) -> LcsResult<KeyCreateRecordsPlan<'a>> {
    let guid_assignment = plan_key_guid_assignment(KeyGuidAssignmentRequest {
        candidate_guid: request.candidate_guid,
        active_key_guids: request.active_key_guids,
    })?;
    validate_layer_name_bytes(request.layer.as_bytes(), limits)?;

    let key_record = validate_key_create_request(
        limits,
        &KeyCreateRequest {
            parent_guid: request.parent_guid,
            parent_is_volatile: request.parent_is_volatile,
            parent_granted_access: request.parent_granted_access,
            child_name: request.child_name,
            child_guid: guid_assignment.guid,
            flags: request.flags,
            caller_has_tcb_or_admin: request.caller_has_tcb_or_admin,
        },
    )?;
    let sequence = sequence_counter.allocate()?;
    let path_entry = validate_path_entry_write_request(
        limits,
        &PathEntryWriteRequest {
            parent_guid: key_record.parent_guid,
            child_name: key_record.name,
            layer: request.layer,
            sequence,
            target: PathTarget::Guid(key_record.guid),
        },
    )?;

    Ok(KeyCreateRecordsPlan {
        guid_assignment,
        key_record,
        path_entry,
    })
}

/// Plans a transaction mutation-log entry for a validated missing-key create.
pub fn plan_key_create_transaction_log_entry<'a>(
    limits: &LcsLimits,
    planned: &KeyCreateRecordsPlan<'a>,
    parent_watch_context: WatchAncestryContext<'a>,
    counter: &mut TransactionOperationIndexCounter,
) -> LcsResult<TransactionKeyPathMutationLogEntry<'a>> {
    let child_guid = validate_planned_key_create_for_log(limits, planned)?;
    validate_parent_watch_context_for_log(
        limits,
        planned.path_entry.parent_guid,
        &parent_watch_context,
    )?;
    Ok(TransactionKeyPathMutationLogEntry {
        operation_index: counter.allocate()?,
        kind: TransactionMutationLogKind::CreateKey,
        parent_guid: planned.path_entry.parent_guid,
        parent_watch_context,
        child_visibility_watch_context: None,
        child_name: planned.path_entry.child_name,
        layer: planned.path_entry.layer,
        target_guid: Some(child_guid),
        sequence: Some(planned.path_entry.sequence),
        update_hive_generation_on_commit: true,
        update_parent_last_write_time_on_commit: false,
        recompute_effective_subkey_events_on_commit: true,
        evaluate_orphaning_on_commit: false,
        publish_new_key_guid_on_commit: true,
    })
}

/// Plans `reg_create_key` behavior after target path resolution.
pub fn plan_reg_create_key_resolution(target: RegCreateKeyTarget) -> RegCreateKeyResolutionPlan {
    match target {
        RegCreateKeyTarget::Exists => RegCreateKeyResolutionPlan::OpenExisting {
            disposition: REG_OPENED_EXISTING,
            ignore_layer_parameter: true,
        },
        RegCreateKeyTarget::Missing => RegCreateKeyResolutionPlan::CreateMissing {
            disposition: REG_CREATED_NEW,
            use_layer_parameter: true,
        },
    }
}

/// Plans handling of the source create response for `reg_create_key`.
pub fn plan_reg_create_key_source_result(
    operation: RegCreateKeySourceOperation,
    status: RsiStatus,
) -> RegCreateKeySourceResultPlan {
    match operation {
        RegCreateKeySourceOperation::CreateEntry => match status {
            RsiStatus::Ok => RegCreateKeySourceResultPlan::ContinueCreateKey,
            RsiStatus::AlreadyExists => RegCreateKeySourceResultPlan::RetryOpenExisting {
                disposition: REG_OPENED_EXISTING,
            },
            other => RegCreateKeySourceResultPlan::PropagateSourceStatus(other),
        },
        RegCreateKeySourceOperation::CreateKey => match status {
            RsiStatus::Ok => RegCreateKeySourceResultPlan::CreatedNew {
                disposition: REG_CREATED_NEW,
            },
            RsiStatus::AlreadyExists => RegCreateKeySourceResultPlan::SourceInconsistency,
            other => RegCreateKeySourceResultPlan::PropagateSourceStatus(other),
        },
    }
}

/// Computes the initial SD for a newly created registry key by delegating to
/// KACS inheritance rather than duplicating inheritance rules in LCS.
pub fn compute_registry_key_initial_security_descriptor(
    input: RegistryKeyInitialSecurityDescriptorInput<'_>,
) -> LcsResult<kacs_core::PkmVec<u8>> {
    let parent_sd = kacs_core::SecurityDescriptor::parse(input.parent_sd).map_err(|_| {
        LcsError::MalformedSecurityDescriptor {
            field: "reg_create_key.parent_sd",
        }
    })?;
    let token_owner =
        kacs_core::Sid::parse(input.token_owner_sid).map_err(|_| LcsError::MalformedTokenSid {
            field: "token.owner_sid",
        })?;
    let token_primary_group =
        kacs_core::Sid::parse(input.token_primary_group_sid).map_err(|_| {
            LcsError::MalformedTokenSid {
                field: "token.primary_group_sid",
            }
        })?;
    let token_default_dacl = input
        .token_default_dacl
        .map(kacs_core::Acl::parse)
        .transpose()
        .map_err(|_| LcsError::MalformedTokenDefaultDacl)?;

    kacs_core::inherit_registry_container_child_sd(kacs_core::RegistryContainerChildInheritance {
        parent_sd,
        token_owner,
        token_primary_group,
        token_default_dacl,
        generic_mapping: kacs_core::GenericMapping {
            read: REGISTRY_GENERIC_MAPPING.read,
            write: REGISTRY_GENERIC_MAPPING.write,
            execute: REGISTRY_GENERIC_MAPPING.execute,
            all: REGISTRY_GENERIC_MAPPING.all,
        },
        valid_mapped_access_mask: REG_VALID_MAPPED_ACCESS_MASK,
    })
    .map_err(|_| LcsError::SecurityDescriptorInheritanceFailed)
}

/// Validates the additional gates for creating a symlink key.
pub fn validate_symlink_create_authority(
    parent_granted_access: u32,
    caller_has_tcb_or_admin: bool,
) -> LcsResult<()> {
    if !registry_fd_has_right(parent_granted_access, KEY_CREATE_LINK) {
        return Err(LcsError::MissingKeyCreateLink);
    }
    if !caller_has_tcb_or_admin {
        return Err(LcsError::MissingSymlinkCreationAuthority);
    }
    Ok(())
}

fn validate_planned_key_create_for_log(
    limits: &LcsLimits,
    planned: &KeyCreateRecordsPlan<'_>,
) -> LcsResult<Guid> {
    if !planned.guid_assignment.assigned_by_lcs || !planned.guid_assignment.persist_in_key_record {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "guid_assignment",
        });
    }
    validate_key_guid(planned.guid_assignment.guid)?;
    validate_key_guid(planned.key_record.guid)?;
    validate_parent_guid(planned.key_record.parent_guid)?;
    validate_key_component_bytes(planned.key_record.name.as_bytes(), limits)?;
    validate_path_entry_write_request(
        limits,
        &PathEntryWriteRequest {
            parent_guid: planned.path_entry.parent_guid,
            child_name: planned.path_entry.child_name,
            layer: planned.path_entry.layer,
            sequence: planned.path_entry.sequence,
            target: planned.path_entry.target,
        },
    )?;
    validate_derived_key_path_mutation(
        limits,
        DerivedKeyPathMutation {
            parent_guid: planned.path_entry.parent_guid,
            child_name: planned.path_entry.child_name,
            layer: planned.path_entry.layer,
        },
    )?;

    let PathTarget::Guid(target_guid) = planned.path_entry.target else {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "path_entry.target",
        });
    };
    if planned.guid_assignment.guid != planned.key_record.guid
        || planned.key_record.guid != target_guid
        || planned.key_record.parent_guid != planned.path_entry.parent_guid
        || planned.key_record.name != planned.path_entry.child_name
    {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_create.records",
        });
    }

    Ok(target_guid)
}

fn validate_key_parent(parent: KeyParent) -> LcsResult<()> {
    match parent {
        KeyParent::HiveRoot => Ok(()),
        KeyParent::Parent(guid) => validate_parent_guid(guid),
    }
}

fn validate_key_guid(guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::NilKeyGuid);
    }
    Ok(())
}

fn validate_parent_guid(guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::NilParentGuid);
    }
    Ok(())
}

fn validate_guid_tracker(field: &'static str, guids: &[Guid]) -> LcsResult<()> {
    for (index, guid) in guids.iter().enumerate() {
        if *guid == NIL_GUID {
            return Err(LcsError::NilTrackedKeyGuid { field, index });
        }
        if guids[..index].iter().any(|previous| previous == guid) {
            return Err(LcsError::DuplicateTrackedKeyGuid { field, index });
        }
    }
    Ok(())
}

fn guid_slice_contains(guids: &[Guid], needle: Guid) -> bool {
    guids.iter().any(|guid| *guid == needle)
}
