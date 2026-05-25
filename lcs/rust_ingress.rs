// SPDX-License-Identifier: GPL-2.0-only

use core::ffi::{c_int, c_long, c_void};
use core::{slice, str};

use crate::kacs_core::PkmVec;
use crate::lcs_core::{
    apply_config_value, backup_restore_complete_audit_payload_len,
    backup_restore_fd_mode_linux_errno, backup_restore_start_audit_payload_len, casefold_eq,
    classify_hive_route, current_user_sid_component_from_binary_sid, find_config_range,
    for_each_effective_value, for_each_effective_value_watch_event,
    for_each_routable_path_component,
    for_each_rsi_enum_children_source_path_entry, for_each_rsi_lookup_source_path_entry,
    for_each_rsi_query_values_source_blanket_entry,
    for_each_rsi_query_values_source_value_entry, for_each_visible_subkey,
    layer_target_admission_linux_errno, parse_rsi_delete_layer_success_response_payload,
    parse_rsi_lookup_success_response_payload, parse_rsi_enum_children_success_response_payload,
    parse_rsi_query_values_success_response_payload, parse_rsi_read_key_success_response_payload,
    parse_rsi_request_header, plan_backup_complete_audit_record, plan_backup_restore_fd_mode,
    plan_backup_start_audit_record, plan_key_guid_assignment, plan_key_open_audit_record,
    plan_source_validation_failure_audit_record, plan_layer_publication,
    plan_layer_target_admission, plan_registry_get_security,
    plan_registry_ioctl_fixed_fd_access_gate, plan_registry_key_open_access,
    plan_registry_open_pre_resolution_access, plan_registry_security_info_fd_access_gate,
    plan_registry_set_security, plan_value_layer_admission,
    plan_rsi_source_read, plan_source_registration_sequence_update,
    registry_ioctl_access_requirement, registry_ioctl_fd_access_gate_errno,
    registry_open_pre_resolution_linux_errno, resolve_named_path_entry, resolve_value, route_hive,
    route_routable_path_hive, route_symlink_target_hive, rsi_queued_request_from_frame,
    rsi_status_code_errno, source_registration_error_linux_errno, source_registration_hive_scope,
    source_slot_hive_status, plan_watch_event_record, plan_watch_notify,
    validate_key_component_bytes, validate_key_create_flags, validate_key_fd_open_view,
    validate_layer_name_bytes,
    validate_registry_open_flags, validate_resolved_relative_path_depth,
    validate_rsi_enum_children_metadata_completeness,
    validate_rsi_enum_children_metadata_security_descriptors,
    validate_rsi_enum_children_path_response_names,
    validate_rsi_enum_children_path_response_sequences, validate_rsi_lookup_metadata_completeness,
    validate_rsi_lookup_metadata_security_descriptors, validate_rsi_lookup_path_response_names,
    validate_rsi_lookup_path_response_sequences,
    validate_rsi_query_values_response_names,
    validate_rsi_delete_layer_orphaned_guids,
    validate_rsi_query_values_response_sequences,
    validate_rsi_query_values_response_value_payloads, validate_rsi_read_key_response_names,
    validate_rsi_read_key_response_security_descriptor,
    validate_rsi_status_only_response_for_request, validate_source_registration,
    validate_source_slots, validate_symlink_target_bytes, validate_syscall_path_c_string,
    validate_value_data_len, validate_value_name_bytes, validate_value_write_type,
    value_data_len_linux_errno, value_layer_admission_linux_errno,
    value_type_validation_linux_errno,
    self_config_audit_intent, self_config_invalid_audit_payload_len,
    source_validation_failure_audit_payload_len, validate_config_value,
    write_backup_restore_complete_audit_payload, write_backup_restore_start_audit_payload,
    write_backup_header_record_frame, write_backup_key_record_frame,
    write_backup_trailer_record_frame,
    write_key_open_audit_payload, write_self_config_invalid_audit_payload,
    write_source_validation_failure_audit_payload, write_rsi_abort_transaction_request_frame,
    write_rsi_begin_transaction_request_frame, write_rsi_commit_transaction_request_frame,
    write_rsi_create_entry_request_frame, write_rsi_create_key_request_frame,
    write_rsi_delete_entry_request_frame, write_rsi_delete_layer_request_frame,
    write_rsi_delete_value_entry_request_frame, write_rsi_enum_children_request_frame,
    write_rsi_drop_key_request_frame,
    write_rsi_flush_request_frame, write_rsi_hide_entry_request_frame,
    write_rsi_lookup_request_frame, write_rsi_query_values_request_frame,
    write_rsi_read_key_request_frame, write_rsi_set_blanket_tombstone_request_frame,
    write_rsi_set_value_request_frame, write_rsi_write_key_request_frame,
    BackupRestoreFdOperation, BlanketTombstoneEntry, CurrentUserRewrite,
    HiveRouteOutcome, HiveView, KeyFdOpenView, KeyGuidAssignmentRequest, KeyWatchState,
    LayerOwnerSelectionInput, LayerOwnerSource, LayerPublicationInput, LayerResolutionContext,
    LayerTargetAdmissionInput, LayerView,
    LCS_CONFIG_ROOT_PATH, LcsAuditEventKind, LcsCallerTokenSummary, LcsError,
    LCS_CONFIG_RANGES, LcsKeyOpenAuditDecision, LcsLimits, LcsSelfConfigInvalidAuditRecord,
    LcsSelfConfigReceivedValue, LinuxErrno, NamedPathEntry, NamedPathResolution, NamedValueEntry,
    PathKind, PathTarget, RegisteredHiveIdentity, RegistryIoctlAccessRequirement,
    RegistryKeyOpenAccessInput, RegistryOpenAccessDecision, RegistryOpenPreResolutionAccessPlan,
    RsiReadPlan, RsiRetainedRequest, RsiTransactionMode, RsiSourceDataValidationFailure,
    SelfConfigRetentionReason, SelfConfigValue, SourceRegistrationDecision, SourceRegistrationHive, SourceRegistrationRequest,
    SourceSlotStatus, SourceSlotView, ValueEntry, ValueLayerAdmissionInput, ValueResolution,
    EffectiveValueWatchEvent, EnumeratedValue, WatchEventRecordPlan,
    WatchEventRecordRequest,
    WatchEventRecordWritePlan, WatchNotifyArgs, WatchNotifyPlan, REG_DWORD, REG_TOMBSTONE,
    RSI_DELETE_LAYER, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_QUERY_VALUES, RSI_READ_KEY,
    select_layer_owner, write_watch_event_record,
};

const PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE: u32 = 0;
const PKM_LCS_SOURCE_SLOT_STATUS_DOWN: u32 = 1;

const PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW: u32 = 0;
const PKM_LCS_SOURCE_REGISTRATION_DECISION_RESUME_DOWN: u32 = 1;

const PKM_LCS_RSI_READ_ACTION_COPY: u32 = 0;
const PKM_LCS_RSI_READ_ACTION_WAIT: u32 = 1;
const PKM_LCS_RSI_READ_ACTION_EAGAIN: u32 = 2;
const PKM_LCS_RSI_READ_ACTION_EMSGSIZE: u32 = 3;
const PKM_LCS_RSI_READ_ACTION_WAKE_CLOSE: u32 = 4;

const PKM_LCS_WATCH_NOTIFY_ACTION_ARM: u32 = 1;
const PKM_LCS_WATCH_NOTIFY_ACTION_DISARM: u32 = 2;

const PKM_LCS_SELF_CONFIG_RECEIVED_MISSING: u32 = 0;
const PKM_LCS_SELF_CONFIG_RECEIVED_WRONG_TYPE: u32 = 1;
const PKM_LCS_SELF_CONFIG_RECEIVED_DWORD_OUT_OF_RANGE: u32 = 2;
const PKM_LCS_SELF_CONFIG_VALUE_DWORD: u32 = 1;
const PKM_LCS_SELF_CONFIG_VALUE_WRONG_TYPE: u32 = 2;
const PKM_LCS_SELF_CONFIG_MAX_AUDITS: usize = 19;
const PKM_LCS_SELF_CONFIG_MAX_PARAMETER_NAME_LEN: usize = 64;

#[repr(C)]
pub struct PkmLcsSourceRegistrationHiveCopy {
    pub name: *const u8,
    pub name_len: u32,
    pub root_guid: [u8; 16],
    pub flags: u32,
    pub scope_guid: [u8; 16],
    pub hive_generation: u64,
}

#[repr(C)]
pub struct PkmLcsSourceSlotViewCopy {
    pub source_id: u32,
    pub status: u32,
    pub hive_count: u32,
    pub _pad: u32,
    pub hives: *const PkmLcsSourceRegistrationHiveCopy,
}

#[repr(C)]
pub struct PkmLcsSourceRegistrationPlanCopy {
    pub hive_count: u32,
    pub source_next_sequence: u64,
    pub effective_next_sequence: u64,
    pub decision: u32,
    pub source_id: u32,
}

#[repr(C)]
pub struct PkmLcsHiveRouteResultCopy {
    pub source_id: u32,
    pub root_guid: [u8; 16],
}

#[repr(C)]
pub struct PkmLcsOpenPreflightPlanCopy {
    pub requested_access: u32,
    pub mapped_desired_access: u32,
    pub maximum_allowed: u8,
    pub path_resolution_allowed: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
pub struct PkmLcsKeyCreateOptionsCopy {
    pub volatile_key: u8,
    pub symlink: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
pub struct PkmLcsKeyGuidAssignmentPlanCopy {
    pub guid: [u8; 16],
    pub assigned_by_lcs: u8,
    pub persist_in_key_record: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
pub struct PkmLcsPathComponentViewCopy {
    pub name: *const u8,
    pub name_len: u32,
}

#[repr(C)]
pub struct PkmLcsPathComponentMaterializationCopy {
    pub component_count: u32,
    pub string_bytes: u32,
}

#[repr(C)]
pub struct PkmLcsKeyOpenAccessPlanCopy {
    pub requested_access: u32,
    pub mapped_desired_access: u32,
    pub access_check_granted: u32,
    pub fd_granted_access: u32,
    pub allowed: u8,
    pub maximum_allowed: u8,
    pub key_open_sacl_audit_required: u8,
    pub audit_payload_failure_blocks_completion: u8,
    pub privilege_use_audit_required: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsAuditCallerSummaryCopy {
    pub effective_token_guid: [u8; 16],
    pub true_token_guid: [u8; 16],
    pub process_guid: [u8; 16],
    pub user_sid: *const u8,
    pub user_sid_len: usize,
    pub authentication_id: u64,
    pub token_id: u64,
    pub token_type: u32,
    pub impersonation_level: u32,
    pub integrity_level: u32,
}

#[repr(C)]
pub struct PkmLcsKeyFdStringViewCopy {
    pub bytes: *const u8,
    pub len: u32,
}

#[repr(C)]
pub struct PkmLcsPathValidationResultCopy {
    pub component_count: u32,
    pub used_forward_separator: bool,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsRuntimeLimitsCopy {
    pub request_timeout_ms: u32,
    pub transaction_timeout_ms: u32,
    pub notification_queue_size: u32,
    pub symlink_depth_limit: u32,
    pub max_value_size: u32,
    pub max_key_depth: u32,
    pub max_path_component_length: u32,
    pub max_total_path_length: u32,
    pub max_layers_per_value: u32,
    pub max_bound_transactions_per_source: u32,
    pub max_read_only_transactions_per_source: u32,
    pub max_total_layers: u32,
    pub max_registered_sources: u32,
    pub max_hives_per_source: u32,
    pub max_concurrent_rsi_requests: u32,
    pub max_scope_guids_per_token: u32,
    pub max_private_layers_per_token: u32,
    pub max_subtree_watch_depth: u32,
    pub max_transaction_watch_event_burst: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PkmLcsSelfConfigEntryCopy {
    pub name: *const u8,
    pub name_len: u32,
    pub value_kind: u32,
    pub value_type: u32,
    pub value_u32: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PkmLcsSelfConfigAuditIntentCopy {
    pub configuration_name: [u8; PKM_LCS_SELF_CONFIG_MAX_PARAMETER_NAME_LEN],
    pub configuration_name_len: u32,
    pub received_kind: u32,
    pub received_type: u32,
    pub received_u32: u32,
    pub retained_value: u32,
}

impl PkmLcsSelfConfigAuditIntentCopy {
    const ZERO: Self = Self {
        configuration_name: [0; PKM_LCS_SELF_CONFIG_MAX_PARAMETER_NAME_LEN],
        configuration_name_len: 0,
        received_kind: 0,
        received_type: 0,
        received_u32: 0,
        retained_value: 0,
    };
}

#[repr(C)]
pub struct PkmLcsSelfConfigApplyPlanCopy {
    pub limits: PkmLcsRuntimeLimitsCopy,
    pub applied_count: u32,
    pub retained_missing_count: u32,
    pub retained_invalid_count: u32,
    pub ignored_unknown_count: u32,
    pub audit_count: u32,
    pub audits: [PkmLcsSelfConfigAuditIntentCopy; PKM_LCS_SELF_CONFIG_MAX_AUDITS],
}

#[repr(C)]
pub struct PkmLcsWatchNotifyPlanCopy {
    pub action: u32,
    pub filter: u32,
    pub subtree: u8,
    pub replaces_existing: u8,
    pub discard_pending_events: u8,
    pub _pad: u8,
}

#[repr(C)]
pub struct PkmLcsRsiBuiltRequestCopy {
    pub len: usize,
    pub request_id: u64,
    pub txn_id: u64,
    pub op_code: u16,
    pub _pad: [u8; 6],
}

#[repr(C)]
pub struct PkmLcsRsiReadPlanCopy {
    pub action: u32,
    pub _pad: u32,
    pub request_len: usize,
    pub required_len: usize,
}

#[repr(C)]
pub struct PkmLcsRsiLookupResponseSummaryCopy {
    pub path_entry_count: u32,
    pub metadata_count: u32,
    pub source_validation_failure: u32,
    pub child_absent: bool,
    pub source_validation_failure_present: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
pub struct PkmLcsRsiLayerViewCopy {
    pub name: *const u8,
    pub name_len: u32,
    pub precedence: u32,
    pub enabled: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsLayerTargetAdmissionPlanCopy {
    pub precedence: u32,
    pub enabled: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsLayerMetadataSdViewCopy {
    pub name: *const u8,
    pub sd: *const u8,
    pub sd_len: usize,
    pub name_len: u32,
    pub _pad: u32,
}

#[repr(C)]
pub struct PkmLcsLayerMetadataSdSelectionCopy {
    pub index: u32,
    pub _pad: u32,
}

#[repr(C)]
pub struct PkmLcsLayerOwnerSelectionCopy {
    pub owner_sid: *const u8,
    pub owner_sid_len: usize,
    pub source: u32,
    pub informational_only: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsRsiPrivateLayerViewCopy {
    pub name: *const u8,
    pub name_len: u32,
}

#[repr(C)]
pub struct PkmLcsRsiLookupChildResultCopy {
    pub source_path_entry_count: u32,
    pub sd_offset: u32,
    pub sd_len: u32,
    pub selected_precedence: u32,
    pub selected_sequence: u64,
    pub last_write_time: u64,
    pub found: u8,
    pub volatile_key: u8,
    pub symlink: u8,
    pub _pad: [u8; 5],
    pub key_guid: [u8; 16],
}

#[repr(C)]
pub struct PkmLcsRsiLookupGuidEntryResultCopy {
    pub source_path_entry_count: u32,
    pub present: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsRsiReadKeyResultCopy {
    pub sd_offset: u32,
    pub sd_len: u32,
    pub name_len: u32,
    pub source_validation_failure: u32,
    pub last_write_time: u64,
    pub volatile_key: u8,
    pub symlink: u8,
    pub source_validation_failure_present: u8,
    pub _pad1: [u8; 5],
    pub parent_guid: [u8; 16],
}

#[repr(C)]
pub struct PkmLcsRsiQueryValuesResponseSummaryCopy {
    pub value_entry_count: u32,
    pub blanket_count: u32,
    pub source_validation_failure: u32,
    pub source_validation_failure_present: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsRsiDeleteLayerResponseSummaryCopy {
    pub orphaned_guid_count: u32,
    pub source_validation_failure: u32,
    pub source_validation_failure_present: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsRsiEnumChildrenInfoSummaryCopy {
    pub subkey_count: u32,
    pub max_subkey_name_len: u32,
    pub source_path_entry_count: u32,
    pub source_validation_failure: u32,
    pub source_validation_failure_present: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsRsiEnumSubkeyResultCopy {
    pub source_path_entry_count: u32,
    pub name_offset: u32,
    pub name_len: u32,
    pub selected_precedence: u32,
    pub selected_sequence: u64,
    pub found: u8,
    pub _pad: [u8; 7],
    pub child_guid: [u8; 16],
}

#[repr(C)]
pub struct PkmLcsRsiQueryValuesInfoSummaryCopy {
    pub value_count: u32,
    pub max_value_name_len: u32,
    pub max_value_data_size: u32,
    pub source_value_entry_count: u32,
    pub source_blanket_count: u32,
    pub _pad: [u32; 3],
}

#[repr(C)]
pub struct PkmLcsRsiQueryValuesBatchResultCopy {
    pub required_len: u32,
    pub count: u32,
    pub written_len: u32,
    pub source_value_entry_count: u32,
    pub source_blanket_count: u32,
    pub _pad: [u32; 3],
}

#[repr(C)]
pub struct PkmLcsRsiValueWatchEventsResultCopy {
    pub required_len: u32,
    pub count: u32,
    pub written_len: u32,
    pub before_source_value_entry_count: u32,
    pub before_source_blanket_count: u32,
    pub after_source_value_entry_count: u32,
    pub after_source_blanket_count: u32,
    pub _pad: u32,
}

#[repr(C)]
pub struct PkmLcsRsiQueryValueResultCopy {
    pub source_value_entry_count: u32,
    pub source_blanket_count: u32,
    pub data_offset: u32,
    pub data_len: u32,
    pub layer: *const u8,
    pub layer_len: u32,
    pub value_type: u32,
    pub selected_precedence: u32,
    pub _pad0: u32,
    pub selected_sequence: u64,
    pub found: u8,
    pub _pad1: [u8; 7],
}

#[repr(C)]
pub struct PkmLcsRsiEnumValueResultCopy {
    pub source_value_entry_count: u32,
    pub source_blanket_count: u32,
    pub name_offset: u32,
    pub name_len: u32,
    pub data_offset: u32,
    pub data_len: u32,
    pub value_type: u32,
    pub _pad0: u32,
    pub found: u8,
    pub _pad1: [u8; 7],
}

#[repr(C)]
pub struct PkmLcsValueLayerAdmissionResultCopy {
    pub current_distinct_layers: u32,
    pub replacing_existing_layer_entry: u8,
    pub _pad: [u8; 3],
}

fn source_registration_error_return(err: crate::lcs_core::LcsError) -> c_int {
    source_registration_error_linux_errno(err)
        .unwrap_or(LinuxErrno::Einval)
        .negated_return() as c_int
}

fn absolute_route_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::NameTooLong { .. } | LcsError::PathTooLong { .. } => LinuxErrno::Enametoolong,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn symlink_target_error_return(_err: LcsError) -> c_int {
    LinuxErrno::Einval.negated_return() as c_int
}

fn lcs_limits_from_copy(raw: *const PkmLcsRuntimeLimitsCopy) -> Result<LcsLimits, LinuxErrno> {
    let Some(raw) = (unsafe { raw.as_ref() }) else {
        return Err(LinuxErrno::Einval);
    };

    Ok(LcsLimits {
        request_timeout_ms: raw.request_timeout_ms,
        transaction_timeout_ms: raw.transaction_timeout_ms,
        max_key_depth: raw.max_key_depth as usize,
        max_path_component_length: raw.max_path_component_length as usize,
        max_total_path_length: raw.max_total_path_length as usize,
        symlink_depth_limit: raw.symlink_depth_limit as usize,
        max_value_size: raw.max_value_size as usize,
        max_layers_per_value: raw.max_layers_per_value as usize,
        max_total_layers: raw.max_total_layers as usize,
        max_bound_transactions_per_source: raw.max_bound_transactions_per_source as usize,
        max_read_only_transactions_per_source: raw.max_read_only_transactions_per_source as usize,
        max_registered_sources: raw.max_registered_sources as usize,
        max_hives_per_source: raw.max_hives_per_source as usize,
        max_concurrent_rsi_requests: raw.max_concurrent_rsi_requests as usize,
        notification_queue_size: raw.notification_queue_size as usize,
        max_subtree_watch_depth: raw.max_subtree_watch_depth as usize,
        max_transaction_watch_event_burst: raw.max_transaction_watch_event_burst as usize,
        max_scope_guids_per_token: raw.max_scope_guids_per_token as usize,
        max_private_layers_per_token: raw.max_private_layers_per_token as usize,
    })
}

fn lcs_limits_to_copy(limits: LcsLimits) -> PkmLcsRuntimeLimitsCopy {
    PkmLcsRuntimeLimitsCopy {
        request_timeout_ms: limits.request_timeout_ms,
        transaction_timeout_ms: limits.transaction_timeout_ms,
        notification_queue_size: limits.notification_queue_size as u32,
        symlink_depth_limit: limits.symlink_depth_limit as u32,
        max_value_size: limits.max_value_size as u32,
        max_key_depth: limits.max_key_depth as u32,
        max_path_component_length: limits.max_path_component_length as u32,
        max_total_path_length: limits.max_total_path_length as u32,
        max_layers_per_value: limits.max_layers_per_value as u32,
        max_bound_transactions_per_source: limits.max_bound_transactions_per_source as u32,
        max_read_only_transactions_per_source: limits.max_read_only_transactions_per_source as u32,
        max_total_layers: limits.max_total_layers as u32,
        max_registered_sources: limits.max_registered_sources as u32,
        max_hives_per_source: limits.max_hives_per_source as u32,
        max_concurrent_rsi_requests: limits.max_concurrent_rsi_requests as u32,
        max_scope_guids_per_token: limits.max_scope_guids_per_token as u32,
        max_private_layers_per_token: limits.max_private_layers_per_token as u32,
        max_subtree_watch_depth: limits.max_subtree_watch_depth as u32,
        max_transaction_watch_event_burst: limits.max_transaction_watch_event_burst as u32,
    }
}

fn empty_self_config_apply_plan() -> PkmLcsSelfConfigApplyPlanCopy {
    PkmLcsSelfConfigApplyPlanCopy {
        limits: lcs_limits_to_copy(LcsLimits::DEFAULT),
        applied_count: 0,
        retained_missing_count: 0,
        retained_invalid_count: 0,
        ignored_unknown_count: 0,
        audit_count: 0,
        audits: [PkmLcsSelfConfigAuditIntentCopy::ZERO; PKM_LCS_SELF_CONFIG_MAX_AUDITS],
    }
}

fn self_config_entry_name<'a>(
    entry: &'a PkmLcsSelfConfigEntryCopy,
) -> Result<&'a str, LinuxErrno> {
    if entry.name_len == 0 {
        return Ok("");
    }
    if entry.name.is_null() {
        return Err(LinuxErrno::Einval);
    }
    let name_bytes = unsafe { slice::from_raw_parts(entry.name, entry.name_len as usize) };
    str::from_utf8(name_bytes).map_err(|_| LinuxErrno::Einval)
}

fn self_config_entry_value(
    entry: &PkmLcsSelfConfigEntryCopy,
) -> Result<SelfConfigValue, LinuxErrno> {
    match entry.value_kind {
        PKM_LCS_SELF_CONFIG_VALUE_DWORD => {
            if entry.value_type != REG_DWORD {
                return Err(LinuxErrno::Einval);
            }
            Ok(SelfConfigValue::Dword(entry.value_u32))
        }
        PKM_LCS_SELF_CONFIG_VALUE_WRONG_TYPE => {
            if entry.value_type == REG_DWORD || entry.value_u32 != 0 {
                return Err(LinuxErrno::Einval);
            }
            Ok(SelfConfigValue::WrongType {
                actual_type: entry.value_type,
            })
        }
        _ => Err(LinuxErrno::Einval),
    }
}

fn self_config_observed_value(
    entries: &[PkmLcsSelfConfigEntryCopy],
    name: &str,
) -> Result<Option<SelfConfigValue>, LinuxErrno> {
    for entry in entries {
        if casefold_eq(self_config_entry_name(entry)?, name) {
            return self_config_entry_value(entry).map(Some);
        }
    }
    Ok(None)
}

fn write_self_config_audit_intent(
    current: &LcsLimits,
    range: crate::lcs_core::ConfigRange,
    value: Option<SelfConfigValue>,
    output: &mut PkmLcsSelfConfigAuditIntentCopy,
) -> Result<bool, LinuxErrno> {
    let Some(intent) = self_config_audit_intent(current, range, value) else {
        return Ok(false);
    };
    let name = intent.parameter.as_bytes();
    if name.len() > output.configuration_name.len() {
        return Err(LinuxErrno::Einval);
    }

    *output = PkmLcsSelfConfigAuditIntentCopy::ZERO;
    output.configuration_name[..name.len()].copy_from_slice(name);
    output.configuration_name_len = name.len() as u32;
    output.retained_value = intent.retained_value;
    match intent.reason {
        SelfConfigRetentionReason::Missing => {
            output.received_kind = PKM_LCS_SELF_CONFIG_RECEIVED_MISSING;
        }
        SelfConfigRetentionReason::WrongType { actual_type } => {
            output.received_kind = PKM_LCS_SELF_CONFIG_RECEIVED_WRONG_TYPE;
            output.received_type = actual_type;
        }
        SelfConfigRetentionReason::OutOfRange { value, .. } => {
            output.received_kind = PKM_LCS_SELF_CONFIG_RECEIVED_DWORD_OUT_OF_RANGE;
            output.received_u32 = value;
        }
    }
    Ok(true)
}

#[derive(Clone, Copy)]
struct ObservedSelfConfigValue<'a> {
    name: &'a str,
    value: SelfConfigValue,
}

fn effective_value_to_self_config(value: EnumeratedValue<'_>) -> SelfConfigValue {
    let actual_type = value.value.value_type.code();
    let data = value.value.data;

    if actual_type == REG_DWORD && data.len() == core::mem::size_of::<u32>() {
        return SelfConfigValue::Dword(u32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ]));
    }

    SelfConfigValue::WrongType { actual_type }
}

fn observed_self_config_value(
    values: &[ObservedSelfConfigValue<'_>],
    name: &str,
) -> Option<SelfConfigValue> {
    values
        .iter()
        .find(|entry| casefold_eq(entry.name, name))
        .map(|entry| entry.value)
}

fn write_self_config_plan_from_observed(
    current: LcsLimits,
    observed_values: &[ObservedSelfConfigValue<'_>],
    plan_out: &mut PkmLcsSelfConfigApplyPlanCopy,
) -> Result<(), LinuxErrno> {
    let mut limits = current;
    let mut applied_count = 0u32;
    let mut retained_missing_count = 0u32;
    let mut retained_invalid_count = 0u32;
    let mut ignored_unknown_count = 0u32;
    let mut audit_count = 0usize;
    let mut audits = [PkmLcsSelfConfigAuditIntentCopy::ZERO; PKM_LCS_SELF_CONFIG_MAX_AUDITS];

    for entry in observed_values {
        if find_config_range(entry.name).is_none() {
            ignored_unknown_count = ignored_unknown_count
                .checked_add(1)
                .ok_or(LinuxErrno::Einval)?;
        }
    }

    for range in LCS_CONFIG_RANGES {
        let observed = observed_self_config_value(observed_values, range.name);

        match observed {
            Some(SelfConfigValue::Dword(value)) => match validate_config_value(range, value) {
                Ok(value) => {
                    apply_config_value(&mut limits, range, value);
                    applied_count = applied_count.checked_add(1).ok_or(LinuxErrno::Einval)?;
                }
                Err(_) => {
                    retained_invalid_count = retained_invalid_count
                        .checked_add(1)
                        .ok_or(LinuxErrno::Einval)?;
                    if audit_count >= audits.len()
                        || !write_self_config_audit_intent(
                            &current,
                            range,
                            observed,
                            &mut audits[audit_count],
                        )?
                    {
                        return Err(LinuxErrno::Einval);
                    }
                    audit_count += 1;
                }
            },
            Some(SelfConfigValue::WrongType { .. }) => {
                retained_invalid_count = retained_invalid_count
                    .checked_add(1)
                    .ok_or(LinuxErrno::Einval)?;
                if audit_count >= audits.len()
                    || !write_self_config_audit_intent(
                        &current,
                        range,
                        observed,
                        &mut audits[audit_count],
                    )?
                {
                    return Err(LinuxErrno::Einval);
                }
                audit_count += 1;
            }
            None => {
                retained_missing_count = retained_missing_count
                    .checked_add(1)
                    .ok_or(LinuxErrno::Einval)?;
                if audit_count >= audits.len()
                    || !write_self_config_audit_intent(
                        &current,
                        range,
                        None,
                        &mut audits[audit_count],
                    )?
                {
                    return Err(LinuxErrno::Einval);
                }
                audit_count += 1;
            }
        }
    }

    *plan_out = PkmLcsSelfConfigApplyPlanCopy {
        limits: lcs_limits_to_copy(limits),
        applied_count,
        retained_missing_count,
        retained_invalid_count,
        ignored_unknown_count,
        audit_count: audit_count as u32,
        audits,
    };
    Ok(())
}

fn key_fd_open_view_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::NameTooLong { .. } | LcsError::PathTooLong { .. } => LinuxErrno::Enametoolong,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn watch_notify_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::OrphanedWatchArm => LinuxErrno::Enoent,
        LcsError::UnknownNotifyFilterFlags { .. }
        | LcsError::InvalidBooleanFlag { .. }
        | LcsError::NonZeroReservedBytes { .. } => LinuxErrno::Einval,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn watch_event_record_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::WatchEventOutputBufferTooSmall { .. } => LinuxErrno::Erange,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn key_open_access_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::MalformedSecurityDescriptor { .. } => LinuxErrno::Eio,
        LcsError::AccessCheckEvaluationFailed => LinuxErrno::Eio,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn key_open_audit_error_return(err: LcsError) -> c_int {
	match err {
		LcsError::AuditPayloadOutputBufferTooSmall { .. } => LinuxErrno::Erange,
		_ => LinuxErrno::Eio,
	}
	.negated_return() as c_int
}

fn backup_audit_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::AuditPayloadOutputBufferTooSmall { .. } => LinuxErrno::Erange,
        _ => LinuxErrno::Eio,
    }
    .negated_return() as c_int
}

fn backup_writer_error_return(err: LcsError, written_out: *mut usize) -> c_int {
    if let LcsError::BackupRecordFrameBufferTooSmall { required, .. } = err {
        unsafe {
            if !written_out.is_null() {
                *written_out = required;
            }
        }
        return LinuxErrno::Erange.negated_return() as c_int;
    }

    match err {
        LcsError::BackupPayloadLengthOverflow => LinuxErrno::Eoverflow,
        LcsError::MalformedSecurityDescriptor { .. } => LinuxErrno::Eio,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

unsafe fn backup_writer_dst<'a>(
    dst: *mut u8,
    dst_len: usize,
) -> Result<&'a mut [u8], LinuxErrno> {
    if dst.is_null() {
        if dst_len != 0 {
            return Err(LinuxErrno::Einval);
        }
        Ok(&mut [])
    } else {
        Ok(unsafe { slice::from_raw_parts_mut(dst, dst_len) })
    }
}

fn audit_caller_summary_from_copy<'a>(
    caller: &'a PkmLcsAuditCallerSummaryCopy,
) -> Result<LcsCallerTokenSummary<'a>, LinuxErrno> {
    if caller.user_sid.is_null() {
        return Err(LinuxErrno::Einval);
    }

    let user_sid = unsafe { slice::from_raw_parts(caller.user_sid, caller.user_sid_len) };
    Ok(LcsCallerTokenSummary {
        effective_token_guid: caller.effective_token_guid,
        true_token_guid: caller.true_token_guid,
        process_guid: caller.process_guid,
        user_sid,
        authentication_id: caller.authentication_id,
        token_id: caller.token_id,
        token_type: caller.token_type,
        impersonation_level: caller.impersonation_level,
        integrity_level: caller.integrity_level,
    })
}

fn source_validation_failure_from_code(
    code: u32,
) -> Result<RsiSourceDataValidationFailure, LinuxErrno> {
    match code {
        0 => Ok(RsiSourceDataValidationFailure::MalformedSecurityDescriptor),
        1 => Ok(RsiSourceDataValidationFailure::MalformedLayerName),
        2 => Ok(RsiSourceDataValidationFailure::UnknownRsiStatusCode),
        3 => Ok(RsiSourceDataValidationFailure::FutureSequenceNumber),
        4 => Ok(RsiSourceDataValidationFailure::DuplicateWinningSequenceTie),
        5 => Ok(RsiSourceDataValidationFailure::MalformedLayerMetadataSecurityDescriptor),
        6 => Ok(RsiSourceDataValidationFailure::MalformedKeyName),
        7 => Ok(RsiSourceDataValidationFailure::MalformedValueName),
        8 => Ok(RsiSourceDataValidationFailure::MalformedResponsePayload),
        9 => Ok(RsiSourceDataValidationFailure::MalformedKeyMetadata),
        10 => Ok(RsiSourceDataValidationFailure::MalformedValuePayload),
        11 => Ok(RsiSourceDataValidationFailure::MalformedDeleteLayerOrphanList),
        _ => Err(LinuxErrno::Einval),
    }
}

fn source_validation_failure_code(failure: RsiSourceDataValidationFailure) -> u32 {
    match failure {
        RsiSourceDataValidationFailure::MalformedSecurityDescriptor => 0,
        RsiSourceDataValidationFailure::MalformedLayerName => 1,
        RsiSourceDataValidationFailure::UnknownRsiStatusCode => 2,
        RsiSourceDataValidationFailure::FutureSequenceNumber => 3,
        RsiSourceDataValidationFailure::DuplicateWinningSequenceTie => 4,
        RsiSourceDataValidationFailure::MalformedLayerMetadataSecurityDescriptor => 5,
        RsiSourceDataValidationFailure::MalformedKeyName => 6,
        RsiSourceDataValidationFailure::MalformedValueName => 7,
        RsiSourceDataValidationFailure::MalformedResponsePayload => 8,
        RsiSourceDataValidationFailure::MalformedKeyMetadata => 9,
        RsiSourceDataValidationFailure::MalformedValuePayload => 10,
        RsiSourceDataValidationFailure::MalformedDeleteLayerOrphanList => 11,
    }
}

fn source_validation_failure_for_name_error(
    err: &LcsError,
) -> Option<RsiSourceDataValidationFailure> {
    let field = match err {
        LcsError::InvalidUtf8 { field }
        | LcsError::NullByte { field }
        | LcsError::EmptyString { field }
        | LcsError::NameContainsSeparator { field }
        | LcsError::NameTooLong { field, .. } => *field,
        _ => return None,
    };

    match field {
        "layer_name" => Some(RsiSourceDataValidationFailure::MalformedLayerName),
        "key_component" => Some(RsiSourceDataValidationFailure::MalformedKeyName),
        "value_name" => Some(RsiSourceDataValidationFailure::MalformedValueName),
        _ => None,
    }
}

fn source_validation_failure_for_response_payload_error(
    err: &LcsError,
) -> Option<RsiSourceDataValidationFailure> {
    match err {
        LcsError::RsiUnexpectedResponsePayload { .. }
        | LcsError::RsiPayloadLengthOverflow
        | LcsError::InvalidRsiPathTargetType(_)
        | LcsError::RsiHiddenPathTargetGuidNotZero => {
            Some(RsiSourceDataValidationFailure::MalformedResponsePayload)
        }
        _ => None,
    }
}

fn source_validation_failure_for_key_metadata_error(
    err: &LcsError,
) -> Option<RsiSourceDataValidationFailure> {
    match err {
        LcsError::RsiPathMetadataMissing { .. }
        | LcsError::RsiPathMetadataDuplicate { .. }
        | LcsError::RsiPathMetadataUnreferenced { .. }
        | LcsError::RsiPathMetadataNilGuid => {
            Some(RsiSourceDataValidationFailure::MalformedKeyMetadata)
        }
        _ => None,
    }
}

fn source_validation_failure_for_value_payload_error(
    err: &LcsError,
) -> Option<RsiSourceDataValidationFailure> {
    match err {
        LcsError::UnknownValueType(_)
        | LcsError::TombstoneNotExplicit
        | LcsError::TombstoneDataMustBeEmpty { .. }
        | LcsError::ValueDataTooLarge { .. } => {
            Some(RsiSourceDataValidationFailure::MalformedValuePayload)
        }
        _ => None,
    }
}

fn source_validation_failure_for_delete_layer_orphan_error(
    err: &LcsError,
) -> Option<RsiSourceDataValidationFailure> {
    match err {
        LcsError::RsiDeleteLayerOrphanedGuidNil
        | LcsError::RsiDeleteLayerOrphanedGuidDuplicate { .. } => {
            Some(RsiSourceDataValidationFailure::MalformedDeleteLayerOrphanList)
        }
        _ => None,
    }
}

fn source_validation_audit_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::AuditPayloadOutputBufferTooSmall { .. } => LinuxErrno::Erange,
        _ => LinuxErrno::Eio,
    }
    .negated_return() as c_int
}

fn self_config_invalid_audit_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::AuditPayloadOutputBufferTooSmall { .. } => LinuxErrno::Erange,
        _ => LinuxErrno::Eio,
    }
    .negated_return() as c_int
}

fn set_security_merge_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::MalformedSecurityDescriptor { field }
            if field.contains("existing_sd") || field.contains("merged_sd") =>
        {
            LinuxErrno::Eio
        }
        LcsError::MalformedSecurityDescriptor { .. }
        | LcsError::ZeroSecurityInfo
        | LcsError::UnknownSecurityInfoFlags { .. }
        | LcsError::SecurityDescriptorMergeMissingOwner { .. }
        | LcsError::SecurityDescriptorConstructionFailed { .. }
        | LcsError::MaximumAllowedInAce(_)
        | LcsError::AceMaskMapsOutsideRegistryRights(_) => LinuxErrno::Einval,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn get_security_plan_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::ZeroSecurityInfo | LcsError::UnknownSecurityInfoFlags { .. } => {
            LinuxErrno::Einval
        }
        LcsError::MalformedSecurityDescriptor { .. }
        | LcsError::SecurityDescriptorConstructionFailed { .. }
        | LcsError::MaximumAllowedInAce(_)
        | LcsError::AceMaskMapsOutsideRegistryRights(_) => LinuxErrno::Eio,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn rsi_request_frame_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::RsiFrameBufferTooSmall { .. } => LinuxErrno::Emsgsize,
        LcsError::NameTooLong { .. } | LcsError::PathTooLong { .. } => LinuxErrno::Enametoolong,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn public_set_value_validation_error_return(err: LcsError) -> c_int {
    value_type_validation_linux_errno(&err)
        .or_else(|| value_data_len_linux_errno(&err))
        .unwrap_or_else(|| match err {
            LcsError::NameTooLong { .. } | LcsError::PathTooLong { .. } => {
                LinuxErrno::Enametoolong
            }
            LcsError::NilKeyGuid => LinuxErrno::Einval,
            _ => LinuxErrno::Einval,
        })
        .negated_return() as c_int
}

fn rsi_lookup_response_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::RsiRequestIdMismatch { .. }
        | LcsError::RsiResponseOpcodeMismatch { .. }
        | LcsError::RsiMessageLengthMismatch { .. }
        | LcsError::RsiResponsePayloadParserMismatch { .. } => {
            LinuxErrno::Einval.negated_return() as c_int
        }
        LcsError::RsiResponseStatusNotOk(status) => match rsi_status_code_errno(status) {
            Ok(Some(errno)) => errno.negated_return() as c_int,
            Ok(None) => 0,
            Err(_) => LinuxErrno::Eio.negated_return() as c_int,
        },
        _ => LinuxErrno::Eio.negated_return() as c_int,
    }
}

fn rsi_read_key_response_error_return(err: LcsError) -> c_int {
    rsi_lookup_response_error_return(err)
}

fn rsi_query_values_response_error_return(err: LcsError) -> c_int {
    rsi_lookup_response_error_return(err)
}

fn rsi_enum_children_response_error_return(err: LcsError) -> c_int {
    rsi_lookup_response_error_return(err)
}

fn rsi_lookup_materialization_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::MissingBaseLayer
        | LcsError::InvalidBaseLayerProperties { .. }
        | LcsError::DuplicateLayerIdentity
        | LcsError::TooManyLayers { .. }
        | LcsError::TooManyPrivateLayers { .. }
        | LcsError::DuplicatePrivateLayerIdentity => LinuxErrno::Einval.negated_return() as c_int,
        _ => rsi_lookup_response_error_return(err),
    }
}

fn ioctl_access_gate_return(plan: crate::lcs_core::RegistryIoctlFdAccessGatePlan) -> c_int {
    match registry_ioctl_fd_access_gate_errno(&plan) {
        Some(errno) => errno.negated_return() as c_int,
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_open_preflight(
    desired_access: u32,
    flags: u32,
    plan_out: *mut PkmLcsOpenPreflightPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *plan_out = PkmLcsOpenPreflightPlanCopy {
            requested_access: 0,
            mapped_desired_access: 0,
            maximum_allowed: 0,
            path_resolution_allowed: 0,
            _pad: [0; 2],
        };
    }

    if validate_registry_open_flags(flags).is_err() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let plan = plan_registry_open_pre_resolution_access(desired_access);
    match plan {
        RegistryOpenPreResolutionAccessPlan::Continue {
            requested_access,
            mapped_desired_access,
            maximum_allowed,
            path_resolution_allowed,
        } => {
            unsafe {
                (*plan_out).requested_access = requested_access;
                (*plan_out).mapped_desired_access = mapped_desired_access;
                (*plan_out).maximum_allowed = maximum_allowed as u8;
                (*plan_out).path_resolution_allowed = path_resolution_allowed as u8;
            }
            0
        }
        RegistryOpenPreResolutionAccessPlan::Reject { .. } => {
            registry_open_pre_resolution_linux_errno(&plan)
                .unwrap_or(LinuxErrno::Einval)
                .negated_return() as c_int
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_key_create_flags(
    flags: u32,
    options_out: *mut PkmLcsKeyCreateOptionsCopy,
) -> c_int {
    if options_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *options_out = PkmLcsKeyCreateOptionsCopy {
            volatile_key: 0,
            symlink: 0,
            _pad: [0; 2],
        };
    }

    match validate_key_create_flags(flags) {
        Ok(options) => {
            unsafe {
                (*options_out).volatile_key = options.volatile as u8;
                (*options_out).symlink = options.symlink as u8;
            }
            0
        }
        Err(_) => LinuxErrno::Einval.negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_plan_key_guid_assignment(
    candidate_guid: *const [u8; 16],
    active_key_guids: *const [u8; 16],
    active_key_guid_count: usize,
    retired_key_guids: *const [u8; 16],
    retired_key_guid_count: usize,
    plan_out: *mut PkmLcsKeyGuidAssignmentPlanCopy,
) -> c_int {
    let Some(plan_out) = (unsafe { plan_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *plan_out = PkmLcsKeyGuidAssignmentPlanCopy {
        guid: [0; 16],
        assigned_by_lcs: 0,
        persist_in_key_record: 0,
        _pad: [0; 2],
    };

    let Some(candidate_guid) = (unsafe { candidate_guid.as_ref() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    let active_key_guids =
        match parse_key_guid_tracker(active_key_guids, active_key_guid_count) {
            Ok(guids) => guids,
            Err(errno) => return errno.negated_return() as c_int,
        };
    let retired_key_guids =
        match parse_key_guid_tracker(retired_key_guids, retired_key_guid_count) {
            Ok(guids) => guids,
            Err(errno) => return errno.negated_return() as c_int,
        };

    match plan_key_guid_assignment(KeyGuidAssignmentRequest {
        candidate_guid: *candidate_guid,
        active_key_guids,
        retired_key_guids,
    }) {
        Ok(plan) => {
            plan_out.guid = plan.guid;
            plan_out.assigned_by_lcs = plan.assigned_by_lcs as u8;
            plan_out.persist_in_key_record = plan.persist_in_key_record as u8;
            0
        }
        Err(_) => LinuxErrno::Eio.negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_admit_layer_target(
    layer_name: *const u8,
    layer_name_len: u32,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    plan_out: *mut PkmLcsLayerTargetAdmissionPlanCopy,
) -> c_int {
    let Some(plan_out) = (unsafe { plan_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *plan_out = PkmLcsLayerTargetAdmissionPlanCopy {
        precedence: 0,
        enabled: 0,
        _pad: [0; 3],
    };

    if layer_name.is_null() || (layer_count != 0 && layers.is_null()) {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };
    let target_layer = match str::from_utf8(layer_name_bytes) {
        Ok(name) => name,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    match plan_layer_target_admission(LayerTargetAdmissionInput {
        target_layer,
        layers: layer_views.as_slice(),
        limits: &limits,
    }) {
        Ok(plan) => {
            plan_out.precedence = plan.matched_layer.precedence;
            plan_out.enabled = plan.matched_layer.enabled as u8;
            0
        }
        Err(err) => layer_target_admission_linux_errno(&err)
            .unwrap_or_else(|| match err {
                LcsError::NameTooLong { .. } => LinuxErrno::Enametoolong,
                _ => LinuxErrno::Einval,
            })
            .negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_select_layer_metadata_sd(
    layer_name: *const u8,
    layer_name_len: u32,
    metadata: *const PkmLcsLayerMetadataSdViewCopy,
    metadata_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    selection_out: *mut PkmLcsLayerMetadataSdSelectionCopy,
) -> c_int {
    let Some(selection_out) = (unsafe { selection_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *selection_out = PkmLcsLayerMetadataSdSelectionCopy { index: 0, _pad: 0 };

    if layer_name.is_null() || (metadata_count != 0 && metadata.is_null()) {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };
    let target_layer = match validate_layer_name_bytes(layer_name_bytes, &limits) {
        Ok(name) => name,
        Err(LcsError::NameTooLong { .. }) => {
            return LinuxErrno::Enametoolong.negated_return() as c_int
        }
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };

    let mut matched_index = None;
    for index in 0..metadata_count {
        let raw = unsafe { &*metadata.add(index) };
        let name = match parse_layer_metadata_sd_view_name(raw, &limits) {
            Ok(name) => name,
            Err(errno) => return errno.negated_return() as c_int,
        };

        for previous_index in 0..index {
            let previous = unsafe { &*metadata.add(previous_index) };
            let previous_name = match parse_layer_metadata_sd_view_name(previous, &limits) {
                Ok(name) => name,
                Err(errno) => return errno.negated_return() as c_int,
            };
            if casefold_eq(previous_name, name) {
                return LinuxErrno::Eio.negated_return() as c_int;
            }
        }

        if casefold_eq(name, target_layer) {
            if raw.sd.is_null() || raw.sd_len == 0 {
                return LinuxErrno::Eio.negated_return() as c_int;
            }
            matched_index = Some(index);
        }
    }

    let Some(index) = matched_index else {
        return LinuxErrno::Eio.negated_return() as c_int;
    };
    if index > u32::MAX as usize {
        return LinuxErrno::Eio.negated_return() as c_int;
    }

    selection_out.index = index as u32;
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_layer_publication(
    layer_name: *const u8,
    layer_name_len: u32,
    metadata_key_guid: *const u8,
    metadata_security_descriptor: *const u8,
    metadata_security_descriptor_len: usize,
    precedence: u32,
    enabled: u8,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    if layer_name.is_null()
        || metadata_key_guid.is_null()
        || metadata_security_descriptor.is_null()
        || metadata_security_descriptor_len == 0
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if enabled > 1 {
        return LinuxErrno::Eio.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };
    let name = match str::from_utf8(layer_name_bytes) {
        Ok(name) => name,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    let mut guid = [0u8; 16];
    guid.copy_from_slice(unsafe { slice::from_raw_parts(metadata_key_guid, 16) });
    let sd = unsafe {
        slice::from_raw_parts(metadata_security_descriptor, metadata_security_descriptor_len)
    };

    match plan_layer_publication(
        &limits,
        LayerPublicationInput {
            name,
            precedence,
            enabled: enabled != 0,
            metadata_key_guid: guid,
            metadata_security_descriptor: sd,
        },
    ) {
        Ok(_) => 0,
        Err(LcsError::NameTooLong { .. }) => LinuxErrno::Enametoolong.negated_return() as c_int,
        Err(LcsError::NilLayerMetadataKeyGuid)
        | Err(LcsError::MalformedSecurityDescriptor { .. }) => {
            LinuxErrno::Eio.negated_return() as c_int
        }
        Err(_) => LinuxErrno::Einval.negated_return() as c_int,
    }
}

fn optional_layer_owner_slice<'a>(
    ptr: *const u8,
    len: usize,
    present: bool,
) -> Result<Option<&'a [u8]>, LinuxErrno> {
    if !present {
        return Ok(None);
    }
    if ptr.is_null() || len == 0 {
        return Err(LinuxErrno::Einval);
    }
    Ok(Some(unsafe { slice::from_raw_parts(ptr, len) }))
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_select_layer_owner(
    metadata_owner_sid: *const u8,
    metadata_owner_sid_len: usize,
    metadata_owner_present: bool,
    creator_sid: *const u8,
    creator_sid_len: usize,
    creator_present: bool,
    previous_owner_sid: *const u8,
    previous_owner_sid_len: usize,
    previous_owner_present: bool,
    metadata_security_descriptor: *const u8,
    metadata_security_descriptor_len: usize,
    metadata_security_descriptor_present: bool,
    is_new_layer: bool,
    selection_out: *mut PkmLcsLayerOwnerSelectionCopy,
) -> c_int {
    let Some(selection_out) = (unsafe { selection_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *selection_out = PkmLcsLayerOwnerSelectionCopy {
        owner_sid: core::ptr::null(),
        owner_sid_len: 0,
        source: 0,
        informational_only: 0,
        _pad: [0; 3],
    };

    let metadata_owner_sid = match optional_layer_owner_slice(
        metadata_owner_sid,
        metadata_owner_sid_len,
        metadata_owner_present,
    ) {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let creator_sid = match optional_layer_owner_slice(creator_sid, creator_sid_len, creator_present)
    {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let previous_known_good_owner_sid = match optional_layer_owner_slice(
        previous_owner_sid,
        previous_owner_sid_len,
        previous_owner_present,
    ) {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let metadata_security_descriptor = match optional_layer_owner_slice(
        metadata_security_descriptor,
        metadata_security_descriptor_len,
        metadata_security_descriptor_present,
    ) {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };

    match select_layer_owner(LayerOwnerSelectionInput {
        metadata_owner_sid,
        creator_sid,
        previous_known_good_owner_sid,
        metadata_security_descriptor,
        is_new_layer,
    }) {
        Ok(selection) => {
            selection_out.owner_sid = selection.owner_sid.as_ptr();
            selection_out.owner_sid_len = selection.owner_sid.len();
            selection_out.source = match selection.source {
                LayerOwnerSource::MetadataValue => 1,
                LayerOwnerSource::CreatorToken => 2,
                LayerOwnerSource::PreviousKnownGood => 3,
                LayerOwnerSource::MetadataSecurityDescriptorOwner => 4,
            };
            selection_out.informational_only = selection.informational_only as u8;
            0
        }
        Err(LcsError::MalformedLayerOwnerSid)
        | Err(LcsError::LayerOwnerUnavailable)
        | Err(LcsError::MalformedSecurityDescriptor { .. }) => {
            LinuxErrno::Eio.negated_return() as c_int
        }
        Err(_) => LinuxErrno::Einval.negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_layer_name_casefold_eq(
    left: *const u8,
    left_len: u32,
    right: *const u8,
    right_len: u32,
    limits: *const PkmLcsRuntimeLimitsCopy,
    equal_out: *mut u8,
) -> c_int {
    let Some(equal_out) = (unsafe { equal_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *equal_out = 0;

    if left.is_null() || right.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let left_bytes = unsafe { slice::from_raw_parts(left, left_len as usize) };
    let right_bytes = unsafe { slice::from_raw_parts(right, right_len as usize) };
    let left_name = match validate_layer_name_bytes(left_bytes, &limits) {
        Ok(name) => name,
        Err(LcsError::NameTooLong { .. }) => {
            return LinuxErrno::Enametoolong.negated_return() as c_int
        }
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    let right_name = match validate_layer_name_bytes(right_bytes, &limits) {
        Ok(name) => name,
        Err(LcsError::NameTooLong { .. }) => {
            return LinuxErrno::Enametoolong.negated_return() as c_int
        }
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };

    *equal_out = u8::from(casefold_eq(left_name, right_name));
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_value_name_casefold_eq(
    left: *const u8,
    left_len: u32,
    right: *const u8,
    right_len: u32,
    limits: *const PkmLcsRuntimeLimitsCopy,
    equal_out: *mut u8,
) -> c_int {
    let Some(equal_out) = (unsafe { equal_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *equal_out = 0;

    if left.is_null() || right.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let left_bytes = unsafe { slice::from_raw_parts(left, left_len as usize) };
    let right_bytes = unsafe { slice::from_raw_parts(right, right_len as usize) };
    let left_name = match validate_value_name_bytes(left_bytes, &limits) {
        Ok(name) => name,
        Err(LcsError::NameTooLong { .. }) => {
            return LinuxErrno::Enametoolong.negated_return() as c_int
        }
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    let right_name = match validate_value_name_bytes(right_bytes, &limits) {
        Ok(name) => name,
        Err(LcsError::NameTooLong { .. }) => {
            return LinuxErrno::Enametoolong.negated_return() as c_int
        }
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };

    *equal_out = u8::from(casefold_eq(left_name, right_name));
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_key_open_access_plan(
    subject_token: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired_access: u32,
    pip_type: u32,
    pip_trust: u32,
    caap_cache: *const c_void,
    plan_out: *mut PkmLcsKeyOpenAccessPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *plan_out = PkmLcsKeyOpenAccessPlanCopy {
            requested_access: 0,
            mapped_desired_access: 0,
            access_check_granted: 0,
            fd_granted_access: 0,
            allowed: 0,
            maximum_allowed: 0,
            key_open_sacl_audit_required: 0,
            audit_payload_failure_blocks_completion: 0,
            privilege_use_audit_required: 0,
            _pad: [0; 3],
        };
    }

    if subject_token.is_null() {
        return LinuxErrno::Eacces.negated_return() as c_int;
    }
    if sd_ptr.is_null() || sd_len == 0 || desired_access == 0 || caap_cache.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let sd_bytes = unsafe { slice::from_raw_parts(sd_ptr, sd_len) };
    let pip = crate::kacs_core::PipContext {
        pip_type,
        pip_trust,
    };
    match crate::caap_cache::with_caap_policies(caap_cache, |policies| {
        crate::token_runtime::with_access_check_resolved_from_token(
            subject_token,
            pip,
            policies,
            |resolved| {
                let conditional_context = crate::kacs_core::ConditionalContext {
                    device_groups: resolved.device_groups,
                    user_claims: resolved.user_claims,
                    device_claims: resolved.device_claims,
                    ..crate::kacs_core::ConditionalContext::default()
                };
                let plan = plan_registry_key_open_access(RegistryKeyOpenAccessInput {
                    key_sd: sd_bytes,
                    token: resolved.token,
                    desired_access,
                    pip,
                    conditional_context,
                    object_audit_context: None,
                    privilege_intent: 0,
                    caap_policies: resolved.policies,
                })
                .map_err(|err| key_open_access_error_return(err) as c_long)?;

                if !crate::token_runtime::mark_token_privileges_used(
                    subject_token,
                    plan.updated_privileges.used,
                ) {
                    return Err(LinuxErrno::Eacces.negated_return() as c_long);
                }

                unsafe {
                    (*plan_out).requested_access = plan.requested_access;
                    (*plan_out).mapped_desired_access = plan.mapped_desired_access;
                    (*plan_out).access_check_granted = plan.access_check_granted;
                    (*plan_out).fd_granted_access = plan.fd_granted_access.unwrap_or(0);
                    (*plan_out).allowed =
                        u8::from(plan.decision == RegistryOpenAccessDecision::Allowed);
                    (*plan_out).maximum_allowed = u8::from(plan.maximum_allowed);
                    (*plan_out).key_open_sacl_audit_required =
                        u8::from(plan.key_open_sacl_audit_required);
                    (*plan_out).audit_payload_failure_blocks_completion =
                        u8::from(plan.audit_payload_failure_blocks_completion);
                    (*plan_out).privilege_use_audit_required =
                        u8::from(plan.privilege_use_audit_required);
                }

                if plan.decision == RegistryOpenAccessDecision::Allowed {
                    Ok(0)
                } else {
                    Ok(LinuxErrno::Eacces.negated_return() as c_long)
                }
            },
        )
    }) {
        Ok(ret) => ret as c_int,
        Err(errno) => errno as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_key_open_audit_payload(
    caller: *const PkmLcsAuditCallerSummaryCopy,
    key_guid: *const u8,
    requested_access: u32,
    granted_access: u32,
    allowed: u8,
    sacl_match_flags: u32,
    output: *mut u8,
    output_len: usize,
    written_out: *mut usize,
) -> c_int {
    let Some(written_out) = (unsafe { written_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *written_out = 0;

    let Some(caller) = (unsafe { caller.as_ref() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    if key_guid.is_null() || allowed > 1 || caller.user_sid.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let user_sid = unsafe { slice::from_raw_parts(caller.user_sid, caller.user_sid_len) };
    let key_guid_bytes = unsafe { slice::from_raw_parts(key_guid, 16) };
    let mut key_guid_copy = [0u8; 16];
    key_guid_copy.copy_from_slice(key_guid_bytes);

    let caller_summary = LcsCallerTokenSummary {
        effective_token_guid: caller.effective_token_guid,
        true_token_guid: caller.true_token_guid,
        process_guid: caller.process_guid,
        user_sid,
        authentication_id: caller.authentication_id,
        token_id: caller.token_id,
        token_type: caller.token_type,
        impersonation_level: caller.impersonation_level,
        integrity_level: caller.integrity_level,
    };
    let decision = if allowed != 0 {
        LcsKeyOpenAuditDecision::Allowed
    } else {
        LcsKeyOpenAuditDecision::Denied
    };
    let record = match plan_key_open_audit_record(
        caller_summary,
        key_guid_copy,
        requested_access,
        granted_access,
        decision,
        sacl_match_flags,
    ) {
        Ok(record) => record,
        Err(err) => return key_open_audit_error_return(err),
    };
    let required_len = match crate::lcs_core::key_open_audit_payload_len(&record) {
        Ok(len) => len,
        Err(err) => return key_open_audit_error_return(err),
    };
    *written_out = required_len;

    if output.is_null() {
        return if output_len == 0 {
            0
        } else {
            LinuxErrno::Einval.negated_return() as c_int
        };
    }

    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };
    match write_key_open_audit_payload(&record, output) {
        Ok(plan) => {
            *written_out = plan.bytes;
            0
        }
        Err(err) => key_open_audit_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_backup_start_audit_payload(
    caller: *const PkmLcsAuditCallerSummaryCopy,
    key_guid: *const u8,
    output_fd: i32,
    output: *mut u8,
    output_len: usize,
    written_out: *mut usize,
) -> c_int {
    let Some(written_out) = (unsafe { written_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *written_out = 0;

    let Some(caller) = (unsafe { caller.as_ref() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    if key_guid.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let caller_summary = match audit_caller_summary_from_copy(caller) {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let key_guid_bytes = unsafe { slice::from_raw_parts(key_guid, 16) };
    let mut key_guid_copy = [0u8; 16];
    key_guid_copy.copy_from_slice(key_guid_bytes);

    let record = match plan_backup_start_audit_record(caller_summary, key_guid_copy, output_fd) {
        Ok(record) => record,
        Err(err) => return backup_audit_error_return(err),
    };
    let required_len = match backup_restore_start_audit_payload_len(&record) {
        Ok(len) => len,
        Err(err) => return backup_audit_error_return(err),
    };
    *written_out = required_len;

    if output.is_null() {
        return if output_len == 0 {
            0
        } else {
            LinuxErrno::Einval.negated_return() as c_int
        };
    }

    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };
    match write_backup_restore_start_audit_payload(&record, output) {
        Ok(plan) => {
            *written_out = plan.bytes;
            0
        }
        Err(err) => backup_audit_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_backup_complete_audit_payload(
    caller: *const PkmLcsAuditCallerSummaryCopy,
    key_guid: *const u8,
    result_errno: u32,
    output: *mut u8,
    output_len: usize,
    written_out: *mut usize,
) -> c_int {
    let Some(written_out) = (unsafe { written_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *written_out = 0;

    let Some(caller) = (unsafe { caller.as_ref() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    if key_guid.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let caller_summary = match audit_caller_summary_from_copy(caller) {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let key_guid_bytes = unsafe { slice::from_raw_parts(key_guid, 16) };
    let mut key_guid_copy = [0u8; 16];
    key_guid_copy.copy_from_slice(key_guid_bytes);

    let record =
        match plan_backup_complete_audit_record(caller_summary, key_guid_copy, result_errno) {
            Ok(record) => record,
            Err(err) => return backup_audit_error_return(err),
        };
    let required_len = match backup_restore_complete_audit_payload_len(&record) {
        Ok(len) => len,
        Err(err) => return backup_audit_error_return(err),
    };
    *written_out = required_len;

    if output.is_null() {
        return if output_len == 0 {
            0
        } else {
            LinuxErrno::Einval.negated_return() as c_int
        };
    }

    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };
    match write_backup_restore_complete_audit_payload(&record, output) {
        Ok(plan) => {
            *written_out = plan.bytes;
            0
        }
        Err(err) => backup_audit_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_backup_header_record_frame(
    dst: *mut u8,
    dst_len: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    format_version: u32,
    min_reader_version: u32,
    timestamp_ns: i64,
    root_guid: *const u8,
    hive_name: *const u8,
    hive_name_len: usize,
    written_out: *mut usize,
) -> c_int {
    let Some(written_out_ref) = (unsafe { written_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *written_out_ref = 0;
    if root_guid.is_null() || (hive_name_len != 0 && hive_name.is_null()) {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };
    let dst_bytes = match unsafe { backup_writer_dst(dst, dst_len) } {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let mut root_guid_copy = [0u8; 16];
    root_guid_copy.copy_from_slice(unsafe { slice::from_raw_parts(root_guid, 16) });
    let hive_name = if hive_name_len == 0 {
        ""
    } else {
        match str::from_utf8(unsafe { slice::from_raw_parts(hive_name, hive_name_len) }) {
            Ok(value) => value,
            Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
        }
    };

    match write_backup_header_record_frame(
        &limits,
        dst_bytes,
        format_version,
        min_reader_version,
        timestamp_ns,
        root_guid_copy,
        hive_name,
    ) {
        Ok(written) => {
            *written_out_ref = written;
            0
        }
        Err(err) => backup_writer_error_return(err, written_out),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_backup_key_record_frame(
    dst: *mut u8,
    dst_len: usize,
    guid: *const u8,
    volatile_key: u8,
    symlink: u8,
    security_descriptor: *const u8,
    security_descriptor_len: usize,
    last_write_time_ns: i64,
    written_out: *mut usize,
) -> c_int {
    let Some(written_out_ref) = (unsafe { written_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *written_out_ref = 0;
    if guid.is_null()
        || security_descriptor.is_null()
        || security_descriptor_len == 0
        || volatile_key > 1
        || symlink > 1
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = match unsafe { backup_writer_dst(dst, dst_len) } {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let mut guid_copy = [0u8; 16];
    guid_copy.copy_from_slice(unsafe { slice::from_raw_parts(guid, 16) });
    let sd = unsafe { slice::from_raw_parts(security_descriptor, security_descriptor_len) };

    match write_backup_key_record_frame(
        dst_bytes,
        guid_copy,
        volatile_key != 0,
        symlink != 0,
        sd,
        last_write_time_ns,
    ) {
        Ok(written) => {
            *written_out_ref = written;
            0
        }
        Err(err) => backup_writer_error_return(err, written_out),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_backup_trailer_record_frame(
    dst: *mut u8,
    dst_len: usize,
    record_count: u64,
    checksum: *const u8,
    written_out: *mut usize,
) -> c_int {
    let Some(written_out_ref) = (unsafe { written_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *written_out_ref = 0;
    if checksum.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = match unsafe { backup_writer_dst(dst, dst_len) } {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let mut checksum_copy = [0u8; 32];
    checksum_copy.copy_from_slice(unsafe { slice::from_raw_parts(checksum, 32) });

    match write_backup_trailer_record_frame(dst_bytes, record_count, checksum_copy) {
        Ok(written) => {
            *written_out_ref = written;
            0
        }
        Err(err) => backup_writer_error_return(err, written_out),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_source_validation_failure_audit_payload(
    source_slot: u32,
    hive_name: *const u8,
    hive_name_len: usize,
    hive_name_present: u8,
    request_id: u64,
    request_id_present: u8,
    op_code: u16,
    op_code_present: u8,
    key_guid: *const u8,
    key_guid_present: u8,
    validation_failure: u32,
    output: *mut u8,
    output_len: usize,
    written_out: *mut usize,
) -> c_int {
    let Some(written_out) = (unsafe { written_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *written_out = 0;

    if hive_name_present > 1
        || request_id_present > 1
        || op_code_present > 1
        || key_guid_present > 1
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let hive_name = if hive_name_present != 0 {
        if hive_name.is_null() || hive_name_len == 0 {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let bytes = unsafe { slice::from_raw_parts(hive_name, hive_name_len) };
        match str::from_utf8(bytes) {
            Ok(value) => Some(value),
            Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
        }
    } else {
        if !hive_name.is_null() || hive_name_len != 0 {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        None
    };

    let key_guid = if key_guid_present != 0 {
        if key_guid.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let bytes = unsafe { slice::from_raw_parts(key_guid, 16) };
        let mut copy = [0u8; 16];
        copy.copy_from_slice(bytes);
        Some(copy)
    } else {
        None
    };

    let validation_failure = match source_validation_failure_from_code(validation_failure) {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let record = match plan_source_validation_failure_audit_record(
        &LcsLimits::default(),
        source_slot,
        hive_name,
        if request_id_present != 0 {
            Some(request_id)
        } else {
            None
        },
        if op_code_present != 0 {
            Some(op_code)
        } else {
            None
        },
        key_guid,
        validation_failure,
    ) {
        Ok(record) => record,
        Err(err) => return source_validation_audit_error_return(err),
    };
    let required_len = match source_validation_failure_audit_payload_len(&record) {
        Ok(len) => len,
        Err(err) => return source_validation_audit_error_return(err),
    };
    *written_out = required_len;

    if output.is_null() {
        return if output_len == 0 {
            0
        } else {
            LinuxErrno::Einval.negated_return() as c_int
        };
    }

    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };
    match write_source_validation_failure_audit_payload(&record, output) {
        Ok(plan) => {
            *written_out = plan.bytes;
            0
        }
        Err(err) => source_validation_audit_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_plan_self_config_apply(
    current_limits: *const PkmLcsRuntimeLimitsCopy,
    entries: *const PkmLcsSelfConfigEntryCopy,
    entry_count: usize,
    plan_out: *mut PkmLcsSelfConfigApplyPlanCopy,
) -> c_int {
    let Some(plan_out) = (unsafe { plan_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *plan_out = empty_self_config_apply_plan();

    let current = match lcs_limits_from_copy(current_limits) {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    if entry_count > isize::MAX as usize {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if entry_count > 0 && entries.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let entries = if entry_count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(entries, entry_count) }
    };

    let mut limits = current;
    let mut applied_count = 0u32;
    let mut retained_missing_count = 0u32;
    let mut retained_invalid_count = 0u32;
    let mut ignored_unknown_count = 0u32;
    let mut audit_count = 0usize;
    let mut audits = [PkmLcsSelfConfigAuditIntentCopy::ZERO; PKM_LCS_SELF_CONFIG_MAX_AUDITS];

    for entry in entries {
        let name = match self_config_entry_name(entry) {
            Ok(value) => value,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if find_config_range(name).is_none() {
            ignored_unknown_count = match ignored_unknown_count.checked_add(1) {
                Some(value) => value,
                None => return LinuxErrno::Einval.negated_return() as c_int,
            };
        }
    }

    for range in LCS_CONFIG_RANGES {
        let observed = match self_config_observed_value(entries, range.name) {
            Ok(value) => value,
            Err(errno) => return errno.negated_return() as c_int,
        };

        match observed {
            Some(SelfConfigValue::Dword(value)) => match validate_config_value(range, value) {
                Ok(value) => {
                    apply_config_value(&mut limits, range, value);
                    applied_count += 1;
                }
                Err(_) => {
                    retained_invalid_count += 1;
                    if audit_count >= audits.len() {
                        return LinuxErrno::Einval.negated_return() as c_int;
                    }
                    match write_self_config_audit_intent(
                        &current,
                        range,
                        observed,
                        &mut audits[audit_count],
                    ) {
                        Ok(true) => {}
                        Ok(false) | Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
                    }
                    audit_count += 1;
                }
            },
            Some(SelfConfigValue::WrongType { .. }) => {
                retained_invalid_count += 1;
                if audit_count >= audits.len() {
                    return LinuxErrno::Einval.negated_return() as c_int;
                }
                match write_self_config_audit_intent(
                    &current,
                    range,
                    observed,
                    &mut audits[audit_count],
                ) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
                }
                audit_count += 1;
            }
            None => {
                retained_missing_count += 1;
                if audit_count >= audits.len() {
                    return LinuxErrno::Einval.negated_return() as c_int;
                }
                match write_self_config_audit_intent(
                    &current,
                    range,
                    None,
                    &mut audits[audit_count],
                ) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
                }
                audit_count += 1;
            }
        }
    }

    *plan_out = PkmLcsSelfConfigApplyPlanCopy {
        limits: lcs_limits_to_copy(limits),
        applied_count,
        retained_missing_count,
        retained_invalid_count,
        ignored_unknown_count,
        audit_count: audit_count as u32,
        audits,
    };
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_plan_self_config_apply_from_query_values(
    current_limits: *const PkmLcsRuntimeLimitsCopy,
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    plan_out: *mut PkmLcsSelfConfigApplyPlanCopy,
) -> c_int {
    let Some(plan_out) = (unsafe { plan_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *plan_out = empty_self_config_apply_plan();

    if frame.is_null()
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let current = match lcs_limits_from_copy(current_limits) {
        Ok(value) => value,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let payload = match parse_rsi_query_values_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_query_values_response_error_return(err),
    };

    if let Err(err) = validate_rsi_query_values_response_names(&payload, &current) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_value_payloads(&payload, &current) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_sequences(&payload, next_sequence) {
        return rsi_query_values_response_error_return(err);
    }

    let mut value_storage =
        match PkmVec::<NamedValueEntry<'_>>::with_capacity(payload.entry_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut blanket_storage =
        match PkmVec::<BlanketTombstoneEntry<'_>>::with_capacity(payload.blanket_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut observed_storage =
        match PkmVec::<ObservedSelfConfigValue<'_>>::with_capacity(payload.entry_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };

    let mut allocation_failed = false;
    if let Err(err) = for_each_rsi_query_values_source_value_entry(&payload, &current, |entry| {
        if value_storage.push(entry).is_err() {
            allocation_failed = true;
            return Err(LcsError::RsiPayloadLengthOverflow);
        }
        Ok(())
    }) {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = for_each_rsi_query_values_source_blanket_entry(&payload, &current, |entry| {
        if blanket_storage.push(entry).is_err() {
            allocation_failed = true;
            return Err(LcsError::RsiPayloadLengthOverflow);
        }
        Ok(())
    }) {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }

    let context = LayerResolutionContext {
        layers: layer_views.as_slice(),
        private_layers: private_layer_views.as_slice(),
        limits: &current,
        next_sequence,
    };
    if let Err(err) = for_each_effective_value(
        &context,
        value_storage.as_slice(),
        blanket_storage.as_slice(),
        |value| {
            if observed_storage
                .push(ObservedSelfConfigValue {
                    name: value.name,
                    value: effective_value_to_self_config(value),
                })
                .is_err()
            {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        },
    ) {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_lookup_materialization_error_return(err);
    }

    match write_self_config_plan_from_observed(current, observed_storage.as_slice(), plan_out) {
        Ok(()) => 0,
        Err(errno) => errno.negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_self_config_invalid_audit_payload(
    configuration_name: *const u8,
    configuration_name_len: usize,
    received_kind: u32,
    received_type: u32,
    received_u32: u32,
    retained_value: u32,
    output: *mut u8,
    output_len: usize,
    written_out: *mut usize,
) -> c_int {
    let Some(written_out) = (unsafe { written_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *written_out = 0;

    if configuration_name.is_null() || configuration_name_len == 0 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let name_bytes = unsafe { slice::from_raw_parts(configuration_name, configuration_name_len) };
    let name = match str::from_utf8(name_bytes) {
        Ok(value) => value,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    let Some(range) = find_config_range(name) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    if retained_value < range.min || retained_value > range.max {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let received = match received_kind {
        PKM_LCS_SELF_CONFIG_RECEIVED_MISSING => {
            if received_type != 0 || received_u32 != 0 {
                return LinuxErrno::Einval.negated_return() as c_int;
            }
            LcsSelfConfigReceivedValue::Missing
        }
        PKM_LCS_SELF_CONFIG_RECEIVED_WRONG_TYPE => {
            if received_type == REG_DWORD || received_u32 != 0 {
                return LinuxErrno::Einval.negated_return() as c_int;
            }
            LcsSelfConfigReceivedValue::WrongType {
                actual_type: received_type,
            }
        }
        PKM_LCS_SELF_CONFIG_RECEIVED_DWORD_OUT_OF_RANGE => {
            if received_type != 0 || (received_u32 >= range.min && received_u32 <= range.max) {
                return LinuxErrno::Einval.negated_return() as c_int;
            }
            LcsSelfConfigReceivedValue::DwordOutOfRange {
                value: received_u32,
            }
        }
        _ => return LinuxErrno::Einval.negated_return() as c_int,
    };

    let record = LcsSelfConfigInvalidAuditRecord {
        event_kind: LcsAuditEventKind::SelfConfigInvalid,
        configuration_parent_path: LCS_CONFIG_ROOT_PATH,
        configuration_name: range.name,
        expected_type: REG_DWORD,
        expected_min: range.min,
        expected_max: range.max,
        received,
        retained_value,
    };
    let required_len = match self_config_invalid_audit_payload_len(&record) {
        Ok(len) => len,
        Err(err) => return self_config_invalid_audit_error_return(err),
    };
    *written_out = required_len;

    if output.is_null() {
        return if output_len == 0 {
            0
        } else {
            LinuxErrno::Einval.negated_return() as c_int
        };
    }

    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };
    match write_self_config_invalid_audit_payload(&record, output) {
        Ok(plan) => {
            *written_out = plan.bytes;
            0
        }
        Err(err) => self_config_invalid_audit_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_watch_event_record(
    event_type: u32,
    name: *const u8,
    name_len: usize,
    subtree: u8,
    path_components: *const PkmLcsKeyFdStringViewCopy,
    path_component_count: usize,
    output: *mut u8,
    output_len: usize,
    written_out: *mut u32,
    overflow_out: *mut u8,
) -> c_int {
    if written_out.is_null() || overflow_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    unsafe {
        *written_out = 0;
        *overflow_out = 0;
    }
    if name_len != 0 && name.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if path_component_count != 0 && path_components.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if output.is_null() && output_len != 0 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let subtree = match subtree {
        0 => false,
        1 => true,
        _ => return LinuxErrno::Einval.negated_return() as c_int,
    };

    let name_bytes = if name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(name, name_len) }
    };
    let name = match str::from_utf8(name_bytes) {
        Ok(name) => name,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };

    let mut parsed_components = match PkmVec::with_capacity(path_component_count) {
        Ok(parsed_components) => parsed_components,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for index in 0..path_component_count {
        let raw = unsafe { &*path_components.add(index) };
        if raw.bytes.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let bytes = unsafe { slice::from_raw_parts(raw.bytes, raw.len as usize) };
        let component = match str::from_utf8(bytes) {
            Ok(component) => component,
            Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
        };
        if parsed_components.push(component).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let request = WatchEventRecordRequest {
        event_type,
        name,
        subtree,
        path_components: parsed_components.as_slice(),
    };

    let required_len = match plan_watch_event_record(&request) {
        Ok(WatchEventRecordPlan::Record(shape)) => shape.total_len,
        Ok(WatchEventRecordPlan::OverflowInstead) => {
            unsafe {
                *overflow_out = 1;
            }
            return 0;
        }
        Err(err) => return watch_event_record_error_return(err),
    };
    unsafe {
        *written_out = required_len;
    }

    if output.is_null() {
        return 0;
    }

    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };
    match write_watch_event_record(&request, output) {
        Ok(WatchEventRecordWritePlan::Written { bytes }) => {
            if bytes > u32::MAX as usize {
                return LinuxErrno::Eoverflow.negated_return() as c_int;
            }
            unsafe {
                *written_out = bytes as u32;
            }
            0
        }
        Ok(WatchEventRecordWritePlan::OverflowInstead) => {
            unsafe {
                *written_out = 0;
                *overflow_out = 1;
            }
            0
        }
        Err(err) => watch_event_record_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_key_fd_open_view(
    key_guid: *const u8,
    granted_access: u32,
    path_components: *const PkmLcsKeyFdStringViewCopy,
    path_component_count: usize,
    ancestor_guids: *const [u8; 16],
    ancestor_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    if key_guid.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if path_component_count != 0 && path_components.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if ancestor_count != 0 && ancestor_guids.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let key_guid_bytes = unsafe { slice::from_raw_parts(key_guid, 16) };
    let mut key_guid_copy = [0u8; 16];
    key_guid_copy.copy_from_slice(key_guid_bytes);

    let mut parsed_components = match PkmVec::with_capacity(path_component_count) {
        Ok(parsed_components) => parsed_components,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };

    for index in 0..path_component_count {
        let raw = unsafe { &*path_components.add(index) };
        if raw.bytes.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }

        let bytes = unsafe { slice::from_raw_parts(raw.bytes, raw.len as usize) };
        let component = match str::from_utf8(bytes) {
            Ok(component) => component,
            Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
        };
        if parsed_components.push(component).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let ancestors = if ancestor_count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ancestor_guids, ancestor_count) }
    };
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let fd = KeyFdOpenView {
        key_guid: key_guid_copy,
        granted_access,
        resolved_path: parsed_components.as_slice(),
        ancestor_guids: ancestors,
        watch_state: KeyWatchState {
            armed: false,
            orphaned: false,
        },
    };

    match validate_key_fd_open_view(&limits, &fd) {
        Ok(()) => 0,
        Err(err) => key_fd_open_view_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_plan_key_fd_watch_notify(
    armed: u8,
    orphaned: u8,
    filter: u32,
    subtree: u8,
    reserved: *const u8,
    plan_out: *mut PkmLcsWatchNotifyPlanCopy,
) -> c_int {
    if reserved.is_null() || plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let armed = match armed {
        0 => false,
        1 => true,
        _ => return LinuxErrno::Einval.negated_return() as c_int,
    };
    let orphaned = match orphaned {
        0 => false,
        1 => true,
        _ => return LinuxErrno::Einval.negated_return() as c_int,
    };

    let reserved = unsafe { slice::from_raw_parts(reserved, 3) };
    let mut reserved_copy = [0u8; 3];
    reserved_copy.copy_from_slice(reserved);

    unsafe {
        *plan_out = PkmLcsWatchNotifyPlanCopy {
            action: 0,
            filter: 0,
            subtree: 0,
            replaces_existing: 0,
            discard_pending_events: 0,
            _pad: 0,
        };
    }

    let state = KeyWatchState { armed, orphaned };
    let args = WatchNotifyArgs {
        filter,
        subtree,
        reserved: reserved_copy,
    };

    match plan_watch_notify(state, &args) {
        Ok(WatchNotifyPlan::Arm {
            filter,
            subtree,
            replaces_existing,
        }) => unsafe {
            *plan_out = PkmLcsWatchNotifyPlanCopy {
                action: PKM_LCS_WATCH_NOTIFY_ACTION_ARM,
                filter,
                subtree: subtree as u8,
                replaces_existing: replaces_existing as u8,
                discard_pending_events: 0,
                _pad: 0,
            };
            0
        },
        Ok(WatchNotifyPlan::Disarm {
            discard_pending_events,
        }) => unsafe {
            *plan_out = PkmLcsWatchNotifyPlanCopy {
                action: PKM_LCS_WATCH_NOTIFY_ACTION_DISARM,
                filter: 0,
                subtree: 0,
                replaces_existing: 0,
                discard_pending_events: discard_pending_events as u8,
                _pad: 0,
            };
            0
        },
        Err(err) => watch_notify_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_syscall_relative_path(
    path: *const u8,
    path_len: u32,
    result_out: *mut PkmLcsPathValidationResultCopy,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    if path.is_null() || result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    unsafe {
        *result_out = PkmLcsPathValidationResultCopy {
            component_count: 0,
            used_forward_separator: false,
            _pad: [0; 3],
        };
    }

    let path_bytes = unsafe { slice::from_raw_parts(path, path_len as usize) };
    match validate_syscall_path_c_string(path_bytes, PathKind::Relative, &limits) {
        Ok(summary) => {
            unsafe {
                (*result_out).component_count = summary.component_count as u32;
                (*result_out).used_forward_separator = summary.used_forward_separator;
            }
            0
        }
        Err(err) => absolute_route_error_return(err),
    }
}

#[no_mangle]
pub extern "C" fn lcs_rust_validate_relative_open_depth(
    parent_depth: u32,
    relative_component_count: u32,
) -> c_int {
    match validate_resolved_relative_path_depth(
        parent_depth as usize,
        relative_component_count as usize,
        &LcsLimits::DEFAULT,
    ) {
        Ok(_) => 0,
        Err(err) => absolute_route_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_lookup_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    parent_guid: *const u8,
    child_name: *const u8,
    child_name_len: u32,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || parent_guid.is_null() || child_name.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let parent_guid_bytes = unsafe { slice::from_raw_parts(parent_guid, 16) };
    let mut parent_guid_copy = [0u8; 16];
    parent_guid_copy.copy_from_slice(parent_guid_bytes);

    let child_name_bytes = unsafe { slice::from_raw_parts(child_name, child_name_len as usize) };
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };
    if let Err(err) = validate_key_component_bytes(child_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_lookup_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        parent_guid_copy,
        child_name_bytes,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_enum_children_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    parent_guid: *const u8,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || parent_guid.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let parent_guid_bytes = unsafe { slice::from_raw_parts(parent_guid, 16) };
    let mut parent_guid_copy = [0u8; 16];
    parent_guid_copy.copy_from_slice(parent_guid_bytes);

    match write_rsi_enum_children_request_frame(dst_bytes, request_id, txn_id, parent_guid_copy) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_read_key_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    guid: *const u8,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || guid.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    let mut guid_copy = [0u8; 16];
    guid_copy.copy_from_slice(guid_bytes);

    match write_rsi_read_key_request_frame(dst_bytes, request_id, txn_id, guid_copy) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_query_values_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    guid: *const u8,
    value_name: *const u8,
    value_name_len: u32,
    query_all: u8,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || guid.is_null() || (value_name_len != 0 && value_name.is_null()) {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if query_all > 1 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    let mut guid_copy = [0u8; 16];
    guid_copy.copy_from_slice(guid_bytes);
    let value_name_bytes = if value_name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value_name, value_name_len as usize) }
    };
    if let Err(err) = validate_value_name_bytes(value_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_query_values_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        guid_copy,
        value_name_bytes,
        query_all != 0,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_set_value_user_shape(
	guid: *const u8,
    value_name: *const u8,
    value_name_len: u32,
    layer_name: *const u8,
    layer_name_len: u32,
    value_type: u32,
    data_len: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    if guid.is_null()
        || (value_name_len != 0 && value_name.is_null())
        || layer_name.is_null()
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    if guid_bytes.iter().all(|byte| *byte == 0) {
        return public_set_value_validation_error_return(LcsError::NilKeyGuid);
    }

    let value_name_bytes = if value_name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value_name, value_name_len as usize) }
    };
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };

    if let Err(err) = validate_value_name_bytes(value_name_bytes, &limits) {
        return public_set_value_validation_error_return(err);
    }
    if let Err(err) = validate_layer_name_bytes(layer_name_bytes, &limits) {
        return public_set_value_validation_error_return(err);
    }
    if let Err(err) = validate_value_data_len(data_len, &limits) {
        return public_set_value_validation_error_return(err);
    }
    if let Err(err) = validate_value_write_type(value_type, data_len, true) {
        return public_set_value_validation_error_return(err);
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_delete_value_user_shape(
    guid: *const u8,
    value_name: *const u8,
    value_name_len: u32,
    layer_name: *const u8,
    layer_name_len: u32,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    if guid.is_null()
        || (value_name_len != 0 && value_name.is_null())
        || layer_name.is_null()
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    if guid_bytes.iter().all(|byte| *byte == 0) {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let value_name_bytes = if value_name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value_name, value_name_len as usize) }
    };
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };

    if let Err(err) = validate_value_name_bytes(value_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }
    if let Err(err) = validate_layer_name_bytes(layer_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_plan_set_value_layer_admission(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    value_name: *const u8,
    value_name_len: u32,
    layer_name: *const u8,
    layer_name_len: u32,
    limits: *const PkmLcsRuntimeLimitsCopy,
    result_out: *mut PkmLcsValueLayerAdmissionResultCopy,
) -> c_int {
    let Some(result_out) = (unsafe { result_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *result_out = PkmLcsValueLayerAdmissionResultCopy {
        current_distinct_layers: 0,
        replacing_existing_layer_entry: 0,
        _pad: [0; 3],
    };

    if frame.is_null()
        || (value_name_len != 0 && value_name.is_null())
        || layer_name.is_null()
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let value_name_bytes = if value_name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value_name, value_name_len as usize) }
    };
    let requested_name = match validate_value_name_bytes(value_name_bytes, &limits) {
        Ok(name) => name,
        Err(err) => return public_set_value_validation_error_return(err),
    };
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };
    let target_layer = match validate_layer_name_bytes(layer_name_bytes, &limits) {
        Ok(layer) => layer,
        Err(err) => return public_set_value_validation_error_return(err),
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let payload = match parse_rsi_query_values_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_query_values_response_error_return(err),
    };
    if let Err(err) = validate_rsi_query_values_response_names(&payload, &limits) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) =
        validate_rsi_query_values_response_value_payloads(&payload, &limits)
    {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_sequences(&payload, next_sequence) {
        return rsi_query_values_response_error_return(err);
    }

    let mut distinct_layers = match PkmVec::<&str>::with_capacity(payload.entry_count as usize) {
        Ok(layers) => layers,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    let mut replacing_existing_layer_entry = false;
    let mut allocation_failed = false;
    let mut malformed = false;

    if let Err(err) =
        for_each_rsi_query_values_source_value_entry(&payload, &limits, |entry| {
            if !casefold_eq(entry.name, requested_name) {
                malformed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            for existing in distinct_layers.as_slice() {
                if casefold_eq(*existing, entry.entry.layer) {
                    malformed = true;
                    return Err(LcsError::RsiPayloadLengthOverflow);
                }
            }
            if casefold_eq(entry.entry.layer, target_layer) {
                replacing_existing_layer_entry = true;
            }
            if distinct_layers.push(entry.entry.layer).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        if malformed {
            return LinuxErrno::Eio.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }

    let current_distinct_layers = distinct_layers.len();
    if current_distinct_layers > u32::MAX as usize {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    if let Err(err) = plan_value_layer_admission(
        &limits,
        ValueLayerAdmissionInput {
            current_distinct_layers,
            replacing_existing_layer_entry,
        },
    ) {
        return value_layer_admission_linux_errno(&err)
            .unwrap_or(LinuxErrno::Einval)
            .negated_return() as c_int;
    }

    result_out.current_distinct_layers = current_distinct_layers as u32;
    result_out.replacing_existing_layer_entry = replacing_existing_layer_entry as u8;
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_set_value_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    guid: *const u8,
    value_name: *const u8,
    value_name_len: u32,
    layer_name: *const u8,
    layer_name_len: u32,
    value_type: u32,
    data: *const u8,
    data_len: usize,
    sequence: u64,
    expected_sequence: u64,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null()
        || guid.is_null()
        || (value_name_len != 0 && value_name.is_null())
        || layer_name.is_null()
        || (data_len != 0 && data.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    let mut guid_copy = [0u8; 16];
    guid_copy.copy_from_slice(guid_bytes);
    let value_name_bytes = if value_name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value_name, value_name_len as usize) }
    };
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };
    let data_bytes = if data_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data, data_len) }
    };

    if let Err(err) = validate_value_name_bytes(value_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }
    if let Err(err) = validate_layer_name_bytes(layer_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }
    if let Err(err) = validate_value_write_type(value_type, data_bytes.len(), true) {
        return rsi_request_frame_error_return(err);
    }
    if let Err(err) = validate_value_data_len(data_bytes.len(), &limits) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_set_value_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        guid_copy,
        value_name_bytes,
        layer_name_bytes,
        value_type,
        data_bytes,
        sequence,
        expected_sequence,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_delete_value_entry_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    guid: *const u8,
    value_name: *const u8,
    value_name_len: u32,
    layer_name: *const u8,
    layer_name_len: u32,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null()
        || guid.is_null()
        || (value_name_len != 0 && value_name.is_null())
        || layer_name.is_null()
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    let mut guid_copy = [0u8; 16];
    guid_copy.copy_from_slice(guid_bytes);
    let value_name_bytes = if value_name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value_name, value_name_len as usize) }
    };
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };

    if let Err(err) = validate_value_name_bytes(value_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }
    if let Err(err) = validate_layer_name_bytes(layer_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_delete_value_entry_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        guid_copy,
        value_name_bytes,
        layer_name_bytes,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_set_blanket_tombstone_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    guid: *const u8,
    layer_name: *const u8,
    layer_name_len: u32,
    set: u8,
    sequence: u64,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || guid.is_null() || layer_name.is_null() || set > 1 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    let mut guid_copy = [0u8; 16];
    guid_copy.copy_from_slice(guid_bytes);
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };

    if let Err(err) = validate_layer_name_bytes(layer_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_set_blanket_tombstone_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        guid_copy,
        layer_name_bytes,
        set != 0,
        sequence,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_create_entry_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    parent_guid: *const u8,
    child_name: *const u8,
    child_name_len: u32,
    layer_name: *const u8,
    layer_name_len: u32,
    child_guid: *const u8,
    sequence: u64,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null()
        || parent_guid.is_null()
        || child_name.is_null()
        || layer_name.is_null()
        || child_guid.is_null()
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let parent_guid_bytes = unsafe { slice::from_raw_parts(parent_guid, 16) };
    let child_guid_bytes = unsafe { slice::from_raw_parts(child_guid, 16) };
    let mut parent_guid_copy = [0u8; 16];
    let mut child_guid_copy = [0u8; 16];
    parent_guid_copy.copy_from_slice(parent_guid_bytes);
    child_guid_copy.copy_from_slice(child_guid_bytes);

    let child_name_bytes = unsafe { slice::from_raw_parts(child_name, child_name_len as usize) };
    if let Err(err) = validate_key_component_bytes(child_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };
    if let Err(err) = validate_layer_name_bytes(layer_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_create_entry_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        parent_guid_copy,
        child_name_bytes,
        layer_name_bytes,
        child_guid_copy,
        sequence,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_hide_entry_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    parent_guid: *const u8,
    child_name: *const u8,
    child_name_len: u32,
    layer_name: *const u8,
    layer_name_len: u32,
    sequence: u64,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || parent_guid.is_null() || child_name.is_null() || layer_name.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let parent_guid_bytes = unsafe { slice::from_raw_parts(parent_guid, 16) };
    let mut parent_guid_copy = [0u8; 16];
    parent_guid_copy.copy_from_slice(parent_guid_bytes);

    let child_name_bytes = unsafe { slice::from_raw_parts(child_name, child_name_len as usize) };
    if let Err(err) = validate_key_component_bytes(child_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };
    if let Err(err) = validate_layer_name_bytes(layer_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_hide_entry_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        parent_guid_copy,
        child_name_bytes,
        layer_name_bytes,
        sequence,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_delete_entry_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    parent_guid: *const u8,
    child_name: *const u8,
    child_name_len: u32,
    layer_name: *const u8,
    layer_name_len: u32,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || parent_guid.is_null() || child_name.is_null() || layer_name.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let parent_guid_bytes = unsafe { slice::from_raw_parts(parent_guid, 16) };
    let mut parent_guid_copy = [0u8; 16];
    parent_guid_copy.copy_from_slice(parent_guid_bytes);

    let child_name_bytes = unsafe { slice::from_raw_parts(child_name, child_name_len as usize) };
    if let Err(err) = validate_key_component_bytes(child_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };
    if let Err(err) = validate_layer_name_bytes(layer_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_delete_entry_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        parent_guid_copy,
        child_name_bytes,
        layer_name_bytes,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_create_key_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    guid: *const u8,
    name: *const u8,
    name_len: u32,
    parent_guid: *const u8,
    sd: *const u8,
    sd_len: usize,
    volatile_key: u8,
    symlink: u8,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null()
        || guid.is_null()
        || name.is_null()
        || parent_guid.is_null()
        || sd.is_null()
        || sd_len == 0
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if volatile_key > 1 || symlink > 1 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(err) => return err.negated_return() as c_int,
    };

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    let parent_guid_bytes = unsafe { slice::from_raw_parts(parent_guid, 16) };
    let mut guid_copy = [0u8; 16];
    let mut parent_guid_copy = [0u8; 16];
    guid_copy.copy_from_slice(guid_bytes);
    parent_guid_copy.copy_from_slice(parent_guid_bytes);

    let name_bytes = unsafe { slice::from_raw_parts(name, name_len as usize) };
    if let Err(err) = validate_key_component_bytes(name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }
    let sd_bytes = unsafe { slice::from_raw_parts(sd, sd_len) };

    match write_rsi_create_key_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        guid_copy,
        name_bytes,
        parent_guid_copy,
        sd_bytes,
        volatile_key != 0,
        symlink != 0,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_write_key_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    guid: *const u8,
    sd: *const u8,
    sd_len: usize,
    last_write_time: u64,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null()
        || guid.is_null()
        || (sd_len != 0 && sd.is_null())
        || (sd_len == 0 && !sd.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    let mut guid_copy = [0u8; 16];
    guid_copy.copy_from_slice(guid_bytes);
    let sd_bytes = if sd_len == 0 {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(sd, sd_len) })
    };

    match write_rsi_write_key_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        guid_copy,
        sd_bytes,
        Some(last_write_time),
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_begin_transaction_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    transaction_id: u64,
    mode: u32,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let Some(mode) = RsiTransactionMode::from_code(mode) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    match write_rsi_begin_transaction_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        transaction_id,
        mode,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_commit_transaction_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    transaction_id: u64,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    match write_rsi_commit_transaction_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        transaction_id,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_abort_transaction_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    transaction_id: u64,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    match write_rsi_abort_transaction_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        transaction_id,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_delete_layer_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    layer_name: *const u8,
    layer_name_len: u32,
    limits: *const PkmLcsRuntimeLimitsCopy,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || layer_name.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let layer_name_bytes = unsafe { slice::from_raw_parts(layer_name, layer_name_len as usize) };
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };
    if let Err(err) = validate_layer_name_bytes(layer_name_bytes, &limits) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_delete_layer_request_frame(dst_bytes, request_id, txn_id, layer_name_bytes) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_flush_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    hive_name: *const u8,
    hive_name_len: u32,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || hive_name.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let hive_name_bytes = unsafe { slice::from_raw_parts(hive_name, hive_name_len as usize) };
    match write_rsi_flush_request_frame(dst_bytes, request_id, txn_id, hive_name_bytes) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_drop_key_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    guid: *const u8,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || guid.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let guid_bytes = unsafe { slice::from_raw_parts(guid, 16) };
    let mut guid_copy = [0u8; 16];
    guid_copy.copy_from_slice(guid_bytes);
    match write_rsi_drop_key_request_frame(dst_bytes, request_id, txn_id, guid_copy) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_rsi_queued_request_frame(
    frame: *const u8,
    frame_len: usize,
    retained_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if retained_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *retained_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if frame.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    match rsi_queued_request_from_frame(frame_bytes) {
        Ok(request) => {
            let header = match parse_rsi_request_header(frame_bytes) {
                Ok(header) => header,
                Err(err) => return rsi_request_frame_error_return(err),
            };
            unsafe {
                *retained_out = PkmLcsRsiBuiltRequestCopy {
                    len: request.frame.len(),
                    request_id: request.retained.request_id,
                    txn_id: header.txn_id,
                    op_code: request.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_rsi_lookup_response_frame(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    limits: *const PkmLcsRuntimeLimitsCopy,
    summary_out: *mut PkmLcsRsiLookupResponseSummaryCopy,
) -> c_int {
    if summary_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *summary_out = PkmLcsRsiLookupResponseSummaryCopy {
            path_entry_count: 0,
            metadata_count: 0,
            source_validation_failure: 0,
            child_absent: false,
            source_validation_failure_present: 0,
            _pad: [0; 2],
        };
    }

    if frame.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let payload = match parse_rsi_lookup_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_LOOKUP,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => {
            if let Some(failure) = source_validation_failure_for_response_payload_error(&err) {
                unsafe {
                    (*summary_out).source_validation_failure =
                        source_validation_failure_code(failure);
                    (*summary_out).source_validation_failure_present = 1;
                }
            }
            return rsi_lookup_response_error_return(err);
        }
    };

    if let Err(err) = validate_rsi_lookup_metadata_completeness(&payload) {
        if let Some(failure) = source_validation_failure_for_key_metadata_error(&err) {
            unsafe {
                (*summary_out).source_validation_failure =
                    source_validation_failure_code(failure);
                (*summary_out).source_validation_failure_present = 1;
            }
        }
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_names(&payload, &limits) {
        if let Some(failure) = source_validation_failure_for_name_error(&err) {
            unsafe {
                (*summary_out).source_validation_failure = source_validation_failure_code(failure);
                (*summary_out).source_validation_failure_present = 1;
            }
        }
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_metadata_security_descriptors(&payload) {
        if matches!(err, LcsError::MalformedSecurityDescriptor { .. }) {
            unsafe {
                (*summary_out).source_validation_failure = source_validation_failure_code(
                    RsiSourceDataValidationFailure::MalformedSecurityDescriptor,
                );
                (*summary_out).source_validation_failure_present = 1;
            }
        }
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_sequences(&payload, next_sequence) {
        if matches!(err, LcsError::FutureSequence { .. }) {
            unsafe {
                (*summary_out).source_validation_failure = source_validation_failure_code(
                    RsiSourceDataValidationFailure::FutureSequenceNumber,
                );
                (*summary_out).source_validation_failure_present = 1;
            }
        }
        return rsi_lookup_response_error_return(err);
    }

    unsafe {
        (*summary_out).path_entry_count = payload.entry_count;
        (*summary_out).metadata_count = payload.metadata_count;
        (*summary_out).child_absent = payload.entry_count == 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_rsi_query_values_response_frame(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    limits: *const PkmLcsRuntimeLimitsCopy,
    summary_out: *mut PkmLcsRsiQueryValuesResponseSummaryCopy,
) -> c_int {
    if summary_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *summary_out = PkmLcsRsiQueryValuesResponseSummaryCopy {
            value_entry_count: 0,
            blanket_count: 0,
            source_validation_failure: 0,
            source_validation_failure_present: 0,
            _pad: [0; 3],
        };
    }

    if frame.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let payload = match parse_rsi_query_values_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => {
            if let Some(failure) = source_validation_failure_for_response_payload_error(&err) {
                unsafe {
                    (*summary_out).source_validation_failure =
                        source_validation_failure_code(failure);
                    (*summary_out).source_validation_failure_present = 1;
                }
            }
            return rsi_query_values_response_error_return(err);
        }
    };

    if let Err(err) = validate_rsi_query_values_response_names(&payload, &limits) {
        if let Some(failure) = source_validation_failure_for_name_error(&err) {
            unsafe {
                (*summary_out).source_validation_failure = source_validation_failure_code(failure);
                (*summary_out).source_validation_failure_present = 1;
            }
        }
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) =
        validate_rsi_query_values_response_value_payloads(&payload, &limits)
    {
        if let Some(failure) = source_validation_failure_for_value_payload_error(&err) {
            unsafe {
                (*summary_out).source_validation_failure =
                    source_validation_failure_code(failure);
                (*summary_out).source_validation_failure_present = 1;
            }
        }
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_sequences(&payload, next_sequence) {
        if matches!(err, LcsError::FutureSequence { .. }) {
            unsafe {
                (*summary_out).source_validation_failure = source_validation_failure_code(
                    RsiSourceDataValidationFailure::FutureSequenceNumber,
                );
                (*summary_out).source_validation_failure_present = 1;
            }
        }
        return rsi_query_values_response_error_return(err);
    }

    unsafe {
        (*summary_out).value_entry_count = payload.entry_count;
        (*summary_out).blanket_count = payload.blanket_count;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_rsi_status_only_response_frame(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    request_op_code: u16,
) -> c_int {
    if frame.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    match validate_rsi_status_only_response_for_request(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: request_op_code,
        },
    ) {
        Ok(_) => 0,
        Err(err) => rsi_lookup_response_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_rsi_delete_layer_response_frame(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    summary_out: *mut PkmLcsRsiDeleteLayerResponseSummaryCopy,
) -> c_int {
    if summary_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *summary_out = PkmLcsRsiDeleteLayerResponseSummaryCopy {
            orphaned_guid_count: 0,
            source_validation_failure: 0,
            source_validation_failure_present: 0,
            _pad: [0; 3],
        };
    }

    if frame.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let payload = match parse_rsi_delete_layer_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_DELETE_LAYER,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => {
            if let Some(failure) = source_validation_failure_for_response_payload_error(&err) {
                unsafe {
                    (*summary_out).source_validation_failure =
                        source_validation_failure_code(failure);
                    (*summary_out).source_validation_failure_present = 1;
                }
            }
            return rsi_lookup_response_error_return(err);
        }
    };

    if let Err(err) = validate_rsi_delete_layer_orphaned_guids(&payload) {
        if let Some(failure) = source_validation_failure_for_delete_layer_orphan_error(&err) {
            unsafe {
                (*summary_out).source_validation_failure =
                    source_validation_failure_code(failure);
                (*summary_out).source_validation_failure_present = 1;
            }
        }
        return rsi_lookup_response_error_return(err);
    }

    unsafe {
        (*summary_out).orphaned_guid_count = payload.orphaned_guids.count;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_enum_children_info_summary(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    result_out: *mut PkmLcsRsiEnumChildrenInfoSummaryCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiEnumChildrenInfoSummaryCopy {
            subkey_count: 0,
            max_subkey_name_len: 0,
            source_path_entry_count: 0,
            source_validation_failure: 0,
            source_validation_failure_present: 0,
            _pad: [0; 3],
        };
    }

    if frame.is_null()
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let payload = match parse_rsi_enum_children_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_ENUM_CHILDREN,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => {
            if let Some(failure) = source_validation_failure_for_response_payload_error(&err) {
                unsafe {
                    (*result_out).source_validation_failure =
                        source_validation_failure_code(failure);
                    (*result_out).source_validation_failure_present = 1;
                }
            }
            return rsi_enum_children_response_error_return(err);
        }
    };

    if let Err(err) = validate_rsi_enum_children_metadata_completeness(&payload) {
        if let Some(failure) = source_validation_failure_for_key_metadata_error(&err) {
            unsafe {
                (*result_out).source_validation_failure =
                    source_validation_failure_code(failure);
                (*result_out).source_validation_failure_present = 1;
            }
        }
        return rsi_enum_children_response_error_return(err);
    }
    if let Err(err) = validate_rsi_enum_children_path_response_names(&payload, &limits) {
        if let Some(failure) = source_validation_failure_for_name_error(&err) {
            unsafe {
                (*result_out).source_validation_failure = source_validation_failure_code(failure);
                (*result_out).source_validation_failure_present = 1;
            }
        }
        return rsi_enum_children_response_error_return(err);
    }
    if let Err(err) = validate_rsi_enum_children_metadata_security_descriptors(&payload) {
        if matches!(err, LcsError::MalformedSecurityDescriptor { .. }) {
            unsafe {
                (*result_out).source_validation_failure = source_validation_failure_code(
                    RsiSourceDataValidationFailure::MalformedSecurityDescriptor,
                );
                (*result_out).source_validation_failure_present = 1;
            }
        }
        return rsi_enum_children_response_error_return(err);
    }
    if let Err(err) = validate_rsi_enum_children_path_response_sequences(&payload, next_sequence) {
        if matches!(err, LcsError::FutureSequence { .. }) {
            unsafe {
                (*result_out).source_validation_failure = source_validation_failure_code(
                    RsiSourceDataValidationFailure::FutureSequenceNumber,
                );
                (*result_out).source_validation_failure_present = 1;
            }
        }
        return rsi_enum_children_response_error_return(err);
    }

    let mut path_storage =
        match PkmVec::<NamedPathEntry<'_>>::with_capacity(payload.child_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut allocation_failed = false;
    if let Err(err) = for_each_rsi_enum_children_source_path_entry(&payload, &limits, |entry| {
            if path_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_enum_children_response_error_return(err);
    }

    let context = LayerResolutionContext {
        layers: layer_views.as_slice(),
        private_layers: private_layer_views.as_slice(),
        limits: &limits,
        next_sequence,
    };
    let mut subkey_count = 0usize;
    let mut max_subkey_name_len = 0usize;
    if let Err(err) = for_each_visible_subkey(&context, path_storage.as_slice(), |subkey| {
        subkey_count = subkey_count
            .checked_add(1)
            .ok_or(LcsError::RsiPayloadLengthOverflow)?;
        max_subkey_name_len = max_subkey_name_len.max(subkey.child_name.len());
        Ok(())
    }) {
        if matches!(err, LcsError::DuplicateWinningSequenceTie { .. }) {
            unsafe {
                (*result_out).source_validation_failure = source_validation_failure_code(
                    RsiSourceDataValidationFailure::DuplicateWinningSequenceTie,
                );
                (*result_out).source_validation_failure_present = 1;
            }
        }
        return rsi_lookup_materialization_error_return(err);
    }

    if subkey_count > u32::MAX as usize
        || max_subkey_name_len > u32::MAX as usize
        || path_storage.len() > u32::MAX as usize
    {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    unsafe {
        (*result_out).subkey_count = subkey_count as u32;
        (*result_out).max_subkey_name_len = max_subkey_name_len as u32;
        (*result_out).source_path_entry_count = path_storage.len() as u32;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_enum_subkey_response(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    index: u32,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    result_out: *mut PkmLcsRsiEnumSubkeyResultCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiEnumSubkeyResultCopy {
            source_path_entry_count: 0,
            name_offset: 0,
            name_len: 0,
            selected_precedence: 0,
            selected_sequence: 0,
            found: 0,
            _pad: [0; 7],
            child_guid: [0; 16],
        };
    }

    if frame.is_null()
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let payload = match parse_rsi_enum_children_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_ENUM_CHILDREN,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_enum_children_response_error_return(err),
    };

    if let Err(err) = validate_rsi_enum_children_metadata_completeness(&payload) {
        return rsi_enum_children_response_error_return(err);
    }
    if let Err(err) = validate_rsi_enum_children_path_response_names(&payload, &limits) {
        return rsi_enum_children_response_error_return(err);
    }
    if let Err(err) = validate_rsi_enum_children_metadata_security_descriptors(&payload) {
        return rsi_enum_children_response_error_return(err);
    }
    if let Err(err) = validate_rsi_enum_children_path_response_sequences(&payload, next_sequence) {
        return rsi_enum_children_response_error_return(err);
    }

    let mut path_storage =
        match PkmVec::<NamedPathEntry<'_>>::with_capacity(payload.child_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut allocation_failed = false;
    if let Err(err) = for_each_rsi_enum_children_source_path_entry(&payload, &limits, |entry| {
            if path_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_enum_children_response_error_return(err);
    }

    if path_storage.len() > u32::MAX as usize {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }
    unsafe {
        (*result_out).source_path_entry_count = path_storage.len() as u32;
    }

    let context = LayerResolutionContext {
        layers: layer_views.as_slice(),
        private_layers: private_layer_views.as_slice(),
        limits: &limits,
        next_sequence,
    };
    let target_index = index as usize;
    let mut current_index = 0usize;
    let mut found = false;
    let mut selected_name: *const u8 = core::ptr::null();
    let mut selected_name_len = 0usize;
    let mut selected_guid = [0u8; 16];
    let mut selected_precedence = 0u32;
    let mut selected_sequence = 0u64;
    if let Err(err) = for_each_visible_subkey(&context, path_storage.as_slice(), |subkey| {
        if current_index == target_index {
            selected_name = subkey.child_name.as_bytes().as_ptr();
            selected_name_len = subkey.child_name.len();
            selected_guid = subkey.path.guid;
            selected_precedence = subkey.path.precedence;
            selected_sequence = subkey.path.sequence;
            found = true;
        }
        current_index = current_index
            .checked_add(1)
            .ok_or(LcsError::RsiPayloadLengthOverflow)?;
        Ok(())
    }) {
        return rsi_lookup_materialization_error_return(err);
    }

    if !found {
        return 0;
    }

    let base = frame_bytes.as_ptr() as usize;
    let end = base.saturating_add(frame_len);
    let name_ptr = selected_name as usize;
    let Some(name_end) = name_ptr.checked_add(selected_name_len) else {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    };
    if name_ptr < base || name_end > end {
        return LinuxErrno::Eio.negated_return() as c_int;
    }

    let name_offset = name_ptr - base;
    if name_offset > u32::MAX as usize || selected_name_len > u32::MAX as usize {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    unsafe {
        (*result_out).name_offset = name_offset as u32;
        (*result_out).name_len = selected_name_len as u32;
        (*result_out).selected_precedence = selected_precedence;
        (*result_out).selected_sequence = selected_sequence;
        (*result_out).found = 1;
        (*result_out).child_guid = selected_guid;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_query_values_info_summary(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    result_out: *mut PkmLcsRsiQueryValuesInfoSummaryCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiQueryValuesInfoSummaryCopy {
            value_count: 0,
            max_value_name_len: 0,
            max_value_data_size: 0,
            source_value_entry_count: 0,
            source_blanket_count: 0,
            _pad: [0; 3],
        };
    }

    if frame.is_null()
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(err) => return err.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let payload = match parse_rsi_query_values_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_query_values_response_error_return(err),
    };

    if let Err(err) = validate_rsi_query_values_response_names(&payload, &limits) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_value_payloads(&payload, &limits) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_sequences(&payload, next_sequence) {
        return rsi_query_values_response_error_return(err);
    }

    let mut value_storage =
        match PkmVec::<NamedValueEntry<'_>>::with_capacity(payload.entry_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut blanket_storage =
        match PkmVec::<BlanketTombstoneEntry<'_>>::with_capacity(payload.blanket_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };

    let mut allocation_failed = false;
    if let Err(err) =
        for_each_rsi_query_values_source_value_entry(&payload, &limits, |entry| {
            if value_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) =
        for_each_rsi_query_values_source_blanket_entry(&payload, &limits, |entry| {
            if blanket_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }

    let context = LayerResolutionContext {
        layers: layer_views.as_slice(),
        private_layers: private_layer_views.as_slice(),
        limits: &limits,
        next_sequence,
    };
    let mut value_count = 0usize;
    let mut max_value_name_len = 0usize;
    let mut max_value_data_size = 0usize;
    if let Err(err) = for_each_effective_value(
        &context,
        value_storage.as_slice(),
        blanket_storage.as_slice(),
        |value| {
            value_count = value_count
                .checked_add(1)
                .ok_or(LcsError::RsiPayloadLengthOverflow)?;
            max_value_name_len = max_value_name_len.max(value.name.len());
            max_value_data_size = max_value_data_size.max(value.value.data.len());
            Ok(())
        },
    ) {
        return rsi_lookup_materialization_error_return(err);
    }

    if value_count > u32::MAX as usize
        || max_value_name_len > u32::MAX as usize
        || max_value_data_size > u32::MAX as usize
        || value_storage.len() > u32::MAX as usize
        || blanket_storage.len() > u32::MAX as usize
    {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    unsafe {
        (*result_out).value_count = value_count as u32;
        (*result_out).max_value_name_len = max_value_name_len as u32;
        (*result_out).max_value_data_size = max_value_data_size as u32;
        (*result_out).source_value_entry_count = value_storage.len() as u32;
        (*result_out).source_blanket_count = blanket_storage.len() as u32;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_query_values_batch_response(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    output: *mut u8,
    output_len: usize,
    result_out: *mut PkmLcsRsiQueryValuesBatchResultCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiQueryValuesBatchResultCopy {
            required_len: 0,
            count: 0,
            written_len: 0,
            source_value_entry_count: 0,
            source_blanket_count: 0,
            _pad: [0; 3],
        };
    }

    if frame.is_null()
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
        || (output.is_null() && output_len != 0)
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(err) => return err.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let payload = match parse_rsi_query_values_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_query_values_response_error_return(err),
    };

    if let Err(err) = validate_rsi_query_values_response_names(&payload, &limits) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_value_payloads(&payload, &limits) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_sequences(&payload, next_sequence) {
        return rsi_query_values_response_error_return(err);
    }

    let mut value_storage =
        match PkmVec::<NamedValueEntry<'_>>::with_capacity(payload.entry_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut blanket_storage =
        match PkmVec::<BlanketTombstoneEntry<'_>>::with_capacity(payload.blanket_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };

    let mut allocation_failed = false;
    if let Err(err) =
        for_each_rsi_query_values_source_value_entry(&payload, &limits, |entry| {
            if value_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) =
        for_each_rsi_query_values_source_blanket_entry(&payload, &limits, |entry| {
            if blanket_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }

    let context = LayerResolutionContext {
        layers: layer_views.as_slice(),
        private_layers: private_layer_views.as_slice(),
        limits: &limits,
        next_sequence,
    };
    let mut count = 0usize;
    let mut required_len = 0usize;
    if let Err(err) = for_each_effective_value(
        &context,
        value_storage.as_slice(),
        blanket_storage.as_slice(),
        |value| {
            let record_len = 12usize
                .checked_add(value.name.len())
                .and_then(|len| len.checked_add(value.value.data.len()))
                .ok_or(LcsError::OutputSizeOverflow)?;
            required_len = required_len
                .checked_add(record_len)
                .ok_or(LcsError::OutputSizeOverflow)?;
            count = count
                .checked_add(1)
                .ok_or(LcsError::OutputSizeOverflow)?;
            Ok(())
        },
    ) {
        return rsi_lookup_materialization_error_return(err);
    }

    if count > u32::MAX as usize
        || required_len > u32::MAX as usize
        || value_storage.len() > u32::MAX as usize
        || blanket_storage.len() > u32::MAX as usize
    {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    unsafe {
        (*result_out).required_len = required_len as u32;
        (*result_out).count = count as u32;
        (*result_out).source_value_entry_count = value_storage.len() as u32;
        (*result_out).source_blanket_count = blanket_storage.len() as u32;
    }

    if output.is_null() {
        return 0;
    }
    if output_len < required_len {
        return LinuxErrno::Erange.negated_return() as c_int;
    }

    let output_bytes = unsafe { slice::from_raw_parts_mut(output, output_len) };
    let mut offset = 0usize;
    if let Err(err) = for_each_effective_value(
        &context,
        value_storage.as_slice(),
        blanket_storage.as_slice(),
        |value| {
            let name = value.name.as_bytes();
            let data = value.value.data;
            if name.len() > u32::MAX as usize || data.len() > u32::MAX as usize {
                return Err(LcsError::OutputSizeOverflow);
            }
            let record_len = 12usize
                .checked_add(name.len())
                .and_then(|len| len.checked_add(data.len()))
                .ok_or(LcsError::OutputSizeOverflow)?;
            if offset > output_bytes.len() || record_len > output_bytes.len() - offset {
                return Err(LcsError::OutputSizeOverflow);
            }

            output_bytes[offset..offset + 4].copy_from_slice(&(name.len() as u32).to_le_bytes());
            offset += 4;
            output_bytes[offset..offset + name.len()].copy_from_slice(name);
            offset += name.len();
            output_bytes[offset..offset + 4]
                .copy_from_slice(&value.value.value_type.code().to_le_bytes());
            offset += 4;
            output_bytes[offset..offset + 4].copy_from_slice(&(data.len() as u32).to_le_bytes());
            offset += 4;
            output_bytes[offset..offset + data.len()].copy_from_slice(data);
            offset += data.len();
            Ok(())
        },
    ) {
        return rsi_lookup_materialization_error_return(err);
    }

    if offset != required_len {
        return LinuxErrno::Eio.negated_return() as c_int;
    }
    unsafe {
        (*result_out).written_len = offset as u32;
    }
    0
}

fn materialize_effective_value_watch_snapshot<'a>(
    frame_bytes: &'a [u8],
    request_id: u64,
    next_sequence: u64,
    layer_views: &'a [LayerView<'a>],
    private_layer_views: &'a [&'a str],
    limits: &'a LcsLimits,
) -> Result<(PkmVec<EnumeratedValue<'a>>, usize, usize), c_int> {
    let payload = match parse_rsi_query_values_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return Err(rsi_query_values_response_error_return(err)),
    };

    if let Err(err) = validate_rsi_query_values_response_names(&payload, limits) {
        return Err(rsi_query_values_response_error_return(err));
    }
    if let Err(err) = validate_rsi_query_values_response_value_payloads(&payload, limits) {
        return Err(rsi_query_values_response_error_return(err));
    }
    if let Err(err) = validate_rsi_query_values_response_sequences(&payload, next_sequence) {
        return Err(rsi_query_values_response_error_return(err));
    }

    let mut value_storage =
        PkmVec::<NamedValueEntry<'a>>::with_capacity(payload.entry_count as usize)
            .map_err(|_| LinuxErrno::Enomem.negated_return() as c_int)?;
    let mut blanket_storage =
        PkmVec::<BlanketTombstoneEntry<'a>>::with_capacity(payload.blanket_count as usize)
            .map_err(|_| LinuxErrno::Enomem.negated_return() as c_int)?;

    let mut allocation_failed = false;
    if let Err(err) =
        for_each_rsi_query_values_source_value_entry(&payload, limits, |entry| {
            if value_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return Err(LinuxErrno::Enomem.negated_return() as c_int);
        }
        return Err(rsi_query_values_response_error_return(err));
    }
    if let Err(err) =
        for_each_rsi_query_values_source_blanket_entry(&payload, limits, |entry| {
            if blanket_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return Err(LinuxErrno::Enomem.negated_return() as c_int);
        }
        return Err(rsi_query_values_response_error_return(err));
    }

    let context = LayerResolutionContext {
        layers: layer_views,
        private_layers: private_layer_views,
        limits,
        next_sequence,
    };
    let mut effective =
        PkmVec::<EnumeratedValue<'a>>::with_capacity(value_storage.len())
            .map_err(|_| LinuxErrno::Enomem.negated_return() as c_int)?;

    allocation_failed = false;
    if let Err(err) = for_each_effective_value(
        &context,
        value_storage.as_slice(),
        blanket_storage.as_slice(),
        |value| {
            if effective.push(value).is_err() {
                allocation_failed = true;
                return Err(LcsError::OutputSizeOverflow);
            }
            Ok(())
        },
    ) {
        if allocation_failed {
            return Err(LinuxErrno::Enomem.negated_return() as c_int);
        }
        return Err(rsi_lookup_materialization_error_return(err));
    }

    Ok((effective, value_storage.len(), blanket_storage.len()))
}

fn effective_value_watch_event_name(event: EffectiveValueWatchEvent<'_>) -> &str {
    match event {
        EffectiveValueWatchEvent::ValueSet { name }
        | EffectiveValueWatchEvent::ValueDeleted { name } => name,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_query_values_watch_events(
    before_frame: *const u8,
    before_frame_len: usize,
    before_request_id: u64,
    after_frame: *const u8,
    after_frame_len: usize,
    after_request_id: u64,
    next_sequence: u64,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    output: *mut u8,
    output_len: usize,
    result_out: *mut PkmLcsRsiValueWatchEventsResultCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiValueWatchEventsResultCopy {
            required_len: 0,
            count: 0,
            written_len: 0,
            before_source_value_entry_count: 0,
            before_source_blanket_count: 0,
            after_source_value_entry_count: 0,
            after_source_blanket_count: 0,
            _pad: 0,
        };
    }

    if before_frame.is_null()
        || after_frame.is_null()
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
        || (output.is_null() && output_len != 0)
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(err) => return err.negated_return() as c_int,
        }
    };

    let before_bytes = unsafe { slice::from_raw_parts(before_frame, before_frame_len) };
    let after_bytes = unsafe { slice::from_raw_parts(after_frame, after_frame_len) };
    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let (before_values, before_source_values, before_source_blankets) =
        match materialize_effective_value_watch_snapshot(
            before_bytes,
            before_request_id,
            next_sequence,
            layer_views.as_slice(),
            private_layer_views.as_slice(),
            &limits,
        ) {
            Ok(snapshot) => snapshot,
            Err(errno) => return errno,
        };
    let (after_values, after_source_values, after_source_blankets) =
        match materialize_effective_value_watch_snapshot(
            after_bytes,
            after_request_id,
            next_sequence,
            layer_views.as_slice(),
            private_layer_views.as_slice(),
            &limits,
        ) {
            Ok(snapshot) => snapshot,
            Err(errno) => return errno,
        };

    let mut count = 0usize;
    let mut required_len = 0usize;
    if let Err(err) = for_each_effective_value_watch_event(
        &limits,
        before_values.as_slice(),
        after_values.as_slice(),
        |event| {
            let name = effective_value_watch_event_name(event).as_bytes();
            let record_len = 8usize
                .checked_add(name.len())
                .ok_or(LcsError::OutputSizeOverflow)?;
            required_len = required_len
                .checked_add(record_len)
                .ok_or(LcsError::OutputSizeOverflow)?;
            count = count
                .checked_add(1)
                .ok_or(LcsError::OutputSizeOverflow)?;
            Ok(())
        },
    ) {
        return rsi_lookup_materialization_error_return(err);
    }

    if count > u32::MAX as usize
        || required_len > u32::MAX as usize
        || before_source_values > u32::MAX as usize
        || before_source_blankets > u32::MAX as usize
        || after_source_values > u32::MAX as usize
        || after_source_blankets > u32::MAX as usize
    {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    unsafe {
        (*result_out).required_len = required_len as u32;
        (*result_out).count = count as u32;
        (*result_out).before_source_value_entry_count = before_source_values as u32;
        (*result_out).before_source_blanket_count = before_source_blankets as u32;
        (*result_out).after_source_value_entry_count = after_source_values as u32;
        (*result_out).after_source_blanket_count = after_source_blankets as u32;
    }

    if output.is_null() {
        return 0;
    }
    if output_len < required_len {
        return LinuxErrno::Erange.negated_return() as c_int;
    }

    let output_bytes = unsafe { slice::from_raw_parts_mut(output, output_len) };
    let mut offset = 0usize;
    if let Err(err) = for_each_effective_value_watch_event(
        &limits,
        before_values.as_slice(),
        after_values.as_slice(),
        |event| {
            let name = effective_value_watch_event_name(event).as_bytes();
            let record_len = 8usize
                .checked_add(name.len())
                .ok_or(LcsError::OutputSizeOverflow)?;
            if offset > output_bytes.len() || record_len > output_bytes.len() - offset {
                return Err(LcsError::OutputSizeOverflow);
            }
            output_bytes[offset..offset + 4].copy_from_slice(&event.event_type().to_le_bytes());
            offset += 4;
            output_bytes[offset..offset + 4].copy_from_slice(&(name.len() as u32).to_le_bytes());
            offset += 4;
            output_bytes[offset..offset + name.len()].copy_from_slice(name);
            offset += name.len();
            Ok(())
        },
    ) {
        return rsi_lookup_materialization_error_return(err);
    }

    if offset != required_len {
        return LinuxErrno::Eio.negated_return() as c_int;
    }
    unsafe {
        (*result_out).written_len = offset as u32;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_lookup_child(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    child_name: *const u8,
    child_name_len: u32,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    result_out: *mut PkmLcsRsiLookupChildResultCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiLookupChildResultCopy {
            source_path_entry_count: 0,
            sd_offset: 0,
            sd_len: 0,
            selected_precedence: 0,
            selected_sequence: 0,
            last_write_time: 0,
            found: 0,
            volatile_key: 0,
            symlink: 0,
            _pad: [0; 5],
            key_guid: [0; 16],
        };
    }

    if frame.is_null()
        || child_name.is_null()
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let child_bytes = unsafe { slice::from_raw_parts(child_name, child_name_len as usize) };
    let child_component = match str::from_utf8(child_bytes) {
        Ok(child_component) => child_component,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    if validate_key_component_bytes(child_bytes, &limits).is_err() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let payload = match parse_rsi_lookup_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_LOOKUP,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_lookup_response_error_return(err),
    };

    if let Err(err) = validate_rsi_lookup_metadata_completeness(&payload) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_names(&payload, &limits) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_metadata_security_descriptors(&payload) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_sequences(&payload, next_sequence) {
        return rsi_lookup_response_error_return(err);
    }

    let context = LayerResolutionContext {
        layers: layer_views.as_slice(),
        private_layers: private_layer_views.as_slice(),
        limits: &limits,
        next_sequence,
    };
    let mut path_storage =
        match PkmVec::<NamedPathEntry<'_>>::with_capacity(payload.entry_count as usize) {
            Ok(path_storage) => path_storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut path_storage_allocation_failed = false;
    if let Err(err) = for_each_rsi_lookup_source_path_entry(
        &payload,
        &limits,
        child_component,
        |entry| {
            if path_storage.push(entry).is_err() {
                path_storage_allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        },
    ) {
        if path_storage_allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_lookup_response_error_return(err);
    }

    let resolved =
        match resolve_named_path_entry(&context, child_component, path_storage.as_slice()) {
            Ok(resolved) => resolved,
            Err(err) => return rsi_lookup_materialization_error_return(err),
        };

    unsafe {
        (*result_out).source_path_entry_count = path_storage.len() as u32;
    }

    let NamedPathResolution::Found(found) = resolved else {
        return 0;
    };

    let base = frame_bytes.as_ptr() as usize;
    let end = base.saturating_add(frame_len);
    let mut matched = false;
    let mut metadata_errno = LinuxErrno::Eio;

    if let Err(err) = payload.for_each_key_metadata(|metadata| {
        if metadata.guid != found.path.guid {
            return Ok(());
        }
        let sd_ptr = metadata.sd.data.as_ptr() as usize;
        let sd_len = metadata.sd.data.len();
        let Some(sd_end) = sd_ptr.checked_add(sd_len) else {
            metadata_errno = LinuxErrno::Eoverflow;
            return Err(LcsError::RsiPayloadLengthOverflow);
        };
        if sd_ptr < base || sd_end > end {
            return Err(LcsError::RsiPayloadLengthOverflow);
        }
        let sd_offset = sd_ptr - base;
        if sd_offset > u32::MAX as usize || sd_len > u32::MAX as usize {
            metadata_errno = LinuxErrno::Eoverflow;
            return Err(LcsError::RsiPayloadLengthOverflow);
        }

        unsafe {
            (*result_out).source_path_entry_count = path_storage.len() as u32;
            (*result_out).sd_offset = sd_offset as u32;
            (*result_out).sd_len = sd_len as u32;
            (*result_out).selected_precedence = found.path.precedence;
            (*result_out).selected_sequence = found.path.sequence;
            (*result_out).last_write_time = metadata.last_write_time;
            (*result_out).found = 1;
            (*result_out).volatile_key = metadata.volatile as u8;
            (*result_out).symlink = metadata.symlink as u8;
            (*result_out).key_guid = found.path.guid;
        }
        matched = true;
        Ok(())
    }) {
        return match metadata_errno {
            LinuxErrno::Eoverflow => metadata_errno.negated_return() as c_int,
            _ => rsi_lookup_response_error_return(err),
        };
    }

    if !matched {
        return LinuxErrno::Eio.negated_return() as c_int;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_lookup_guid_entry(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    child_name: *const u8,
    child_name_len: u32,
    target_guid: *const u8,
    limits: *const PkmLcsRuntimeLimitsCopy,
    result_out: *mut PkmLcsRsiLookupGuidEntryResultCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiLookupGuidEntryResultCopy {
            source_path_entry_count: 0,
            present: 0,
            _pad: [0; 3],
        };
    }

    if frame.is_null() || child_name.is_null() || target_guid.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let child_bytes = unsafe { slice::from_raw_parts(child_name, child_name_len as usize) };
    let child_component = match str::from_utf8(child_bytes) {
        Ok(child_component) => child_component,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    if validate_key_component_bytes(child_bytes, &limits).is_err() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let mut target = [0u8; 16];
    target.copy_from_slice(unsafe { slice::from_raw_parts(target_guid, 16) });

    let payload = match parse_rsi_lookup_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_LOOKUP,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_lookup_response_error_return(err),
    };

    if let Err(err) = validate_rsi_lookup_metadata_completeness(&payload) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_names(&payload, &limits) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_metadata_security_descriptors(&payload) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_sequences(&payload, next_sequence) {
        return rsi_lookup_response_error_return(err);
    }

    let mut source_path_entry_count = 0usize;
    let mut present = false;
    if let Err(err) = for_each_rsi_lookup_source_path_entry(
        &payload,
        &limits,
        child_component,
        |entry| {
            source_path_entry_count = source_path_entry_count
                .checked_add(1)
                .ok_or(LcsError::RsiPayloadLengthOverflow)?;
            if let PathTarget::Guid(guid) = entry.entry.target {
                if guid == target {
                    present = true;
                }
            }
            Ok(())
        },
    ) {
        return rsi_lookup_response_error_return(err);
    }
    if source_path_entry_count > u32::MAX as usize {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    unsafe {
        (*result_out).source_path_entry_count = source_path_entry_count as u32;
        (*result_out).present = present as u8;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_query_value_response(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    value_name: *const u8,
    value_name_len: u32,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    result_out: *mut PkmLcsRsiQueryValueResultCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiQueryValueResultCopy {
            source_value_entry_count: 0,
            source_blanket_count: 0,
            data_offset: 0,
            data_len: 0,
            layer: core::ptr::null(),
            layer_len: 0,
            value_type: 0,
            selected_precedence: 0,
            _pad0: 0,
            selected_sequence: 0,
            found: 0,
            _pad1: [0; 7],
        };
    }

    if frame.is_null()
        || (value_name_len != 0 && value_name.is_null())
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(err) => return err.negated_return() as c_int,
        }
    };

    let value_name_bytes = if value_name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value_name, value_name_len as usize) }
    };
    let requested_name = match str::from_utf8(value_name_bytes) {
        Ok(name) => name,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    if validate_value_name_bytes(value_name_bytes, &limits).is_err() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let payload = match parse_rsi_query_values_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_query_values_response_error_return(err),
    };

    if let Err(err) = validate_rsi_query_values_response_names(&payload, &limits) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_value_payloads(&payload, &limits) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_sequences(&payload, next_sequence) {
        return rsi_query_values_response_error_return(err);
    }

    let context = LayerResolutionContext {
        layers: layer_views.as_slice(),
        private_layers: private_layer_views.as_slice(),
        limits: &limits,
        next_sequence,
    };
    let mut value_storage =
        match PkmVec::<ValueEntry<'_>>::with_capacity(payload.entry_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut blanket_storage =
        match PkmVec::<BlanketTombstoneEntry<'_>>::with_capacity(payload.blanket_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };

    let mut allocation_failed = false;
    let mut wrong_value_name = false;
    if let Err(err) = payload.for_each_value_entry(|entry| {
        let name = validate_value_name_bytes(entry.value_name.data, &limits)?;
        if !casefold_eq(name, requested_name) {
            wrong_value_name = true;
            return Err(LcsError::RsiPayloadLengthOverflow);
        }
        let layer = validate_layer_name_bytes(entry.layer_name.data, &limits)?;
        validate_value_data_len(entry.data.data.len(), &limits)?;
        validate_value_write_type(
            entry.value_type,
            entry.data.data.len(),
            entry.value_type == REG_TOMBSTONE,
        )?;
        if value_storage
            .push(ValueEntry {
                layer,
                sequence: entry.sequence,
                value_type: entry.value_type,
                data: entry.data.data,
            })
            .is_err()
        {
            allocation_failed = true;
            return Err(LcsError::RsiPayloadLengthOverflow);
        }
        Ok(())
    }) {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        if wrong_value_name {
            return LinuxErrno::Eio.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }

    if let Err(err) = payload.for_each_blanket_entry(|entry| {
        let layer = validate_layer_name_bytes(entry.layer_name.data, &limits)?;
        if blanket_storage
            .push(BlanketTombstoneEntry {
                layer,
                sequence: entry.sequence,
            })
            .is_err()
        {
            allocation_failed = true;
            return Err(LcsError::RsiPayloadLengthOverflow);
        }
        Ok(())
    }) {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }

    unsafe {
        (*result_out).source_value_entry_count = value_storage.len() as u32;
        (*result_out).source_blanket_count = blanket_storage.len() as u32;
    }

    let resolved = match resolve_value(
        &context,
        value_storage.as_slice(),
        blanket_storage.as_slice(),
    ) {
        Ok(resolved) => resolved,
        Err(err) => return rsi_lookup_materialization_error_return(err),
    };

    let ValueResolution::Found(value) = resolved else {
        return 0;
    };

    let base = frame_bytes.as_ptr() as usize;
    let end = base.saturating_add(frame_len);
    let data_ptr = value.data.as_ptr() as usize;
    let data_len = value.data.len();
    let Some(data_end) = data_ptr.checked_add(data_len) else {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    };
    if data_ptr < base || data_end > end {
        return LinuxErrno::Eio.negated_return() as c_int;
    }
    let data_offset = data_ptr - base;
    let layer_bytes = value.layer.as_bytes();
    let layer_len = layer_bytes.len();
    if data_offset > u32::MAX as usize
        || data_len > u32::MAX as usize
        || layer_len > u32::MAX as usize
    {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    unsafe {
        (*result_out).data_offset = data_offset as u32;
        (*result_out).data_len = data_len as u32;
        (*result_out).layer = layer_bytes.as_ptr();
        (*result_out).layer_len = layer_len as u32;
        (*result_out).value_type = value.value_type.code();
        (*result_out).selected_precedence = value.precedence;
        (*result_out).selected_sequence = value.sequence;
        (*result_out).found = 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_enum_value_response(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    index: u32,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    limits: *const PkmLcsRuntimeLimitsCopy,
    result_out: *mut PkmLcsRsiEnumValueResultCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiEnumValueResultCopy {
            source_value_entry_count: 0,
            source_blanket_count: 0,
            name_offset: 0,
            name_len: 0,
            data_offset: 0,
            data_len: 0,
            value_type: 0,
            _pad0: 0,
            found: 0,
            _pad1: [0; 7],
        };
    }

    if frame.is_null()
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(err) => return err.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let payload = match parse_rsi_query_values_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_query_values_response_error_return(err),
    };

    if let Err(err) = validate_rsi_query_values_response_names(&payload, &limits) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_value_payloads(&payload, &limits) {
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) = validate_rsi_query_values_response_sequences(&payload, next_sequence) {
        return rsi_query_values_response_error_return(err);
    }

    let mut value_storage =
        match PkmVec::<NamedValueEntry<'_>>::with_capacity(payload.entry_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut blanket_storage =
        match PkmVec::<BlanketTombstoneEntry<'_>>::with_capacity(payload.blanket_count as usize) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };

    let mut allocation_failed = false;
    if let Err(err) =
        for_each_rsi_query_values_source_value_entry(&payload, &limits, |entry| {
            if value_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }
    if let Err(err) =
        for_each_rsi_query_values_source_blanket_entry(&payload, &limits, |entry| {
            if blanket_storage.push(entry).is_err() {
                allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        })
    {
        if allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_query_values_response_error_return(err);
    }

    unsafe {
        (*result_out).source_value_entry_count = value_storage.len() as u32;
        (*result_out).source_blanket_count = blanket_storage.len() as u32;
    }

    let context = LayerResolutionContext {
        layers: layer_views.as_slice(),
        private_layers: private_layer_views.as_slice(),
        limits: &limits,
        next_sequence,
    };
    let mut current_index = 0usize;
    let target_index = index as usize;
    let mut found = false;
    let mut selected_name: *const u8 = core::ptr::null();
    let mut selected_name_len = 0usize;
    let mut selected_data: *const u8 = core::ptr::null();
    let mut selected_data_len = 0usize;
    let mut selected_type = 0u32;
    if let Err(err) = for_each_effective_value(
        &context,
        value_storage.as_slice(),
        blanket_storage.as_slice(),
        |value| {
            if current_index == target_index {
                selected_name = value.name.as_bytes().as_ptr();
                selected_name_len = value.name.len();
                selected_data = value.value.data.as_ptr();
                selected_data_len = value.value.data.len();
                selected_type = value.value.value_type.code();
                found = true;
            }
            current_index = current_index
                .checked_add(1)
                .ok_or(LcsError::RsiPayloadLengthOverflow)?;
            Ok(())
        },
    ) {
        return rsi_lookup_materialization_error_return(err);
    }

    if !found {
        return 0;
    }

    let base = frame_bytes.as_ptr() as usize;
    let end = base.saturating_add(frame_len);
    let name_ptr = selected_name as usize;
    let Some(name_end) = name_ptr.checked_add(selected_name_len) else {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    };
    let data_ptr = selected_data as usize;
    let Some(data_end) = data_ptr.checked_add(selected_data_len) else {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    };
    if name_ptr < base || name_end > end || data_ptr < base || data_end > end {
        return LinuxErrno::Eio.negated_return() as c_int;
    }

    let name_offset = name_ptr - base;
    let data_offset = data_ptr - base;
    if name_offset > u32::MAX as usize
        || selected_name_len > u32::MAX as usize
        || data_offset > u32::MAX as usize
        || selected_data_len > u32::MAX as usize
    {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    unsafe {
        (*result_out).name_offset = name_offset as u32;
        (*result_out).name_len = selected_name_len as u32;
        (*result_out).data_offset = data_offset as u32;
        (*result_out).data_len = selected_data_len as u32;
        (*result_out).value_type = selected_type;
        (*result_out).found = 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_read_key_response(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    limits: *const PkmLcsRuntimeLimitsCopy,
    result_out: *mut PkmLcsRsiReadKeyResultCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiReadKeyResultCopy {
            sd_offset: 0,
            sd_len: 0,
            name_len: 0,
            source_validation_failure: 0,
            last_write_time: 0,
            volatile_key: 0,
            symlink: 0,
            source_validation_failure_present: 0,
            _pad1: [0; 5],
            parent_guid: [0; 16],
        };
    }

    if frame.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = if limits.is_null() {
        LcsLimits::DEFAULT
    } else {
        match lcs_limits_from_copy(limits) {
            Ok(limits) => limits,
            Err(errno) => return errno.negated_return() as c_int,
        }
    };

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let payload = match parse_rsi_read_key_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_READ_KEY,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => {
            if let Some(failure) = source_validation_failure_for_response_payload_error(&err) {
                unsafe {
                    (*result_out).source_validation_failure =
                        source_validation_failure_code(failure);
                    (*result_out).source_validation_failure_present = 1;
                }
            }
            return rsi_read_key_response_error_return(err);
        }
    };

    if let Err(err) = validate_rsi_read_key_response_names(&payload, &limits) {
        if let Some(failure) = source_validation_failure_for_name_error(&err) {
            unsafe {
                (*result_out).source_validation_failure = source_validation_failure_code(failure);
                (*result_out).source_validation_failure_present = 1;
            }
        }
        return rsi_read_key_response_error_return(err);
    }
    if let Err(err) = validate_rsi_read_key_response_security_descriptor(&payload) {
        if matches!(err, LcsError::MalformedSecurityDescriptor { .. }) {
            unsafe {
                (*result_out).source_validation_failure = source_validation_failure_code(
                    RsiSourceDataValidationFailure::MalformedSecurityDescriptor,
                );
                (*result_out).source_validation_failure_present = 1;
            }
        }
        return rsi_read_key_response_error_return(err);
    }

    let base = frame_bytes.as_ptr() as usize;
    let end = base.saturating_add(frame_len);
    let sd_ptr = payload.sd.data.as_ptr() as usize;
    let sd_len = payload.sd.data.len();
    let Some(sd_end) = sd_ptr.checked_add(sd_len) else {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    };
    if sd_ptr < base || sd_end > end {
        return LinuxErrno::Eio.negated_return() as c_int;
    }
    let sd_offset = sd_ptr - base;
    if sd_offset > u32::MAX as usize
        || sd_len > u32::MAX as usize
        || payload.name.data.len() > u32::MAX as usize
    {
        return LinuxErrno::Eoverflow.negated_return() as c_int;
    }

    unsafe {
        (*result_out).sd_offset = sd_offset as u32;
        (*result_out).sd_len = sd_len as u32;
        (*result_out).name_len = payload.name.data.len() as u32;
        (*result_out).last_write_time = payload.last_write_time;
        (*result_out).volatile_key = payload.volatile as u8;
        (*result_out).symlink = payload.symlink as u8;
        (*result_out).parent_guid = payload.parent_guid;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_plan_rsi_source_read(
    has_next_request: bool,
    next_request_len: usize,
    caller_buffer_len: usize,
    nonblocking: bool,
    fd_closing: bool,
    plan_out: *mut PkmLcsRsiReadPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *plan_out = PkmLcsRsiReadPlanCopy {
            action: PKM_LCS_RSI_READ_ACTION_WAIT,
            _pad: 0,
            request_len: 0,
            required_len: 0,
        };
    }

    let next_request = if has_next_request {
        Some(next_request_len)
    } else {
        None
    };

    match plan_rsi_source_read(next_request, caller_buffer_len, nonblocking, fd_closing) {
        Ok(RsiReadPlan::ReturnOneCompleteRequest { request_len, .. }) => unsafe {
            *plan_out = PkmLcsRsiReadPlanCopy {
                action: PKM_LCS_RSI_READ_ACTION_COPY,
                _pad: 0,
                request_len,
                required_len: request_len,
            };
            0
        },
        Ok(RsiReadPlan::WaitForRequestOrClose) => unsafe {
            (*plan_out).action = PKM_LCS_RSI_READ_ACTION_WAIT;
            0
        },
        Ok(RsiReadPlan::ReturnEagain) => unsafe {
            (*plan_out).action = PKM_LCS_RSI_READ_ACTION_EAGAIN;
            0
        },
        Ok(RsiReadPlan::ReturnEmsgsize { required_len, .. }) => unsafe {
            *plan_out = PkmLcsRsiReadPlanCopy {
                action: PKM_LCS_RSI_READ_ACTION_EMSGSIZE,
                _pad: 0,
                request_len: 0,
                required_len,
            };
            0
        },
        Ok(RsiReadPlan::WakeForClose) => unsafe {
            (*plan_out).action = PKM_LCS_RSI_READ_ACTION_WAKE_CLOSE;
            0
        },
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_key_fd_fixed_ioctl_access_gate(
    granted_access: u32,
    ioctl_number: u32,
) -> c_int {
    if ioctl_number > u8::MAX as u32 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let ioctl_number = ioctl_number as u8;

    match plan_registry_ioctl_fixed_fd_access_gate(granted_access, ioctl_number) {
        Ok(Some(plan)) => ioctl_access_gate_return(plan),
        Ok(None) | Err(_) => LinuxErrno::Einval.negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_backup_restore_fd_mode_gate(
    operation: u32,
    fd_readable: u8,
    fd_writable: u8,
) -> c_int {
    let operation = match operation {
        0 => BackupRestoreFdOperation::BackupOutput,
        1 => BackupRestoreFdOperation::RestoreInput,
        _ => return LinuxErrno::Einval.negated_return() as c_int,
    };

    let plan =
        plan_backup_restore_fd_mode(operation, fd_readable != 0, fd_writable != 0);
    match backup_restore_fd_mode_linux_errno(&plan) {
        Some(errno) => errno.negated_return() as c_int,
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_key_fd_security_ioctl_access_gate(
    granted_access: u32,
    ioctl_number: u32,
    security_info: u32,
) -> c_int {
    if ioctl_number > u8::MAX as u32 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let ioctl_number = ioctl_number as u8;

    let operation = match registry_ioctl_access_requirement(ioctl_number) {
        Ok(RegistryIoctlAccessRequirement::KeySecurityInfo(operation)) => operation,
        Ok(_) | Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };

    match plan_registry_security_info_fd_access_gate(granted_access, operation, security_info) {
        Ok(plan) => ioctl_access_gate_return(plan),
        Err(_) => LinuxErrno::Einval.negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_plan_registry_set_security(
    existing_sd: *const u8,
    existing_sd_len: usize,
    input_sd: *const u8,
    input_sd_len: usize,
    security_info: u32,
    output: *mut u8,
    output_len: usize,
    written_out: *mut usize,
) -> c_int {
    if written_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    unsafe {
        *written_out = 0;
    }

    if existing_sd.is_null() || input_sd.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if output.is_null() && output_len != 0 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let existing = unsafe { slice::from_raw_parts(existing_sd, existing_sd_len) };
    let input = unsafe { slice::from_raw_parts(input_sd, input_sd_len) };
    let plan = match plan_registry_set_security(existing, input, security_info) {
        Ok(plan) => plan,
        Err(err) => return set_security_merge_error_return(err),
    };
    let merged = plan.merged_sd.as_slice();
    unsafe {
        *written_out = merged.len();
    }

    if output.is_null() {
        return 0;
    }
    if output_len < merged.len() {
        return LinuxErrno::Erange.negated_return() as c_int;
    }

    let output_bytes = unsafe { slice::from_raw_parts_mut(output, output_len) };
    output_bytes[..merged.len()].copy_from_slice(merged);
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_plan_registry_get_security(
    existing_sd: *const u8,
    existing_sd_len: usize,
    security_info: u32,
    output: *mut u8,
    output_len: usize,
    written_out: *mut usize,
) -> c_int {
    if written_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    unsafe {
        *written_out = 0;
    }

    if existing_sd.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if output.is_null() && output_len != 0 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let existing = unsafe { slice::from_raw_parts(existing_sd, existing_sd_len) };
    let plan = match plan_registry_get_security(existing, security_info) {
        Ok(plan) => plan,
        Err(err) => return get_security_plan_error_return(err),
    };
    let sd = plan.output_sd.as_slice();
    unsafe {
        *written_out = sd.len();
    }

    if output.is_null() {
        return 0;
    }
    if output_len < sd.len() {
        return LinuxErrno::Erange.negated_return() as c_int;
    }

    let output_bytes = unsafe { slice::from_raw_parts_mut(output, output_len) };
    output_bytes[..sd.len()].copy_from_slice(sd);
    0
}

fn parse_registration_hives<'a>(
    hives: *const PkmLcsSourceRegistrationHiveCopy,
    hive_count: usize,
) -> Result<PkmVec<SourceRegistrationHive<'a>>, LinuxErrno> {
    let mut parsed = PkmVec::with_capacity(hive_count).map_err(|_| LinuxErrno::Enomem)?;

    for index in 0..hive_count {
        let raw = unsafe { &*hives.add(index) };
        if raw.name.is_null() {
            return Err(LinuxErrno::Einval);
        }
        let name_bytes = unsafe { slice::from_raw_parts(raw.name, raw.name_len as usize) };
        let name = str::from_utf8(name_bytes).map_err(|_| LinuxErrno::Einval)?;

        parsed
            .push(SourceRegistrationHive {
                name,
                root_guid: raw.root_guid,
                flags: raw.flags,
                scope_guid: raw.scope_guid,
            })
            .map_err(|_| LinuxErrno::Enomem)?;
    }

    Ok(parsed)
}

fn parse_existing_hives<'a>(
    hives: *const PkmLcsSourceRegistrationHiveCopy,
    hive_count: usize,
) -> Result<PkmVec<RegisteredHiveIdentity<'a>>, LinuxErrno> {
    let registration_hives = parse_registration_hives(hives, hive_count)?;
    let mut existing_hives =
        PkmVec::with_capacity(registration_hives.len()).map_err(|_| LinuxErrno::Enomem)?;

    for hive in registration_hives.as_slice() {
        let scope = source_registration_hive_scope(hive).map_err(|err| {
            source_registration_error_linux_errno(err).unwrap_or(LinuxErrno::Einval)
        })?;
        existing_hives
            .push(RegisteredHiveIdentity {
                name: hive.name,
                root_guid: hive.root_guid,
                scope,
            })
            .map_err(|_| LinuxErrno::Enomem)?;
    }

    Ok(existing_hives)
}

fn source_slot_status_from_raw(status: u32) -> Result<SourceSlotStatus, LinuxErrno> {
    match status {
        PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE => Ok(SourceSlotStatus::Active),
        PKM_LCS_SOURCE_SLOT_STATUS_DOWN => Ok(SourceSlotStatus::Down),
        _ => Err(LinuxErrno::Einval),
    }
}

fn parse_scope_guids<'a>(
    scope_guids: *const [u8; 16],
    scope_count: usize,
) -> Result<&'a [[u8; 16]], LinuxErrno> {
    if scope_count == 0 {
        return Ok(&[]);
    }
    if scope_guids.is_null() {
        return Err(LinuxErrno::Einval);
    }
    Ok(unsafe { slice::from_raw_parts(scope_guids, scope_count) })
}

fn parse_key_guid_tracker<'a>(
    guids: *const [u8; 16],
    count: usize,
) -> Result<&'a [[u8; 16]], LinuxErrno> {
    if count == 0 {
        return Ok(&[]);
    }
    if guids.is_null() {
        return Err(LinuxErrno::Einval);
    }
    Ok(unsafe { slice::from_raw_parts(guids, count) })
}

fn parse_current_user_rewrite<'a>(
    rewrite_current_user: bool,
    current_user_sid_component: *const u8,
    current_user_sid_component_len: u32,
) -> Result<CurrentUserRewrite<'a>, LinuxErrno> {
    if !rewrite_current_user {
        return Ok(CurrentUserRewrite::Literal);
    }
    if current_user_sid_component.is_null() || current_user_sid_component_len == 0 {
        return Err(LinuxErrno::Einval);
    }

    let sid_bytes = unsafe {
        slice::from_raw_parts(
            current_user_sid_component,
            current_user_sid_component_len as usize,
        )
    };
    let sid_component = str::from_utf8(sid_bytes).map_err(|_| LinuxErrno::Einval)?;
    Ok(CurrentUserRewrite::InitialCallerPath {
        user_sid_component: sid_component,
    })
}

fn parse_layer_views<'a>(
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
) -> Result<PkmVec<LayerView<'a>>, LinuxErrno> {
    let mut parsed = PkmVec::with_capacity(layer_count).map_err(|_| LinuxErrno::Enomem)?;

    for index in 0..layer_count {
        let raw = unsafe { &*layers.add(index) };
        if raw.name.is_null() {
            return Err(LinuxErrno::Einval);
        }
        let name_bytes = unsafe { slice::from_raw_parts(raw.name, raw.name_len as usize) };
        let name = str::from_utf8(name_bytes).map_err(|_| LinuxErrno::Einval)?;
        let enabled = match raw.enabled {
            0 => false,
            1 => true,
            _ => return Err(LinuxErrno::Einval),
        };
        parsed
            .push(LayerView {
                name,
                precedence: raw.precedence,
                enabled,
            })
            .map_err(|_| LinuxErrno::Enomem)?;
    }

    Ok(parsed)
}

fn parse_layer_metadata_sd_view_name<'a>(
    raw: &PkmLcsLayerMetadataSdViewCopy,
    limits: &LcsLimits,
) -> Result<&'a str, LinuxErrno> {
    if raw.name.is_null() {
        return Err(LinuxErrno::Eio);
    }

    let name_bytes = unsafe { slice::from_raw_parts(raw.name, raw.name_len as usize) };
    validate_layer_name_bytes(name_bytes, limits).map_err(|_| LinuxErrno::Eio)
}

fn parse_private_layer_views<'a>(
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
) -> Result<PkmVec<&'a str>, LinuxErrno> {
    let mut parsed = PkmVec::with_capacity(private_layer_count).map_err(|_| LinuxErrno::Enomem)?;

    for index in 0..private_layer_count {
        let raw = unsafe { &*private_layers.add(index) };
        if raw.name.is_null() {
            return Err(LinuxErrno::Einval);
        }
        let name_bytes = unsafe { slice::from_raw_parts(raw.name, raw.name_len as usize) };
        let name = str::from_utf8(name_bytes).map_err(|_| LinuxErrno::Einval)?;
        parsed.push(name).map_err(|_| LinuxErrno::Enomem)?;
    }

    Ok(parsed)
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_source_registration_empty(
    limits_raw: *const PkmLcsRuntimeLimitsCopy,
    hives: *const PkmLcsSourceRegistrationHiveCopy,
    hive_count: usize,
    max_sequence: u64,
    caller_has_tcb: bool,
    plan_out: *mut PkmLcsSourceRegistrationPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if hive_count != 0 && hives.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let limits = match lcs_limits_from_copy(limits_raw) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let parsed = match parse_registration_hives(hives, hive_count) {
        Ok(parsed) => parsed,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let request = SourceRegistrationRequest {
        hives: parsed.as_slice(),
        max_sequence,
        caller_has_tcb,
    };
    let plan = match validate_source_registration(&limits, &[], &request) {
        Ok(plan) => plan,
        Err(err) => return source_registration_error_return(err),
    };

    unsafe {
        (*plan_out).hive_count = plan.hive_count as u32;
        (*plan_out).source_next_sequence = plan.source_next_sequence;
        (*plan_out).effective_next_sequence = plan.source_next_sequence;
        (*plan_out).decision = PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW;
        (*plan_out).source_id = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_source_registration(
    limits_raw: *const PkmLcsRuntimeLimitsCopy,
    hives: *const PkmLcsSourceRegistrationHiveCopy,
    hive_count: usize,
    max_sequence: u64,
    caller_has_tcb: bool,
    slots: *const PkmLcsSourceSlotViewCopy,
    slot_count: usize,
    current_next_sequence_valid: bool,
    current_next_sequence: u64,
    plan_out: *mut PkmLcsSourceRegistrationPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if hive_count != 0 && hives.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if slot_count != 0 && slots.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let limits = match lcs_limits_from_copy(limits_raw) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let parsed = match parse_registration_hives(hives, hive_count) {
        Ok(parsed) => parsed,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let mut slot_hive_storage =
        match PkmVec::<PkmVec<RegisteredHiveIdentity<'_>>>::with_capacity(slot_count) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };

    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        if raw_slot.hive_count != 0 && raw_slot.hives.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let parsed_hives = match parse_existing_hives(raw_slot.hives, raw_slot.hive_count as usize)
        {
            Ok(hives) => hives,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if slot_hive_storage.push(parsed_hives).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let mut existing_slots = match PkmVec::with_capacity(slot_count) {
        Ok(slots) => slots,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };

    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        let status = match source_slot_status_from_raw(raw_slot.status) {
            Ok(status) => status,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if existing_slots
            .push(SourceSlotView {
                source_id: raw_slot.source_id,
                status,
                hives: slot_hive_storage[index].as_slice(),
            })
            .is_err()
        {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let request = SourceRegistrationRequest {
        hives: parsed.as_slice(),
        max_sequence,
        caller_has_tcb,
    };
    let plan = match validate_source_registration(
        &limits,
        existing_slots.as_slice(),
        &request,
    ) {
        Ok(plan) => plan,
        Err(err) => return source_registration_error_return(err),
    };
    let sequence_plan = match plan_source_registration_sequence_update(
        current_next_sequence_valid.then_some(current_next_sequence),
        max_sequence,
    ) {
        Ok(plan) => plan,
        Err(err) => return source_registration_error_return(err),
    };

    unsafe {
        (*plan_out).hive_count = plan.hive_count as u32;
        (*plan_out).source_next_sequence = plan.source_next_sequence;
        (*plan_out).effective_next_sequence = sequence_plan.effective_next_sequence;
        match plan.decision {
            SourceRegistrationDecision::NewSlot => {
                (*plan_out).decision = PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW;
                (*plan_out).source_id = 0;
            }
            SourceRegistrationDecision::ResumeDownSlot(source_id) => {
                (*plan_out).decision = PKM_LCS_SOURCE_REGISTRATION_DECISION_RESUME_DOWN;
                (*plan_out).source_id = source_id;
            }
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_route_hive_from_source_slots(
    slots: *const PkmLcsSourceSlotViewCopy,
    slot_count: usize,
    hive_name: *const u8,
    hive_name_len: u32,
    scope_guids: *const [u8; 16],
    scope_count: usize,
    result_out: *mut PkmLcsHiveRouteResultCopy,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    if result_out.is_null() || hive_name.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if slot_count != 0 && slots.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let name_bytes = unsafe { slice::from_raw_parts(hive_name, hive_name_len as usize) };
    let hive_name = match str::from_utf8(name_bytes) {
        Ok(name) => name,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    let scope_guids = match parse_scope_guids(scope_guids, scope_count) {
        Ok(scopes) => scopes,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let mut slot_hive_storage =
        match PkmVec::<PkmVec<RegisteredHiveIdentity<'_>>>::with_capacity(slot_count) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut total_hives = 0usize;
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        if raw_slot.hive_count != 0 && raw_slot.hives.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let parsed_hives = match parse_existing_hives(raw_slot.hives, raw_slot.hive_count as usize)
        {
            Ok(hives) => hives,
            Err(errno) => return errno.negated_return() as c_int,
        };
        total_hives += parsed_hives.len();
        if slot_hive_storage.push(parsed_hives).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let mut existing_slots = match PkmVec::with_capacity(slot_count) {
        Ok(slots) => slots,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        let status = match source_slot_status_from_raw(raw_slot.status) {
            Ok(status) => status,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if existing_slots
            .push(SourceSlotView {
                source_id: raw_slot.source_id,
                status,
                hives: slot_hive_storage[index].as_slice(),
            })
            .is_err()
        {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    if let Err(err) = validate_source_slots(&limits, existing_slots.as_slice()) {
        return source_registration_error_return(err);
    }

    let mut hive_views = match PkmVec::with_capacity(total_hives) {
        Ok(hives) => hives,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for slot in existing_slots.as_slice() {
        let status = source_slot_hive_status(slot.status);
        for hive in slot.hives {
            if hive_views
                .push(HiveView {
                    name: hive.name,
                    root_guid: hive.root_guid,
                    source_id: slot.source_id,
                    status,
                    scope: hive.scope,
                })
                .is_err()
            {
                return LinuxErrno::Enomem.negated_return() as c_int;
            }
        }
    }

    let route = match route_hive(
        &limits,
        hive_views.as_slice(),
        hive_name,
        scope_guids,
    ) {
        Ok(route) => route,
        Err(err) => return source_registration_error_return(err),
    };
    match classify_hive_route(route) {
        HiveRouteOutcome::Dispatch(hive) => unsafe {
            (*result_out).source_id = hive.source_id;
            (*result_out).root_guid = hive.root_guid;
            0
        },
        HiveRouteOutcome::Failure(errno) => LinuxErrno::from(errno).negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_route_absolute_path_from_source_slots(
    slots: *const PkmLcsSourceSlotViewCopy,
    slot_count: usize,
    path: *const u8,
    path_len: u32,
    rewrite_current_user: bool,
    current_user_sid_component: *const u8,
    current_user_sid_component_len: u32,
    scope_guids: *const [u8; 16],
    scope_count: usize,
    result_out: *mut PkmLcsHiveRouteResultCopy,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    if result_out.is_null() || path.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if slot_count != 0 && slots.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let path_bytes = unsafe { slice::from_raw_parts(path, path_len as usize) };
    let path = match validate_syscall_path_c_string(path_bytes, PathKind::Absolute, &limits) {
        Ok(summary) => summary.raw,
        Err(err) => return absolute_route_error_return(err),
    };
    let rewrite = match parse_current_user_rewrite(
        rewrite_current_user,
        current_user_sid_component,
        current_user_sid_component_len,
    ) {
        Ok(rewrite) => rewrite,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let scope_guids = match parse_scope_guids(scope_guids, scope_count) {
        Ok(scopes) => scopes,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let mut slot_hive_storage =
        match PkmVec::<PkmVec<RegisteredHiveIdentity<'_>>>::with_capacity(slot_count) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut total_hives = 0usize;
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        if raw_slot.hive_count != 0 && raw_slot.hives.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let parsed_hives = match parse_existing_hives(raw_slot.hives, raw_slot.hive_count as usize)
        {
            Ok(hives) => hives,
            Err(errno) => return errno.negated_return() as c_int,
        };
        total_hives += parsed_hives.len();
        if slot_hive_storage.push(parsed_hives).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let mut existing_slots = match PkmVec::with_capacity(slot_count) {
        Ok(slots) => slots,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        let status = match source_slot_status_from_raw(raw_slot.status) {
            Ok(status) => status,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if existing_slots
            .push(SourceSlotView {
                source_id: raw_slot.source_id,
                status,
                hives: slot_hive_storage[index].as_slice(),
            })
            .is_err()
        {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    if let Err(err) = validate_source_slots(&limits, existing_slots.as_slice()) {
        return source_registration_error_return(err);
    }

    let mut hive_views = match PkmVec::with_capacity(total_hives) {
        Ok(hives) => hives,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for slot in existing_slots.as_slice() {
        let status = source_slot_hive_status(slot.status);
        for hive in slot.hives {
            if hive_views
                .push(HiveView {
                    name: hive.name,
                    root_guid: hive.root_guid,
                    source_id: slot.source_id,
                    status,
                    scope: hive.scope,
                })
                .is_err()
            {
                return LinuxErrno::Enomem.negated_return() as c_int;
            }
        }
    }

    let route = match route_routable_path_hive(
        &limits,
        hive_views.as_slice(),
        path,
        rewrite,
        scope_guids,
    ) {
        Ok(route) => route,
        Err(err) => return absolute_route_error_return(err),
    };
    match route {
        HiveRouteOutcome::Dispatch(hive) => unsafe {
            (*result_out).source_id = hive.source_id;
            (*result_out).root_guid = hive.root_guid;
            0
        },
        HiveRouteOutcome::Failure(errno) => LinuxErrno::from(errno).negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_route_absolute_path_from_source_slots_with_token_sid(
    slots: *const PkmLcsSourceSlotViewCopy,
    slot_count: usize,
    path: *const u8,
    path_len: u32,
    rewrite_current_user: bool,
    current_user_sid: *const u8,
    current_user_sid_len: usize,
    scope_guids: *const [u8; 16],
    scope_count: usize,
    result_out: *mut PkmLcsHiveRouteResultCopy,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    if result_out.is_null() || path.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let parsed_limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };
    if !rewrite_current_user {
        return unsafe {
            lcs_rust_route_absolute_path_from_source_slots(
                slots,
                slot_count,
                path,
                path_len,
                false,
                core::ptr::null(),
                0,
                scope_guids,
                scope_count,
                result_out,
                limits,
            )
        };
    }
    if current_user_sid.is_null() || current_user_sid_len == 0 {
        return LinuxErrno::Eacces.negated_return() as c_int;
    }

    let sid_bytes = unsafe { slice::from_raw_parts(current_user_sid, current_user_sid_len) };
    let sid_component =
        match current_user_sid_component_from_binary_sid(&parsed_limits, sid_bytes) {
            Ok(component) => component,
            Err(err) => return absolute_route_error_return(err),
        };
    let sid_component = sid_component.as_str();
    unsafe {
        lcs_rust_route_absolute_path_from_source_slots(
            slots,
            slot_count,
            path,
            path_len,
            true,
            sid_component.as_ptr(),
            sid_component.len() as u32,
            scope_guids,
            scope_count,
            result_out,
            limits,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_route_symlink_target_from_source_slots(
    slots: *const PkmLcsSourceSlotViewCopy,
    slot_count: usize,
    target: *const u8,
    target_len: u32,
    scope_guids: *const [u8; 16],
    scope_count: usize,
    result_out: *mut PkmLcsHiveRouteResultCopy,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    if result_out.is_null() || target.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if slot_count != 0 && slots.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let target_bytes = unsafe { slice::from_raw_parts(target, target_len as usize) };
    let scope_guids = match parse_scope_guids(scope_guids, scope_count) {
        Ok(scopes) => scopes,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let mut slot_hive_storage =
        match PkmVec::<PkmVec<RegisteredHiveIdentity<'_>>>::with_capacity(slot_count) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut total_hives = 0usize;
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        if raw_slot.hive_count != 0 && raw_slot.hives.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let parsed_hives = match parse_existing_hives(raw_slot.hives, raw_slot.hive_count as usize)
        {
            Ok(hives) => hives,
            Err(errno) => return errno.negated_return() as c_int,
        };
        total_hives += parsed_hives.len();
        if slot_hive_storage.push(parsed_hives).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let mut existing_slots = match PkmVec::with_capacity(slot_count) {
        Ok(slots) => slots,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        let status = match source_slot_status_from_raw(raw_slot.status) {
            Ok(status) => status,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if existing_slots
            .push(SourceSlotView {
                source_id: raw_slot.source_id,
                status,
                hives: slot_hive_storage[index].as_slice(),
            })
            .is_err()
        {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    if let Err(err) = validate_source_slots(&limits, existing_slots.as_slice()) {
        return source_registration_error_return(err);
    }

    let mut hive_views = match PkmVec::with_capacity(total_hives) {
        Ok(hives) => hives,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for slot in existing_slots.as_slice() {
        let status = source_slot_hive_status(slot.status);
        for hive in slot.hives {
            if hive_views
                .push(HiveView {
                    name: hive.name,
                    root_guid: hive.root_guid,
                    source_id: slot.source_id,
                    status,
                    scope: hive.scope,
                })
                .is_err()
            {
                return LinuxErrno::Enomem.negated_return() as c_int;
            }
        }
    }

    let route = match route_symlink_target_hive(
        &limits,
        hive_views.as_slice(),
        target_bytes,
        scope_guids,
    ) {
        Ok(route) => route,
        Err(err) => return symlink_target_error_return(err),
    };
    match route {
        HiveRouteOutcome::Dispatch(hive) => unsafe {
            (*result_out).source_id = hive.source_id;
            (*result_out).root_guid = hive.root_guid;
            0
        },
        HiveRouteOutcome::Failure(errno) => LinuxErrno::from(errno).negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_absolute_path_components_with_token_sid(
    path: *const u8,
    path_len: u32,
    rewrite_current_user: bool,
    current_user_sid: *const u8,
    current_user_sid_len: usize,
    components: *mut PkmLcsPathComponentViewCopy,
    component_capacity: usize,
    string_buf: *mut u8,
    string_capacity: usize,
    result_out: *mut PkmLcsPathComponentMaterializationCopy,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    let Some(result_out) = (unsafe { result_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *result_out = PkmLcsPathComponentMaterializationCopy {
        component_count: 0,
        string_bytes: 0,
    };
    if path.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let path_bytes = unsafe { slice::from_raw_parts(path, path_len as usize) };
    let path = match validate_syscall_path_c_string(path_bytes, PathKind::Absolute, &limits) {
        Ok(summary) => summary.raw,
        Err(err) => return absolute_route_error_return(err),
    };

    let sid_component_storage = if rewrite_current_user {
        if current_user_sid.is_null() || current_user_sid_len == 0 {
            return LinuxErrno::Eacces.negated_return() as c_int;
        }
        let sid_bytes = unsafe { slice::from_raw_parts(current_user_sid, current_user_sid_len) };
        match current_user_sid_component_from_binary_sid(&limits, sid_bytes) {
            Ok(component) => Some(component),
            Err(err) => return absolute_route_error_return(err),
        }
    } else {
        None
    };
    let rewrite = match sid_component_storage.as_ref() {
        Some(component) => CurrentUserRewrite::InitialCallerPath {
            user_sid_component: component.as_str(),
        },
        None => CurrentUserRewrite::Literal,
    };

    let mut component_count = 0usize;
    let mut string_bytes = 0usize;
    if let Err(err) =
        for_each_routable_path_component(&limits, path, rewrite, |component| {
            component_count = component_count
                .checked_add(1)
                .ok_or(LcsError::KeyDepthExceeded {
                    depth: usize::MAX,
                    max: limits.max_key_depth,
                })?;
            string_bytes =
                string_bytes
                    .checked_add(component.len())
                    .ok_or(LcsError::PathTooLong {
                        len: usize::MAX,
                        max: limits.max_total_path_length,
                    })?;
            Ok(())
        })
    {
        return absolute_route_error_return(err);
    }

    let Ok(component_count_u32) = u32::try_from(component_count) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    let Ok(string_bytes_u32) = u32::try_from(string_bytes) else {
        return LinuxErrno::Enametoolong.negated_return() as c_int;
    };
    *result_out = PkmLcsPathComponentMaterializationCopy {
        component_count: component_count_u32,
        string_bytes: string_bytes_u32,
    };

    if components.is_null()
        && component_capacity == 0
        && string_buf.is_null()
        && string_capacity == 0
    {
        return 0;
    }
    if components.is_null() || string_buf.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if component_capacity < component_count || string_capacity < string_bytes {
        return LinuxErrno::Erange.negated_return() as c_int;
    }

    let component_out = unsafe { slice::from_raw_parts_mut(components, component_capacity) };
    let string_out = unsafe { slice::from_raw_parts_mut(string_buf, string_capacity) };
    let mut index = 0usize;
    let mut offset = 0usize;
    if let Err(err) =
        for_each_routable_path_component(&limits, path, rewrite, |component| {
            let bytes = component.as_bytes();
            let end = offset + bytes.len();
            string_out[offset..end].copy_from_slice(bytes);
            component_out[index].name = unsafe { string_buf.add(offset) as *const u8 };
            component_out[index].name_len = bytes.len() as u32;
            index += 1;
            offset = end;
            Ok(())
        })
    {
        return absolute_route_error_return(err);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_symlink_target_components(
    target: *const u8,
    target_len: u32,
    components: *mut PkmLcsPathComponentViewCopy,
    component_capacity: usize,
    string_buf: *mut u8,
    string_capacity: usize,
    result_out: *mut PkmLcsPathComponentMaterializationCopy,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    let Some(result_out) = (unsafe { result_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *result_out = PkmLcsPathComponentMaterializationCopy {
        component_count: 0,
        string_bytes: 0,
    };
    if target.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let target_bytes = unsafe { slice::from_raw_parts(target, target_len as usize) };
    let path = match validate_symlink_target_bytes(&limits, target_bytes) {
        Ok(summary) => summary.raw,
        Err(err) => return symlink_target_error_return(err),
    };
    let rewrite = CurrentUserRewrite::Literal;

    let mut component_count = 0usize;
    let mut string_bytes = 0usize;
    if let Err(err) =
        for_each_routable_path_component(&limits, path, rewrite, |component| {
            component_count = component_count
                .checked_add(1)
                .ok_or(LcsError::KeyDepthExceeded {
                    depth: usize::MAX,
                    max: limits.max_key_depth,
                })?;
            string_bytes =
                string_bytes
                    .checked_add(component.len())
                    .ok_or(LcsError::PathTooLong {
                        len: usize::MAX,
                        max: limits.max_total_path_length,
                    })?;
            Ok(())
        })
    {
        return symlink_target_error_return(err);
    }

    let Ok(component_count_u32) = u32::try_from(component_count) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    let Ok(string_bytes_u32) = u32::try_from(string_bytes) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *result_out = PkmLcsPathComponentMaterializationCopy {
        component_count: component_count_u32,
        string_bytes: string_bytes_u32,
    };

    if components.is_null()
        && component_capacity == 0
        && string_buf.is_null()
        && string_capacity == 0
    {
        return 0;
    }
    if components.is_null() || string_buf.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if component_capacity < component_count || string_capacity < string_bytes {
        return LinuxErrno::Erange.negated_return() as c_int;
    }

    let component_out = unsafe { slice::from_raw_parts_mut(components, component_capacity) };
    let string_out = unsafe { slice::from_raw_parts_mut(string_buf, string_capacity) };
    let mut index = 0usize;
    let mut offset = 0usize;
    if let Err(err) =
        for_each_routable_path_component(&limits, path, rewrite, |component| {
            let bytes = component.as_bytes();
            let end = offset + bytes.len();
            string_out[offset..end].copy_from_slice(bytes);
            component_out[index].name = unsafe { string_buf.add(offset) as *const u8 };
            component_out[index].name_len = bytes.len() as u32;
            index += 1;
            offset = end;
            Ok(())
        })
    {
        return symlink_target_error_return(err);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_relative_path_components(
    path: *const u8,
    path_len: u32,
    components: *mut PkmLcsPathComponentViewCopy,
    component_capacity: usize,
    string_buf: *mut u8,
    string_capacity: usize,
    result_out: *mut PkmLcsPathComponentMaterializationCopy,
    limits: *const PkmLcsRuntimeLimitsCopy,
) -> c_int {
    let Some(result_out) = (unsafe { result_out.as_mut() }) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    *result_out = PkmLcsPathComponentMaterializationCopy {
        component_count: 0,
        string_bytes: 0,
    };
    if path.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let limits = match lcs_limits_from_copy(limits) {
        Ok(limits) => limits,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let path_bytes = unsafe { slice::from_raw_parts(path, path_len as usize) };
    let path = match validate_syscall_path_c_string(path_bytes, PathKind::Relative, &limits) {
        Ok(summary) => summary.raw,
        Err(err) => return absolute_route_error_return(err),
    };

    let mut component_count = 0usize;
    let mut string_bytes = 0usize;
    if let Err(err) = for_each_syscall_path_component(path, |component| {
        component_count = component_count
            .checked_add(1)
            .ok_or(LcsError::KeyDepthExceeded {
                depth: usize::MAX,
                max: limits.max_key_depth,
            })?;
        string_bytes = string_bytes
            .checked_add(component.len())
            .ok_or(LcsError::PathTooLong {
                len: usize::MAX,
                max: limits.max_total_path_length,
            })?;
        Ok(())
    }) {
        return absolute_route_error_return(err);
    }

    let Ok(component_count_u32) = u32::try_from(component_count) else {
        return LinuxErrno::Einval.negated_return() as c_int;
    };
    let Ok(string_bytes_u32) = u32::try_from(string_bytes) else {
        return LinuxErrno::Enametoolong.negated_return() as c_int;
    };
    *result_out = PkmLcsPathComponentMaterializationCopy {
        component_count: component_count_u32,
        string_bytes: string_bytes_u32,
    };

    if components.is_null()
        && component_capacity == 0
        && string_buf.is_null()
        && string_capacity == 0
    {
        return 0;
    }
    if components.is_null() || string_buf.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if component_capacity < component_count || string_capacity < string_bytes {
        return LinuxErrno::Erange.negated_return() as c_int;
    }

    let component_out = unsafe { slice::from_raw_parts_mut(components, component_capacity) };
    let string_out = unsafe { slice::from_raw_parts_mut(string_buf, string_capacity) };
    let mut index = 0usize;
    let mut offset = 0usize;
    if let Err(err) = for_each_syscall_path_component(path, |component| {
        let bytes = component.as_bytes();
        let end = offset + bytes.len();
        string_out[offset..end].copy_from_slice(bytes);
        component_out[index].name = unsafe { string_buf.add(offset) as *const u8 };
        component_out[index].name_len = bytes.len() as u32;
        index += 1;
        offset = end;
        Ok(())
    }) {
        return absolute_route_error_return(err);
    }
    0
}

fn for_each_syscall_path_component<'a, F>(path: &'a str, mut emit: F) -> Result<(), LcsError>
where
    F: FnMut(&'a str) -> Result<(), LcsError>,
{
    let mut start = 0usize;
    for (index, byte) in path.as_bytes().iter().copied().enumerate() {
        if byte == b'\\' || byte == b'/' {
            emit(&path[start..index])?;
            start = index + 1;
        }
    }
    emit(&path[start..])
}
