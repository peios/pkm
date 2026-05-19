//! Slow-track LCS semantic core.
//!
//! This crate contains pure, reusable PSD-005 validation and normalization
//! primitives. It intentionally does not perform syscalls, source I/O, KACS
//! access checks, fd management, or KMES emission.

#![cfg_attr(feature = "kernel", no_std)]
#![allow(unreachable_pub)]

pub mod access;
pub mod casefold;
pub mod config;
pub mod constants;
pub mod error;
pub mod hives;
pub mod ioctl;
pub mod key;
pub mod key_path;
pub mod layers;
pub mod metadata;
pub mod output_buffer;
pub mod path;
pub mod query;
pub mod resolution;
pub mod rsi;
pub mod sequence;
pub mod source;
pub mod string;
pub mod symlink;
pub mod value;
pub mod watch;

pub use access::{
    NormalizedRegistryAccess, REGISTRY_GENERIC_MAPPING, RegistryGenericMapping,
    map_registry_generic_bits, registry_fd_has_right, validate_registry_ace_mask,
    validate_registry_desired_access,
};
pub use casefold::{
    casefold_cmp, casefold_eq, casefold_eq_bytes, casefold_is, unicode_simple_case_fold,
};
pub use config::{
    ConfigRange, LcsLimits, MAX_BOUND_TRANSACTIONS_PER_SOURCE, MAX_CONCURRENT_RSI_REQUESTS,
    MAX_HIVES_PER_SOURCE, MAX_KEY_DEPTH, MAX_LAYERS_PER_VALUE, MAX_PATH_COMPONENT_LENGTH,
    MAX_PRIVATE_LAYERS_PER_TOKEN, MAX_READ_ONLY_TRANSACTIONS_PER_SOURCE, MAX_REGISTERED_SOURCES,
    MAX_SCOPE_GUIDS_PER_TOKEN, MAX_SUBTREE_WATCH_DEPTH, MAX_TOTAL_LAYERS, MAX_TOTAL_PATH_LENGTH,
    MAX_TRANSACTION_WATCH_EVENT_BURST, MAX_VALUE_SIZE, NOTIFICATION_QUEUE_SIZE, REQUEST_TIMEOUT_MS,
    SYMLINK_DEPTH_LIMIT, TRANSACTION_TIMEOUT_MS, validate_config_value,
};
pub use constants::*;
pub use error::{LcsError, LcsResult};
pub use hives::{
    CurrentUserRewrite, HiveRoute, HiveScope, HiveStatus, HiveView, RoutedHive, SourceId,
    for_each_routable_path_component, route_hive, validate_hive_table, validate_scope_guid_set,
};
pub use ioctl::{
    RegistryIoctlAccessRequirement, RegistryIoctlPrivilege, RegistrySecurityOperation,
    registry_ioctl_access_requirement, registry_ioctl_fixed_granted_mask_allows,
    registry_security_info_granted_mask_allows, registry_security_info_required_access,
    validate_registry_security_info,
};
pub use key::{
    KeyCreateOptions, KeyCreatePlan, KeyCreateRequest, KeyParent, KeyRecordView,
    validate_key_create_flags, validate_key_create_request, validate_key_record,
    validate_symlink_create_authority,
};
pub use key_path::{
    DeleteKeyInput, DerivedKeyPathMutation, HideKeyInput, KeyFdNamespaceView, KeyPathMutationInput,
    PlannedKeyDelete, PlannedKeyHide, derive_key_path_mutation, plan_key_delete, plan_key_hide,
};
pub use layers::{
    BASE_LAYER_VIEW, LayerMetadataEntry, for_each_effective_layer, normalize_layer_target,
    validate_layer_resolution_context, validate_layer_views, validate_private_layer_set,
};
pub use metadata::{
    HiveGenerationCounter, QueryKeyInfoInput, QueryKeyInfoOutputBufferDecision, QueryKeyInfoResult,
    query_key_info_result, validate_query_key_info_output_buffer,
};
pub use output_buffer::{
    OutputBufferAggregate, OutputBufferDecision, OutputBufferRequest, OutputBufferShape,
    aggregate_output_buffer_decisions, classify_output_buffer_request,
    validate_output_buffer_required_size,
};
pub use path::{
    PathKind, PathSummary, is_base_layer_name, is_reserved_current_user_name,
    validate_hive_name_bytes, validate_key_component_bytes, validate_layer_name_bytes,
    validate_registry_path_bytes, validate_registry_path_str, validate_value_name_bytes,
};
pub use query::{
    EnumSubkeyOutcome, EnumSubkeyOutputBufferDecision, EnumSubkeyResult, EnumValueOutcome,
    EnumValueOutputBufferDecision, EnumValueOutputBuffers, EnumValueResult, EnumeratedSubkeyInfo,
    QueryValueOutcome, QueryValueOutputBufferDecision, QueryValueOutputBuffers, QueryValueResult,
    QueryValuesBatchOutputDecision, enum_subkey_result_at, enum_value_result_at,
    packed_batch_value_len, query_value_result_from_resolution, query_values_batch_required_len,
    validate_enum_subkey_output_buffer, validate_enum_value_output_buffers,
    validate_query_value_output_buffers, validate_query_values_batch_output,
};
pub use resolution::{
    BlanketTombstoneEntry, EnumeratedSubkey, EnumeratedValue, Guid, LayerResolutionContext,
    LayerView, NamedPathEntry, NamedValueEntry, PathEntry, PathEntryWriteRequest, PathResolution,
    PathTarget, ResolvedPathEntry, ResolvedValueEntry, ValidatedPathEntryWrite, ValueEntry,
    ValueResolution, for_each_effective_value, for_each_visible_subkey, resolve_path_entry,
    resolve_value, validate_path_entry_write_request, validate_path_target,
};
pub use rsi::{
    RsiMappedErrno, RsiStatus, RsiStatusOutcome, classify_rsi_status_code, map_rsi_status,
    parse_rsi_status,
};
pub use sequence::SequenceCounter;
pub use source::{
    NIL_GUID, RegisteredHiveIdentity, SourceRegistrationDecision, SourceRegistrationHive,
    SourceRegistrationPlan, SourceRegistrationRequest, SourceSlotStatus, SourceSlotView,
    for_each_source_slot_hive, source_registration_hive_scope, source_slot_hive_status,
    validate_source_registration, validate_source_registration_hives, validate_source_slots,
};
pub use string::validate_lcs_str;
pub use symlink::{
    SymlinkDefaultValue, validate_symlink_default_value, validate_symlink_follow_depth,
    validate_symlink_target_bytes,
};
pub use value::{
    BlanketTombstoneAction, BlanketTombstoneInput, BlanketTombstoneRequest,
    PlannedBlanketTombstone, PlannedValueDelete, PlannedValueWrite, RegistryValueType,
    ValidatedBlanketTombstone, ValidatedValueDelete, ValidatedValueType, ValidatedValueWrite,
    ValueDeleteRequest, ValueWriteInput, ValueWriteRequest, plan_blanket_tombstone,
    plan_value_delete, plan_value_write, validate_blanket_tombstone_request,
    validate_value_data_len, validate_value_delete_request, validate_value_write_request,
    validate_value_write_type,
};
pub use watch::{
    KeyWatchState, QueuedWatchEvent, WatchDelivery, WatchDispatchDecision, WatchEventCategory,
    WatchEventRecordPlan, WatchEventRecordRequest, WatchEventRecordShape, WatchMutationContext,
    WatchNotifyArgs, WatchNotifyPlan, WatchQueueInsertPlan, WatchQueueState, WatchReadBatchPlan,
    WatcherView, plan_watch_dispatch, plan_watch_event_record, plan_watch_notify,
    plan_watch_queue_insert, plan_watch_read_batch, validate_abi_bool, validate_notify_filter,
    validate_notify_reserved, watch_event_category, watch_event_matches_filter,
};

/// Returns a stable value from the staged crate so integration build steps can
/// prove the real `lcs-core` module graph compiled and linked.
pub fn kernel_compile_probe() -> usize {
    REG_VALID_DESIRED_ACCESS_MASK as usize
}
