//! Slow-track LCS semantic core.
//!
//! This crate contains pure, reusable PSD-005 validation and normalization
//! primitives. It intentionally does not perform syscalls, source I/O, KACS
//! access checks, fd management, or KMES emission.

#![cfg_attr(feature = "kernel", no_std)]
#![allow(unreachable_pub)]

pub mod access;
pub mod backup;
pub mod casefold;
pub mod config;
pub mod constants;
pub mod error;
pub mod fd;
pub mod hives;
pub mod ioctl;
pub mod key;
pub mod key_path;
pub mod layers;
pub mod maintenance;
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
pub mod transaction;
pub mod value;
pub mod watch;

pub use access::{
    NormalizedRegistryAccess, REGISTRY_GENERIC_MAPPING, RegistryGenericMapping,
    map_registry_generic_bits, registry_fd_has_right, validate_registry_ace_mask,
    validate_registry_desired_access, validate_registry_granted_access,
};
pub use backup::{
    BACKUP_RECORD_HEADER_LEN, BACKUP_TRAILER_CHECKSUM_LEN, BACKUP_TRAILER_PAYLOAD_LEN,
    BackupBlanketTombstonePayload, BackupHeaderPayload, BackupKeyPayload,
    BackupLayerManifestPayload, BackupLayerManifestSetSummary, BackupPathEntryPayload,
    BackupRecordFrame, BackupRecordHeader, BackupRecordKind, BackupRestoreBlanketTombstone,
    BackupRestoreKeySetSummary, BackupRestoreLayerPrecedencePlan,
    BackupRestoreNonRootKeyCreatePlan, BackupRestoreNonRootKeyTimestampWritePlan,
    BackupRestorePathEntry, BackupRestoreProcessedKeySet, BackupRestoreRecordDispatchDisposition,
    BackupRestoreRootSectionPathEntrySkip, BackupRestoreRootWritePlan,
    BackupRestoreSequenceRemapper, BackupRestoreTargetRoot, BackupRestoreTeardownDeleteBlanketPlan,
    BackupRestoreTeardownDeletePathEntryPlan, BackupRestoreTeardownDeleteValuePlan,
    BackupRestoreTeardownDropKeyPlan, BackupRestoreUnknownRecordSkipPlan, BackupRestoreValue,
    BackupStreamEnvelopeState, BackupStreamEnvelopeSummary, BackupStreamOrderingPhase,
    BackupStreamOrderingState, BackupStreamOrderingSummary, BackupTrailerPayload,
    BackupValuePayload, parse_backup_blanket_tombstone_payload,
    parse_backup_blanket_tombstone_record, parse_backup_header_payload, parse_backup_header_record,
    parse_backup_key_payload, parse_backup_key_record, parse_backup_layer_manifest_payload,
    parse_backup_layer_manifest_record, parse_backup_path_entry_payload,
    parse_backup_path_entry_record, parse_backup_record_frame, parse_backup_record_header,
    parse_backup_trailer_payload, parse_backup_trailer_record, parse_backup_value_payload,
    parse_backup_value_record, plan_backup_restore_layer_precedence_gate,
    plan_backup_restore_non_root_key_create, plan_backup_restore_non_root_key_timestamp_write,
    plan_backup_restore_record_dispatch, plan_backup_restore_root_section_path_entry_skip,
    plan_backup_restore_root_write, plan_backup_restore_teardown_delete_blanket,
    plan_backup_restore_teardown_delete_path_entry, plan_backup_restore_teardown_delete_value,
    plan_backup_restore_teardown_drop_descendant_key, remap_backup_restore_blanket_tombstone,
    remap_backup_restore_guid, remap_backup_restore_path_entry,
    remap_backup_restore_path_entry_for_dispatch,
    remap_backup_restore_path_entry_for_dispatch_with_key_set,
    remap_backup_restore_path_entry_with_key_set,
    remap_backup_restore_root_section_blanket_tombstone, remap_backup_restore_root_section_value,
    remap_backup_restore_value, validate_backup_layer_manifest_set,
    validate_backup_restore_key_set, validate_backup_restore_path_entry_target_in_key_set,
    write_backup_blanket_tombstone_record_frame, write_backup_header_record_frame,
    write_backup_key_record_frame, write_backup_layer_manifest_record_frame,
    write_backup_path_entry_record_frame, write_backup_record_header,
    write_backup_trailer_record_frame, write_backup_value_record_frame,
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
pub use fd::{
    KeyFdClosePlan, KeyFdDelegationPlan, KeyFdOpenView, key_fd_granted_access_allows,
    plan_key_fd_close, plan_key_fd_delegation, validate_key_fd_open_view,
};
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
    RegCreateKeyResolutionPlan, RegCreateKeySourceResultPlan, RegCreateKeyTarget,
    plan_reg_create_key_resolution, plan_reg_create_key_source_result, validate_key_create_flags,
    validate_key_create_request, validate_key_record, validate_symlink_create_authority,
};
pub use key_path::{
    DeleteKeyInput, DerivedKeyPathMutation, HideKeyInput, KeyFdNamespaceView, KeyPathMutationInput,
    PlannedKeyDelete, PlannedKeyHide, derive_key_path_mutation, plan_key_delete, plan_key_hide,
};
pub use layers::{
    BASE_LAYER_VIEW, LayerDeletionPlan, LayerMetadataCacheUpdatePlan, LayerMetadataEntry,
    LayerMetadataMutationTiming, LayerWriteAuthorizationInput, LayerWriteAuthorizationPlan,
    TransactionalLayerReadPlan, TransactionalLayerReadSubject, for_each_effective_layer,
    normalize_layer_target, plan_layer_deletion, plan_layer_metadata_cache_update,
    plan_layer_write_authorization, plan_transactional_layer_read,
    validate_layer_metadata_security_descriptor, validate_layer_resolution_context,
    validate_layer_views, validate_private_layer_set,
};
pub use maintenance::{KeyFdHiveView, PlannedFlush, plan_flush_for_key_fd};
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
    RSI_PATH_TARGET_GUID, RSI_PATH_TARGET_HIDDEN, RSI_WRITE_KEY_FIELD_KNOWN_MASK,
    RSI_WRITE_KEY_FIELD_LAST_WRITE_TIME, RSI_WRITE_KEY_FIELD_SD, RsiAbortTransactionRequestPayload,
    RsiBeginTransactionRequestPayload, RsiBuiltRequest, RsiCommitTransactionRequestPayload,
    RsiCreateEntryRequestPayload, RsiCreateKeyRequestPayload, RsiDeleteEntryRequestPayload,
    RsiDeleteLayerRequestPayload, RsiDeleteLayerSuccessResponsePayload,
    RsiDeleteValueEntryRequestPayload, RsiDispatchedWaitPlan, RsiDropKeyRequestPayload,
    RsiEnumChildResponseEntry, RsiEnumChildrenRequestPayload,
    RsiEnumChildrenSuccessResponsePayload, RsiFlushRequestPayload, RsiGuidArray,
    RsiHideEntryRequestPayload, RsiKeyMetadataResponseEntry, RsiLateResponseRecordPlan,
    RsiLateResponseRecordState, RsiLengthPrefixedField, RsiLookupPathEntry,
    RsiLookupRequestPayload, RsiLookupSuccessResponsePayload, RsiMalformedProtocolReason,
    RsiMalformedSourceDataPlan, RsiMappedErrno, RsiPathTargetType, RsiPayloadCursor, RsiPollPlan,
    RsiQueryValueResponseEntry, RsiQueryValuesBlanketResponseEntry, RsiQueryValuesRequestPayload,
    RsiQueryValuesSuccessResponsePayload, RsiReadKeyRequestPayload,
    RsiReadKeySuccessResponsePayload, RsiReadPlan, RsiRequestHeader, RsiRequestId,
    RsiRequestIdCounter, RsiResponseHeader, RsiRetainedRequest,
    RsiSetBlanketTombstoneRequestPayload, RsiSetValueRequestPayload, RsiSlotReservationPlan,
    RsiSourceDataValidationFailure, RsiStatus, RsiStatusOutcome, RsiTrailingOptionalFieldsPlan,
    RsiTransactionBeginStatusPlan, RsiTransactionBeginUse, RsiTransactionMode,
    RsiValidatedResponse, RsiWriteKeyRequestPayload, classify_rsi_status_code, map_rsi_status,
    parse_rsi_abort_transaction_request_payload, parse_rsi_begin_transaction_request_payload,
    parse_rsi_commit_transaction_request_payload, parse_rsi_create_entry_request_payload,
    parse_rsi_create_key_request_payload, parse_rsi_delete_entry_request_payload,
    parse_rsi_delete_layer_request_payload, parse_rsi_delete_layer_success_response_payload,
    parse_rsi_delete_value_entry_request_payload, parse_rsi_drop_key_request_payload,
    parse_rsi_enum_children_request_payload, parse_rsi_enum_children_success_response_payload,
    parse_rsi_flush_request_payload, parse_rsi_hide_entry_request_payload,
    parse_rsi_lookup_request_payload, parse_rsi_lookup_success_response_payload,
    parse_rsi_query_values_request_payload, parse_rsi_query_values_success_response_payload,
    parse_rsi_read_key_request_payload, parse_rsi_read_key_success_response_payload,
    parse_rsi_request_header, parse_rsi_response_header,
    parse_rsi_set_blanket_tombstone_request_payload, parse_rsi_set_value_request_payload,
    parse_rsi_status, parse_rsi_write_key_request_payload, plan_rsi_dispatched_wait,
    plan_rsi_late_response_record, plan_rsi_malformed_source_data, plan_rsi_slot_reservation,
    plan_rsi_source_poll, plan_rsi_source_read, plan_rsi_transaction_begin_status,
    rsi_request_has_status_only_response, rsi_response_op_code,
    validate_rsi_delete_layer_orphaned_guids, validate_rsi_enum_children_metadata_completeness,
    validate_rsi_enum_children_metadata_security_descriptors,
    validate_rsi_enum_children_path_response_names,
    validate_rsi_enum_children_path_response_sequences, validate_rsi_lookup_metadata_completeness,
    validate_rsi_lookup_metadata_security_descriptors, validate_rsi_lookup_path_response_names,
    validate_rsi_lookup_path_response_sequences, validate_rsi_query_values_response_names,
    validate_rsi_query_values_response_sequences,
    validate_rsi_query_values_response_value_payloads, validate_rsi_read_key_response_names,
    validate_rsi_read_key_response_security_descriptor, validate_rsi_request_op_code,
    validate_rsi_response_for_request, validate_rsi_status_only_response_for_request,
    validate_rsi_write_key_field_mask, write_rsi_abort_transaction_request_frame,
    write_rsi_begin_transaction_request_frame, write_rsi_commit_transaction_request_frame,
    write_rsi_create_entry_request_frame, write_rsi_create_key_request_frame,
    write_rsi_delete_entry_request_frame, write_rsi_delete_layer_request_frame,
    write_rsi_delete_value_entry_request_frame, write_rsi_drop_key_request_frame,
    write_rsi_enum_children_request_frame, write_rsi_flush_request_frame,
    write_rsi_hide_entry_request_frame, write_rsi_lookup_request_frame,
    write_rsi_query_values_request_frame, write_rsi_read_key_request_frame,
    write_rsi_set_blanket_tombstone_request_frame, write_rsi_set_value_request_frame,
    write_rsi_write_key_request_frame,
};
pub use sequence::SequenceCounter;
pub use source::{
    NIL_GUID, RegisteredHiveIdentity, SourceDeviceOpenPlan, SourceRegistrationDecision,
    SourceRegistrationHive, SourceRegistrationPlan, SourceRegistrationRequest, SourceSlotStatus,
    SourceSlotView, for_each_source_slot_hive, plan_source_device_open,
    source_registration_hive_scope, source_slot_hive_status, validate_source_registration,
    validate_source_registration_hives, validate_source_slots,
};
pub use string::validate_lcs_str;
pub use symlink::{
    SymlinkDefaultValue, validate_symlink_default_value, validate_symlink_follow_depth,
    validate_symlink_target_bytes,
};
pub use transaction::{
    StartedTransaction, TransactionBinding, TransactionCommitPlan, TransactionCompletionEvent,
    TransactionFdClosePlan, TransactionFdPublicationPlan, TransactionId, TransactionIdCounter,
    TransactionKernelEffectsPlan, TransactionMutationBindingPlan, TransactionReadPlan,
    TransactionState, TransactionStatusResult, TransactionTerminalErrno, TransactionUseFailure,
    plan_begin_transaction, plan_begin_transaction_fd, plan_transaction_commit,
    plan_transaction_completion_effects, plan_transaction_fd_close,
    plan_transaction_mutation_binding, plan_transaction_read, transaction_status,
    transaction_terminal_failure,
};
pub use value::{
    BlanketTombstoneAction, BlanketTombstoneInput, BlanketTombstoneRequest,
    PlannedBlanketTombstone, PlannedValueDelete, PlannedValueWrite, RegistryValueType,
    ValidatedBlanketTombstone, ValidatedValueDelete, ValidatedValueType, ValidatedValueWrite,
    ValueDeleteRequest, ValueLayerAdmissionInput, ValueLayerAdmissionPlan, ValueWriteInput,
    ValueWriteRequest, plan_blanket_tombstone, plan_value_delete, plan_value_layer_admission,
    plan_value_write, validate_blanket_tombstone_request, validate_value_data_len,
    validate_value_delete_request, validate_value_write_request, validate_value_write_type,
};
pub use watch::{
    KeyWatchState, QueuedWatchEvent, TransactionWatchBurstPlan, WatchDelivery,
    WatchDispatchDecision, WatchEventCategory, WatchEventRecordPlan, WatchEventRecordRequest,
    WatchEventRecordShape, WatchMutationContext, WatchNotifyArgs, WatchNotifyPlan,
    WatchQueueInsertPlan, WatchQueueState, WatchReadBatchPlan, WatcherView,
    plan_transaction_watch_burst, plan_watch_dispatch, plan_watch_event_record, plan_watch_notify,
    plan_watch_queue_insert, plan_watch_read_batch, validate_abi_bool, validate_notify_filter,
    validate_notify_reserved, watch_event_category, watch_event_matches_filter,
};

/// Returns a stable value from the staged crate so integration build steps can
/// prove the real `lcs-core` module graph compiled and linked.
pub fn kernel_compile_probe() -> usize {
    REG_VALID_DESIRED_ACCESS_MASK as usize
}
