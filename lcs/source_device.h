/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_SOURCE_DEVICE_H
#define _SECURITY_PKM_LCS_SOURCE_DEVICE_H

#include <linux/compiler_types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/types.h>
#include <linux/wait.h>

#include <pkm/lcs.h>

#include "../kmes/kmes.h"
#include "key_fd.h"

struct file;
struct pkm_lcs_rsi_layer_view;
struct pkm_lcs_rsi_private_layer_view;
struct pkm_lcs_source_response_waiter;

enum pkm_lcs_source_fd_state {
	PKM_LCS_SOURCE_FD_UNREGISTERED = 0,
	PKM_LCS_SOURCE_FD_ACTIVE = 1,
};

#define PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT 256U
#define PKM_LCS_REQUEST_TIMEOUT_MS_DEFAULT 30000U
#define PKM_LCS_SYMLINK_DEPTH_LIMIT_DEFAULT 16U
#define PKM_LCS_KEY_GUID_ASSIGNMENT_MAX_ATTEMPTS 8U

struct pkm_lcs_runtime_limits {
	u32 request_timeout_ms;
	u32 transaction_timeout_ms;
	u32 notification_queue_size;
	u32 symlink_depth_limit;
	u32 max_value_size;
	u32 max_key_depth;
	u32 max_path_component_length;
	u32 max_total_path_length;
	u32 max_layers_per_value;
	u32 max_bound_transactions_per_source;
	u32 max_read_only_transactions_per_source;
	u32 max_total_layers;
	u32 max_registered_sources;
	u32 max_hives_per_source;
	u32 max_concurrent_rsi_requests;
	u32 max_scope_guids_per_token;
	u32 max_private_layers_per_token;
	u32 max_subtree_watch_depth;
	u32 max_transaction_watch_event_burst;
};

enum pkm_lcs_source_late_effect_kind {
	PKM_LCS_SOURCE_LATE_EFFECT_NONE = 0,
	PKM_LCS_SOURCE_LATE_EFFECT_RESTORE_COMMIT = 1,
};

struct pkm_lcs_source_restore_commit_late_effect_input {
	const u8 *key_guid;
	const u8 (*ancestor_guids)[RSI_GUID_SIZE];
	const char * const *resolved_path;
	u32 path_component_count;
};

struct pkm_lcs_source_late_effect {
	u32 kind;
	u32 path_component_count;
	u8 key_guid[RSI_GUID_SIZE];
	u8 (*ancestor_guids)[RSI_GUID_SIZE];
	char **resolved_path;
};

struct pkm_lcs_source_in_flight_request {
	struct list_head link;
	bool occupied;
	bool delivered;
	bool response_accepted;
	bool key_guid_present;
	u64 request_id;
	u64 txn_id;
	u16 op_code;
	u16 _pad1;
	u8 key_guid[RSI_GUID_SIZE];
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_source_late_effect late_effect;
	struct pkm_lcs_source_response_waiter *waiter;
};

struct pkm_lcs_source_fd {
	enum pkm_lcs_source_fd_state state;
	u32 source_id;
	struct mutex queue_lock;
	wait_queue_head_t read_wait;
	struct list_head request_queue;
	u32 queued_request_count;
	u32 in_flight_request_count;
	u64 next_request_id;
	struct list_head in_flight_requests;
	bool closing;
};

struct pkm_lcs_usercopy_ops {
	bool (*read)(void *ctx, void *dst, const void __user *src, size_t len);
	bool (*write)(void *ctx, void __user *dst, const void *src, size_t len);
	size_t (*strnlen)(void *ctx, const char __user *src, size_t max);
	void *ctx;
};

struct pkm_lcs_syscall_path_copy {
	char *path;
	u32 path_len;
};

struct pkm_lcs_source_registration_hive_copy {
	char *name;
	u32 name_len;
	u8 root_guid[16];
	u32 flags;
	u8 scope_guid[16];
	u64 hive_generation;
};

struct pkm_lcs_source_registration_copy {
	u32 hive_count;
	u64 max_sequence;
	struct pkm_lcs_source_registration_hive_copy *hives;
};

#define PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE 0U
#define PKM_LCS_SOURCE_SLOT_STATUS_DOWN 1U

#define PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW 0U
#define PKM_LCS_SOURCE_REGISTRATION_DECISION_RESUME_DOWN 1U

struct pkm_lcs_source_slot_view_copy {
	u32 source_id;
	u32 status;
	u32 hive_count;
	u32 _pad;
	const struct pkm_lcs_source_registration_hive_copy *hives;
};

struct pkm_lcs_source_registration_plan_copy {
	u32 hive_count;
	u64 source_next_sequence;
	u64 effective_next_sequence;
	u32 decision;
	u32 source_id;
};

struct pkm_lcs_source_table_snapshot {
	u32 occupied_count;
	u32 active_count;
	u32 down_count;
	u64 next_sequence;
	bool sequence_initialized;
};

struct pkm_lcs_restore_sequence_gate {
	u64 restore_sequence_offset;
	u64 max_dispatched_sequence;
	bool held;
	bool max_dispatched_valid;
};

struct pkm_lcs_source_fd_snapshot {
	enum pkm_lcs_source_fd_state state;
	u32 source_id;
	u32 queued_request_count;
	u32 in_flight_request_count;
	u32 bound_transaction_count;
	u32 read_only_transaction_count;
	u64 next_request_id;
	bool closing;
};

struct pkm_lcs_hive_route_result {
	u32 source_id;
	u8 root_guid[16];
};

struct pkm_lcs_open_preflight_plan {
	u32 requested_access;
	u32 mapped_desired_access;
	u8 maximum_allowed;
	u8 path_resolution_allowed;
	u8 _pad[2];
};

struct pkm_lcs_key_create_options {
	u8 volatile_key;
	u8 symlink;
	u8 _pad[2];
};

struct pkm_lcs_key_guid_assignment_plan {
	u8 guid[16];
	u8 assigned_by_lcs;
	u8 persist_in_key_record;
	u8 _pad[2];
};

typedef void (*pkm_lcs_key_guid_generator_fn)(void *ctx, u8 guid[16]);

struct pkm_lcs_key_guid_generator {
	pkm_lcs_key_guid_generator_fn generate;
	void *ctx;
};

struct pkm_lcs_create_preflight_plan {
	struct pkm_lcs_open_preflight_plan access;
	struct pkm_lcs_key_create_options options;
};

struct pkm_lcs_create_layer_target {
	const char *name;
	char *owned_name;
	u32 name_len;
	u8 implicit_base;
	u8 _pad[3];
};

struct pkm_lcs_layer_target_admission_plan {
	u32 precedence;
	u8 enabled;
	u8 _pad[3];
};

struct pkm_lcs_layer_metadata_sd_view {
	const char *name;
	const u8 *sd;
	size_t sd_len;
	u32 name_len;
	u32 _pad;
};

struct pkm_lcs_create_missing_runtime_inputs {
	const u8 (*scope_guids)[16];
	u32 scope_count;
	u32 _pad0;
	const struct pkm_lcs_rsi_layer_view *layers;
	u32 layer_count;
	u32 _pad1;
	const struct pkm_lcs_rsi_private_layer_view *private_layers;
	u32 private_layer_count;
	bool base_metadata_present;
	u8 _pad2[3];
	const u8 *base_metadata_sd;
	size_t base_metadata_sd_len;
	const struct pkm_lcs_layer_metadata_sd_view *metadata;
	u32 metadata_count;
	u32 _pad3;
	const u8 (*active_key_guids)[16];
	u32 active_key_guid_count;
	u32 _pad4;
	const struct pkm_lcs_key_guid_generator *generator;
};

struct pkm_lcs_private_credential_view {
	u8 (*scope_guids)[16];
	u32 scope_count;
	u32 _pad0;
	struct pkm_lcs_rsi_private_layer_view *private_layers;
	u32 private_layer_count;
	u32 _pad1;
};

struct pkm_lcs_layer_metadata_sd_selection {
	u32 index;
	u32 _pad;
};

struct pkm_lcs_key_open_access_plan {
	u32 requested_access;
	u32 mapped_desired_access;
	u32 access_check_granted;
	u32 fd_granted_access;
	u8 allowed;
	u8 maximum_allowed;
	u8 key_open_sacl_audit_required;
	u8 audit_payload_failure_blocks_completion;
	u8 privilege_use_audit_required;
	u8 _pad[3];
};

enum pkm_lcs_source_validation_failure {
	PKM_LCS_SOURCE_VALIDATION_MALFORMED_SECURITY_DESCRIPTOR = 0,
	PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_NAME = 1,
	PKM_LCS_SOURCE_VALIDATION_UNKNOWN_RSI_STATUS_CODE = 2,
	PKM_LCS_SOURCE_VALIDATION_FUTURE_SEQUENCE_NUMBER = 3,
	PKM_LCS_SOURCE_VALIDATION_DUPLICATE_WINNING_SEQUENCE_TIE = 4,
	PKM_LCS_SOURCE_VALIDATION_MALFORMED_LAYER_METADATA_SD = 5,
	PKM_LCS_SOURCE_VALIDATION_MALFORMED_KEY_NAME = 6,
	PKM_LCS_SOURCE_VALIDATION_MALFORMED_VALUE_NAME = 7,
	PKM_LCS_SOURCE_VALIDATION_MALFORMED_RESPONSE_PAYLOAD = 8,
	PKM_LCS_SOURCE_VALIDATION_MALFORMED_KEY_METADATA = 9,
	PKM_LCS_SOURCE_VALIDATION_MALFORMED_VALUE_PAYLOAD = 10,
	PKM_LCS_SOURCE_VALIDATION_MALFORMED_DELETE_LAYER_ORPHAN_LIST = 11,
};

enum pkm_lcs_self_config_received_kind {
	PKM_LCS_SELF_CONFIG_RECEIVED_MISSING = 0,
	PKM_LCS_SELF_CONFIG_RECEIVED_WRONG_TYPE = 1,
	PKM_LCS_SELF_CONFIG_RECEIVED_DWORD_OUT_OF_RANGE = 2,
};

enum pkm_lcs_self_config_value_kind {
	PKM_LCS_SELF_CONFIG_VALUE_DWORD = 1,
	PKM_LCS_SELF_CONFIG_VALUE_WRONG_TYPE = 2,
};

#define PKM_LCS_SELF_CONFIG_MAX_AUDITS 19U
#define PKM_LCS_SELF_CONFIG_MAX_PARAMETER_NAME_LEN 64U

struct pkm_lcs_self_config_entry {
	const char *name;
	u32 name_len;
	u32 value_kind;
	u32 value_type;
	u32 value_u32;
};

struct pkm_lcs_self_config_audit_intent {
	char configuration_name[PKM_LCS_SELF_CONFIG_MAX_PARAMETER_NAME_LEN];
	u32 configuration_name_len;
	u32 received_kind;
	u32 received_type;
	u32 received_u32;
	u32 retained_value;
};

struct pkm_lcs_self_config_apply_plan {
	struct pkm_lcs_runtime_limits limits;
	u32 applied_count;
	u32 retained_missing_count;
	u32 retained_invalid_count;
	u32 ignored_unknown_count;
	u32 audit_count;
	struct pkm_lcs_self_config_audit_intent
		audits[PKM_LCS_SELF_CONFIG_MAX_AUDITS];
};

struct pkm_lcs_layer_metadata_child {
	char *name;
	u32 name_len;
	u8 guid[RSI_GUID_SIZE];
};

struct pkm_lcs_layer_metadata_child_list {
	struct pkm_lcs_layer_metadata_child *children;
	u32 child_count;
};

struct pkm_lcs_layer_metadata_refresh_all_result {
	u32 enumerated_child_count;
	u32 refreshed_child_count;
	u32 effective_changed_count;
};

struct pkm_lcs_source_bootstrap_refresh_result {
	struct pkm_lcs_self_config_apply_plan self_config;
	struct pkm_kmes_self_config_apply_plan kmes_config;
	struct pkm_lcs_layer_metadata_refresh_all_result layers;
	struct pkm_lcs_internal_self_watch_arm_result self_watch;
	bool registry_root_present;
	bool kmes_root_present;
	bool layers_root_present;
	u8 _pad;
};

struct pkm_lcs_path_validation_result {
	u32 component_count;
	bool used_forward_separator;
	u8 _pad[3];
};

struct pkm_lcs_path_component_materialization {
	u32 component_count;
	u32 string_bytes;
};

struct pkm_lcs_path_component_view;

struct pkm_lcs_materialized_path {
	struct pkm_lcs_path_component_view *components;
	char *strings;
	u32 component_count;
	u32 string_bytes;
};

struct pkm_lcs_relative_open_preflight {
	struct pkm_lcs_open_preflight_plan access;
	struct pkm_lcs_path_validation_result path;
	struct pkm_lcs_key_fd_relative_base parent;
};

struct pkm_lcs_source_enqueue_result {
	size_t len;
	u64 request_id;
	u64 txn_id;
	u16 op_code;
	u16 _pad0;
	u32 queue_depth;
	u32 in_flight_count;
	u64 next_request_id;
};

struct pkm_lcs_source_response_result {
	size_t len;
	u64 request_id;
	u64 txn_id;
	u32 source_id;
	u32 in_flight_count;
	u16 request_op_code;
	u16 response_op_code;
	u32 status;
	u8 key_guid[RSI_GUID_SIZE];
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_source_late_effect late_effect;
	u32 source_validation_failure;
	bool malformed_source_data;
	bool source_validation_failure_present;
	bool caller_waiter_attached;
	bool key_guid_present;
};

struct pkm_lcs_layer_owner_selection_copy {
	const u8 *owner_sid;
	size_t owner_sid_len;
	u32 source;
	u8 informational_only;
	u8 _pad[3];
};

#define PKM_LCS_REG_CREATE_SOURCE_ACTION_CREATE_KEY 1U
#define PKM_LCS_REG_CREATE_SOURCE_ACTION_RETRY_OPEN_EXISTING 2U
#define PKM_LCS_REG_CREATE_SOURCE_ACTION_PUBLISH_CREATED_NEW 3U

struct pkm_lcs_reg_create_source_response_plan {
	u32 action;
	u32 disposition;
};

struct pkm_lcs_create_missing_source_records_result {
	u64 sequence;
	u32 disposition;
	u8 created_new;
	u8 retry_open_existing;
	u8 _pad[2];
};

struct pkm_lcs_create_missing_prepared_result {
	long fd;
	u64 sequence;
	u32 disposition;
	u8 created_new;
	u8 retry_open_existing;
	u8 _pad[2];
};

struct pkm_lcs_source_response_frame {
	u8 *data;
	size_t len;
};

struct pkm_lcs_delete_layer_orphan_apply_result {
	u32 orphaned_guid_count;
	u32 marked_fd_count;
	u32 immediate_drop_count;
	u32 _pad;
};

struct pkm_lcs_delete_layer_broadcast_result {
	u32 active_source_count;
	u32 completed_source_count;
	u32 orphaned_guid_count;
	u32 marked_fd_count;
	u32 immediate_drop_count;
	u32 generation_hive_count;
	u32 watch_overflow_count;
};

struct pkm_lcs_delete_layer_orchestration_result {
	u32 inspected_transaction_count;
	u32 affected_bound_transaction_count;
	u32 abort_dispatched_count;
	u32 layer_table_entry_removed;
	u32 active_source_count;
	u32 completed_source_count;
	u32 orphaned_guid_count;
	u32 marked_fd_count;
	u32 immediate_drop_count;
	u32 generation_hive_count;
	u32 watch_overflow_count;
};

struct pkm_lcs_layer_operation_recovery_result {
	u32 active_source_count;
	u32 completed_source_count;
	u32 generation_hive_count;
	u32 watch_overflow_count;
};

struct pkm_lcs_layer_table_publish_result {
	bool existed_before;
	bool effective_changed;
	u8 previous_enabled;
	u8 new_enabled;
	u32 previous_precedence;
	u32 new_precedence;
};

struct pkm_lcs_layer_snapshot {
	const struct pkm_lcs_rsi_layer_view *layers;
	u32 layer_count;
	bool base_metadata_present;
	const u8 *base_metadata_sd;
	size_t base_metadata_sd_len;
	const struct pkm_lcs_layer_metadata_sd_view *metadata;
	u32 metadata_count;
	struct pkm_lcs_rsi_layer_view *owned_layers;
	char *owned_names;
	struct pkm_lcs_layer_metadata_sd_view *owned_metadata;
	u8 *owned_metadata_sds;
};

struct pkm_lcs_path_component_view {
	const char *name;
	u32 name_len;
};

struct pkm_lcs_resolved_key_path {
	u32 source_id;
	u32 component_count;
	u32 final_sd_offset;
	u32 final_sd_len;
	bool final_volatile;
	bool final_symlink;
	u8 _pad[2];
	u64 final_last_write_time;
	u8 key_guid[RSI_GUID_SIZE];
	char **resolved_path;
	u8 (*ancestor_guids)[RSI_GUID_SIZE];
	struct pkm_lcs_source_response_frame final_frame;
};

struct pkm_lcs_create_missing_parent_resolution {
	struct pkm_lcs_resolved_key_path parent;
	struct pkm_lcs_runtime_limits limits;
	char *child_name;
	u32 child_name_len;
	u32 child_depth;
	bool limits_present;
	u8 _pad[3];
};

struct pkm_lcs_created_key_sd {
	const u8 *sd;
	size_t sd_len;
};

struct pkm_lcs_symlink_target_resolution {
	struct pkm_lcs_hive_route_result route;
	struct pkm_lcs_materialized_path components;
	u32 value_type;
	u32 selected_precedence;
	u64 selected_sequence;
};

struct pkm_lcs_source_response_waiter {
	wait_queue_head_t wait;
	bool completed;
	bool attached;
	bool detached;
	u8 _pad[5];
	u32 source_id;
	long response_errno;
	u64 request_id;
	struct pkm_lcs_source_response_result response;
	struct pkm_lcs_source_response_frame *retained_frame;
};

long pkm_lcs_source_device_open_for_token(const void *token);
long pkm_lcs_source_device_open_file_for_token(const void *token,
					       struct file *file);
int pkm_lcs_source_device_release_file(struct file *file);
void pkm_lcs_source_registration_copy_destroy(
	struct pkm_lcs_source_registration_copy *registration);
void pkm_lcs_syscall_path_copy_destroy(
	struct pkm_lcs_syscall_path_copy *copy);
long pkm_lcs_source_registration_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs, u32 max_hives,
	struct pkm_lcs_source_registration_copy *out);
long pkm_lcs_syscall_path_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *upath,
	struct pkm_lcs_syscall_path_copy *out);
long pkm_lcs_source_registration_validate_copied(
	const struct pkm_lcs_source_registration_copy *registration,
	bool caller_has_tcb,
	struct pkm_lcs_source_registration_plan_copy *plan);
long pkm_lcs_source_register_file_for_token(
	const void *token, struct file *file, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs);
long pkm_lcs_route_hive_name(const char *hive_name, u32 hive_name_len,
			     const u8 (*scope_guids)[16], u32 scope_count,
			     struct pkm_lcs_hive_route_result *result);
long pkm_lcs_route_absolute_path(const char *path, u32 path_len,
				 bool rewrite_current_user,
				 const char *current_user_sid_component,
				 u32 current_user_sid_component_len,
				 const u8 (*scope_guids)[16], u32 scope_count,
				 struct pkm_lcs_hive_route_result *result);
long pkm_lcs_route_absolute_path_for_token(
	const void *token, const char *path, u32 path_len,
	bool rewrite_current_user, const u8 (*scope_guids)[16], u32 scope_count,
	struct pkm_lcs_hive_route_result *result);
long pkm_lcs_route_current_absolute_path(
	const char *path, u32 path_len, bool rewrite_current_user,
	const u8 (*scope_guids)[16], u32 scope_count,
	struct pkm_lcs_hive_route_result *result);
long pkm_lcs_route_user_absolute_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, bool rewrite_current_user,
	const u8 (*scope_guids)[16], u32 scope_count,
	struct pkm_lcs_hive_route_result *result);
long pkm_lcs_open_preflight(u32 desired_access, u32 flags,
			    struct pkm_lcs_open_preflight_plan *plan);
long pkm_lcs_create_preflight(u32 desired_access, u32 flags,
			      struct pkm_lcs_create_preflight_plan *plan);
void pkm_lcs_create_layer_target_destroy(
	struct pkm_lcs_create_layer_target *target);
long pkm_lcs_create_layer_target_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *ulayer,
	struct pkm_lcs_create_layer_target *target);
long pkm_lcs_create_layer_target_admit(
	const struct pkm_lcs_create_layer_target *target,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	struct pkm_lcs_layer_target_admission_plan *plan);
long pkm_lcs_create_layer_target_admit_with_limits(
	const struct pkm_lcs_create_layer_target *target,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_layer_target_admission_plan *plan);
long pkm_lcs_create_layer_target_prepare(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *ulayer,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	struct pkm_lcs_create_layer_target *target,
	struct pkm_lcs_layer_target_admission_plan *plan);
long pkm_lcs_create_layer_target_prepare_with_limits(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *ulayer,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_create_layer_target *target,
	struct pkm_lcs_layer_target_admission_plan *plan);
long pkm_lcs_key_open_access_check_for_token(
	const void *token, const u8 *sd, size_t sd_len, u32 desired_access,
	struct pkm_lcs_key_open_access_plan *plan);
long pkm_lcs_emit_key_open_audit_for_token(
	const void *token, const u8 key_guid[16],
	const struct pkm_lcs_key_open_access_plan *plan);
long pkm_lcs_emit_backup_start_audit_for_token(
	const void *token, const u8 key_guid[16], int output_fd);
long pkm_lcs_emit_backup_complete_audit_for_token(
	const void *token, const u8 key_guid[16], u32 result_errno);
long pkm_lcs_emit_restore_start_audit_for_token(
	const void *token, const u8 key_guid[16], int input_fd);
long pkm_lcs_emit_restore_complete_audit_for_token(
	const void *token, const u8 key_guid[16], u32 result_errno);
long pkm_lcs_emit_source_validation_failure_audit(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	bool hive_name_present, u64 request_id, bool request_id_present,
	u16 op_code, bool op_code_present, const u8 key_guid[16],
	bool key_guid_present, u32 validation_failure);
long pkm_lcs_emit_self_config_invalid_audit(
	const char *configuration_name, u32 configuration_name_len,
	u32 received_kind, u32 received_type, u32 received_u32,
	u32 retained_value);
long pkm_lcs_runtime_limits_defaults(struct pkm_lcs_runtime_limits *limits);
long pkm_lcs_runtime_limits_validate(
	const struct pkm_lcs_runtime_limits *limits);
long pkm_lcs_runtime_limits_snapshot(struct pkm_lcs_runtime_limits *limits);
long pkm_lcs_runtime_limits_publish(
	const struct pkm_lcs_runtime_limits *limits);
void pkm_lcs_runtime_limits_reset_defaults(void);
long pkm_lcs_runtime_limits_apply_self_config(
	const struct pkm_lcs_self_config_entry *entries, u32 entry_count,
	struct pkm_lcs_self_config_apply_plan *result_out);
long pkm_lcs_runtime_limits_refresh_self_config_from_key(
	u32 source_id, const u8 registry_guid[RSI_GUID_SIZE],
	struct pkm_lcs_self_config_apply_plan *result_out);
long pkm_lcs_self_config_registry_root_discover_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[RSI_GUID_SIZE],
	bool *present_out, u8 registry_guid_out[RSI_GUID_SIZE]);
long pkm_lcs_runtime_limits_refresh_self_config_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_self_config_apply_plan *result_out);
long pkm_lcs_private_credentials_acquire_for_token(
	const void *token, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_private_credential_view *view);
void pkm_lcs_private_credentials_release(
	struct pkm_lcs_private_credential_view *view);
long pkm_lcs_layer_metadata_root_discover_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[RSI_GUID_SIZE],
	bool *present_out, u8 layers_root_guid_out[RSI_GUID_SIZE]);
void pkm_lcs_layer_metadata_child_list_destroy(
	struct pkm_lcs_layer_metadata_child_list *list);
long pkm_lcs_layer_metadata_children_enumerate_from_root(
	u32 source_id, const u8 layers_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_layer_metadata_child_list *children_out);
long pkm_lcs_layer_metadata_child_lookup_from_root(
	u32 source_id, const u8 layers_root_guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len,
	u8 child_guid_out[RSI_GUID_SIZE], bool *present_out);
long pkm_lcs_layer_metadata_child_lookup_from_root_with_limits(
	u32 source_id, const u8 layers_root_guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	u8 child_guid_out[RSI_GUID_SIZE], bool *present_out);
long pkm_lcs_layer_metadata_refresh_all_from_root(
	u32 source_id, const u8 layers_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_layer_metadata_refresh_all_result *result_out);
long pkm_lcs_source_bootstrap_refresh_machine_hive(
	u32 source_id, const u8 machine_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_bootstrap_refresh_result *result_out);
u32 pkm_lcs_runtime_request_timeout_ms(void);
u32 pkm_lcs_runtime_transaction_timeout_ms(void);
u32 pkm_lcs_runtime_symlink_depth_limit(void);
u32 pkm_lcs_runtime_max_key_depth(void);
u32 pkm_lcs_runtime_max_bound_transactions_per_source(void);
u32 pkm_lcs_runtime_max_read_only_transactions_per_source(void);
u32 pkm_lcs_runtime_max_registered_sources(void);
u32 pkm_lcs_runtime_max_hives_per_source(void);
u32 pkm_lcs_runtime_max_concurrent_rsi_requests(void);
u32 pkm_lcs_runtime_notification_queue_size(void);
u32 pkm_lcs_runtime_max_subtree_watch_depth(void);
u32 pkm_lcs_runtime_max_transaction_watch_event_burst(void);
long pkm_lcs_validate_syscall_relative_path(
	const char *path, u32 path_len,
	struct pkm_lcs_path_validation_result *result);
long pkm_lcs_open_user_absolute_path_preflight_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, u32 desired_access, u32 flags,
	bool rewrite_current_user, const u8 (*scope_guids)[16],
	u32 scope_count, struct pkm_lcs_open_preflight_plan *plan,
	struct pkm_lcs_hive_route_result *route);
long pkm_lcs_open_user_absolute_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, u32 desired_access, u32 flags,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count);
long pkm_lcs_open_copied_absolute_path_for_token(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count);
long pkm_lcs_open_user_relative_path_preflight(
	const struct pkm_lcs_usercopy_ops *ops, int parent_fd,
	const char __user *upath, u32 desired_access, u32 flags,
	struct pkm_lcs_relative_open_preflight *result);
long pkm_lcs_materialize_absolute_path_components_for_token(
	const void *token, const char *path, u32 path_len,
	bool rewrite_current_user, struct pkm_lcs_materialized_path *result);
long pkm_lcs_materialize_relative_path_components(
	const char *path, u32 path_len,
	struct pkm_lcs_materialized_path *result);
long pkm_lcs_route_symlink_target(
	const char *target, u32 target_len, const u8 (*scope_guids)[16],
	u32 scope_count, struct pkm_lcs_hive_route_result *result);
long pkm_lcs_materialize_symlink_target_components(
	const char *target, u32 target_len,
	struct pkm_lcs_materialized_path *result);
long pkm_lcs_resolve_symlink_target_for_key(
	u32 source_id, u64 txn_id, const u8 key_guid[RSI_GUID_SIZE],
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_symlink_target_resolution *result);
void pkm_lcs_symlink_target_resolution_destroy(
	struct pkm_lcs_symlink_target_resolution *resolution);
void pkm_lcs_materialized_path_destroy(
	struct pkm_lcs_materialized_path *path);
long pkm_lcs_open_user_relative_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count);
long pkm_lcs_open_copied_relative_path_for_token(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count);
long pkm_lcs_reg_open_key_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags);
long pkm_lcs_create_existing_user_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags,
	u32 *disposition);
long pkm_lcs_create_existing_copied_path_for_token(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, u32 *disposition);
long pkm_lcs_reg_create_key_copy_disposition_to_user(
	const struct pkm_lcs_usercopy_ops *ops, u32 __user *udisposition,
	u32 disposition);
long pkm_lcs_reg_create_key_finish_success_to_user(
	const struct pkm_lcs_usercopy_ops *ops, u32 __user *udisposition,
	long fd, u32 disposition);
long pkm_lcs_create_existing_user_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags,
	u32 __user *udisposition);
long pkm_lcs_create_existing_copied_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags, u32 __user *udisposition);
void pkm_lcs_create_missing_parent_resolution_destroy(
	struct pkm_lcs_create_missing_parent_resolution *resolution);
long pkm_lcs_create_missing_absolute_parent_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result);
long pkm_lcs_create_missing_relative_parent(
	const struct pkm_lcs_usercopy_ops *ops, int parent_fd,
	const char __user *upath, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result);
long pkm_lcs_create_missing_copied_absolute_parent_for_token(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result);
long pkm_lcs_create_missing_copied_relative_parent(
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result);
long pkm_lcs_create_missing_copied_parent_for_token(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result);
long pkm_lcs_create_missing_parent_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result);
long pkm_lcs_create_missing_parent_access_check_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	struct pkm_lcs_key_open_access_plan *plan);
long pkm_lcs_create_missing_volatile_parent_check(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_preflight_plan *preflight);
void pkm_lcs_created_key_sd_destroy(struct pkm_lcs_created_key_sd *created);
long pkm_lcs_create_missing_initial_sd_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	struct pkm_lcs_created_key_sd *created);
long pkm_lcs_layer_write_access_check_for_token(
	const void *token, const u8 *metadata_sd, size_t metadata_sd_len,
	struct pkm_lcs_key_open_access_plan *plan);
long pkm_lcs_base_layer_write_access_check_for_token(
	const void *token, bool base_metadata_present,
	const u8 *base_metadata_sd, size_t base_metadata_sd_len,
	struct pkm_lcs_key_open_access_plan *plan);
long pkm_lcs_create_layer_write_access_check_for_token(
	const void *token, const struct pkm_lcs_create_layer_target *target,
	bool base_metadata_present, const u8 *base_metadata_sd,
	size_t base_metadata_sd_len,
	const struct pkm_lcs_layer_metadata_sd_view *metadata,
	u32 metadata_count, struct pkm_lcs_key_open_access_plan *plan);
long pkm_lcs_create_layer_write_access_check_for_token_with_limits(
	const void *token, const struct pkm_lcs_create_layer_target *target,
	bool base_metadata_present, const u8 *base_metadata_sd,
	size_t base_metadata_sd_len,
	const struct pkm_lcs_layer_metadata_sd_view *metadata,
	u32 metadata_count, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_key_open_access_plan *plan);
long pkm_lcs_live_layer_write_access_check_for_token(
	const void *token, const struct pkm_lcs_create_layer_target *target,
	struct pkm_lcs_key_open_access_plan *plan);
long pkm_lcs_assign_new_key_guid(
	const u8 (*active_key_guids)[16], u32 active_key_guid_count,
	const struct pkm_lcs_key_guid_generator *generator,
	struct pkm_lcs_key_guid_assignment_plan *plan);
long pkm_lcs_create_missing_symlink_authority_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	u32 flags, struct pkm_lcs_key_open_access_plan *link_plan);
long pkm_lcs_reg_create_key_source_response_plan(
	u16 request_op_code, u32 status,
	struct pkm_lcs_reg_create_source_response_plan *plan);
long pkm_lcs_create_missing_source_records(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_layer_target *target,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd,
	bool volatile_key, bool symlink,
	struct pkm_lcs_create_missing_source_records_result *result);
long pkm_lcs_create_missing_publish_created_key_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd, u32 desired_access);
long pkm_lcs_create_missing_prepared_key_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_layer_target *target,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd, u32 desired_access,
	bool volatile_key, bool symlink,
	struct pkm_lcs_create_missing_prepared_result *result);
long pkm_lcs_create_missing_created_result_finish_to_user(
	const struct pkm_lcs_usercopy_ops *ops, u32 __user *udisposition,
	struct pkm_lcs_create_missing_prepared_result *result);
long pkm_lcs_create_missing_retry_open_existing_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	u32 desired_access, const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, u32 __user *udisposition);
long pkm_lcs_create_missing_user_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access,
	const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	u32 __user *udisposition);
long pkm_lcs_create_missing_copied_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	u32 __user *udisposition);
long pkm_lcs_reg_create_key_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access,
	const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	u32 __user *udisposition);
long pkm_lcs_reg_create_key_args_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_create_key_args __user *uargs,
	struct reg_create_key_args *out);
long pkm_lcs_reg_create_key_args_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_create_key_args *args,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs);
long pkm_lcs_allocate_sequence(u64 *sequence);
long pkm_lcs_restore_sequence_gate_acquire(
	struct pkm_lcs_restore_sequence_gate *gate);
long pkm_lcs_restore_sequence_gate_validate(
	const struct pkm_lcs_restore_sequence_gate *gate,
	u64 backup_sequence, u64 *new_sequence);
long pkm_lcs_restore_sequence_gate_record_dispatched(
	struct pkm_lcs_restore_sequence_gate *gate,
	u64 backup_sequence, u64 *new_sequence);
long pkm_lcs_restore_sequence_gate_release_terminal(
	struct pkm_lcs_restore_sequence_gate *gate);
long pkm_lcs_source_enqueue_request(
	u32 source_id, const u8 *frame, size_t frame_len,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_lookup_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_lookup_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_lookup_waitable_request_retaining_frame(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_lookup_round_trip(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_lookup_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_lookup_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_dispatch_create_entry_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_create_entry_request_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_create_entry_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_create_entry_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_create_entry_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_dispatch_hide_entry_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_hide_entry_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_delete_entry_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_delete_entry_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_hide_entry_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_hide_entry_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_delete_entry_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_delete_entry_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_dispatch_create_key_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_create_key_request_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_create_key_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_write_key_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_write_key_request_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_write_key_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_set_value_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_set_value_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_delete_value_entry_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_delete_value_entry_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_set_blanket_tombstone_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_set_blanket_tombstone_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_drop_key_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_drop_key_request_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_drop_key_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_bound_transaction_acquire(u32 source_id, u32 *count_out);
long pkm_lcs_source_bound_transaction_release(u32 source_id, u32 *count_out);
long pkm_lcs_source_read_only_transaction_acquire_with_limits(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits,
	u32 *count_out);
long pkm_lcs_source_read_only_transaction_acquire(u32 source_id,
						  u32 *count_out);
long pkm_lcs_source_read_only_transaction_release(u32 source_id,
						 u32 *count_out);
long pkm_lcs_source_dispatch_begin_transaction_request(
	u32 source_id, u64 transaction_id, u32 mode,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_begin_transaction_waitable_request(
	u32 source_id, u64 transaction_id, u32 mode,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_commit_transaction_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_commit_transaction_waitable_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_abort_transaction_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_abort_transaction_request_with_limits(
	u32 source_id, u64 transaction_id,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_abort_transaction_waitable_request(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_delete_layer_request(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_delete_layer_waitable_request(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_flush_request(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_flush_waitable_request(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_begin_transaction_round_trip_timeout(
	u32 source_id, u64 transaction_id, u32 mode, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_begin_transaction_round_trip_timeout_with_limits(
	u32 source_id, u64 transaction_id, u32 mode,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_begin_transaction_round_trip(
	u32 source_id, u64 transaction_id, u32 mode,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_commit_transaction_round_trip_timeout(
	u32 source_id, u64 transaction_id, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_commit_transaction_round_trip_timeout_with_limits(
	u32 source_id, u64 transaction_id,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_restore_commit_transaction_round_trip_timeout_with_limits(
	u32 source_id, u64 transaction_id,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	const struct pkm_lcs_source_restore_commit_late_effect_input *late_effect,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_commit_transaction_round_trip(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_abort_transaction_round_trip_timeout(
	u32 source_id, u64 transaction_id, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_abort_transaction_round_trip_timeout_with_limits(
	u32 source_id, u64 transaction_id,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_abort_transaction_round_trip(
	u32 source_id, u64 transaction_id,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_delete_layer_round_trip_timeout(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_delete_layer_round_trip_timeout_with_limits(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_delete_layer_round_trip(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_delete_layer_round_trip_retaining_frame_timeout(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_apply_delete_layer_orphan_response(
	u32 source_id, const struct pkm_lcs_source_response_frame *frame,
	u64 request_id,
	struct pkm_lcs_delete_layer_orphan_apply_result *result);
long pkm_lcs_source_delete_layer_round_trip_apply_orphans_timeout(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	u32 timeout_ms,
	struct pkm_lcs_delete_layer_orphan_apply_result *orphan_result,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_delete_layer_broadcast_apply_orphans_timeout(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	struct pkm_lcs_delete_layer_broadcast_result *result);
long pkm_lcs_source_delete_layer_orchestrate_timeout(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	struct pkm_lcs_delete_layer_orchestration_result *result);
long pkm_lcs_source_delete_layer_orchestrate_skip_generation_timeout(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	u32 skip_source_id, const u8 skip_root_guid[PKM_LCS_GUID_BYTES],
	struct pkm_lcs_delete_layer_orchestration_result *result);
long pkm_lcs_source_delete_layer_orchestrate_skip_generation_timeout_with_limits(
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	u32 skip_source_id, const u8 skip_root_guid[PKM_LCS_GUID_BYTES],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_delete_layer_orchestration_result *result);
long pkm_lcs_source_layer_operation_recover_skip_generation(
	u32 skip_source_id, const u8 skip_root_guid[PKM_LCS_GUID_BYTES],
	struct pkm_lcs_layer_operation_recovery_result *result);
long pkm_lcs_source_layer_operation_recover_skip_generation_with_limits(
	u32 skip_source_id, const u8 skip_root_guid[PKM_LCS_GUID_BYTES],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_layer_operation_recovery_result *result);
long pkm_lcs_source_layer_operation_recover(
	struct pkm_lcs_layer_operation_recovery_result *result);
long pkm_lcs_source_flush_round_trip_timeout(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_flush_round_trip_timeout_with_limits(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_flush_round_trip(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_drop_key_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_drop_key_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_drop_key_round_trip(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_record_transaction_generation(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE],
	u64 *generation_out);
long pkm_lcs_source_hive_generation_snapshot(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE],
	u64 *generation_out);
long pkm_lcs_source_next_sequence_snapshot(u64 *next_sequence);
void pkm_lcs_source_base_layer_snapshot(
	const struct pkm_lcs_rsi_layer_view **layers, u32 *layer_count);
long pkm_lcs_source_layer_snapshot_copy(
	struct pkm_lcs_rsi_layer_view *layers, u32 max_layers,
	char *name_buf, size_t name_buf_len, u32 *count_out);
long pkm_lcs_source_layer_snapshot_acquire(
	struct pkm_lcs_layer_snapshot *snapshot);
void pkm_lcs_source_layer_snapshot_release(
	struct pkm_lcs_layer_snapshot *snapshot);
long pkm_lcs_layer_table_publish(
	const char *layer_name, u32 layer_name_len, u32 precedence,
	u8 enabled, const u8 metadata_key_guid[RSI_GUID_SIZE],
	const u8 *metadata_sd, size_t metadata_sd_len,
	const u8 *owner_sid, size_t owner_sid_len);
long pkm_lcs_layer_table_publish_with_result(
	const char *layer_name, u32 layer_name_len, u32 precedence,
	u8 enabled, const u8 metadata_key_guid[RSI_GUID_SIZE],
	const u8 *metadata_sd, size_t metadata_sd_len,
	const u8 *owner_sid, size_t owner_sid_len,
	struct pkm_lcs_layer_table_publish_result *result);
long pkm_lcs_layer_table_publish_with_result_with_limits(
	const char *layer_name, u32 layer_name_len, u32 precedence,
	u8 enabled, const u8 metadata_key_guid[RSI_GUID_SIZE],
	const u8 *metadata_sd, size_t metadata_sd_len,
	const u8 *owner_sid, size_t owner_sid_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_layer_table_publish_result *result);
long pkm_lcs_base_layer_metadata_publish(
	const u8 metadata_key_guid[RSI_GUID_SIZE],
	const u8 *metadata_sd, size_t metadata_sd_len);
long pkm_lcs_layer_table_owner_snapshot(
	const char *layer_name, u32 layer_name_len, u8 **owner_sid_out,
	size_t *owner_sid_len_out, bool *present_out);
long pkm_lcs_layer_owner_select_copy(
	const u8 *metadata_owner_sid, size_t metadata_owner_sid_len,
	bool metadata_owner_present, const u8 *creator_sid,
	size_t creator_sid_len, bool creator_present,
	const u8 *previous_owner_sid, size_t previous_owner_sid_len,
	bool previous_owner_present, const u8 *metadata_sd,
	size_t metadata_sd_len, bool metadata_sd_present, bool is_new_layer,
	u8 **owner_sid_out, size_t *owner_sid_len_out, u32 *source_out);
long pkm_lcs_layer_table_remove(const char *layer_name, u32 layer_name_len,
				bool *removed_out);
long pkm_lcs_layer_table_remove_with_limits(
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, bool *removed_out);
long pkm_lcs_layer_table_metadata_key_guid_present(
	const u8 metadata_key_guid[RSI_GUID_SIZE], bool *present_out);
long pkm_lcs_source_active_ids_snapshot(u32 *source_ids,
					u32 max_source_ids,
					u32 *count_out);
long pkm_lcs_source_restart_generation_snapshot(u32 source_id,
						u64 *generation_out);
void pkm_lcs_source_mark_down_by_id(u32 source_id);
long pkm_lcs_source_create_key_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_create_key_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_write_key_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_write_key_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_set_value_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_set_value_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_delete_value_entry_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_delete_value_entry_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_set_blanket_tombstone_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	u32 timeout_ms, struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_set_blanket_tombstone_round_trip_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_lookup_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len, bool query_all,
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len, bool query_all,
	const struct pkm_lcs_runtime_limits *limits, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_walk_absolute_components(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result);
long pkm_lcs_walk_absolute_components_for_open(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	struct pkm_lcs_resolved_key_path *result);
long pkm_lcs_walk_relative_components(
	const struct pkm_lcs_key_fd_parent_snapshot *parent, u64 txn_id,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result);
long pkm_lcs_walk_relative_components_for_open(
	const struct pkm_lcs_key_fd_parent_snapshot *parent, u64 txn_id,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	struct pkm_lcs_resolved_key_path *result);
void pkm_lcs_resolved_key_path_destroy(
	struct pkm_lcs_resolved_key_path *path);
long pkm_lcs_source_accept_response_file(
	struct file *file, const u8 *frame, size_t frame_len,
	struct pkm_lcs_source_response_result *result);
void pkm_lcs_source_response_waiter_init(
	struct pkm_lcs_source_response_waiter *waiter);
void pkm_lcs_source_response_frame_init(
	struct pkm_lcs_source_response_frame *frame);
void pkm_lcs_source_response_frame_destroy(
	struct pkm_lcs_source_response_frame *frame);
long pkm_lcs_source_response_waiter_wait(
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_response_result *result);

#ifdef CONFIG_SECURITY_PKM_KUNIT
void pkm_lcs_kunit_reset_source_table(void);
void pkm_lcs_kunit_reset_layer_table(void);
void pkm_lcs_kunit_set_sequence_state(bool initialized, u64 next_sequence);
void pkm_lcs_kunit_source_table_snapshot(
	struct pkm_lcs_source_table_snapshot *snapshot);
void pkm_lcs_kunit_source_fd_snapshot(
	struct file *file, struct pkm_lcs_source_fd_snapshot *snapshot);
ssize_t pkm_lcs_kunit_source_device_read_file(
	struct file *file, void *buf, size_t count, bool nonblocking);
ssize_t pkm_lcs_kunit_source_device_write_file(
	struct file *file, const void *buf, size_t count, bool fault,
	struct pkm_lcs_source_response_result *result);
__poll_t pkm_lcs_kunit_source_device_poll_file(struct file *file);
__poll_t pkm_lcs_kunit_source_device_poll_file_with_table(
	struct file *file, struct poll_table_struct *wait);
long pkm_lcs_kunit_source_slot_admission_state(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits);
long pkm_lcs_kunit_source_dispatch_enum_children_waitable_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_kunit_source_hive_generation_snapshot(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE],
	u64 *generation_out);
long pkm_lcs_kunit_source_hive_generation_set(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE], u64 generation);
long pkm_lcs_kunit_create_missing_child_depth(u32 parent_depth,
					      u32 *child_depth_out);
long pkm_lcs_kunit_source_register_file_for_token_with_bootstrap(
	const void *token, struct file *file, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs);
long pkm_lcs_kunit_source_device_raw_ioctl(struct file *file, unsigned int cmd,
					   unsigned long arg);
void pkm_lcs_kunit_flush_source_bootstrap_work(void);
#endif

#endif /* _SECURITY_PKM_LCS_SOURCE_DEVICE_H */
