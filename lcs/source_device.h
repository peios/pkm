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

struct pkm_lcs_source_in_flight_request {
	bool occupied;
	bool delivered;
	bool response_accepted;
	u8 _pad0;
	u64 request_id;
	u64 txn_id;
	u16 op_code;
	u16 _pad1;
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
	struct pkm_lcs_source_in_flight_request
		in_flight_requests[PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT];
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

struct pkm_lcs_source_fd_snapshot {
	enum pkm_lcs_source_fd_state state;
	u32 source_id;
	u32 queued_request_count;
	u32 in_flight_request_count;
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
	const u8 (*retired_key_guids)[16];
	u32 retired_key_guid_count;
	u32 _pad5;
	const struct pkm_lcs_key_guid_generator *generator;
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
	u16 request_op_code;
	u16 response_op_code;
	u32 status;
	u32 in_flight_count;
	bool malformed_source_data;
	bool caller_waiter_attached;
	u8 _pad[2];
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
	char *child_name;
	u32 child_name_len;
	u32 child_depth;
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
long pkm_lcs_create_layer_target_prepare(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *ulayer,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	struct pkm_lcs_create_layer_target *target,
	struct pkm_lcs_layer_target_admission_plan *plan);
long pkm_lcs_key_open_access_check_for_token(
	const void *token, const u8 *sd, size_t sd_len, u32 desired_access,
	struct pkm_lcs_key_open_access_plan *plan);
long pkm_lcs_emit_key_open_audit_for_token(
	const void *token, const u8 key_guid[16],
	const struct pkm_lcs_key_open_access_plan *plan);
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
long pkm_lcs_assign_new_key_guid(
	const u8 (*active_key_guids)[16], u32 active_key_guid_count,
	const u8 (*retired_key_guids)[16], u32 retired_key_guid_count,
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
long pkm_lcs_allocate_sequence(u64 *sequence);
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
long pkm_lcs_source_dispatch_create_entry_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
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
long pkm_lcs_source_dispatch_create_key_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_create_key_waitable_request(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_create_key_round_trip_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink, u32 timeout_ms,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_lookup_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len, u32 timeout_ms,
	struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_read_key_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
	struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_source_enqueue_result *enqueue);
long pkm_lcs_source_query_values_round_trip_retaining_frame_timeout(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len, bool query_all,
	u32 timeout_ms, struct pkm_lcs_source_response_frame *frame,
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
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result);
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
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result);
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
#endif

#endif /* _SECURITY_PKM_LCS_SOURCE_DEVICE_H */
