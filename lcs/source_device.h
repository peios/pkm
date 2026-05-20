/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_SOURCE_DEVICE_H
#define _SECURITY_PKM_LCS_SOURCE_DEVICE_H

#include <linux/compiler_types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/wait.h>

#include <pkm/lcs.h>

#include "key_fd.h"

struct file;

enum pkm_lcs_source_fd_state {
	PKM_LCS_SOURCE_FD_UNREGISTERED = 0,
	PKM_LCS_SOURCE_FD_ACTIVE = 1,
};

#define PKM_LCS_MAX_CONCURRENT_RSI_REQUESTS_DEFAULT 256U

struct pkm_lcs_source_in_flight_request {
	bool occupied;
	bool delivered;
	u64 request_id;
	u64 txn_id;
	u16 op_code;
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

struct pkm_lcs_path_validation_result {
	u32 component_count;
	bool used_forward_separator;
	u8 _pad[3];
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
	u8 _pad[3];
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
long pkm_lcs_validate_syscall_relative_path(
	const char *path, u32 path_len,
	struct pkm_lcs_path_validation_result *result);
long pkm_lcs_open_user_absolute_path_preflight_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, u32 desired_access, u32 flags,
	bool rewrite_current_user, const u8 (*scope_guids)[16],
	u32 scope_count, struct pkm_lcs_open_preflight_plan *plan,
	struct pkm_lcs_hive_route_result *route);
long pkm_lcs_open_user_relative_path_preflight(
	const struct pkm_lcs_usercopy_ops *ops, int parent_fd,
	const char __user *upath, u32 desired_access, u32 flags,
	struct pkm_lcs_relative_open_preflight *result);
long pkm_lcs_source_enqueue_request(
	u32 source_id, const u8 *frame, size_t frame_len,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_lookup_request(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_accept_response_file(
	struct file *file, const u8 *frame, size_t frame_len,
	struct pkm_lcs_source_response_result *result);

#ifdef CONFIG_SECURITY_PKM_KUNIT
void pkm_lcs_kunit_reset_source_table(void);
void pkm_lcs_kunit_source_table_snapshot(
	struct pkm_lcs_source_table_snapshot *snapshot);
void pkm_lcs_kunit_source_fd_snapshot(
	struct file *file, struct pkm_lcs_source_fd_snapshot *snapshot);
ssize_t pkm_lcs_kunit_source_device_read_file(
	struct file *file, void *buf, size_t count, bool nonblocking);
ssize_t pkm_lcs_kunit_source_device_write_file(
	struct file *file, const void *buf, size_t count, bool fault,
	struct pkm_lcs_source_response_result *result);
#endif

#endif /* _SECURITY_PKM_LCS_SOURCE_DEVICE_H */
