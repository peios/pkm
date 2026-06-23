/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_SOURCE_INTERNAL_H
#define _SECURITY_PKM_LCS_SOURCE_INTERNAL_H

#include <linux/list.h>
#include <linux/types.h>

#include "rsi.h"
#include "source_device.h"

#define PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT 32U
#define PKM_LCS_MAX_REGISTERED_SOURCES_HARD 256U

struct pkm_lcs_pending_layer_delete {
	struct list_head link;
	u32 name_len;
	char name[];
};

struct pkm_lcs_source_slot {
	bool occupied;
	u32 status;
	u32 source_id;
	u32 hive_count;
	struct pkm_lcs_source_registration_hive_copy *hives;
	struct pkm_lcs_source_fd *active_fd;
	struct list_head pending_layer_deletes;
	u64 source_next_sequence;
	u64 restart_generation;
	u32 bound_transaction_count;
	u32 read_only_transaction_count;
	u32 pending_layer_delete_count;
};

struct pkm_lcs_source_queued_request {
	struct list_head link;
	u8 *frame;
	size_t len;
	u64 request_id;
	u64 txn_id;
	u16 op_code;
};

struct pkm_lcs_source_slot_view_buffer {
	struct pkm_lcs_source_slot_view_copy
		stack[PKM_LCS_MAX_REGISTERED_SOURCES_DEFAULT];
	struct pkm_lcs_source_slot_view_copy *views;
	u32 capacity;
};

void pkm_lcs_source_table_lock(void);
void pkm_lcs_source_table_unlock(void);
void pkm_lcs_source_table_assert_locked(void);

void pkm_lcs_source_sequence_gate_lock(void);
void pkm_lcs_source_sequence_gate_unlock(void);
void pkm_lcs_source_table_sequence_snapshot_locked(bool *initialized,
						   u64 *next_sequence);
void pkm_lcs_source_table_sequence_set_locked(bool initialized,
					      u64 next_sequence);

s64 pkm_lcs_source_slot_wait_epoch_snapshot(void);
long pkm_lcs_source_slot_wait_epoch_change_interruptible_timeout(
	s64 epoch, long timeout);
unsigned long pkm_lcs_source_deadline_from_timeout_ms(u32 timeout_ms);
long pkm_lcs_source_deadline_remaining(unsigned long deadline);
long pkm_lcs_source_wait_for_slot(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits,
	unsigned long deadline);

void pkm_lcs_source_slot_pending_layer_deletes_destroy(
	struct pkm_lcs_source_slot *slot);
void pkm_lcs_source_slot_view_buffer_init(
	struct pkm_lcs_source_slot_view_buffer *buffer);
void pkm_lcs_source_slot_view_buffer_destroy(
	struct pkm_lcs_source_slot_view_buffer *buffer);
long pkm_lcs_source_slot_view_buffer_prepare_locked(
	struct pkm_lcs_source_slot_view_buffer *buffer, u32 *count_out);
struct pkm_lcs_source_slot *pkm_lcs_source_slot_find_locked(u32 source_id);
struct pkm_lcs_source_slot *pkm_lcs_source_slot_free_locked(void);
u32 pkm_lcs_source_slot_id(const struct pkm_lcs_source_slot *slot);
long pkm_lcs_source_record_down_layer_delete_locked(
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits, u32 *pending_count_out);
long pkm_lcs_source_replay_pending_layer_deletes_with_limits(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits);
struct pkm_lcs_source_registration_hive_copy *
pkm_lcs_source_slot_hive_find_locked(struct pkm_lcs_source_slot *slot,
				     const u8 root_guid[RSI_GUID_SIZE]);
bool pkm_lcs_source_in_flight_at_limit_locked(
	const struct pkm_lcs_source_fd *source_fd,
	const struct pkm_lcs_runtime_limits *limits);
long pkm_lcs_source_request_id_successor(u64 request_id, u64 *next);
long pkm_lcs_source_in_flight_insert_locked(
	struct pkm_lcs_source_fd *source_fd, u64 request_id, u64 txn_id,
	u16 op_code, const u8 key_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_restore_commit_late_effect_input *late_effect,
	struct pkm_lcs_source_response_waiter *waiter);
struct pkm_lcs_source_in_flight_request *
pkm_lcs_source_in_flight_find_locked(struct pkm_lcs_source_fd *source_fd,
				     u64 request_id);
long pkm_lcs_source_in_flight_set_key_late_effect_locked(
	struct pkm_lcs_source_fd *source_fd, u64 request_id,
	const struct pkm_lcs_source_key_mutation_late_effect_input *late_effect);
long pkm_lcs_source_in_flight_set_delivered_locked(
	struct pkm_lcs_source_fd *source_fd, u64 request_id, bool delivered);
void pkm_lcs_source_in_flight_release_locked(
	struct pkm_lcs_source_fd *source_fd,
	struct pkm_lcs_source_in_flight_request *record);
void pkm_lcs_source_enqueue_result_fill_locked(
	struct pkm_lcs_source_enqueue_result *result,
	const struct pkm_lcs_source_queued_request *request,
	const struct pkm_lcs_source_fd *source_fd);
void pkm_lcs_source_queued_request_free(
	struct pkm_lcs_source_queued_request *request);
bool pkm_lcs_source_read_ready(struct pkm_lcs_source_fd *source_fd);
void pkm_lcs_source_device_mark_down_file(struct file *file);
void pkm_lcs_source_device_mark_malformed_protocol_file(struct file *file);
ssize_t pkm_lcs_source_device_read_user(struct file *file, char __user *buf,
					size_t count);
ssize_t pkm_lcs_source_device_write_user(
	struct file *file, const char __user *buf, size_t count,
	struct pkm_lcs_source_response_result *result);
long pkm_lcs_source_response_waiter_retain_frame(
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_response_frame *frame);
void pkm_lcs_source_response_waiter_complete_with_frame(
	struct pkm_lcs_source_response_waiter *waiter, long response_errno,
	const struct pkm_lcs_source_response_result *result,
	const u8 *frame, size_t frame_len);
void pkm_lcs_source_response_waiter_complete(
	struct pkm_lcs_source_response_waiter *waiter, long response_errno,
	const struct pkm_lcs_source_response_result *result);
bool pkm_lcs_source_response_waiter_detach(
	struct pkm_lcs_source_response_waiter *waiter);
long pkm_lcs_source_response_waiter_wait_until(
	struct pkm_lcs_source_response_waiter *waiter, unsigned long deadline,
	struct pkm_lcs_source_response_result *result);
long pkm_lcs_source_dispatch_lookup_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_read_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_enum_children_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_query_values_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len, bool query_all,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_set_value_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len, u32 value_type,
	const u8 *data, size_t data_len, u64 sequence, u64 expected_sequence,
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_key_mutation_late_effect_input *late_effect,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_delete_value_entry_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_set_blanket_tombstone_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len, bool set, u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_drop_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_create_entry_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_hide_delete_entry_request_with_waiter(
	u32 source_id, u64 txn_id, bool hide,
	const u8 parent_guid[RSI_GUID_SIZE],
	const char *child_name, u32 child_name_len,
	const char *layer_name, u32 layer_name_len, u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_create_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_write_key_request_with_waiter(
	u32 source_id, u64 txn_id, const u8 guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u64 last_write_time,
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_key_mutation_late_effect_input *late_effect,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_transaction_request_with_waiter(
	u32 source_id, u16 op_code, u64 transaction_id, u32 mode,
	const struct pkm_lcs_runtime_limits *limits,
	const struct pkm_lcs_source_restore_commit_late_effect_input *late_effect,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_flush_request_with_waiter(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_source_dispatch_delete_layer_request_with_waiter(
	u32 source_id, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_enqueue_result *result);
long pkm_lcs_route_absolute_path_for_token_with_limits(
	const void *token, const char *path, u32 path_len,
	bool rewrite_current_user, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_hive_route_result *result);
long pkm_lcs_route_symlink_target_with_limits(
	const char *target, u32 target_len, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_hive_route_result *result);
long pkm_lcs_publish_open_key_for_token(
	const void *token, u32 source_id, const u8 key_guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u32 desired_access,
	const char * const *resolved_path,
	const u8 (*ancestor_guids)[RSI_GUID_SIZE], u32 path_component_count,
	const struct pkm_lcs_runtime_limits *limits);
long pkm_lcs_open_copied_absolute_path_after_preflight_for_token(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd);
long pkm_lcs_open_copied_relative_path_after_preflight(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd);
long pkm_lcs_source_bootstrap_workqueue_init(void);
void pkm_lcs_source_bootstrap_workqueue_destroy(void);
void pkm_lcs_source_bootstrap_workqueue_flush(void);

#endif /* _SECURITY_PKM_LCS_SOURCE_INTERNAL_H */
