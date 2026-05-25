/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_KEY_FD_H
#define _SECURITY_PKM_LCS_KEY_FD_H

#include <linux/poll.h>
#include <linux/types.h>

#include <pkm/lcs.h>

#define PKM_LCS_GUID_BYTES 16U
#define PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES 32U
#define PKM_LCS_KEY_FD_WATCH_QUEUE_LIMIT 256U
#define PKM_LCS_KEY_FD_TRANSACTION_WATCH_BURST_LIMIT 4096U

struct pkm_lcs_usercopy_ops;
struct pkm_lcs_runtime_limits;

struct pkm_lcs_key_fd_publish_input {
	u32 source_id;
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u32 granted_access;
	const struct pkm_lcs_runtime_limits *limits;
	const char * const *resolved_path;
	const u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
	u32 path_component_count;
};

struct pkm_lcs_key_fd_snapshot {
	u32 source_id;
	u32 granted_access;
	u32 path_component_count;
	u32 first_component_len;
	u32 last_component_len;
	u32 watch_filter;
	u32 watch_pending_events;
	bool orphaned;
	bool watch_armed;
	bool watch_subtree;
	u8 _pad;
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u8 first_ancestor_guid[PKM_LCS_GUID_BYTES];
	u8 last_ancestor_guid[PKM_LCS_GUID_BYTES];
	char first_component[PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES];
	char last_component[PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES];
};

struct pkm_lcs_backup_value_entry_view {
	u32 name_offset;
	u32 name_len;
	u32 data_offset;
	u32 data_len;
	u32 layer_offset;
	u32 layer_len;
	u32 value_type;
	u32 _pad;
	u64 sequence;
};

struct pkm_lcs_backup_blanket_entry_view {
	u32 layer_offset;
	u32 layer_len;
	u32 _pad0;
	u32 _pad1;
	u64 sequence;
};

struct pkm_lcs_backup_path_entry_view {
	u32 child_name_offset;
	u32 child_name_len;
	u32 layer_offset;
	u32 layer_len;
	u8 child_guid[PKM_LCS_GUID_BYTES];
	u8 hidden;
	u8 _pad[7];
	u64 sequence;
};

struct pkm_lcs_key_fd_relative_base {
	u32 source_id;
	u32 parent_depth;
	bool orphaned;
	u8 _pad[3];
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u8 root_guid[PKM_LCS_GUID_BYTES];
};

struct pkm_lcs_key_fd_parent_snapshot {
	u32 source_id;
	u32 path_component_count;
	bool orphaned;
	u8 _pad[3];
	u8 key_guid[PKM_LCS_GUID_BYTES];
	char **resolved_path;
	u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
};

struct pkm_lcs_key_fd_watch_registry_snapshot {
	u32 direct_watchers;
	u32 subtree_watchers;
};

enum pkm_lcs_internal_watch_target {
	PKM_LCS_INTERNAL_WATCH_SELF_CONFIGURATION = 1,
	PKM_LCS_INTERNAL_WATCH_LAYER_METADATA = 2,
	PKM_LCS_INTERNAL_WATCH_MACHINE_ROOT_FALLBACK = 3,
};

enum pkm_lcs_internal_self_watch_mode {
	PKM_LCS_INTERNAL_SELF_WATCH_DISARMED = 0,
	PKM_LCS_INTERNAL_SELF_WATCH_TARGETED = 1,
	PKM_LCS_INTERNAL_SELF_WATCH_MACHINE_ROOT_FALLBACK = 2,
};

struct pkm_lcs_internal_self_watch_arm_result {
	u32 source_id;
	u32 watch_count;
	u32 mode;
	u8 registry_guid[PKM_LCS_GUID_BYTES];
	u8 layers_guid[PKM_LCS_GUID_BYTES];
	u8 fallback_guid[PKM_LCS_GUID_BYTES];
};

struct pkm_lcs_internal_self_watch_snapshot {
	u32 source_id;
	u32 watch_count;
	u32 mode;
	u8 registry_guid[PKM_LCS_GUID_BYTES];
	u8 layers_guid[PKM_LCS_GUID_BYTES];
	u8 fallback_guid[PKM_LCS_GUID_BYTES];
};

struct pkm_lcs_watch_dispatch_input {
	int mutation_fd;
	u32 event_type;
	const u8 *name;
	u32 name_len;
};

struct pkm_lcs_watch_dispatch_context {
	const u8 *changed_key_guid;
	const u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
	const char * const *resolved_path;
	const struct pkm_lcs_runtime_limits *limits;
	u32 path_component_count;
	u32 event_type;
	const u8 *name;
	u32 name_len;
};

struct pkm_lcs_set_security_merge_result {
	u8 *merged_sd;
	size_t merged_sd_len;
};

#define PKM_LCS_INTERNAL_WATCH_EFFECT_LAYER_DELETE (1U << 0)

long pkm_lcs_key_fd_publish(const struct pkm_lcs_key_fd_publish_input *input);
long pkm_lcs_key_fd_snapshot(int fd, struct pkm_lcs_key_fd_snapshot *out);
long pkm_lcs_key_fd_check_fixed_ioctl_access(int fd, unsigned int cmd);
long pkm_lcs_key_fd_check_security_ioctl_access(int fd, unsigned int cmd,
						u32 security_info);
long pkm_lcs_key_fd_plan_set_security_merge(
	const u8 *existing_sd, size_t existing_sd_len,
	const u8 *input_sd, size_t input_sd_len, u32 security_info,
	struct pkm_lcs_set_security_merge_result *out);
void pkm_lcs_set_security_merge_result_destroy(
	struct pkm_lcs_set_security_merge_result *result);
long pkm_lcs_key_fd_relative_base(int fd,
				  struct pkm_lcs_key_fd_relative_base *out);
long pkm_lcs_key_fd_parent_snapshot(int fd,
				    struct pkm_lcs_key_fd_parent_snapshot *out);
void pkm_lcs_key_fd_parent_snapshot_destroy(
	struct pkm_lcs_key_fd_parent_snapshot *snapshot);
long pkm_lcs_key_fd_dispatch_watch_event_context(
	const struct pkm_lcs_watch_dispatch_context *context);
long pkm_lcs_key_fd_dispatch_watch_event_context_effects(
	const struct pkm_lcs_watch_dispatch_context *context,
	u32 *internal_effects_out);
long pkm_lcs_key_fd_dispatch_watch_event_context_batch(
	const struct pkm_lcs_watch_dispatch_context *contexts,
	u32 context_count);
long pkm_lcs_key_fd_dispatch_watch_event_context_batch_effects(
	const struct pkm_lcs_watch_dispatch_context *contexts, u32 context_count,
	u32 *internal_effects_out);
long pkm_lcs_key_fd_dispatch_overflow_context(
	const struct pkm_lcs_watch_dispatch_context *context);
long pkm_lcs_key_fd_dispatch_source_overflow(u32 source_id,
					     u32 *watch_count_out);
long pkm_lcs_key_fd_dispatch_source_overflow_with_limits(
	u32 source_id, const struct pkm_lcs_runtime_limits *limits,
	u32 *watch_count_out);
long pkm_lcs_key_fd_dispatch_watch_event(
	const struct pkm_lcs_watch_dispatch_input *input);
long pkm_lcs_internal_self_watch_arm(
	u32 source_id, const u8 machine_root_guid[PKM_LCS_GUID_BYTES],
	bool registry_present,
	const u8 registry_guid[PKM_LCS_GUID_BYTES],
	bool layers_present, const u8 layers_guid[PKM_LCS_GUID_BYTES],
	struct pkm_lcs_internal_self_watch_arm_result *result_out);
void pkm_lcs_internal_self_watch_disarm(void);
long pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES], u32 *marked_out);
long pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted_with_refs(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES], u32 *marked_out,
	u32 *live_refs_out);
long pkm_lcs_key_fd_mark_orphaned_and_dispatch_deleted_with_refs_limits(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES],
	const struct pkm_lcs_runtime_limits *limits, u32 *marked_out,
	u32 *live_refs_out);
long pkm_lcs_key_fd_mark_orphaned_no_watch(
	u32 source_id, const u8 guid[PKM_LCS_GUID_BYTES], u32 *marked_out,
	u32 *live_refs_out);
long pkm_lcs_key_path_refresh_layer_metadata(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count);
long pkm_lcs_key_path_refresh_layer_metadata_result(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count,
	bool *effective_changed_out);
long pkm_lcs_key_path_refresh_layer_metadata_with_owner_context(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count,
	const u8 *creator_sid, size_t creator_sid_len, bool is_new_layer);
long pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count,
	const u8 *creator_sid, size_t creator_sid_len, bool is_new_layer,
	bool *effective_changed_out);
long pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
	u32 source_id, const u8 key_guid[PKM_LCS_GUID_BYTES],
	const char * const *resolved_path, u32 path_component_count,
	const u8 *creator_sid, size_t creator_sid_len, bool is_new_layer,
	const struct pkm_lcs_runtime_limits *limits,
	bool *effective_changed_out);

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_lcs_kunit_key_fd_set_orphaned(int fd, bool orphaned);
long pkm_lcs_kunit_key_fd_get_security(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_get_security_args *args);
long pkm_lcs_kunit_key_fd_query_value(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_query_value_args *args);
long pkm_lcs_kunit_key_fd_query_values_batch(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_query_values_batch_args *args);
long pkm_lcs_kunit_key_fd_enum_value(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_enum_value_args *args);
long pkm_lcs_kunit_key_fd_enum_subkey(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_enum_subkey_args *args);
long pkm_lcs_kunit_key_fd_query_key_info(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	struct reg_query_key_info_args *args);
long pkm_lcs_kunit_key_fd_set_security(
	int fd, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_security_args *args);
long pkm_lcs_kunit_key_fd_set_value_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_set_value_args *args);
long pkm_lcs_kunit_key_fd_refresh_layer_metadata(int fd);
long pkm_lcs_kunit_key_fd_delete_value_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_value_args *args);
long pkm_lcs_kunit_key_fd_blanket_tombstone_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_blanket_tombstone_args *args);
long pkm_lcs_kunit_key_fd_delete_key_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_delete_key_args *args);
long pkm_lcs_kunit_key_fd_hide_key_for_token(
	int fd, const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_hide_key_args *args);
long pkm_lcs_kunit_key_fd_backup_for_token(
	int fd, const void *token, const struct reg_backup_args *args);
long pkm_lcs_kunit_backup_layer_manifest_frame(
	const char *layer_name, u32 layer_name_len, u32 precedence, u8 enabled,
	bool base_metadata_present, const u8 *base_metadata_sd,
	size_t base_metadata_sd_len, u8 **frame_out, size_t *frame_len_out);
long pkm_lcs_kunit_backup_path_entry_frame(
	const u8 parent_guid[PKM_LCS_GUID_BYTES], const char *child_name,
	size_t child_name_len, const u8 child_guid[PKM_LCS_GUID_BYTES],
	bool hidden, const char *layer_name, size_t layer_name_len,
	u64 sequence, u8 **frame_out, size_t *frame_len_out);
long pkm_lcs_kunit_backup_value_frame(
	const u8 key_guid[PKM_LCS_GUID_BYTES], const char *name,
	size_t name_len, u32 value_type, const u8 *data, size_t data_len,
	const char *layer_name, size_t layer_name_len, u64 sequence,
	u8 **frame_out, size_t *frame_len_out);
long pkm_lcs_kunit_backup_blanket_tombstone_frame(
	const u8 key_guid[PKM_LCS_GUID_BYTES], const char *layer_name,
	size_t layer_name_len, u64 sequence, u8 **frame_out,
	size_t *frame_len_out);
long pkm_lcs_kunit_backup_query_values_entries(
	const u8 *frame, size_t frame_len, u64 request_id, u64 next_sequence,
	struct pkm_lcs_backup_value_entry_view *values, size_t value_capacity,
	struct pkm_lcs_backup_blanket_entry_view *blankets,
	size_t blanket_capacity, u32 *value_count_out,
	u32 *blanket_count_out);
long pkm_lcs_kunit_backup_enum_children_path_entries(
	const u8 *frame, size_t frame_len, u64 request_id, u64 next_sequence,
	struct pkm_lcs_backup_path_entry_view *entries, size_t entry_capacity,
	u32 *entry_count_out);
long pkm_lcs_kunit_key_fd_restore_for_token(
	int fd, const void *token, const struct reg_restore_args *args);
long pkm_lcs_kunit_key_fd_flush(int fd);
long pkm_lcs_kunit_key_fd_notify(int fd, const struct reg_notify_args *args);
long pkm_lcs_kunit_key_fd_queue_watch_event(int fd, u32 event_type,
					    const u8 *record, u32 record_len);
ssize_t pkm_lcs_kunit_key_fd_read(int fd, u8 *buf, size_t count,
				  bool nonblocking);
__poll_t pkm_lcs_kunit_key_fd_poll(int fd);
long pkm_lcs_kunit_key_fd_watch_registry_snapshot(
	int fd, struct pkm_lcs_key_fd_watch_registry_snapshot *out);
long pkm_lcs_kunit_internal_self_watch_snapshot(
	struct pkm_lcs_internal_self_watch_snapshot *out);
#endif

#endif /* _SECURITY_PKM_LCS_KEY_FD_H */
