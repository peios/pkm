/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_TRANSACTION_FD_H
#define _SECURITY_PKM_LCS_TRANSACTION_FD_H

#include <linux/file.h>
#include <linux/types.h>

#define PKM_LCS_TRANSACTION_TIMEOUT_MS_DEFAULT 30000U
#define PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES 16U

#define PKM_LCS_TRANSACTION_BIND_NEW 1U
#define PKM_LCS_TRANSACTION_BIND_REUSE 2U
#define PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY 1U
#define PKM_LCS_TRANSACTION_LOG_KIND_SET_SECURITY 2U
#define PKM_LCS_TRANSACTION_LOG_KIND_SET_VALUE 3U
#define PKM_LCS_TRANSACTION_LOG_KIND_DELETE_VALUE 4U
#define PKM_LCS_TRANSACTION_LOG_KIND_DELETE_KEY 5U
#define PKM_LCS_TRANSACTION_LOG_KIND_HIDE_KEY 6U
#define PKM_LCS_TRANSACTION_LOG_KIND_BLANKET_TOMBSTONE 7U
#define PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT 4096U

struct reg_txn_status_args;
struct pkm_lcs_transaction_fd;
struct pkm_lcs_transaction_log_entry;
struct pkm_lcs_runtime_limits;

struct pkm_lcs_transaction_fd_snapshot {
	u64 transaction_id;
	u32 state;
	u32 bound_source_id;
	bool timer_pending;
	u8 _pad[3];
	u8 bound_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
};

struct pkm_lcs_transaction_binding_plan {
	u64 transaction_id;
	u32 action;
	u32 state;
	u32 bound_source_id;
	u8 bound_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
};

struct pkm_lcs_transaction_read_plan {
	u64 txn_id;
	u32 state;
	u32 bound_source_id;
	bool use_transaction;
	u8 _pad[3];
	u8 bound_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
};

long pkm_lcs_transaction_id_allocate(u64 *transaction_id);

struct pkm_lcs_transaction_key_create_log_input {
	const u8 *parent_guid;
	const u8 *target_guid;
	const char *child_name;
	size_t child_name_len;
	const char *layer;
	size_t layer_len;
	const char * const *parent_path;
	const u8 (*parent_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	const u8 *creator_sid;
	size_t creator_sid_len;
	u32 parent_depth;
	u64 sequence;
};

struct pkm_lcs_transaction_set_security_log_input {
	const u8 *key_guid;
	const char * const *path;
	const u8 (*ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 depth;
};

struct pkm_lcs_transaction_set_value_log_input {
	const u8 *key_guid;
	const char *value_name;
	size_t value_name_len;
	const char *layer;
	size_t layer_len;
	const char * const *path;
	const u8 (*ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 depth;
	u64 sequence;
};

struct pkm_lcs_transaction_delete_value_log_input {
	const u8 *key_guid;
	const char *value_name;
	size_t value_name_len;
	const char *layer;
	size_t layer_len;
	const char * const *path;
	const u8 (*ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 depth;
};

struct pkm_lcs_transaction_blanket_tombstone_log_input {
	const u8 *key_guid;
	const char *layer;
	size_t layer_len;
	const char * const *path;
	const u8 (*ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 depth;
	u64 sequence;
	bool set;
};

struct pkm_lcs_transaction_delete_key_log_input {
	const u8 *key_guid;
	const u8 *parent_guid;
	const char *child_name;
	size_t child_name_len;
	const char *layer;
	size_t layer_len;
	const char * const *parent_path;
	const u8 (*parent_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 parent_depth;
};

struct pkm_lcs_transaction_hide_key_log_input {
	const u8 *key_guid;
	const u8 *parent_guid;
	const char *child_name;
	size_t child_name_len;
	const char *layer;
	size_t layer_len;
	const char * const *parent_path;
	const u8 (*parent_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 parent_depth;
	u64 sequence;
};

struct pkm_lcs_transaction_mutation_handle {
	struct fd held;
	struct pkm_lcs_transaction_fd *txn;
	struct pkm_lcs_transaction_log_entry *entry;
	bool active;
};

struct pkm_lcs_transaction_mutation_log_snapshot {
	u64 next_operation_index;
	u64 last_operation_index;
	u64 last_sequence;
	u32 entry_count;
	u32 capacity;
	u32 last_kind;
	u32 last_parent_depth;
	u8 last_key_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	char last_child_name[64];
	char last_layer[64];
};

struct pkm_lcs_transaction_layer_abort_result {
	u32 inspected_transaction_count;
	u32 affected_bound_transaction_count;
	u32 abort_dispatched_count;
};

long pkm_lcs_transaction_fd_publish(u32 timeout_ms);
long pkm_lcs_reg_begin_transaction(void);
long pkm_lcs_transaction_fd_commit(int fd);
long pkm_lcs_transaction_fd_status(int fd, struct reg_txn_status_args *out);
long pkm_lcs_transaction_fd_abort_layer_writers(
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_transaction_layer_abort_result *result);
long pkm_lcs_transaction_fd_abort_layer_writers_with_limits(
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_transaction_layer_abort_result *result);
long pkm_lcs_transaction_fd_begin_key_create_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_key_create_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding);
long pkm_lcs_transaction_fd_begin_set_security_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_set_security_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding);
long pkm_lcs_transaction_fd_begin_set_value_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_set_value_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding);
long pkm_lcs_transaction_fd_begin_delete_value_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_delete_value_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding);
long pkm_lcs_transaction_fd_begin_blanket_tombstone_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_blanket_tombstone_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding);
long pkm_lcs_transaction_fd_begin_delete_key_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_delete_key_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding);
long pkm_lcs_transaction_fd_begin_hide_key_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_hide_key_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding);
long pkm_lcs_transaction_fd_set_delete_value_event(
	struct pkm_lcs_transaction_mutation_handle *handle, u32 event_type);
long pkm_lcs_transaction_fd_set_blanket_tombstone_events(
	struct pkm_lcs_transaction_mutation_handle *handle,
	const u8 *events, size_t events_len, u32 event_count);
long pkm_lcs_transaction_fd_commit_mutation(
	struct pkm_lcs_transaction_mutation_handle *handle);
void pkm_lcs_transaction_fd_cancel_mutation(
	struct pkm_lcs_transaction_mutation_handle *handle);
long pkm_lcs_transaction_fd_prepare_read_context(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_read_plan *out);
long pkm_lcs_transaction_fd_prepare_mutation_binding(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_binding_plan *out);
long pkm_lcs_transaction_fd_complete_first_bind(
	int fd, u64 transaction_id, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES]);
long pkm_lcs_transaction_fd_bind_for_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_binding_plan *out);
long pkm_lcs_transaction_fd_mark_source_down(u32 source_id, u32 *marked_out);
long pkm_lcs_transaction_fd_handle_late_commit_response(
	u32 source_id, u64 transaction_id, u32 status,
	const struct pkm_lcs_runtime_limits *limits);
long pkm_lcs_transaction_fd_snapshot(
	int fd, struct pkm_lcs_transaction_fd_snapshot *out);
long pkm_lcs_transaction_fd_log_snapshot(
	int fd, struct pkm_lcs_transaction_mutation_log_snapshot *out);

#ifdef CONFIG_SECURITY_PKM_KUNIT
u32 pkm_lcs_kunit_transaction_fd_poll_mask(int fd);
long pkm_lcs_kunit_transaction_fd_set_state(int fd, u32 state,
					    u32 bound_source_id);
long pkm_lcs_kunit_transaction_fd_set_log_capacity(int fd, u32 capacity);
long pkm_lcs_kunit_transaction_fd_set_commit_in_flight(int fd,
						       bool in_flight);
long pkm_lcs_kunit_transaction_fd_flush_timeout_work(int fd);
long pkm_lcs_kunit_transaction_fd_commit_timeout(int fd, u32 timeout_ms);
long pkm_lcs_kunit_transaction_fd_raw_ioctl(int fd, unsigned int cmd,
					    unsigned long arg);
u32 pkm_lcs_kunit_transaction_fd_retained_commit_count(void);
#endif

#endif /* _SECURITY_PKM_LCS_TRANSACTION_FD_H */
