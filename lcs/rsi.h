/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_RSI_H
#define _SECURITY_PKM_LCS_RSI_H

#include <linux/types.h>

#include <pkm/lcs.h>

struct pkm_lcs_runtime_limits;

struct pkm_lcs_rsi_built_request {
	size_t len;
	u64 request_id;
	u64 txn_id;
	u16 op_code;
	u8 _pad[6];
};

struct pkm_lcs_rsi_lookup_response_summary {
	u32 path_entry_count;
	u32 metadata_count;
	u32 source_validation_failure;
	bool child_absent;
	u8 source_validation_failure_present;
	u8 _pad[2];
};

struct pkm_lcs_rsi_query_values_response_summary {
	u32 value_entry_count;
	u32 blanket_count;
	u32 source_validation_failure;
	u8 source_validation_failure_present;
	u8 _pad[3];
};

struct pkm_lcs_rsi_delete_layer_response_summary {
	u32 orphaned_guid_count;
	u32 source_validation_failure;
	u8 source_validation_failure_present;
	u8 _pad[3];
};

struct pkm_lcs_rsi_enum_children_info_summary {
	u32 subkey_count;
	u32 max_subkey_name_len;
	u32 source_path_entry_count;
	u32 source_validation_failure;
	u8 source_validation_failure_present;
	u8 _pad[3];
};

struct pkm_lcs_rsi_enum_subkey_result {
	u32 source_path_entry_count;
	u32 name_offset;
	u32 name_len;
	u32 selected_precedence;
	u64 selected_sequence;
	u8 found;
	u8 _pad[7];
	u8 child_guid[RSI_GUID_SIZE];
};

struct pkm_lcs_rsi_query_values_info_summary {
	u32 value_count;
	u32 max_value_name_len;
	u32 max_value_data_size;
	u32 source_value_entry_count;
	u32 source_blanket_count;
	u32 _pad[3];
};

struct pkm_lcs_rsi_query_values_batch_result {
	u32 required_len;
	u32 count;
	u32 written_len;
	u32 source_value_entry_count;
	u32 source_blanket_count;
	u32 _pad[3];
};

struct pkm_lcs_rsi_value_watch_events_result {
	u32 required_len;
	u32 count;
	u32 written_len;
	u32 before_source_value_entry_count;
	u32 before_source_blanket_count;
	u32 after_source_value_entry_count;
	u32 after_source_blanket_count;
	u32 _pad;
};

struct pkm_lcs_rsi_layer_view {
	const char *name;
	u32 name_len;
	u32 precedence;
	u8 enabled;
	u8 _pad[3];
};

struct pkm_lcs_rsi_private_layer_view {
	const char *name;
	u32 name_len;
};

struct pkm_lcs_rsi_lookup_child_result {
	u32 source_path_entry_count;
	u32 sd_offset;
	u32 sd_len;
	u32 selected_precedence;
	u64 selected_sequence;
	u64 last_write_time;
	u8 found;
	u8 volatile_key;
	u8 symlink;
	u8 _pad[5];
	u8 key_guid[RSI_GUID_SIZE];
};

struct pkm_lcs_rsi_lookup_guid_entry_result {
	u32 source_path_entry_count;
	u8 present;
	u8 _pad[3];
};

struct pkm_lcs_rsi_read_key_result {
	u32 sd_offset;
	u32 sd_len;
	u32 name_len;
	u32 source_validation_failure;
	u64 last_write_time;
	u8 volatile_key;
	u8 symlink;
	u8 source_validation_failure_present;
	u8 _pad1[5];
	u8 parent_guid[RSI_GUID_SIZE];
};

struct pkm_lcs_rsi_query_value_result {
	u32 source_value_entry_count;
	u32 source_blanket_count;
	u32 data_offset;
	u32 data_len;
	const u8 *layer;
	u32 layer_len;
	u32 value_type;
	u32 selected_precedence;
	u32 _pad0;
	u64 selected_sequence;
	u8 found;
	u8 _pad1[7];
};

struct pkm_lcs_rsi_enum_value_result {
	u32 source_value_entry_count;
	u32 source_blanket_count;
	u32 name_offset;
	u32 name_len;
	u32 data_offset;
	u32 data_len;
	u32 value_type;
	u32 _pad0;
	u8 found;
	u8 _pad1[7];
};

struct pkm_lcs_value_layer_admission_result {
	u32 current_distinct_layers;
	u8 replacing_existing_layer_entry;
	u8 _pad[3];
};

long pkm_lcs_rsi_build_lookup_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE], const char *child_name,
	u32 child_name_len, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_enum_children_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE],
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_read_key_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_query_values_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], const char *value_name,
	u32 value_name_len, bool query_all,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_set_value_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], const char *value_name,
	u32 value_name_len, const char *layer_name, u32 layer_name_len,
	u32 value_type, const u8 *data, size_t data_len, u64 sequence,
	u64 expected_sequence, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_delete_value_entry_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], const char *value_name,
	u32 value_name_len, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_set_blanket_tombstone_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], const char *layer_name,
	u32 layer_name_len, bool set, u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_validate_set_value_user_shape(
	const u8 guid[RSI_GUID_SIZE], const char *value_name,
	u32 value_name_len, const char *layer_name, u32 layer_name_len,
	u32 value_type, size_t data_len,
	const struct pkm_lcs_runtime_limits *limits);
long pkm_lcs_rsi_validate_delete_value_user_shape(
	const u8 guid[RSI_GUID_SIZE], const char *value_name,
	u32 value_name_len, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits);
long pkm_lcs_rsi_plan_set_value_layer_admission(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const char *value_name, u32 value_name_len,
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_value_layer_admission_result *result);
long pkm_lcs_rsi_build_create_entry_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE], const char *child_name,
	u32 child_name_len, const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_hide_entry_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE], const char *child_name,
	u32 child_name_len, const char *layer_name, u32 layer_name_len,
	u64 sequence, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_delete_entry_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE], const char *child_name,
	u32 child_name_len, const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_create_key_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_write_key_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	u64 last_write_time, struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_drop_key_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_begin_transaction_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	u64 transaction_id, u32 mode,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_commit_transaction_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	u64 transaction_id, struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_abort_transaction_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	u64 transaction_id, struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_delete_layer_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const char *layer_name, u32 layer_name_len,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_build_flush_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const char *hive_name, u32 hive_name_len,
	struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_validate_lookup_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_lookup_response_summary *summary);
long pkm_lcs_rsi_validate_query_values_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_query_values_response_summary *summary);
long pkm_lcs_rsi_validate_status_only_response(
	const u8 *frame, size_t frame_len, u64 request_id, u16 request_op_code);
long pkm_lcs_rsi_validate_delete_layer_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	struct pkm_lcs_rsi_delete_layer_response_summary *summary);
long pkm_lcs_rsi_materialize_enum_children_info_summary(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_enum_children_info_summary *summary);
long pkm_lcs_rsi_materialize_enum_subkey_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, u32 index,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_enum_subkey_result *result);
long pkm_lcs_rsi_materialize_query_values_info_summary(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_query_values_info_summary *summary);
long pkm_lcs_rsi_materialize_query_values_batch_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	u8 *output, size_t output_len,
	struct pkm_lcs_rsi_query_values_batch_result *result);
long pkm_lcs_rsi_materialize_query_values_watch_events(
	const u8 *before_frame, size_t before_frame_len,
	u64 before_request_id, const u8 *after_frame,
	size_t after_frame_len, u64 after_request_id, u64 next_sequence,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	u8 *output, size_t output_len,
	struct pkm_lcs_rsi_value_watch_events_result *result);
long pkm_lcs_rsi_materialize_lookup_child(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const char *child_name, u32 child_name_len,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_lookup_child_result *result);
long pkm_lcs_rsi_materialize_lookup_guid_entry(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const char *child_name, u32 child_name_len,
	const u8 target_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_lookup_guid_entry_result *result);
long pkm_lcs_rsi_materialize_read_key_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	struct pkm_lcs_rsi_read_key_result *result);
long pkm_lcs_rsi_materialize_query_value_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const char *value_name, u32 value_name_len,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_query_value_result *result);
long pkm_lcs_rsi_materialize_enum_value_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, u32 index,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_rsi_enum_value_result *result);

#endif /* _SECURITY_PKM_LCS_RSI_H */
