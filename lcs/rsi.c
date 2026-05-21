// SPDX-License-Identifier: GPL-2.0-only

#include <linux/errno.h>
#include <linux/string.h>

#include "rsi.h"

extern int lcs_rust_write_rsi_lookup_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 *parent_guid, const u8 *child_name, u32 child_name_len,
	struct pkm_lcs_rsi_built_request *built);
extern int lcs_rust_write_rsi_read_key_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 *guid, struct pkm_lcs_rsi_built_request *built);
extern int lcs_rust_write_rsi_query_values_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 *guid, const u8 *value_name, u32 value_name_len,
	u8 query_all, struct pkm_lcs_rsi_built_request *built);
extern int lcs_rust_write_rsi_create_entry_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 *parent_guid, const u8 *child_name, u32 child_name_len,
	const u8 *layer_name, u32 layer_name_len, const u8 *child_guid,
	u64 sequence, struct pkm_lcs_rsi_built_request *built);
extern int lcs_rust_write_rsi_create_key_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 *guid, const u8 *name, u32 name_len,
	const u8 *parent_guid, const u8 *sd, size_t sd_len,
	u8 volatile_key, u8 symlink,
	struct pkm_lcs_rsi_built_request *built);
extern int lcs_rust_write_rsi_begin_transaction_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	u64 transaction_id, u32 mode,
	struct pkm_lcs_rsi_built_request *built);
extern int lcs_rust_write_rsi_commit_transaction_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	u64 transaction_id, struct pkm_lcs_rsi_built_request *built);
extern int lcs_rust_write_rsi_abort_transaction_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	u64 transaction_id, struct pkm_lcs_rsi_built_request *built);
extern int lcs_rust_validate_rsi_lookup_response_frame(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence,
	struct pkm_lcs_rsi_lookup_response_summary *summary);
extern int lcs_rust_validate_rsi_query_values_response_frame(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence,
	struct pkm_lcs_rsi_query_values_response_summary *summary);
extern int lcs_rust_materialize_rsi_lookup_child(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const u8 *child_name, u32 child_name_len,
	const struct pkm_lcs_rsi_layer_view *layers, size_t layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	size_t private_layer_count,
	struct pkm_lcs_rsi_lookup_child_result *result);
extern int lcs_rust_materialize_rsi_read_key_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	struct pkm_lcs_rsi_read_key_result *result);
extern int lcs_rust_materialize_rsi_query_value_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const u8 *value_name, u32 value_name_len,
	const struct pkm_lcs_rsi_layer_view *layers, size_t layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	size_t private_layer_count,
	struct pkm_lcs_rsi_query_value_result *result);

long pkm_lcs_rsi_build_lookup_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE], const char *child_name,
	u32 child_name_len, struct pkm_lcs_rsi_built_request *built)
{
	if (!built)
		return -EINVAL;

	memset(built, 0, sizeof(*built));
	if (!dst || !parent_guid || !child_name)
		return -EINVAL;

	return lcs_rust_write_rsi_lookup_request_frame(
		dst, dst_len, request_id, txn_id, parent_guid,
		(const u8 *)child_name, child_name_len, built);
}

long pkm_lcs_rsi_build_read_key_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], struct pkm_lcs_rsi_built_request *built)
{
	if (!built)
		return -EINVAL;

	memset(built, 0, sizeof(*built));
	if (!dst || !guid)
		return -EINVAL;

	return lcs_rust_write_rsi_read_key_request_frame(
		dst, dst_len, request_id, txn_id, guid, built);
}

long pkm_lcs_rsi_build_query_values_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], const char *value_name,
	u32 value_name_len, bool query_all,
	struct pkm_lcs_rsi_built_request *built)
{
	if (!built)
		return -EINVAL;

	memset(built, 0, sizeof(*built));
	if (!dst || !guid || (value_name_len && !value_name))
		return -EINVAL;

	return lcs_rust_write_rsi_query_values_request_frame(
		dst, dst_len, request_id, txn_id, guid,
		(const u8 *)value_name, value_name_len, query_all ? 1 : 0,
		built);
}

long pkm_lcs_rsi_build_create_entry_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE], const char *child_name,
	u32 child_name_len, const char *layer_name, u32 layer_name_len,
	const u8 child_guid[RSI_GUID_SIZE], u64 sequence,
	struct pkm_lcs_rsi_built_request *built)
{
	if (!built)
		return -EINVAL;

	memset(built, 0, sizeof(*built));
	if (!dst || !parent_guid || !child_name || !layer_name || !child_guid)
		return -EINVAL;

	return lcs_rust_write_rsi_create_entry_request_frame(
		dst, dst_len, request_id, txn_id, parent_guid,
		(const u8 *)child_name, child_name_len,
		(const u8 *)layer_name, layer_name_len, child_guid, sequence,
		built);
}

long pkm_lcs_rsi_build_create_key_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 guid[RSI_GUID_SIZE], const char *name, u32 name_len,
	const u8 parent_guid[RSI_GUID_SIZE], const u8 *sd, size_t sd_len,
	bool volatile_key, bool symlink,
	struct pkm_lcs_rsi_built_request *built)
{
	if (!built)
		return -EINVAL;

	memset(built, 0, sizeof(*built));
	if (!dst || !guid || !name || !parent_guid || !sd || !sd_len)
		return -EINVAL;

	return lcs_rust_write_rsi_create_key_request_frame(
		dst, dst_len, request_id, txn_id, guid, (const u8 *)name,
		name_len, parent_guid, sd, sd_len, volatile_key ? 1 : 0,
		symlink ? 1 : 0, built);
}

long pkm_lcs_rsi_build_begin_transaction_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	u64 transaction_id, u32 mode,
	struct pkm_lcs_rsi_built_request *built)
{
	if (!built)
		return -EINVAL;

	memset(built, 0, sizeof(*built));
	if (!dst)
		return -EINVAL;

	return lcs_rust_write_rsi_begin_transaction_request_frame(
		dst, dst_len, request_id, txn_id, transaction_id, mode,
		built);
}

long pkm_lcs_rsi_build_commit_transaction_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	u64 transaction_id, struct pkm_lcs_rsi_built_request *built)
{
	if (!built)
		return -EINVAL;

	memset(built, 0, sizeof(*built));
	if (!dst)
		return -EINVAL;

	return lcs_rust_write_rsi_commit_transaction_request_frame(
		dst, dst_len, request_id, txn_id, transaction_id, built);
}

long pkm_lcs_rsi_build_abort_transaction_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	u64 transaction_id, struct pkm_lcs_rsi_built_request *built)
{
	if (!built)
		return -EINVAL;

	memset(built, 0, sizeof(*built));
	if (!dst)
		return -EINVAL;

	return lcs_rust_write_rsi_abort_transaction_request_frame(
		dst, dst_len, request_id, txn_id, transaction_id, built);
}

long pkm_lcs_rsi_validate_lookup_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence,
	struct pkm_lcs_rsi_lookup_response_summary *summary)
{
	if (!summary)
		return -EINVAL;

	memset(summary, 0, sizeof(*summary));
	if (!frame)
		return -EINVAL;
	if (frame_len < RSI_MIN_RESPONSE_SIZE)
		return -EINVAL;

	return lcs_rust_validate_rsi_lookup_response_frame(
		frame, frame_len, request_id, next_sequence, summary);
}

long pkm_lcs_rsi_validate_query_values_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence,
	struct pkm_lcs_rsi_query_values_response_summary *summary)
{
	if (!summary)
		return -EINVAL;

	memset(summary, 0, sizeof(*summary));
	if (!frame)
		return -EINVAL;
	if (frame_len < RSI_MIN_RESPONSE_SIZE)
		return -EINVAL;

	return lcs_rust_validate_rsi_query_values_response_frame(
		frame, frame_len, request_id, next_sequence, summary);
}

long pkm_lcs_rsi_materialize_lookup_child(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const char *child_name, u32 child_name_len,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_rsi_lookup_child_result *result)
{
	if (!result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	if (!frame || !child_name)
		return -EINVAL;
	if (frame_len < RSI_MIN_RESPONSE_SIZE)
		return -EINVAL;
	if (layer_count && !layers)
		return -EINVAL;
	if (private_layer_count && !private_layers)
		return -EINVAL;

	return lcs_rust_materialize_rsi_lookup_child(
		frame, frame_len, request_id, next_sequence,
		(const u8 *)child_name, child_name_len, layers, layer_count,
		private_layers, private_layer_count, result);
}

long pkm_lcs_rsi_materialize_read_key_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	struct pkm_lcs_rsi_read_key_result *result)
{
	if (!result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	if (!frame)
		return -EINVAL;
	if (frame_len < RSI_MIN_RESPONSE_SIZE)
		return -EINVAL;

	return lcs_rust_materialize_rsi_read_key_response(
		frame, frame_len, request_id, result);
}

long pkm_lcs_rsi_materialize_query_value_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const char *value_name, u32 value_name_len,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_rsi_query_value_result *result)
{
	if (!result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	if (!frame || (value_name_len && !value_name))
		return -EINVAL;
	if (frame_len < RSI_MIN_RESPONSE_SIZE)
		return -EINVAL;
	if (layer_count && !layers)
		return -EINVAL;
	if (private_layer_count && !private_layers)
		return -EINVAL;

	return lcs_rust_materialize_rsi_query_value_response(
		frame, frame_len, request_id, next_sequence,
		(const u8 *)value_name, value_name_len, layers, layer_count,
		private_layers, private_layer_count, result);
}
