// SPDX-License-Identifier: GPL-2.0-only

#include <linux/errno.h>
#include <linux/string.h>

#include "rsi.h"

extern int lcs_rust_write_rsi_lookup_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 *parent_guid, const u8 *child_name, u32 child_name_len,
	struct pkm_lcs_rsi_built_request *built);
extern int lcs_rust_validate_rsi_lookup_response_frame(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence,
	struct pkm_lcs_rsi_lookup_response_summary *summary);
extern int lcs_rust_materialize_rsi_lookup_child(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence, const u8 *child_name, u32 child_name_len,
	const struct pkm_lcs_rsi_layer_view *layers, size_t layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	size_t private_layer_count,
	struct pkm_lcs_rsi_lookup_child_result *result);

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
