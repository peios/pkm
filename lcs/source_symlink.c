// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS registry symlink target resolution.
 */

#include <linux/errno.h>
#include <linux/string.h>

#include "source_internal.h"

long pkm_lcs_resolve_symlink_target_for_key(
	u32 source_id, u64 txn_id, const u8 key_guid[RSI_GUID_SIZE],
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_symlink_target_resolution *result)
{
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *active_private_layers =
		private_layers;
	struct pkm_lcs_runtime_limits effective_limits;
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_query_value_result value = { };
	struct pkm_lcs_source_response_frame frame;
	const char *target;
	u64 next_sequence;
	long ret;
	u32 active_layer_count = layer_count;
	u32 active_private_layer_count = private_layer_count;

	if (!source_id || !key_guid || !result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	pkm_lcs_source_response_frame_init(&frame);
	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}

	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &active_private_layers,
		&active_private_layer_count);
	if (ret)
		return ret;

	ret = pkm_lcs_source_query_values_round_trip_retaining_frame_timeout_with_limits(
		source_id, txn_id, key_guid, "", 0, false, limits,
		limits->request_timeout_ms, &frame, &response, &enqueue);
	if (ret)
		goto out_destroy;

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		goto out_destroy;

	ret = pkm_lcs_rsi_materialize_query_value_response(
		frame.data, frame.len, response.request_id, next_sequence,
		"", 0, active_layers, active_layer_count,
		active_private_layers, active_private_layer_count, limits,
		&value);
	if (ret)
		goto out_destroy;
	if (!value.found || value.value_type != REG_LINK) {
		ret = -EINVAL;
		goto out_destroy;
	}
	if ((size_t)value.data_offset > frame.len ||
	    (size_t)value.data_len > frame.len - (size_t)value.data_offset) {
		ret = -EIO;
		goto out_destroy;
	}

	target = (const char *)(frame.data + value.data_offset);
	ret = pkm_lcs_route_symlink_target_with_limits(
		target, value.data_len, scope_guids, scope_count,
		limits, &result->route);
	if (ret)
		goto out_destroy;

	ret = pkm_lcs_materialize_symlink_target_components_with_limits(
		target, value.data_len, limits, &result->components);
	if (ret)
		goto out_destroy;

	result->value_type = value.value_type;
	result->selected_precedence = value.selected_precedence;
	result->selected_sequence = value.selected_sequence;
	pkm_lcs_source_response_frame_destroy(&frame);
	return 0;

out_destroy:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_symlink_target_resolution_destroy(result);
	return ret;
}
