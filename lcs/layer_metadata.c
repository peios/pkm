// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS layer-metadata discovery and refresh helpers.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "key_fd.h"
#include "rsi.h"
#include "source_device.h"

#include <trace/events/lcs.h>

long pkm_lcs_layer_metadata_root_discover_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[RSI_GUID_SIZE],
	bool *present_out, u8 layers_root_guid_out[RSI_GUID_SIZE])
{
	static const struct pkm_lcs_path_component_view layers_path[] = {
		{ .name = "Machine", .name_len = sizeof("Machine") - 1 },
		{ .name = "System", .name_len = sizeof("System") - 1 },
		{ .name = "Registry", .name_len = sizeof("Registry") - 1 },
		{ .name = "Layers", .name_len = sizeof("Layers") - 1 },
	};
	struct pkm_lcs_resolved_key_path layers_root = { };
	struct pkm_lcs_layer_snapshot layers = { };
	long ret;

	if (present_out)
		*present_out = false;
	if (layers_root_guid_out)
		memset(layers_root_guid_out, 0, RSI_GUID_SIZE);
	if (!source_id || !machine_root_guid || !present_out ||
	    !layers_root_guid_out)
		return -EINVAL;

	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components(
		source_id, 0, machine_root_guid, layers_path,
		ARRAY_SIZE(layers_path), layers.layers, layers.layer_count,
		NULL, 0, &layers_root);
	if (ret == -ENOENT) {
		ret = 0;
		goto out_layers;
	}
	if (ret)
		goto out_layers;

	memcpy(layers_root_guid_out, layers_root.key_guid, RSI_GUID_SIZE);
	*present_out = true;
	pkm_lcs_resolved_key_path_destroy(&layers_root);

out_layers:
	pkm_lcs_source_layer_snapshot_release(&layers);
	return ret;
}

void pkm_lcs_layer_metadata_child_list_destroy(
	struct pkm_lcs_layer_metadata_child_list *list)
{
	u32 i;

	if (!list)
		return;
	for (i = 0; i < list->child_count; i++)
		kfree(list->children[i].name);
	kvfree(list->children);
	memset(list, 0, sizeof(*list));
}

long pkm_lcs_layer_metadata_children_enumerate_from_root(
	u32 source_id, const u8 layers_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_layer_metadata_child_list *children_out)
{
	struct pkm_lcs_layer_metadata_child_list result = { };
	struct pkm_lcs_rsi_enum_children_info_summary summary = { };
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_runtime_limits active_limits = { };
	struct pkm_lcs_layer_snapshot layers = { };
	u64 next_sequence = 0;
	u32 i;
	long ret;

	if (children_out)
		memset(children_out, 0, sizeof(*children_out));
	if (!source_id || !layers_root_guid || !children_out)
		return -EINVAL;

	ret = pkm_lcs_runtime_limits_snapshot(&active_limits);
	if (ret)
		return ret;
	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_enum_children_round_trip_retaining_frame_timeout_with_limits(
		source_id, 0, layers_root_guid, &active_limits,
		active_limits.request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_enum_children_info_summary(
		frame.data, frame.len, response.request_id, next_sequence,
		layers.layers, layers.layer_count, NULL, 0, &response.limits,
		&summary);
	if (ret)
		goto out_frame;
	if (summary.subkey_count > active_limits.max_total_layers) {
		ret = -ENOSPC;
		goto out_frame;
	}
	if (!summary.subkey_count) {
		*children_out = result;
		ret = 0;
		goto out_frame;
	}

	result.children = kvcalloc(summary.subkey_count,
				   sizeof(*result.children), GFP_KERNEL);
	if (!result.children) {
		ret = -ENOMEM;
		goto out_frame;
	}

	for (i = 0; i < summary.subkey_count; i++) {
		struct pkm_lcs_rsi_enum_subkey_result subkey = { };
		char *name;

		ret = pkm_lcs_rsi_materialize_enum_subkey_response(
			frame.data, frame.len, response.request_id,
			next_sequence, i, layers.layers, layers.layer_count,
			NULL, 0, &response.limits, &subkey);
		if (ret)
			goto out_result;
		if (!subkey.found ||
		    (size_t)subkey.name_offset > frame.len ||
		    (size_t)subkey.name_len >
			    frame.len - (size_t)subkey.name_offset) {
			ret = -EIO;
			goto out_result;
		}

		name = kmemdup_nul(frame.data + subkey.name_offset,
				   subkey.name_len, GFP_KERNEL);
		if (!name) {
			ret = -ENOMEM;
			goto out_result;
		}

		result.children[result.child_count].name = name;
		result.children[result.child_count].name_len = subkey.name_len;
		memcpy(result.children[result.child_count].guid,
		       subkey.child_guid, RSI_GUID_SIZE);
		result.child_count++;
	}

	*children_out = result;
	memset(&result, 0, sizeof(result));
	ret = 0;

out_result:
	pkm_lcs_layer_metadata_child_list_destroy(&result);
out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layers);
	return ret;
}

long pkm_lcs_layer_metadata_child_lookup_from_root_with_limits(
	u32 source_id, const u8 layers_root_guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len,
	const struct pkm_lcs_runtime_limits *limits,
	u8 child_guid_out[RSI_GUID_SIZE], bool *present_out)
{
	struct pkm_lcs_source_response_frame frame = { };
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_rsi_lookup_child_result child = { };
	struct pkm_lcs_layer_snapshot layers = { };
	u64 next_sequence = 0;
	long ret;

	if (child_guid_out)
		memset(child_guid_out, 0, RSI_GUID_SIZE);
	if (present_out)
		*present_out = false;
	if (!source_id || !layers_root_guid || !layer_name || !layer_name_len ||
	    !limits || !child_guid_out || !present_out)
		return -EINVAL;

	ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&layers);
	if (ret)
		return ret;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
		source_id, 0, layers_root_guid, layer_name, layer_name_len,
		limits, limits->request_timeout_ms, &frame, &response, NULL);
	if (ret)
		goto out_frame;

	ret = pkm_lcs_rsi_materialize_lookup_child(
		frame.data, frame.len, response.request_id, next_sequence,
		layer_name, layer_name_len, layers.layers, layers.layer_count,
		NULL, 0, &response.limits, &child);
	if (ret)
		goto out_frame;
	if (child.found) {
		memcpy(child_guid_out, child.key_guid, RSI_GUID_SIZE);
		*present_out = true;
	}

out_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	pkm_lcs_source_layer_snapshot_release(&layers);
	return ret;
}

long pkm_lcs_layer_metadata_child_lookup_from_root(
	u32 source_id, const u8 layers_root_guid[RSI_GUID_SIZE],
	const char *layer_name, u32 layer_name_len,
	u8 child_guid_out[RSI_GUID_SIZE], bool *present_out)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_layer_metadata_child_lookup_from_root_with_limits(
		source_id, layers_root_guid, layer_name, layer_name_len,
		&limits, child_guid_out, present_out);
}

static long pkm_lcs_layer_metadata_refresh_all_admit_children(
	const struct pkm_lcs_layer_metadata_child_list *children,
	const struct pkm_lcs_runtime_limits *limits)
{
	u32 non_base_count = 0;
	u32 i;

	if (!children || !limits)
		return -EINVAL;

	for (i = 0; i < children->child_count; i++) {
		bool is_base = false;
		long ret;

		ret = pkm_lcs_layer_name_casefold_is_base(
			children->children[i].name,
			children->children[i].name_len, &is_base);
		if (ret)
			return ret;
		if (is_base)
			continue;
		non_base_count++;
		if (non_base_count >= limits->max_total_layers)
			return -ENOSPC;
	}

	return 0;
}

/*
 * Which per-child refresh failures the bootstrap refresh isolates. Malformed
 * metadata -- an unparseable descriptor, a wrong-typed or mis-sized value, an
 * Enabled above one -- comes back from the refresh as -EIO, and a child that
 * vanished between enumeration and refresh as -ENOENT; either is that layer's
 * problem alone. Anything else is the source or the kernel failing, and fails
 * the whole refresh as before.
 */
static bool pkm_lcs_layer_metadata_refresh_child_isolated(long ret)
{
	return ret == -EIO || ret == -EINVAL || ret == -ENOENT ||
	       ret == -ENAMETOOLONG;
}

long pkm_lcs_layer_metadata_refresh_all_from_root(
	u32 source_id, const u8 layers_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_layer_metadata_refresh_all_result *result_out)
{
	static const char * const path_prefix[] = {
		"Machine", "System", "Registry", "Layers",
	};
	struct pkm_lcs_layer_metadata_refresh_all_result result = { };
	struct pkm_lcs_layer_metadata_child_list children = { };
	struct pkm_lcs_runtime_limits active_limits = { };
	u32 i;
	long ret;

	if (result_out)
		memset(result_out, 0, sizeof(*result_out));
	if (!source_id || !layers_root_guid || !result_out)
		return -EINVAL;

	ret = pkm_lcs_runtime_limits_snapshot(&active_limits);
	if (ret)
		return ret;

	ret = pkm_lcs_layer_metadata_children_enumerate_from_root(
		source_id, layers_root_guid, &children);
	if (ret)
		goto out_children;
	result.enumerated_child_count = children.child_count;

	ret = pkm_lcs_layer_metadata_refresh_all_admit_children(
		&children, &active_limits);
	if (ret)
		goto out_children;

	for (i = 0; i < children.child_count; i++) {
		const char *resolved_path[] = {
			path_prefix[0], path_prefix[1], path_prefix[2],
			path_prefix[3], children.children[i].name,
		};
		bool effective_changed = false;

		ret = pkm_lcs_key_path_refresh_layer_metadata_result(
			source_id, children.children[i].guid, resolved_path,
			ARRAY_SIZE(resolved_path), &effective_changed);
		if (ret && pkm_lcs_layer_metadata_refresh_child_isolated(ret)) {
			/*
			 * §5.3.3: a layer whose metadata will not parse is not
			 * published, and its siblings are unaffected. The live
			 * refresh has that isolation by construction -- one
			 * layer per watch event -- and bootstrap has to supply
			 * it here, or one badly authored layer suppresses every
			 * other on the machine at boot (PEI-762). The refresh
			 * has already audited a malformed descriptor; the count
			 * records the skip.
			 */
			trace_lcs_layer_metadata_refresh(
				source_id, 0, 0, result.refreshed_child_count, 0,
				0, ret);
			result.skipped_child_count++;
			ret = 0;
			continue;
		}
		if (ret)
			goto out_children;
		result.refreshed_child_count++;
		if (effective_changed)
			result.effective_changed_count++;
	}

	*result_out = result;
	ret = 0;

out_children:
	trace_lcs_layer_metadata_refresh(source_id, 0, 0,
					 result.refreshed_child_count, 0,
					 result.effective_changed_count ? 1 : 0,
					 ret);
	pkm_lcs_layer_metadata_child_list_destroy(&children);
	return ret;
}
