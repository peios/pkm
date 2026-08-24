// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS path component walkers.
 */

#include <linux/errno.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "rsi.h"
#include "source_device.h"
#include "transaction_fd.h"

#include <trace/events/lcs.h>

struct pkm_lcs_symlink_follow_components {
	struct pkm_lcs_path_component_view *components;
	u32 component_count;
};

struct pkm_lcs_owned_path_components {
	struct pkm_lcs_path_component_view *components;
	u32 component_count;
};

long pkm_lcs_validate_relative_open_depth_counts(
	u32 parent_depth, u32 relative_component_count, u32 max_key_depth)
{
	u32 depth;

	if (check_add_overflow(parent_depth, relative_component_count, &depth))
		return -EINVAL;
	if (depth > max_key_depth)
		return -EINVAL;
	return 0;
}

long pkm_lcs_transaction_read_txn_id_for_target(
	int txn_fd, u32 source_id, const u8 root_guid[RSI_GUID_SIZE],
	u64 fallback_txn_id, u64 *txn_id_out)
{
	struct pkm_lcs_transaction_read_plan plan = { };
	long ret;

	if (!txn_id_out)
		return -EINVAL;
	*txn_id_out = 0;
	if (txn_fd < 0) {
		*txn_id_out = fallback_txn_id;
		return 0;
	}

	ret = pkm_lcs_transaction_fd_prepare_read_context(
		txn_fd, source_id, root_guid, &plan);
	if (ret)
		return ret;

	*txn_id_out = plan.txn_id;
	return 0;
}

void pkm_lcs_resolved_key_path_destroy(struct pkm_lcs_resolved_key_path *path)
{
	u32 i;

	if (!path)
		return;

	if (path->resolved_path) {
		for (i = 0; i < path->component_count; i++)
			kfree(path->resolved_path[i]);
		kfree(path->resolved_path);
	}
	kfree(path->ancestor_guids);
	pkm_lcs_source_response_frame_destroy(&path->final_frame);
	memset(path, 0, sizeof(*path));
}

static long pkm_lcs_resolved_key_path_prepare(
	u32 source_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, struct pkm_lcs_resolved_key_path *result)
{
	u32 i;

	if (!source_id || !root_guid || !components || !result)
		return -EINVAL;
	if (!component_count)
		return -EINVAL;
	if (component_count > PKM_LCS_MAX_KEY_DEPTH_HARD)
		return -EINVAL;

	result->resolved_path = kcalloc(component_count,
					sizeof(*result->resolved_path),
					GFP_KERNEL);
	if (!result->resolved_path)
		return -ENOMEM;
	result->ancestor_guids = kcalloc(component_count,
					 sizeof(*result->ancestor_guids),
					 GFP_KERNEL);
	if (!result->ancestor_guids)
		return -ENOMEM;

	for (i = 0; i < component_count; i++) {
		if (!components[i].name || !components[i].name_len)
			return -EINVAL;
		if (components[i].name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
			return -ENAMETOOLONG;
		result->resolved_path[i] =
			kmemdup_nul(components[i].name,
				    components[i].name_len, GFP_KERNEL);
		if (!result->resolved_path[i])
			return -ENOMEM;
	}

	result->source_id = source_id;
	result->component_count = component_count;
	memcpy(result->ancestor_guids[0], root_guid, RSI_GUID_SIZE);
	pkm_lcs_source_response_frame_init(&result->final_frame);
	return 0;
}

static long pkm_lcs_walk_absolute_components_impl(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link, bool follow_symlinks,
	u32 symlink_depth, u32 symlink_depth_limit,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_resolved_key_path *result);

static long pkm_lcs_walk_absolute_components_at_symlink_limit(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_lookup_child_result child = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_source_response_frame frame;
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *active_private_layers =
		private_layers;
	u32 active_layer_count = layer_count;
	u32 active_private_layer_count = private_layer_count;
	u8 current_guid[RSI_GUID_SIZE];
	u64 next_sequence;
	u64 effective_txn_id;
	u32 i;
	long ret;

	if (!result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &active_private_layers,
		&active_private_layer_count);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_read_txn_id_for_target(
		txn_fd, source_id, root_guid, txn_id, &effective_txn_id);
	if (ret)
		return ret;

	ret = pkm_lcs_resolved_key_path_prepare(source_id, root_guid,
						components, component_count,
						result);
	if (ret)
		goto out_destroy;

	if (component_count == 1) {
		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
			source_id, effective_txn_id, root_guid, limits,
			limits->request_timeout_ms, &frame, &response, &enqueue);
		if (ret)
			goto out_root_frame;

		ret = pkm_lcs_rsi_materialize_read_key_response_with_limits(
			frame.data, frame.len, response.request_id, limits,
			&read_key);
		if (ret)
			goto out_root_frame;
		if (!read_key.sd_len ||
		    (size_t)read_key.sd_offset > frame.len ||
		    (size_t)read_key.sd_len >
			    frame.len - (size_t)read_key.sd_offset) {
			ret = -EIO;
			goto out_root_frame;
		}
		if (read_key.symlink && !open_final_link) {
			ret = -ELOOP;
			goto out_root_frame;
		}

		memcpy(result->key_guid, root_guid, sizeof(result->key_guid));
		result->final_sd_offset = read_key.sd_offset;
		result->final_sd_len = read_key.sd_len;
		result->final_volatile = read_key.volatile_key != 0;
		result->final_symlink = read_key.symlink != 0;
		result->final_last_write_time = read_key.last_write_time;
		result->final_frame = frame;
		pkm_lcs_source_response_frame_init(&frame);
		pkm_lcs_source_response_frame_destroy(&frame);
		return 0;
	}

	memcpy(current_guid, root_guid, sizeof(current_guid));
	for (i = 1; i < component_count; i++) {
		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
			source_id, effective_txn_id, current_guid,
			components[i].name, components[i].name_len,
			limits, limits->request_timeout_ms, &frame, &response,
			&enqueue);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_rsi_materialize_lookup_child(
			frame.data, frame.len, response.request_id,
			next_sequence, components[i].name,
			components[i].name_len, active_layers,
			active_layer_count, active_private_layers,
			active_private_layer_count, limits, &child);
		if (ret)
			goto out_destroy_frame;
		if (!child.found) {
			ret = -ENOENT;
			goto out_destroy_frame;
		}
		if (child.symlink && !(open_final_link &&
				       i == component_count - 1U)) {
			ret = -ELOOP;
			goto out_destroy_frame;
		}

		memcpy(result->ancestor_guids[i], child.key_guid,
		       RSI_GUID_SIZE);
		memcpy(current_guid, child.key_guid, sizeof(current_guid));
		if (i == component_count - 1U) {
			memcpy(result->key_guid, child.key_guid,
			       sizeof(result->key_guid));
			result->final_sd_offset = child.sd_offset;
			result->final_sd_len = child.sd_len;
			result->final_volatile = child.volatile_key != 0;
			result->final_symlink = child.symlink != 0;
			result->final_last_write_time = child.last_write_time;
			result->final_frame = frame;
			pkm_lcs_source_response_frame_init(&frame);
		}
out_destroy_frame:
		pkm_lcs_source_response_frame_destroy(&frame);
		if (ret)
			goto out_destroy;
	}

	return 0;

out_root_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
out_destroy:
	pkm_lcs_resolved_key_path_destroy(result);
	return ret;
}

static void pkm_lcs_symlink_follow_components_destroy(
	struct pkm_lcs_symlink_follow_components *components)
{
	if (!components)
		return;

	kfree(components->components);
	memset(components, 0, sizeof(*components));
}

static long pkm_lcs_symlink_follow_components_prepare(
	const struct pkm_lcs_materialized_path *target,
	const struct pkm_lcs_path_component_view *suffix, u32 suffix_count,
	struct pkm_lcs_symlink_follow_components *result)
{
	size_t total_count;

	if (!target || !target->components || !target->component_count ||
	    !result || (suffix_count && !suffix))
		return -EINVAL;
	if (check_add_overflow((size_t)target->component_count,
			       (size_t)suffix_count, &total_count))
		return -EINVAL;
	if (!total_count || total_count > PKM_LCS_MAX_KEY_DEPTH_HARD ||
	    total_count > U32_MAX)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->components = kcalloc(total_count, sizeof(*result->components),
				     GFP_KERNEL);
	if (!result->components)
		return -ENOMEM;

	memcpy(result->components, target->components,
	       target->component_count * sizeof(*result->components));
	if (suffix_count) {
		memcpy(&result->components[target->component_count], suffix,
		       suffix_count * sizeof(*result->components));
	}
	result->component_count = (u32)total_count;
	return 0;
}

static void
pkm_lcs_owned_path_components_destroy(struct pkm_lcs_owned_path_components *path)
{
	u32 i;

	if (!path)
		return;
	if (path->components) {
		for (i = 0; i < path->component_count; i++)
			kfree(path->components[i].name);
		kfree(path->components);
	}
	memset(path, 0, sizeof(*path));
}

static long pkm_lcs_owned_path_component_copy(
	struct pkm_lcs_path_component_view *dst,
	const struct pkm_lcs_path_component_view *src)
{
	char *name;

	if (!dst || !src || !src->name || !src->name_len)
		return -EINVAL;
	if (src->name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	name = kmemdup_nul(src->name, src->name_len, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	dst->name = name;
	dst->name_len = src->name_len;
	return 0;
}

static long pkm_lcs_prepare_owned_symlink_follow_components(
	const struct pkm_lcs_materialized_path *target,
	const struct pkm_lcs_path_component_view *suffix, u32 suffix_count,
	struct pkm_lcs_owned_path_components *result)
{
	size_t total_count;
	u32 i;
	long ret;

	if (!target || !target->components || !target->component_count ||
	    !result || (suffix_count && !suffix))
		return -EINVAL;
	if (check_add_overflow((size_t)target->component_count,
			       (size_t)suffix_count, &total_count))
		return -EINVAL;
	if (!total_count || total_count > PKM_LCS_MAX_KEY_DEPTH_HARD ||
	    total_count > U32_MAX)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->components = kcalloc(total_count, sizeof(*result->components),
				     GFP_KERNEL);
	if (!result->components)
		return -ENOMEM;
	result->component_count = (u32)total_count;

	for (i = 0; i < target->component_count; i++) {
		ret = pkm_lcs_owned_path_component_copy(
			&result->components[i], &target->components[i]);
		if (ret)
			goto out_destroy;
	}
	for (i = 0; i < suffix_count; i++) {
		ret = pkm_lcs_owned_path_component_copy(
			&result->components[target->component_count + i],
			&suffix[i]);
		if (ret)
			goto out_destroy;
	}

	return 0;

out_destroy:
	pkm_lcs_owned_path_components_destroy(result);
	return ret;
}

static long pkm_lcs_prepare_absolute_symlink_restart(
	u32 source_id, u64 txn_id, const u8 link_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *suffix, u32 suffix_count,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, const struct pkm_lcs_runtime_limits *limits,
	u32 *next_source_id,
	u8 next_root_guid[RSI_GUID_SIZE],
	struct pkm_lcs_owned_path_components *next_components)
{
	struct pkm_lcs_symlink_target_resolution target = { };
	long ret;

	if (!next_source_id || !next_root_guid || !next_components)
		return -EINVAL;

	ret = pkm_lcs_resolve_symlink_target_for_key(
		source_id, txn_id, link_guid, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count,
		limits, &target);
	if (ret)
		return ret;

	ret = pkm_lcs_prepare_owned_symlink_follow_components(
		&target.components, suffix, suffix_count, next_components);
	if (!ret) {
		*next_source_id = target.route.source_id;
		memcpy(next_root_guid, target.route.root_guid, RSI_GUID_SIZE);
	}

	pkm_lcs_symlink_target_resolution_destroy(&target);
	return ret;
}

static long pkm_lcs_walk_symlink_target(
	u32 source_id, u64 txn_id, const u8 link_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *suffix, u32 suffix_count,
	bool open_final_link, u32 symlink_depth, u32 symlink_depth_limit,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_symlink_target_resolution target = { };
	struct pkm_lcs_symlink_follow_components walk = { };
	long ret;

	if (symlink_depth >= symlink_depth_limit) {
		trace_lcs_walk_symlink(source_id, txn_id,
				       link_guid ? (u64)jhash(link_guid,
							      RSI_GUID_SIZE, 0) :
						   0,
				       suffix_count, 0, symlink_depth, -ELOOP);
		return -ELOOP;
	}

	ret = pkm_lcs_resolve_symlink_target_for_key(
		source_id, txn_id, link_guid, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count,
		limits, &target);
	if (ret)
		return ret;

	ret = pkm_lcs_symlink_follow_components_prepare(
		&target.components, suffix, suffix_count, &walk);
	if (ret)
		goto out_destroy_target;

	pkm_lcs_resolved_key_path_destroy(result);
	if (symlink_depth + 1U >= symlink_depth_limit) {
		ret = pkm_lcs_walk_absolute_components_at_symlink_limit(
			target.route.source_id, txn_id, target.route.root_guid,
			walk.components, walk.component_count, open_final_link,
			layers, layer_count, private_layers, private_layer_count,
			txn_fd, limits, result);
	} else {
		ret = pkm_lcs_walk_absolute_components_impl(
			target.route.source_id, txn_id, target.route.root_guid,
			walk.components, walk.component_count, open_final_link,
			true, symlink_depth + 1U, symlink_depth_limit,
			scope_guids, scope_count, layers, layer_count,
			private_layers, private_layer_count, txn_fd, limits,
			result);
	}

	pkm_lcs_symlink_follow_components_destroy(&walk);
out_destroy_target:
	pkm_lcs_symlink_target_resolution_destroy(&target);
	trace_lcs_walk_symlink(source_id, txn_id,
			       link_guid ? (u64)jhash(link_guid, RSI_GUID_SIZE,
						      0) :
					   0,
			       walk.component_count, 0, symlink_depth, ret);
	return ret;
}

static long pkm_lcs_walk_absolute_components_impl(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link, bool follow_symlinks,
	u32 symlink_depth, u32 symlink_depth_limit,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_lookup_child_result child = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_owned_path_components owned_components = { };
	struct pkm_lcs_source_response_frame frame;
	const struct pkm_lcs_path_component_view *walk_components = components;
	u8 walk_root_guid[RSI_GUID_SIZE];
	u8 current_guid[RSI_GUID_SIZE];
	u64 next_sequence;
	u64 walk_txn_id = txn_id;
	u32 walk_source_id = source_id;
	u32 walk_component_count = component_count;
	u32 walk_symlink_depth = symlink_depth;
	u32 i;
	long ret;
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *active_private_layers =
		private_layers;
	u32 active_layer_count = layer_count;
	u32 active_private_layer_count = private_layer_count;

	if (!result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &active_private_layers,
		&active_private_layer_count);
	if (ret)
		return ret;
	memcpy(walk_root_guid, root_guid, RSI_GUID_SIZE);

restart:
	ret = pkm_lcs_transaction_read_txn_id_for_target(
		txn_fd, walk_source_id, walk_root_guid, txn_id,
		&walk_txn_id);
	if (ret)
		goto out_destroy;

	ret = pkm_lcs_resolved_key_path_prepare(walk_source_id, walk_root_guid,
						walk_components,
						walk_component_count,
						result);
	if (ret)
		goto out_destroy;
	if (walk_component_count == 1) {
		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
			walk_source_id, walk_txn_id, walk_root_guid, limits,
			limits->request_timeout_ms, &frame, &response, &enqueue);
		if (ret)
			goto out_root_frame;

		ret = pkm_lcs_rsi_materialize_read_key_response_with_limits(
			frame.data, frame.len, response.request_id, limits,
			&read_key);
		if (ret)
			goto out_root_frame;
		if (!read_key.sd_len ||
		    (size_t)read_key.sd_offset > frame.len ||
		    (size_t)read_key.sd_len >
			    frame.len - (size_t)read_key.sd_offset) {
			ret = -EIO;
			goto out_root_frame;
		}
		if (read_key.symlink) {
			if (open_final_link) {
				/* Open the root link key itself. */
			} else if (follow_symlinks) {
				struct pkm_lcs_owned_path_components replacement =
					{ };
				u8 next_root_guid[RSI_GUID_SIZE];
				u32 next_source_id = 0;

				if (walk_symlink_depth >= symlink_depth_limit) {
					ret = -ELOOP;
					goto out_root_frame;
				}
				ret = pkm_lcs_prepare_absolute_symlink_restart(
					walk_source_id, walk_txn_id, walk_root_guid,
					NULL, 0, scope_guids, scope_count,
					active_layers, active_layer_count,
					active_private_layers,
					active_private_layer_count, limits,
					&next_source_id, next_root_guid,
					&replacement);
				pkm_lcs_source_response_frame_destroy(&frame);
				if (ret)
					goto out_destroy;
				pkm_lcs_resolved_key_path_destroy(result);
				pkm_lcs_owned_path_components_destroy(
					&owned_components);
				owned_components = replacement;
				walk_source_id = next_source_id;
				memcpy(walk_root_guid, next_root_guid,
				       RSI_GUID_SIZE);
				walk_components = owned_components.components;
				walk_component_count =
					owned_components.component_count;
				walk_symlink_depth++;
				goto restart;
			} else {
				ret = -EOPNOTSUPP;
				goto out_root_frame;
			}
		}

		memcpy(result->key_guid, walk_root_guid,
		       sizeof(result->key_guid));
		result->final_sd_offset = read_key.sd_offset;
		result->final_sd_len = read_key.sd_len;
		result->final_volatile = read_key.volatile_key != 0;
		result->final_symlink = read_key.symlink != 0;
		result->final_last_write_time = read_key.last_write_time;
		result->final_frame = frame;
		pkm_lcs_source_response_frame_init(&frame);
		pkm_lcs_source_response_frame_destroy(&frame);
		pkm_lcs_owned_path_components_destroy(&owned_components);
		return 0;
	}

	memcpy(current_guid, walk_root_guid, sizeof(current_guid));
	for (i = 1; i < walk_component_count; i++) {
		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
			walk_source_id, walk_txn_id, current_guid,
			walk_components[i].name, walk_components[i].name_len,
			limits, limits->request_timeout_ms, &frame, &response,
			&enqueue);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_rsi_materialize_lookup_child(
			frame.data, frame.len, response.request_id,
			next_sequence, walk_components[i].name,
			walk_components[i].name_len, active_layers,
			active_layer_count, active_private_layers,
			active_private_layer_count, limits, &child);
		if (ret)
			goto out_destroy_frame;
		if (!child.found) {
			ret = -ENOENT;
			goto out_destroy_frame;
		}
		if (child.symlink) {
			if (open_final_link && i == walk_component_count - 1U) {
				/* Open the link key itself. */
			} else if (follow_symlinks) {
				const struct pkm_lcs_path_component_view *suffix =
					NULL;
				u32 suffix_count = 0;
				struct pkm_lcs_owned_path_components replacement =
					{ };
				u8 next_root_guid[RSI_GUID_SIZE];
				u32 next_source_id = 0;

				if (walk_symlink_depth >= symlink_depth_limit) {
					ret = -ELOOP;
					goto out_destroy_frame;
				}
				if (i + 1U < walk_component_count) {
					suffix = &walk_components[i + 1U];
					suffix_count = walk_component_count - i - 1U;
				}
				ret = pkm_lcs_prepare_absolute_symlink_restart(
					walk_source_id, walk_txn_id, child.key_guid,
					suffix, suffix_count, scope_guids,
					scope_count, active_layers, active_layer_count,
					active_private_layers,
					active_private_layer_count, limits,
					&next_source_id, next_root_guid,
					&replacement);
				pkm_lcs_source_response_frame_destroy(&frame);
				if (ret)
					goto out_destroy;
				pkm_lcs_resolved_key_path_destroy(result);
				pkm_lcs_owned_path_components_destroy(
					&owned_components);
				owned_components = replacement;
				walk_source_id = next_source_id;
				memcpy(walk_root_guid, next_root_guid,
				       RSI_GUID_SIZE);
				walk_components = owned_components.components;
				walk_component_count =
					owned_components.component_count;
				walk_symlink_depth++;
				goto restart;
			} else {
				ret = -EOPNOTSUPP;
				goto out_destroy_frame;
			}
		}

		memcpy(result->ancestor_guids[i], child.key_guid,
		       RSI_GUID_SIZE);
		memcpy(current_guid, child.key_guid, sizeof(current_guid));
		if (i == walk_component_count - 1U) {
			memcpy(result->key_guid, child.key_guid,
			       sizeof(result->key_guid));
			result->final_sd_offset = child.sd_offset;
			result->final_sd_len = child.sd_len;
			result->final_volatile = child.volatile_key != 0;
			result->final_symlink = child.symlink != 0;
			result->final_last_write_time = child.last_write_time;
			result->final_frame = frame;
			pkm_lcs_source_response_frame_init(&frame);
		}
out_destroy_frame:
		pkm_lcs_source_response_frame_destroy(&frame);
		if (ret)
			goto out_destroy;
	}

	pkm_lcs_owned_path_components_destroy(&owned_components);
	return 0;

out_root_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
out_destroy:
	pkm_lcs_owned_path_components_destroy(&owned_components);
	pkm_lcs_resolved_key_path_destroy(result);
	return ret;
}

long pkm_lcs_walk_absolute_components_for_open_with_limits(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_runtime_limits effective_limits;
	u32 symlink_depth_limit;
	long ret;

	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	symlink_depth_limit = limits->symlink_depth_limit;

	ret = pkm_lcs_walk_absolute_components_impl(
		source_id, txn_id, root_guid, components, component_count,
		open_final_link, true, 0, symlink_depth_limit, scope_guids,
		scope_count, layers, layer_count, private_layers,
		private_layer_count, txn_fd, limits, result);
	trace_lcs_walk_absolute(source_id, txn_id,
				root_guid ? (u64)jhash(root_guid, RSI_GUID_SIZE,
						       0) :
					    0,
				component_count,
				ret ? 0 : result->component_count, 0, ret);
	return ret;
}

long pkm_lcs_walk_absolute_components_for_open(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	struct pkm_lcs_resolved_key_path *result)
{
	return pkm_lcs_walk_absolute_components_for_open_with_limits(
		source_id, txn_id, root_guid, components, component_count,
		open_final_link, scope_guids, scope_count, layers, layer_count,
		private_layers, private_layer_count, txn_fd, NULL, result);
}

long pkm_lcs_walk_absolute_components(
	u32 source_id, u64 txn_id, const u8 root_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_runtime_limits limits;
	long ret;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_walk_absolute_components_impl(
		source_id, txn_id, root_guid, components, component_count,
		false, false, 0, limits.symlink_depth_limit, NULL, 0, layers,
		layer_count, private_layers, private_layer_count, -1, &limits,
		result);
	trace_lcs_walk_absolute(source_id, txn_id,
				root_guid ? (u64)jhash(root_guid, RSI_GUID_SIZE,
						       0) :
					    0,
				component_count,
				ret ? 0 : result->component_count, 0, ret);
	return ret;
}

static long pkm_lcs_resolved_key_path_prepare_relative(
	const struct pkm_lcs_key_fd_parent_snapshot *parent,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, struct pkm_lcs_resolved_key_path *result)
{
	size_t total_count;
	size_t guid_bytes;
	u32 parent_count;
	u32 i;
	long ret;

	if (!parent || !components || !result || !parent->source_id ||
	    !parent->path_component_count || !parent->resolved_path ||
	    !parent->ancestor_guids || !component_count)
		return -EINVAL;
	if (parent->orphaned)
		return -ENOENT;
	if (check_add_overflow((size_t)parent->path_component_count,
			       (size_t)component_count, &total_count))
		return -EINVAL;
	if (!total_count || total_count > PKM_LCS_MAX_KEY_DEPTH_HARD ||
	    total_count > U32_MAX)
		return -EINVAL;

	parent_count = parent->path_component_count;
	result->source_id = parent->source_id;
	result->component_count = (u32)total_count;
	pkm_lcs_source_response_frame_init(&result->final_frame);

	result->resolved_path = kcalloc(total_count,
					sizeof(*result->resolved_path),
					GFP_KERNEL);
	if (!result->resolved_path)
		return -ENOMEM;
	result->ancestor_guids = kcalloc(total_count,
					 sizeof(*result->ancestor_guids),
					 GFP_KERNEL);
	if (!result->ancestor_guids)
		goto out_nomem;

	if (check_mul_overflow((size_t)parent_count,
			       sizeof(*result->ancestor_guids), &guid_bytes)) {
		ret = -EINVAL;
		goto out_error;
	}
	memcpy(result->ancestor_guids, parent->ancestor_guids, guid_bytes);

	for (i = 0; i < parent_count; i++) {
		if (!parent->resolved_path[i]) {
			ret = -EINVAL;
			goto out_error;
		}
		result->resolved_path[i] =
			kstrdup(parent->resolved_path[i], GFP_KERNEL);
		if (!result->resolved_path[i])
			goto out_nomem;
	}

	for (i = 0; i < component_count; i++) {
		u32 path_index = parent_count + i;

		if (!components[i].name || !components[i].name_len) {
			ret = -EINVAL;
			goto out_error;
		}
		if (components[i].name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD) {
			ret = -ENAMETOOLONG;
			goto out_error;
		}
		result->resolved_path[path_index] =
			kmemdup_nul(components[i].name,
				    components[i].name_len, GFP_KERNEL);
		if (!result->resolved_path[path_index])
			goto out_nomem;
	}

	return 0;

out_nomem:
	pkm_lcs_resolved_key_path_destroy(result);
	return -ENOMEM;
out_error:
	pkm_lcs_resolved_key_path_destroy(result);
	return ret;
}

static long pkm_lcs_walk_relative_components_impl(
	const struct pkm_lcs_key_fd_parent_snapshot *parent, u64 txn_id,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link, bool follow_symlinks,
	u32 symlink_depth, u32 symlink_depth_limit,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_lookup_child_result child = { };
	struct pkm_lcs_source_response_frame frame;
	u8 current_guid[RSI_GUID_SIZE];
	u64 next_sequence;
	u64 effective_txn_id = txn_id;
	u32 parent_count;
	u32 i;
	long ret;
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *active_private_layers =
		private_layers;
	u32 active_layer_count = layer_count;
	u32 active_private_layer_count = private_layer_count;

	if (!result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &active_private_layers,
		&active_private_layer_count);
	if (ret)
		return ret;

	ret = pkm_lcs_resolved_key_path_prepare_relative(
		parent, components, component_count, result);
	if (ret)
		goto out_destroy;

	ret = pkm_lcs_transaction_read_txn_id_for_target(
		txn_fd, parent->source_id, parent->ancestor_guids[0],
		txn_id, &effective_txn_id);
	if (ret)
		goto out_destroy;

	parent_count = parent->path_component_count;
	memcpy(current_guid, parent->key_guid, sizeof(current_guid));
	for (i = 0; i < component_count; i++) {
		u32 path_index = parent_count + i;

		pkm_lcs_source_response_frame_init(&frame);
		ret = pkm_lcs_source_lookup_round_trip_retaining_frame_timeout_with_limits(
			parent->source_id, effective_txn_id, current_guid,
			components[i].name, components[i].name_len,
			limits, limits->request_timeout_ms, &frame, &response,
			&enqueue);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_source_next_sequence_snapshot(&next_sequence);
		if (ret)
			goto out_destroy_frame;

		ret = pkm_lcs_rsi_materialize_lookup_child(
			frame.data, frame.len, response.request_id,
			next_sequence, components[i].name,
			components[i].name_len, active_layers,
			active_layer_count, active_private_layers,
			active_private_layer_count, limits, &child);
		if (ret)
			goto out_destroy_frame;
		if (!child.found) {
			ret = -ENOENT;
			goto out_destroy_frame;
		}
		if (child.symlink) {
			if (open_final_link && i == component_count - 1U) {
				/* Open the link key itself. */
			} else if (follow_symlinks) {
				const struct pkm_lcs_path_component_view *suffix =
					NULL;
				u32 suffix_count = 0;

				if (i + 1U < component_count) {
					suffix = &components[i + 1U];
					suffix_count = component_count - i - 1U;
				}
				ret = pkm_lcs_walk_symlink_target(
					parent->source_id, effective_txn_id,
					child.key_guid, suffix, suffix_count,
					open_final_link, symlink_depth,
					symlink_depth_limit, scope_guids,
					scope_count, active_layers, active_layer_count,
					active_private_layers,
					active_private_layer_count, txn_fd,
					limits, result);
				pkm_lcs_source_response_frame_destroy(&frame);
				if (ret)
					goto out_destroy;
				return 0;
			} else {
				ret = -EOPNOTSUPP;
				goto out_destroy_frame;
			}
		}

		memcpy(result->ancestor_guids[path_index], child.key_guid,
		       RSI_GUID_SIZE);
		memcpy(current_guid, child.key_guid, sizeof(current_guid));
		if (i == component_count - 1U) {
			memcpy(result->key_guid, child.key_guid,
			       sizeof(result->key_guid));
			result->final_sd_offset = child.sd_offset;
			result->final_sd_len = child.sd_len;
			result->final_volatile = child.volatile_key != 0;
			result->final_symlink = child.symlink != 0;
			result->final_last_write_time = child.last_write_time;
			result->final_frame = frame;
			pkm_lcs_source_response_frame_init(&frame);
		}
out_destroy_frame:
		pkm_lcs_source_response_frame_destroy(&frame);
		if (ret)
			goto out_destroy;
	}

	return 0;

out_destroy:
	pkm_lcs_resolved_key_path_destroy(result);
	return ret;
}

long pkm_lcs_walk_relative_components_for_open_with_limits(
	const struct pkm_lcs_key_fd_parent_snapshot *parent, u64 txn_id,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_runtime_limits effective_limits;
	u32 symlink_depth_limit;
	long ret;

	if (!limits) {
		pkm_lcs_runtime_limits_snapshot_or_default(&effective_limits);
		limits = &effective_limits;
	}
	symlink_depth_limit = limits->symlink_depth_limit;

	ret = pkm_lcs_walk_relative_components_impl(
		parent, txn_id, components, component_count, open_final_link,
		true, 0, symlink_depth_limit, scope_guids, scope_count, layers,
		layer_count, private_layers, private_layer_count, txn_fd,
		limits, result);
	trace_lcs_walk_relative(
		parent ? parent->source_id : 0, txn_id,
		(parent && parent->ancestor_guids) ?
			(u64)jhash(parent->ancestor_guids[0], RSI_GUID_SIZE, 0) :
			0,
		component_count, ret ? 0 : result->component_count, 0, ret);
	return ret;
}

long pkm_lcs_walk_relative_components_for_open(
	const struct pkm_lcs_key_fd_parent_snapshot *parent, u64 txn_id,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, bool open_final_link,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	struct pkm_lcs_resolved_key_path *result)
{
	return pkm_lcs_walk_relative_components_for_open_with_limits(
		parent, txn_id, components, component_count, open_final_link,
		scope_guids, scope_count, layers, layer_count, private_layers,
		private_layer_count, txn_fd, NULL, result);
}

long pkm_lcs_walk_relative_components(
	const struct pkm_lcs_key_fd_parent_snapshot *parent, u64 txn_id,
	const struct pkm_lcs_path_component_view *components,
	u32 component_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, struct pkm_lcs_resolved_key_path *result)
{
	struct pkm_lcs_runtime_limits limits;
	long ret;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_walk_relative_components_impl(
		parent, txn_id, components, component_count, false, false, 0,
		limits.symlink_depth_limit, NULL, 0, layers, layer_count,
		private_layers, private_layer_count, -1, &limits, result);
	trace_lcs_walk_relative(
		parent ? parent->source_id : 0, txn_id,
		(parent && parent->ancestor_guids) ?
			(u64)jhash(parent->ancestor_guids[0], RSI_GUID_SIZE, 0) :
			0,
		component_count, ret ? 0 : result->component_count, 0, ret);
	return ret;
}
