// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS registry create-key helpers.
 */

#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/kernel.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include "../kacs/token_runtime.h"
#include "source_internal.h"
#include "transaction_fd.h"

long pkm_lcs_create_existing_user_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags,
	u32 *disposition)
{
	struct pkm_lcs_create_preflight_plan preflight = { };
	long ret;

	if (disposition)
		*disposition = 0;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	if (parent_fd == -1)
		ret = pkm_lcs_open_user_absolute_path_for_token(
			token, ops, upath, desired_access, 0, NULL, 0, NULL, 0,
			NULL, 0);
	else
		ret = pkm_lcs_open_user_relative_path_for_token(
			token, ops, parent_fd, upath, desired_access, 0, NULL, 0,
			NULL, 0);

	if (ret >= 0 && disposition)
		*disposition = REG_OPENED_EXISTING;
	return ret;
}

static long pkm_lcs_create_existing_copied_path_for_token_with_txn(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd, u32 *disposition)
{
	struct pkm_lcs_create_preflight_plan preflight = { };
	long ret;

	if (disposition)
		*disposition = 0;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	if (parent_fd == -1)
		ret = pkm_lcs_open_copied_absolute_path_after_preflight_for_token(
			token, copy, desired_access, 0, NULL, 0, layers,
			layer_count, private_layers, private_layer_count, txn_fd);
	else
		ret = pkm_lcs_open_copied_relative_path_after_preflight(
			token, parent_fd, copy, desired_access, 0, layers,
			layer_count, private_layers, private_layer_count, txn_fd);

	if (ret >= 0 && disposition)
		*disposition = REG_OPENED_EXISTING;
	return ret;
}

long pkm_lcs_create_existing_copied_path_for_token(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, u32 *disposition)
{
	return pkm_lcs_create_existing_copied_path_for_token_with_txn(
		token, parent_fd, copy, desired_access, flags, NULL, 0, NULL, 0, -1,
		disposition);
}

long pkm_lcs_reg_create_key_copy_disposition_to_user(
	const struct pkm_lcs_usercopy_ops *ops, u32 __user *udisposition,
	u32 disposition)
{
	if (!udisposition)
		return 0;
	if (!ops)
		ops = pkm_lcs_default_usercopy_ops();
	if (!ops->write)
		return -EINVAL;

	if (!ops->write(ops->ctx, udisposition, &disposition,
			sizeof(disposition)))
		return -EFAULT;
	return 0;
}

long pkm_lcs_reg_create_key_finish_success_to_user(
	const struct pkm_lcs_usercopy_ops *ops, u32 __user *udisposition,
	long fd, u32 disposition)
{
	long ret;

	if (fd < 0 || fd > INT_MAX)
		return -EINVAL;

	ret = pkm_lcs_reg_create_key_copy_disposition_to_user(
		ops, udisposition, disposition);
	if (ret) {
		close_fd((unsigned int)fd);
		return ret;
	}

	return fd;
}

long pkm_lcs_create_existing_user_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags,
	u32 __user *udisposition)
{
	long fd;

	fd = pkm_lcs_create_existing_user_path_for_token(
		token, ops, parent_fd, upath, desired_access, flags, NULL);
	if (fd < 0)
		return fd;

	return pkm_lcs_reg_create_key_finish_success_to_user(
		ops, udisposition, fd, REG_OPENED_EXISTING);
}

long pkm_lcs_create_existing_copied_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags, u32 __user *udisposition)
{
	long fd;

	fd = pkm_lcs_create_existing_copied_path_for_token(
		token, parent_fd, copy, desired_access, flags, NULL);
	if (fd < 0)
		return fd;

	return pkm_lcs_reg_create_key_finish_success_to_user(
		ops, udisposition, fd, REG_OPENED_EXISTING);
}

static long pkm_lcs_create_existing_copied_path_finish_for_token_with_txn(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd, u32 __user *udisposition)
{
	long fd;

	fd = pkm_lcs_create_existing_copied_path_for_token_with_txn(
		token, parent_fd, copy, desired_access, flags, layers,
		layer_count, private_layers, private_layer_count, txn_fd, NULL);
	if (fd < 0)
		return fd;

	return pkm_lcs_reg_create_key_finish_success_to_user(
		ops, udisposition, fd, REG_OPENED_EXISTING);
}

void pkm_lcs_create_missing_parent_resolution_destroy(
	struct pkm_lcs_create_missing_parent_resolution *resolution)
{
	if (!resolution)
		return;

	pkm_lcs_resolved_key_path_destroy(&resolution->parent);
	kfree(resolution->child_name);
	memset(resolution, 0, sizeof(*resolution));
}

static long pkm_lcs_create_missing_parent_copy_child(
	const struct pkm_lcs_path_component_view *component,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	char *name;

	if (!component || !component->name || !component->name_len || !result)
		return -EINVAL;
	if (component->name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	name = kmemdup_nul(component->name, component->name_len, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	kfree(result->child_name);
	result->child_name = name;
	result->child_name_len = component->name_len;
	return 0;
}

static __maybe_unused long pkm_lcs_create_missing_validate_child_depth(
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	const struct pkm_lcs_runtime_limits *limits;
	long ret;

	if (!result || !result->parent.component_count)
		return -EINVAL;
	limits = result->limits_present ? &result->limits : NULL;

	ret = pkm_lcs_validate_relative_open_depth_counts(
		result->parent.component_count, 1,
		limits ? limits->max_key_depth : pkm_lcs_runtime_max_key_depth());
	if (ret)
		return ret;

	result->child_depth = result->parent.component_count + 1U;
	return 0;
}

static const struct pkm_lcs_runtime_limits *
pkm_lcs_create_missing_resolution_limits_or_snapshot(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	struct pkm_lcs_runtime_limits *fallback)
{
	if (resolution && resolution->limits_present)
		return &resolution->limits;
	if (!fallback)
		return NULL;
	pkm_lcs_runtime_limits_snapshot_or_default(fallback);
	return fallback;
}

static long pkm_lcs_resolved_parent_from_snapshot_prepare(
	const struct pkm_lcs_key_fd_parent_snapshot *parent,
	struct pkm_lcs_resolved_key_path *result)
{
	size_t guid_bytes;
	u32 i;

	if (!parent || !result || !parent->source_id ||
	    !parent->path_component_count || !parent->resolved_path ||
	    !parent->ancestor_guids)
		return -EINVAL;
	if (parent->orphaned)
		return -ENOENT;
	if (parent->path_component_count > PKM_LCS_MAX_KEY_DEPTH_HARD)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->source_id = parent->source_id;
	result->component_count = parent->path_component_count;
	memcpy(result->key_guid, parent->key_guid, sizeof(result->key_guid));
	pkm_lcs_source_response_frame_init(&result->final_frame);

	result->resolved_path = kcalloc(parent->path_component_count,
					sizeof(*result->resolved_path),
					GFP_KERNEL);
	if (!result->resolved_path)
		return -ENOMEM;

	if (check_mul_overflow((size_t)parent->path_component_count,
			       sizeof(*result->ancestor_guids), &guid_bytes)) {
		pkm_lcs_resolved_key_path_destroy(result);
		return -EINVAL;
	}
	result->ancestor_guids = kmemdup(parent->ancestor_guids, guid_bytes,
					GFP_KERNEL);
	if (!result->ancestor_guids) {
		pkm_lcs_resolved_key_path_destroy(result);
		return -ENOMEM;
	}

	for (i = 0; i < parent->path_component_count; i++) {
		if (!parent->resolved_path[i]) {
			pkm_lcs_resolved_key_path_destroy(result);
			return -EINVAL;
		}
		result->resolved_path[i] = kstrdup(parent->resolved_path[i],
						   GFP_KERNEL);
		if (!result->resolved_path[i]) {
			pkm_lcs_resolved_key_path_destroy(result);
			return -ENOMEM;
		}
	}

	return 0;
}

static long pkm_lcs_create_missing_read_parent_key(
	u32 source_id, u64 txn_id, const u8 key_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_resolved_key_path *parent)
{
	struct pkm_lcs_source_response_result response = { };
	struct pkm_lcs_source_enqueue_result enqueue = { };
	struct pkm_lcs_rsi_read_key_result read_key = { };
	struct pkm_lcs_source_response_frame frame;
	long ret;

	if (!source_id || !key_guid || !limits || !parent)
		return -EINVAL;

	pkm_lcs_source_response_frame_init(&frame);
	ret = pkm_lcs_source_read_key_round_trip_retaining_frame_timeout_with_limits(
		source_id, txn_id, key_guid, limits,
		limits->request_timeout_ms, &frame, &response, &enqueue);
	if (ret)
		goto out_destroy_frame;

	ret = pkm_lcs_rsi_materialize_read_key_response_with_limits(
		frame.data, frame.len, response.request_id, limits, &read_key);
	if (ret)
		goto out_destroy_frame;
	if (!read_key.sd_len ||
	    (size_t)read_key.sd_offset > frame.len ||
	    (size_t)read_key.sd_len >
		    frame.len - (size_t)read_key.sd_offset) {
		ret = -EIO;
		goto out_destroy_frame;
	}

	parent->final_sd_offset = read_key.sd_offset;
	parent->final_sd_len = read_key.sd_len;
	parent->final_volatile = read_key.volatile_key != 0;
	parent->final_symlink = read_key.symlink != 0;
	parent->final_last_write_time = read_key.last_write_time;
	parent->final_frame = frame;
	pkm_lcs_source_response_frame_init(&frame);

out_destroy_frame:
	pkm_lcs_source_response_frame_destroy(&frame);
	return ret;
}

long pkm_lcs_create_missing_absolute_parent_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_hive_route_result route = { };
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_syscall_path_copy copy = { };
	u32 parent_component_count;
	long ret;

	if (!token || !result)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	result->limits = limits;
	result->limits_present = true;
	ret = pkm_lcs_route_absolute_path_for_token_with_limits(
		token, copy.path, copy.path_len, true, scope_guids,
		scope_count, &limits, &route);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_materialize_absolute_path_components_for_token_with_limits(
		token, copy.path, copy.path_len, true, &limits, &components);
	if (ret)
		goto out_copy;
	if (components.component_count < 2U) {
		ret = -EINVAL;
		goto out_components;
	}

	ret = pkm_lcs_create_missing_parent_copy_child(
		&components.components[components.component_count - 1U],
		result);
	if (ret)
		goto out_components;

	parent_component_count = components.component_count - 1U;
	ret = pkm_lcs_walk_absolute_components_for_open_with_limits(
		route.source_id, 0, route.root_guid, components.components,
		parent_component_count, false, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count,
		-1, &limits, &result->parent);
	if (ret)
		goto out_result;

	ret = pkm_lcs_validate_relative_open_depth_counts(
		result->parent.component_count, 1, limits.max_key_depth);
	if (ret)
		goto out_result;
	result->child_depth = result->parent.component_count + 1U;

	pkm_lcs_materialized_path_destroy(&components);
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return 0;

out_result:
	pkm_lcs_create_missing_parent_resolution_destroy(result);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_create_missing_relative_parent(
	const struct pkm_lcs_usercopy_ops *ops, int parent_fd,
	const char __user *upath, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	struct pkm_lcs_key_fd_parent_snapshot parent = { };
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_path_validation_result path = { };
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_syscall_path_copy copy = { };
	long ret;

	if (!result)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	result->limits = limits;
	result->limits_present = true;
	ret = pkm_lcs_validate_syscall_relative_path_with_limits(
		copy.path, copy.path_len, &limits, &path);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_key_fd_parent_snapshot(parent_fd, &parent);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_validate_relative_open_depth_counts(
		parent.path_component_count, path.component_count,
		limits.max_key_depth);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_materialize_relative_path_components_with_limits(
		copy.path, copy.path_len, &limits, &components);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_create_missing_parent_copy_child(
		&components.components[components.component_count - 1U],
		result);
	if (ret)
		goto out_components;

	if (components.component_count == 1U) {
		ret = pkm_lcs_resolved_parent_from_snapshot_prepare(
			&parent, &result->parent);
		if (ret)
			goto out_result;
		ret = pkm_lcs_create_missing_read_parent_key(
			parent.source_id, 0, parent.key_guid, &limits,
			&result->parent);
	} else {
		ret = pkm_lcs_walk_relative_components_for_open_with_limits(
			&parent, 0, components.components,
			components.component_count - 1U, false, scope_guids,
			scope_count, layers, layer_count, private_layers,
			private_layer_count, -1, &limits, &result->parent);
	}
	if (ret)
		goto out_result;

	ret = pkm_lcs_validate_relative_open_depth_counts(
		result->parent.component_count, 1, limits.max_key_depth);
	if (ret)
		goto out_result;
	result->child_depth = result->parent.component_count + 1U;

	pkm_lcs_materialized_path_destroy(&components);
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return 0;

out_result:
	pkm_lcs_create_missing_parent_resolution_destroy(result);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_parent:
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
out_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

static long pkm_lcs_create_missing_copied_absolute_parent_for_token_with_txn(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_hive_route_result route = { };
	struct pkm_lcs_runtime_limits limits;
	u32 parent_component_count;
	long ret;

	if (!token || !result)
		return -EINVAL;
	if (!copy || !copy->path || !copy->path_len)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	result->limits = limits;
	result->limits_present = true;
	ret = pkm_lcs_route_absolute_path_for_token_with_limits(
		token, copy->path, copy->path_len, true, scope_guids,
		scope_count, &limits, &route);
	if (ret)
		return ret;

	ret = pkm_lcs_materialize_absolute_path_components_for_token_with_limits(
		token, copy->path, copy->path_len, true, &limits, &components);
	if (ret)
		return ret;
	if (components.component_count < 2U) {
		ret = -EINVAL;
		goto out_components;
	}

	ret = pkm_lcs_create_missing_parent_copy_child(
		&components.components[components.component_count - 1U],
		result);
	if (ret)
		goto out_components;

	parent_component_count = components.component_count - 1U;
	ret = pkm_lcs_walk_absolute_components_for_open_with_limits(
		route.source_id, 0, route.root_guid, components.components,
		parent_component_count, false, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count,
		txn_fd, &limits, &result->parent);
	if (ret)
		goto out_result;

	ret = pkm_lcs_validate_relative_open_depth_counts(
		result->parent.component_count, 1, limits.max_key_depth);
	if (ret)
		goto out_result;
	result->child_depth = result->parent.component_count + 1U;

	pkm_lcs_materialized_path_destroy(&components);
	return 0;

out_result:
	pkm_lcs_create_missing_parent_resolution_destroy(result);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
	return ret;
}

long pkm_lcs_create_missing_copied_absolute_parent_for_token(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	return pkm_lcs_create_missing_copied_absolute_parent_for_token_with_txn(
		token, copy, scope_guids, scope_count, layers, layer_count,
		private_layers, private_layer_count, -1, result);
}

static long pkm_lcs_create_missing_copied_relative_parent_with_txn(
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	struct pkm_lcs_key_fd_parent_snapshot parent = { };
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_path_validation_result path = { };
	struct pkm_lcs_runtime_limits limits;
	long ret;

	if (!result)
		return -EINVAL;
	if (!copy || !copy->path || !copy->path_len)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	result->limits = limits;
	result->limits_present = true;
	ret = pkm_lcs_validate_syscall_relative_path_with_limits(
		copy->path, copy->path_len, &limits, &path);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_parent_snapshot(parent_fd, &parent);
	if (ret)
		return ret;

	ret = pkm_lcs_validate_relative_open_depth_counts(
		parent.path_component_count, path.component_count,
		limits.max_key_depth);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_materialize_relative_path_components_with_limits(
		copy->path, copy->path_len, &limits, &components);
	if (ret)
		goto out_parent;

	ret = pkm_lcs_create_missing_parent_copy_child(
		&components.components[components.component_count - 1U],
		result);
	if (ret)
		goto out_components;

	if (components.component_count == 1U) {
		u64 effective_txn_id = 0;

		ret = pkm_lcs_resolved_parent_from_snapshot_prepare(
			&parent, &result->parent);
		if (ret)
			goto out_result;
		ret = pkm_lcs_transaction_read_txn_id_for_target(
			txn_fd, parent.source_id, parent.ancestor_guids[0],
			0, &effective_txn_id);
		if (ret)
			goto out_result;
		ret = pkm_lcs_create_missing_read_parent_key(
			parent.source_id, effective_txn_id, parent.key_guid,
			&limits, &result->parent);
	} else {
		ret = pkm_lcs_walk_relative_components_for_open_with_limits(
			&parent, 0, components.components,
			components.component_count - 1U, false, scope_guids,
			scope_count, layers, layer_count, private_layers,
			private_layer_count, txn_fd, &limits, &result->parent);
	}
	if (ret)
		goto out_result;

	ret = pkm_lcs_validate_relative_open_depth_counts(
		result->parent.component_count, 1, limits.max_key_depth);
	if (ret)
		goto out_result;
	result->child_depth = result->parent.component_count + 1U;

	pkm_lcs_materialized_path_destroy(&components);
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
	return 0;

out_result:
	pkm_lcs_create_missing_parent_resolution_destroy(result);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_parent:
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
	return ret;
}

long pkm_lcs_create_missing_copied_relative_parent(
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	return pkm_lcs_create_missing_copied_relative_parent_with_txn(
		parent_fd, copy, scope_guids, scope_count, layers, layer_count,
		private_layers, private_layer_count, -1, result);
}

static long pkm_lcs_create_missing_copied_parent_for_token_with_txn(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	if (parent_fd == -1)
		return pkm_lcs_create_missing_copied_absolute_parent_for_token_with_txn(
			token, copy, scope_guids, scope_count, layers,
			layer_count, private_layers, private_layer_count,
			txn_fd, result);

	return pkm_lcs_create_missing_copied_relative_parent_with_txn(
		parent_fd, copy, scope_guids, scope_count, layers,
		layer_count, private_layers, private_layer_count, txn_fd,
		result);
}

long pkm_lcs_create_missing_copied_parent_for_token(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	return pkm_lcs_create_missing_copied_parent_for_token_with_txn(
		token, parent_fd, copy, scope_guids, scope_count, layers,
		layer_count, private_layers, private_layer_count, -1, result);
}

long pkm_lcs_create_missing_parent_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count,
	struct pkm_lcs_create_missing_parent_resolution *result)
{
	if (parent_fd == -1)
		return pkm_lcs_create_missing_absolute_parent_for_token(
			token, ops, upath, scope_guids, scope_count, layers,
			layer_count, private_layers, private_layer_count,
			result);

	return pkm_lcs_create_missing_relative_parent(
		ops, parent_fd, upath, scope_guids, scope_count, layers,
		layer_count, private_layers, private_layer_count, result);
}

static long pkm_lcs_create_missing_parent_sd_view(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 **sd, size_t *sd_len)
{
	const struct pkm_lcs_resolved_key_path *parent;
	size_t sd_offset;
	size_t local_sd_len;

	if (!resolution || !sd || !sd_len)
		return -EINVAL;

	*sd = NULL;
	*sd_len = 0;
	parent = &resolution->parent;
	sd_offset = parent->final_sd_offset;
	local_sd_len = parent->final_sd_len;
	if (!parent->final_frame.data || !parent->final_frame.len ||
	    !local_sd_len || sd_offset > parent->final_frame.len ||
	    local_sd_len > parent->final_frame.len - sd_offset)
		return -EIO;

	*sd = parent->final_frame.data + sd_offset;
	*sd_len = local_sd_len;
	return 0;
}

long pkm_lcs_create_missing_parent_access_check_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	struct pkm_lcs_key_open_access_plan *plan)
{
	const u8 *sd;
	size_t sd_len;
	long ret;

	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	ret = pkm_lcs_create_missing_parent_sd_view(resolution, &sd, &sd_len);
	if (ret)
		return ret;

	return pkm_lcs_key_open_access_check_for_token(
		token, sd, sd_len, KEY_CREATE_SUB_KEY, plan);
}

long pkm_lcs_create_missing_volatile_parent_check(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_preflight_plan *preflight)
{
	if (!resolution || !preflight)
		return -EINVAL;

	if (resolution->parent.final_volatile &&
	    !preflight->options.volatile_key)
		return -EINVAL;

	return 0;
}

void pkm_lcs_created_key_sd_destroy(struct pkm_lcs_created_key_sd *created)
{
	if (!created)
		return;

	pkm_kacs_free((void *)created->sd);
	memset(created, 0, sizeof(*created));
}

long pkm_lcs_create_missing_initial_sd_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	struct pkm_lcs_created_key_sd *created)
{
	const u8 *parent_sd;
	const u8 *child_sd = NULL;
	size_t parent_sd_len;
	size_t child_sd_len = 0;
	long ret;

	if (!created)
		return -EINVAL;

	memset(created, 0, sizeof(*created));
	if (!token)
		return -EACCES;

	ret = pkm_lcs_create_missing_parent_sd_view(resolution, &parent_sd,
						    &parent_sd_len);
	if (ret)
		return ret;

	ret = kacs_rust_build_created_container_sd(
		token, parent_sd, parent_sd_len, KEY_READ, KEY_WRITE, 0,
		KEY_ALL_ACCESS, REG_VALID_MAPPED_ACCESS_MASK, &child_sd,
		&child_sd_len);
	if (ret == -EINVAL || ret == -ERANGE)
		return -EIO;
	if (ret)
		return ret;
	if (!child_sd || !child_sd_len) {
		pkm_kacs_free((void *)child_sd);
		return -EIO;
	}

	created->sd = child_sd;
	created->sd_len = child_sd_len;
	return 0;
}

long pkm_lcs_create_missing_symlink_authority_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	u32 flags, struct pkm_lcs_key_open_access_plan *link_plan)
{
	const u32 known_flags = REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK;
	const u8 *sd;
	size_t sd_len;
	long ret;

	if (!link_plan)
		return -EINVAL;

	memset(link_plan, 0, sizeof(*link_plan));
	if (flags & ~known_flags)
		return -EINVAL;
	if (!(flags & REG_OPTION_CREATE_LINK))
		return 0;

	ret = pkm_lcs_create_missing_parent_sd_view(resolution, &sd, &sd_len);
	if (ret)
		return ret;

	ret = pkm_lcs_key_open_access_check_for_token(
		token, sd, sd_len, KEY_CREATE_LINK, link_plan);
	if (ret)
		return ret;

	if (!pkm_lcs_token_has_tcb_or_admin_authority(token))
		return -EPERM;

	return 0;
}

static long pkm_lcs_create_missing_source_response_plan(
	long round_trip_ret,
	const struct pkm_lcs_source_response_result *response,
	struct pkm_lcs_reg_create_source_response_plan *plan)
{
	if (!response || !plan)
		return -EINVAL;
	if (!response->len)
		return round_trip_ret ? round_trip_ret : -EIO;

	return pkm_lcs_reg_create_key_source_response_plan(
		response->request_op_code, response->status, plan);
}

static long pkm_lcs_create_missing_source_records_with_sequence(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_layer_target *target,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd,
	bool volatile_key, bool symlink, u64 txn_id, u64 sequence,
	struct pkm_lcs_create_missing_source_records_result *result)
{
	struct pkm_lcs_source_response_result entry_response = { };
	struct pkm_lcs_source_response_result key_response = { };
	struct pkm_lcs_reg_create_source_response_plan plan = { };
	struct pkm_lcs_runtime_limits fallback_limits;
	const struct pkm_lcs_runtime_limits *limits;
	long ret;

	if (!result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	if (!resolution || !target || !target->name || !child_guid ||
	    !created_sd || !created_sd->sd || !created_sd->sd_len ||
	    !resolution->parent.source_id || !resolution->child_name ||
	    !resolution->child_name_len || !sequence)
		return -EINVAL;
	if (resolution->limits_present) {
		limits = &resolution->limits;
	} else {
		pkm_lcs_runtime_limits_snapshot_or_default(&fallback_limits);
		limits = &fallback_limits;
	}

	ret = pkm_lcs_source_create_entry_round_trip_timeout_with_limits(
		resolution->parent.source_id, txn_id,
		resolution->parent.key_guid, resolution->child_name,
		resolution->child_name_len,
		target->name, target->name_len, child_guid, sequence,
		limits, limits->request_timeout_ms, &entry_response, NULL);
	ret = pkm_lcs_create_missing_source_response_plan(ret, &entry_response,
							  &plan);
	if (ret)
		return ret;

	result->sequence = sequence;
	if (plan.action ==
	    PKM_LCS_REG_CREATE_SOURCE_ACTION_RETRY_OPEN_EXISTING) {
		result->disposition = plan.disposition;
		result->retry_open_existing = true;
		return 0;
	}
	if (plan.action != PKM_LCS_REG_CREATE_SOURCE_ACTION_CREATE_KEY)
		return -EIO;

	ret = pkm_lcs_source_create_key_round_trip_timeout_with_limits(
		resolution->parent.source_id, txn_id, child_guid,
		resolution->child_name, resolution->child_name_len,
		resolution->parent.key_guid, created_sd->sd, created_sd->sd_len,
		volatile_key, symlink, limits, limits->request_timeout_ms,
		&key_response, NULL);
	ret = pkm_lcs_create_missing_source_response_plan(ret, &key_response,
							  &plan);
	if (ret)
		return ret;
	if (plan.action !=
	    PKM_LCS_REG_CREATE_SOURCE_ACTION_PUBLISH_CREATED_NEW)
		return -EIO;

	result->disposition = plan.disposition;
	result->created_new = true;
	return 0;
}

long pkm_lcs_create_missing_source_records(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_layer_target *target,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd,
	bool volatile_key, bool symlink,
	struct pkm_lcs_create_missing_source_records_result *result)
{
	u64 sequence = 0;
	long ret;

	if (!result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	if (!resolution || !target || !target->name || !child_guid ||
	    !created_sd || !created_sd->sd || !created_sd->sd_len ||
	    !resolution->parent.source_id || !resolution->child_name ||
	    !resolution->child_name_len)
		return -EINVAL;

	ret = pkm_lcs_allocate_sequence(&sequence);
	if (ret)
		return ret;

	return pkm_lcs_create_missing_source_records_with_sequence(
		resolution, target, child_guid, created_sd, volatile_key,
		symlink, 0, sequence, result);
}

static long pkm_lcs_create_missing_child_path_prepare(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 child_guid[RSI_GUID_SIZE],
	struct pkm_lcs_resolved_key_path *child)
{
	size_t guid_bytes;
	u32 parent_count;
	u32 child_index;
	u32 i;
	long ret;

	if (!child)
		return -EINVAL;

	memset(child, 0, sizeof(*child));
	if (!resolution || !child_guid || !resolution->parent.source_id ||
	    !resolution->parent.component_count ||
	    !resolution->parent.resolved_path ||
	    !resolution->parent.ancestor_guids ||
	    !resolution->child_name || !resolution->child_name_len)
		return -EINVAL;

	parent_count = resolution->parent.component_count;
	if (parent_count >= PKM_LCS_MAX_KEY_DEPTH_HARD)
		return -EINVAL;
	if (resolution->child_depth != parent_count + 1U)
		return -EINVAL;
	if (resolution->child_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	child->source_id = resolution->parent.source_id;
	child->component_count = resolution->child_depth;
	pkm_lcs_source_response_frame_init(&child->final_frame);
	memcpy(child->key_guid, child_guid, sizeof(child->key_guid));

	child->resolved_path = kcalloc(child->component_count,
				       sizeof(*child->resolved_path),
				       GFP_KERNEL);
	if (!child->resolved_path)
		return -ENOMEM;
	child->ancestor_guids = kcalloc(child->component_count,
					sizeof(*child->ancestor_guids),
					GFP_KERNEL);
	if (!child->ancestor_guids)
		goto out_nomem;

	if (check_mul_overflow((size_t)parent_count,
			       sizeof(*child->ancestor_guids), &guid_bytes)) {
		ret = -EINVAL;
		goto out_error;
	}
	memcpy(child->ancestor_guids, resolution->parent.ancestor_guids,
	       guid_bytes);

	for (i = 0; i < parent_count; i++) {
		if (!resolution->parent.resolved_path[i]) {
			ret = -EINVAL;
			goto out_error;
		}
		child->resolved_path[i] =
			kstrdup(resolution->parent.resolved_path[i],
				GFP_KERNEL);
		if (!child->resolved_path[i])
			goto out_nomem;
	}

	child_index = parent_count;
	child->resolved_path[child_index] =
		kmemdup_nul(resolution->child_name,
			    resolution->child_name_len, GFP_KERNEL);
	if (!child->resolved_path[child_index])
		goto out_nomem;
	memcpy(child->ancestor_guids[child_index], child_guid, RSI_GUID_SIZE);
	return 0;

out_nomem:
	pkm_lcs_resolved_key_path_destroy(child);
	return -ENOMEM;
out_error:
	pkm_lcs_resolved_key_path_destroy(child);
	return ret;
}

long pkm_lcs_create_missing_publish_created_key_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd, u32 desired_access)
{
	struct pkm_lcs_resolved_key_path child = { };
	struct pkm_lcs_runtime_limits fallback_limits;
	const struct pkm_lcs_runtime_limits *limits;
	long ret;

	if (!created_sd || !created_sd->sd || !created_sd->sd_len)
		return -EINVAL;
	if (!resolution)
		return -EINVAL;
	limits = pkm_lcs_create_missing_resolution_limits_or_snapshot(
		resolution, &fallback_limits);
	if (!limits)
		return -EINVAL;

	ret = pkm_lcs_create_missing_child_path_prepare(resolution, child_guid,
						       &child);
	if (ret)
		return ret;

	ret = pkm_lcs_publish_open_key_for_token(
		token, child.source_id, child.key_guid, created_sd->sd,
		created_sd->sd_len, desired_access,
		(const char * const *)child.resolved_path,
		child.ancestor_guids, child.component_count, limits);
	pkm_lcs_resolved_key_path_destroy(&child);
	return ret;
}

static void pkm_lcs_create_missing_dispatch_subkey_created_best_effort(
	const struct pkm_lcs_create_missing_parent_resolution *resolution)
{
	struct pkm_lcs_watch_dispatch_context context = { };
	struct pkm_lcs_runtime_limits fallback_limits;
	const struct pkm_lcs_runtime_limits *limits;

	if (!resolution || !resolution->parent.ancestor_guids ||
	    !resolution->parent.resolved_path ||
	    !resolution->parent.component_count || !resolution->child_name ||
	    !resolution->child_name_len)
		return;
	limits = pkm_lcs_create_missing_resolution_limits_or_snapshot(
		resolution, &fallback_limits);
	if (!limits)
		return;

	context.changed_key_guid = resolution->parent.key_guid;
	context.ancestor_guids = resolution->parent.ancestor_guids;
	context.resolved_path =
		(const char * const *)resolution->parent.resolved_path;
	context.limits = limits;
	context.path_component_count = resolution->parent.component_count;
	context.event_type = REG_WATCH_SUBKEY_CREATED;
	context.name = resolution->child_name;
	context.name_len = resolution->child_name_len;
	(void)pkm_lcs_key_fd_dispatch_watch_event_context(&context);
}

static long pkm_lcs_create_missing_refresh_layer_metadata_if_needed(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const u8 child_guid[RSI_GUID_SIZE], bool *effective_changed_out)
{
	struct pkm_lcs_resolved_key_path child = { };
	struct pkm_lcs_runtime_limits fallback_limits;
	const struct pkm_lcs_runtime_limits *limits;
	const u8 *creator_sid = NULL;
	size_t creator_sid_len = 0;
	long ret;

	if (effective_changed_out)
		*effective_changed_out = false;
	if (!resolution)
		return -EINVAL;
	limits = pkm_lcs_create_missing_resolution_limits_or_snapshot(
		resolution, &fallback_limits);
	if (!limits)
		return -EINVAL;

	ret = pkm_lcs_create_missing_child_path_prepare(resolution, child_guid,
						       &child);
	if (ret)
		return ret;

	ret = kacs_rust_token_user_sid(token, &creator_sid, &creator_sid_len);
	if (ret)
		goto out_child;

	ret = pkm_lcs_key_path_refresh_layer_metadata_with_owner_context_result_with_limits(
		child.source_id, child.key_guid,
		(const char * const *)child.resolved_path,
		child.component_count, creator_sid, creator_sid_len, true, limits,
		effective_changed_out);
out_child:
	pkm_lcs_resolved_key_path_destroy(&child);
	return ret;
}

long pkm_lcs_create_missing_prepared_key_for_token(
	const void *token,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	const struct pkm_lcs_create_layer_target *target,
	const u8 child_guid[RSI_GUID_SIZE],
	const struct pkm_lcs_created_key_sd *created_sd, u32 desired_access,
	bool volatile_key, bool symlink,
	struct pkm_lcs_create_missing_prepared_result *result)
{
	struct pkm_lcs_create_missing_source_records_result source = { };
	struct pkm_lcs_runtime_limits fallback_limits;
	const struct pkm_lcs_runtime_limits *limits;
	bool layer_effective_changed = false;
	u64 generation = 0;
	long fd;
	long ret;

	if (!result)
		return -EINVAL;
	limits = pkm_lcs_create_missing_resolution_limits_or_snapshot(
		resolution, &fallback_limits);
	if (!limits)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	result->fd = -1;

	ret = pkm_lcs_create_missing_source_records(
		resolution, target, child_guid, created_sd, volatile_key,
		symlink, &source);
	if (ret)
		return ret;

	result->sequence = source.sequence;
	result->disposition = source.disposition;
	result->created_new = source.created_new;
	result->retry_open_existing = source.retry_open_existing;
	if (source.retry_open_existing)
		return 0;
	if (!source.created_new)
		return -EIO;

	ret = pkm_lcs_create_missing_refresh_layer_metadata_if_needed(
		token, resolution, child_guid, &layer_effective_changed);
	if (ret)
		return ret;

	ret = pkm_lcs_source_record_transaction_generation(
		resolution->parent.source_id, resolution->parent.ancestor_guids[0],
		&generation);
	if (ret) {
		pkm_lcs_source_mark_down_by_id(resolution->parent.source_id);
		return -EIO;
	}

	if (layer_effective_changed) {
		struct pkm_lcs_layer_operation_recovery_result recovery = { };

		ret = pkm_lcs_source_layer_operation_recover_skip_generation_with_limits(
			resolution->parent.source_id,
			resolution->parent.ancestor_guids[0], limits, &recovery);
		if (ret) {
			pkm_lcs_source_mark_down_by_id(
				resolution->parent.source_id);
			return -EIO;
		}
	}

	pkm_lcs_create_missing_dispatch_subkey_created_best_effort(resolution);

	fd = pkm_lcs_create_missing_publish_created_key_for_token(
		token, resolution, child_guid, created_sd, desired_access);
	if (fd < 0)
		return fd;

	result->fd = fd;
	return 0;
}

long pkm_lcs_create_missing_created_result_finish_to_user(
	const struct pkm_lcs_usercopy_ops *ops, u32 __user *udisposition,
	struct pkm_lcs_create_missing_prepared_result *result)
{
	long fd;
	long ret;

	if (!result || !result->created_new || result->retry_open_existing ||
	    result->disposition != REG_CREATED_NEW || result->fd < 0 ||
	    result->fd > INT_MAX)
		return -EINVAL;

	fd = result->fd;
	ret = pkm_lcs_reg_create_key_finish_success_to_user(
		ops, udisposition, fd, REG_CREATED_NEW);
	result->fd = -1;
	return ret;
}

static void pkm_lcs_retry_open_components_destroy(
	struct pkm_lcs_path_component_view *components)
{
	kfree(components);
}

static long pkm_lcs_retry_open_components_prepare(
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	struct pkm_lcs_path_component_view **components_out, u32 *count_out)
{
	struct pkm_lcs_path_component_view *components;
	u32 parent_count;
	u32 component_count;
	u32 i;

	if (!components_out || !count_out)
		return -EINVAL;
	*components_out = NULL;
	*count_out = 0;

	if (!resolution || !resolution->parent.source_id ||
	    !resolution->parent.component_count ||
	    !resolution->parent.resolved_path ||
	    !resolution->parent.ancestor_guids ||
	    !resolution->child_name || !resolution->child_name_len)
		return -EINVAL;

	parent_count = resolution->parent.component_count;
	if (parent_count >= PKM_LCS_MAX_KEY_DEPTH_HARD)
		return -EINVAL;
	component_count = parent_count + 1U;
	if (resolution->child_depth != component_count)
		return -EINVAL;
	if (resolution->child_name_len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	components = kcalloc(component_count, sizeof(*components), GFP_KERNEL);
	if (!components)
		return -ENOMEM;

	for (i = 0; i < parent_count; i++) {
		size_t len;

		if (!resolution->parent.resolved_path[i]) {
			pkm_lcs_retry_open_components_destroy(components);
			return -EINVAL;
		}
		len = strlen(resolution->parent.resolved_path[i]);
		if (!len || len > PKM_LCS_MAX_TOTAL_PATH_BYTES_HARD ||
		    len > U32_MAX) {
			pkm_lcs_retry_open_components_destroy(components);
			return -EINVAL;
		}
		components[i].name = resolution->parent.resolved_path[i];
		components[i].name_len = (u32)len;
	}

	components[parent_count].name = resolution->child_name;
	components[parent_count].name_len = resolution->child_name_len;
	*components_out = components;
	*count_out = component_count;
	return 0;
}

static long pkm_lcs_create_missing_retry_open_existing_for_token_with_txn(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	u32 desired_access, const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd, u32 __user *udisposition)
{
	struct pkm_lcs_path_component_view *components = NULL;
	struct pkm_lcs_resolved_key_path resolved = { };
	struct pkm_lcs_runtime_limits fallback_limits;
	const struct pkm_lcs_runtime_limits *limits;
	const u8 *final_sd;
	u32 component_count = 0;
	long fd;
	long ret;

	if (!resolution)
		return -EINVAL;
	limits = pkm_lcs_create_missing_resolution_limits_or_snapshot(
		resolution, &fallback_limits);
	if (!limits)
		return -EINVAL;

	ret = pkm_lcs_retry_open_components_prepare(
		resolution, &components, &component_count);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components_for_open_with_limits(
		resolution->parent.source_id, 0,
		resolution->parent.ancestor_guids[0], components,
		component_count, false, scope_guids, scope_count, layers,
		layer_count, private_layers, private_layer_count, txn_fd,
		limits, &resolved);
	if (ret)
		goto out_components;

	if (!resolved.final_frame.data || !resolved.final_sd_len ||
	    (size_t)resolved.final_sd_offset > resolved.final_frame.len ||
	    (size_t)resolved.final_sd_len >
		    resolved.final_frame.len -
			    (size_t)resolved.final_sd_offset) {
		ret = -EIO;
		goto out_resolved;
	}

	final_sd = resolved.final_frame.data + resolved.final_sd_offset;
	fd = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count, limits);
	if (fd < 0) {
		ret = fd;
		goto out_resolved;
	}

	ret = pkm_lcs_reg_create_key_finish_success_to_user(
		ops, udisposition, fd, REG_OPENED_EXISTING);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_retry_open_components_destroy(components);
	return ret;
}

long pkm_lcs_create_missing_retry_open_existing_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct pkm_lcs_create_missing_parent_resolution *resolution,
	u32 desired_access, const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, u32 __user *udisposition)
{
	return pkm_lcs_create_missing_retry_open_existing_for_token_with_txn(
		token, ops, resolution, desired_access, scope_guids,
		scope_count, layers, layer_count, private_layers,
		private_layer_count, -1, udisposition);
}

static long pkm_lcs_create_missing_runtime_inputs_validate(
	const struct pkm_lcs_create_missing_runtime_inputs *inputs)
{
	if (!inputs)
		return 0;
	if ((inputs->scope_count && !inputs->scope_guids) ||
	    (inputs->layer_count && !inputs->layers) ||
	    (inputs->private_layer_count && !inputs->private_layers) ||
	    (inputs->metadata_count && !inputs->metadata) ||
	    (inputs->active_key_guid_count && !inputs->active_key_guids))
		return -EINVAL;
	if (inputs->base_metadata_present &&
	    (!inputs->base_metadata_sd || !inputs->base_metadata_sd_len))
		return -EIO;
	return 0;
}

long pkm_lcs_create_missing_user_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access,
	const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	u32 __user *udisposition)
{
	static const struct pkm_lcs_create_missing_runtime_inputs empty_inputs;
	struct pkm_lcs_create_preflight_plan preflight = { };
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan target_plan = { };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_key_open_access_plan parent_plan = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	struct pkm_lcs_key_open_access_plan layer_plan = { };
	struct pkm_lcs_key_guid_assignment_plan guid_plan = { };
	struct pkm_lcs_created_key_sd created_sd = { };
	struct pkm_lcs_create_missing_prepared_result prepared = { };
	long ret;

	prepared.fd = -1;
	if (!inputs)
		inputs = &empty_inputs;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;
	ret = pkm_lcs_create_missing_runtime_inputs_validate(inputs);
	if (ret)
		return ret;

	ret = pkm_lcs_create_missing_parent_for_token(
		token, ops, parent_fd, upath, inputs->scope_guids,
		inputs->scope_count, inputs->layers, inputs->layer_count,
		inputs->private_layers, inputs->private_layer_count,
		&resolution);
	if (ret)
		return ret;

	ret = pkm_lcs_create_missing_parent_access_check_for_token(
		token, &resolution, &parent_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_missing_volatile_parent_check(&resolution,
							   &preflight);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_missing_symlink_authority_for_token(
		token, &resolution, flags, &link_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_layer_target_prepare_with_limits(
		ops, ulayer, inputs->layers, inputs->layer_count,
		resolution.limits_present ? &resolution.limits : NULL, &target,
		&target_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_layer_write_access_check_for_token_with_limits(
		token, &target, inputs->base_metadata_present,
		inputs->base_metadata_sd, inputs->base_metadata_sd_len,
		inputs->metadata, inputs->metadata_count,
		resolution.limits_present ? &resolution.limits : NULL,
		&layer_plan);
	if (ret)
		goto out_target;
	ret = pkm_lcs_assign_new_key_guid(
		inputs->active_key_guids, inputs->active_key_guid_count,
		inputs->generator, &guid_plan);
	if (ret)
		goto out_target;
	ret = pkm_lcs_create_missing_initial_sd_for_token(
		token, &resolution, &created_sd);
	if (ret)
		goto out_target;

	ret = pkm_lcs_create_missing_prepared_key_for_token(
		token, &resolution, &target, guid_plan.guid, &created_sd,
		desired_access, preflight.options.volatile_key,
		preflight.options.symlink, &prepared);
	if (ret)
		goto out_created_sd;

	if (prepared.retry_open_existing) {
		ret = pkm_lcs_create_missing_retry_open_existing_for_token(
			token, ops, &resolution, desired_access,
			inputs->scope_guids, inputs->scope_count,
			inputs->layers, inputs->layer_count,
			inputs->private_layers, inputs->private_layer_count,
			udisposition);
	} else {
		ret = pkm_lcs_create_missing_created_result_finish_to_user(
			ops, udisposition, &prepared);
	}

out_created_sd:
	if (ret && prepared.fd >= 0) {
		close_fd((unsigned int)prepared.fd);
		prepared.fd = -1;
	}
	pkm_lcs_created_key_sd_destroy(&created_sd);
out_target:
	pkm_lcs_create_layer_target_destroy(&target);
out_resolution:
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	return ret;
}

static long pkm_lcs_create_missing_copied_path_finish_for_token_with_txn(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	int txn_fd, u32 __user *udisposition)
{
	static const struct pkm_lcs_create_missing_runtime_inputs empty_inputs;
	struct pkm_lcs_create_preflight_plan preflight = { };
	struct pkm_lcs_create_layer_target target = { };
	struct pkm_lcs_layer_target_admission_plan target_plan = { };
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	struct pkm_lcs_key_open_access_plan parent_plan = { };
	struct pkm_lcs_key_open_access_plan link_plan = { };
	struct pkm_lcs_key_open_access_plan layer_plan = { };
	struct pkm_lcs_key_guid_assignment_plan guid_plan = { };
	struct pkm_lcs_created_key_sd created_sd = { };
	struct pkm_lcs_create_missing_prepared_result prepared = { };
	struct pkm_lcs_create_missing_source_records_result source = { };
	struct pkm_lcs_transaction_binding_plan binding = { };
	struct pkm_lcs_transaction_mutation_handle mutation = { };
	struct pkm_lcs_transaction_key_create_log_input log_input = { };
	const u8 *creator_sid = NULL;
	size_t creator_sid_len = 0;
	u64 sequence = 0;
	long ret;

	prepared.fd = -1;
	if (!inputs)
		inputs = &empty_inputs;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;
	ret = pkm_lcs_create_missing_runtime_inputs_validate(inputs);
	if (ret)
		return ret;

	ret = pkm_lcs_create_missing_copied_parent_for_token_with_txn(
		token, parent_fd, copy, inputs->scope_guids,
		inputs->scope_count, inputs->layers, inputs->layer_count,
		inputs->private_layers, inputs->private_layer_count,
		txn_fd, &resolution);
	if (ret)
		return ret;

	ret = pkm_lcs_create_missing_parent_access_check_for_token(
		token, &resolution, &parent_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_missing_volatile_parent_check(&resolution,
							   &preflight);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_missing_symlink_authority_for_token(
		token, &resolution, flags, &link_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_layer_target_prepare_with_limits(
		ops, ulayer, inputs->layers, inputs->layer_count,
		resolution.limits_present ? &resolution.limits : NULL, &target,
		&target_plan);
	if (ret)
		goto out_resolution;
	ret = pkm_lcs_create_layer_write_access_check_for_token_with_limits(
		token, &target, inputs->base_metadata_present,
		inputs->base_metadata_sd, inputs->base_metadata_sd_len,
		inputs->metadata, inputs->metadata_count,
		resolution.limits_present ? &resolution.limits : NULL,
		&layer_plan);
	if (ret)
		goto out_target;
	ret = pkm_lcs_assign_new_key_guid(
		inputs->active_key_guids, inputs->active_key_guid_count,
		inputs->generator, &guid_plan);
	if (ret)
		goto out_target;
	ret = pkm_lcs_create_missing_initial_sd_for_token(
		token, &resolution, &created_sd);
	if (ret)
		goto out_target;

	if (txn_fd >= 0) {
		ret = pkm_lcs_allocate_sequence(&sequence);
		if (ret)
			goto out_created_sd;
		ret = kacs_rust_token_user_sid(token, &creator_sid,
					       &creator_sid_len);
		if (ret)
			goto out_created_sd;

		log_input.parent_guid = resolution.parent.key_guid;
		log_input.target_guid = guid_plan.guid;
		log_input.child_name = resolution.child_name;
		log_input.child_name_len = resolution.child_name_len;
		log_input.layer = target.name;
		log_input.layer_len = target.name_len;
		log_input.parent_path =
			(const char * const *)resolution.parent.resolved_path;
		log_input.parent_ancestor_guids =
			resolution.parent.ancestor_guids;
		log_input.creator_sid = creator_sid;
		log_input.creator_sid_len = creator_sid_len;
		log_input.parent_depth = resolution.parent.component_count;
		log_input.sequence = sequence;

		ret = pkm_lcs_transaction_fd_begin_key_create_mutation(
			txn_fd, resolution.parent.source_id,
			resolution.parent.ancestor_guids[0], &log_input,
			&mutation, &binding);
		if (ret)
			goto out_created_sd;

		ret = pkm_lcs_create_missing_source_records_with_sequence(
			&resolution, &target, guid_plan.guid, &created_sd,
			preflight.options.volatile_key,
			preflight.options.symlink, binding.transaction_id,
			sequence, &source);
		if (ret) {
			pkm_lcs_transaction_fd_cancel_mutation(&mutation);
			goto out_created_sd;
		}
		prepared.sequence = source.sequence;
		prepared.disposition = source.disposition;
		prepared.created_new = source.created_new;
		prepared.retry_open_existing = source.retry_open_existing;
	} else {
		ret = pkm_lcs_create_missing_prepared_key_for_token(
			token, &resolution, &target, guid_plan.guid,
			&created_sd, desired_access,
			preflight.options.volatile_key,
			preflight.options.symlink, &prepared);
		if (ret)
			goto out_created_sd;
	}

	if (prepared.retry_open_existing) {
		if (txn_fd >= 0)
			pkm_lcs_transaction_fd_cancel_mutation(&mutation);
		ret = pkm_lcs_create_missing_retry_open_existing_for_token_with_txn(
			token, ops, &resolution, desired_access,
			inputs->scope_guids, inputs->scope_count,
			inputs->layers, inputs->layer_count,
			inputs->private_layers, inputs->private_layer_count,
			txn_fd, udisposition);
	} else {
		if (txn_fd >= 0) {
			ret = pkm_lcs_transaction_fd_commit_mutation(
				&mutation);
			if (ret)
				goto out_created_sd;
			ret = pkm_lcs_create_missing_publish_created_key_for_token(
				token, &resolution, guid_plan.guid, &created_sd,
				desired_access);
			if (ret < 0)
				goto out_created_sd;
			prepared.fd = ret;
			prepared.disposition = REG_CREATED_NEW;
			prepared.created_new = true;
		}
		ret = pkm_lcs_create_missing_created_result_finish_to_user(
			ops, udisposition, &prepared);
	}

out_created_sd:
	if (ret && prepared.fd >= 0) {
		close_fd((unsigned int)prepared.fd);
		prepared.fd = -1;
	}
	pkm_lcs_created_key_sd_destroy(&created_sd);
out_target:
	pkm_lcs_create_layer_target_destroy(&target);
out_resolution:
	pkm_lcs_create_missing_parent_resolution_destroy(&resolution);
	return ret;
}

long pkm_lcs_create_missing_copied_path_finish_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	u32 __user *udisposition)
{
	return pkm_lcs_create_missing_copied_path_finish_for_token_with_txn(
		token, ops, parent_fd, copy, desired_access, ulayer, flags,
		inputs, -1, udisposition);
}

static long pkm_lcs_reg_create_key_for_token_with_txn(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access,
	const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	int txn_fd, u32 __user *udisposition)
{
	struct pkm_lcs_create_preflight_plan preflight = { };
	struct pkm_lcs_syscall_path_copy copy = { };
	struct pkm_lcs_create_missing_runtime_inputs live_inputs = { };
	struct pkm_lcs_private_credential_view private_view = { };
	struct pkm_lcs_layer_snapshot snapshot = { };
	struct pkm_lcs_runtime_limits limits;
	const struct pkm_lcs_create_missing_runtime_inputs *active_inputs =
		inputs;
	long ret;

	ret = pkm_lcs_create_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	if (!active_inputs) {
		ret = pkm_lcs_source_layer_snapshot_acquire(&snapshot);
		if (ret)
			goto out_copy;
		pkm_lcs_runtime_limits_snapshot_or_default(&limits);
		ret = pkm_lcs_private_credentials_acquire_for_token(
			token, &limits, &private_view);
		if (ret)
			goto out_snapshot;
		live_inputs.scope_guids = private_view.scope_guids;
		live_inputs.scope_count = private_view.scope_count;
		live_inputs.layers = snapshot.layers;
		live_inputs.layer_count = snapshot.layer_count;
		live_inputs.private_layers = private_view.private_layers;
		live_inputs.private_layer_count =
			private_view.private_layer_count;
		live_inputs.base_metadata_present =
			snapshot.base_metadata_present;
		live_inputs.base_metadata_sd = snapshot.base_metadata_sd;
		live_inputs.base_metadata_sd_len =
			snapshot.base_metadata_sd_len;
		live_inputs.metadata = snapshot.metadata;
		live_inputs.metadata_count = snapshot.metadata_count;
		active_inputs = &live_inputs;
	}

	ret = pkm_lcs_create_existing_copied_path_finish_for_token_with_txn(
		token, ops, parent_fd, &copy, desired_access, flags,
		active_inputs->layers, active_inputs->layer_count,
		active_inputs->private_layers, active_inputs->private_layer_count,
		txn_fd, udisposition);
	if (ret == -ENOENT) {
		ret = pkm_lcs_create_missing_copied_path_finish_for_token_with_txn(
			token, ops, parent_fd, &copy, desired_access, ulayer,
			flags, active_inputs, txn_fd, udisposition);
	}
	pkm_lcs_private_credentials_release(&private_view);
out_snapshot:
	pkm_lcs_source_layer_snapshot_release(&snapshot);
out_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_reg_create_key_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access,
	const char __user *ulayer, u32 flags,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs,
	u32 __user *udisposition)
{
	return pkm_lcs_reg_create_key_for_token_with_txn(
		token, ops, parent_fd, upath, desired_access, ulayer, flags,
		inputs, -1, udisposition);
}

long pkm_lcs_reg_create_key_args_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_create_key_args __user *uargs,
	struct reg_create_key_args *out)
{
	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!ops)
		ops = pkm_lcs_default_usercopy_ops();
	if (!ops->read)
		return -EINVAL;
	if (!uargs)
		return -EFAULT;
	if (!ops->read(ops->ctx, out, uargs, sizeof(*out)))
		return -EFAULT;
	return 0;
}

long pkm_lcs_reg_create_key_args_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_create_key_args *args,
	const struct pkm_lcs_create_missing_runtime_inputs *inputs)
{
	struct pkm_lcs_create_preflight_plan preflight = { };
	long ret;

	if (!args)
		return -EINVAL;
	if (args->_pad0 || args->_pad1)
		return -EINVAL;
	ret = pkm_lcs_create_preflight(args->desired_access, args->flags,
				       &preflight);
	if (ret)
		return ret;
	return pkm_lcs_reg_create_key_for_token_with_txn(
		token, ops, args->parent_fd,
		(const char __user *)(unsigned long)args->path_ptr,
		args->desired_access,
		(const char __user *)(unsigned long)args->layer_ptr,
		args->flags, inputs, args->txn_fd,
		(u32 __user *)(unsigned long)args->disposition_ptr);
}

SYSCALL_DEFINE1(reg_create_key, const struct reg_create_key_args __user *, args)
{
	struct reg_create_key_args copied;
	long ret;

	ret = pkm_lcs_reg_create_key_args_copy_from_user(NULL, args, &copied);
	if (ret)
		return ret;

	return pkm_lcs_reg_create_key_args_for_token(
		pkm_kacs_current_effective_token_ptr(), NULL, &copied, NULL);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_lcs_kunit_create_missing_child_depth(u32 parent_depth,
					      u32 *child_depth_out)
{
	struct pkm_lcs_create_missing_parent_resolution resolution = { };
	long ret;

	if (!child_depth_out)
		return -EINVAL;

	resolution.parent.component_count = parent_depth;
	ret = pkm_lcs_create_missing_validate_child_depth(&resolution);
	*child_depth_out = ret ? 0 : resolution.child_depth;
	return ret;
}
#endif
