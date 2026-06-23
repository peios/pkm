// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS registry open path helpers.
 */

#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/string.h>

#include "../kacs/token_runtime.h"
#include "source_internal.h"

long pkm_lcs_publish_open_key_for_token(
	const void *token, u32 source_id, const u8 key_guid[RSI_GUID_SIZE],
	const u8 *sd, size_t sd_len, u32 desired_access,
	const char * const *resolved_path,
	const u8 (*ancestor_guids)[RSI_GUID_SIZE], u32 path_component_count,
	const struct pkm_lcs_runtime_limits *limits)
{
	struct pkm_lcs_key_fd_publish_input publish = { };
	struct pkm_lcs_key_open_access_plan access = { };
	long audit_ret;
	long ret;

	ret = pkm_lcs_key_open_access_check_for_token(
		token, sd, sd_len, desired_access, &access);
	if (ret) {
		if (ret == -EACCES && access.key_open_sacl_audit_required) {
			audit_ret = pkm_lcs_emit_key_open_audit_for_token(
				token, key_guid, &access);
			if (audit_ret)
				ret = audit_ret;
		}
		return ret;
	}

	ret = pkm_lcs_emit_key_open_audit_for_token(token, key_guid, &access);
	if (ret)
		return ret;

	publish.source_id = source_id;
	memcpy(publish.key_guid, key_guid, sizeof(publish.key_guid));
	publish.granted_access = access.fd_granted_access;
	publish.limits = limits;
	publish.resolved_path = resolved_path;
	publish.ancestor_guids = ancestor_guids;
	publish.path_component_count = path_component_count;
	return pkm_lcs_key_fd_publish(&publish);
}

long pkm_lcs_open_copied_absolute_path_after_preflight_for_token(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd)
{
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_resolved_key_path resolved = { };
	struct pkm_lcs_hive_route_result route = { };
	struct pkm_lcs_runtime_limits limits;
	const u8 *final_sd;
	long ret;

	if (!token)
		return -EACCES;
	if (!copy || !copy->path || !copy->path_len)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_route_absolute_path_for_token_with_limits(
		token, copy->path, copy->path_len, true, scope_guids,
		scope_count, &limits, &route);
	if (ret)
		return ret;

	ret = pkm_lcs_materialize_absolute_path_components_for_token_with_limits(
		token, copy->path, copy->path_len, true, &limits, &components);
	if (ret)
		return ret;

	ret = pkm_lcs_walk_absolute_components_for_open_with_limits(
		route.source_id, 0, route.root_guid, components.components,
		components.component_count, (flags & REG_OPEN_LINK) != 0,
		scope_guids, scope_count, layers, layer_count, private_layers,
		private_layer_count, txn_fd, &limits, &resolved);
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
	ret = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count, &limits);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
	return ret;
}

long pkm_lcs_open_copied_relative_path_after_preflight(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count, int txn_fd)
{
	struct pkm_lcs_key_fd_parent_snapshot parent = { };
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_path_validation_result path = { };
	struct pkm_lcs_resolved_key_path resolved = { };
	struct pkm_lcs_runtime_limits limits;
	const u8 *final_sd;
	long ret;

	if (!token)
		return -EACCES;
	if (!copy || !copy->path || !copy->path_len)
		return -EINVAL;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
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

	ret = pkm_lcs_walk_relative_components_for_open_with_limits(
		&parent, 0, components.components, components.component_count,
		(flags & REG_OPEN_LINK) != 0, NULL, 0, layers, layer_count,
		private_layers, private_layer_count, txn_fd, &limits,
		&resolved);
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
	ret = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count, &limits);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_parent:
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
	return ret;
}

long pkm_lcs_open_copied_absolute_path_for_token(
	const void *token, const struct pkm_lcs_syscall_path_copy *copy,
	u32 desired_access, u32 flags, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_open_preflight_plan preflight = { };
	long ret;

	ret = pkm_lcs_open_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	return pkm_lcs_open_copied_absolute_path_after_preflight_for_token(
		token, copy, desired_access, flags, scope_guids, scope_count,
		layers, layer_count, private_layers, private_layer_count, -1);
}

long pkm_lcs_open_copied_relative_path_for_token(
	const void *token, int parent_fd,
	const struct pkm_lcs_syscall_path_copy *copy, u32 desired_access,
	u32 flags, const struct pkm_lcs_rsi_layer_view *layers,
	u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_open_preflight_plan preflight = { };
	long ret;

	ret = pkm_lcs_open_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	return pkm_lcs_open_copied_relative_path_after_preflight(
		token, parent_fd, copy, desired_access, flags, layers,
		layer_count, private_layers, private_layer_count, -1);
}

long pkm_lcs_open_user_absolute_path_preflight_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, u32 desired_access, u32 flags,
	bool rewrite_current_user, const u8 (*scope_guids)[16],
	u32 scope_count, struct pkm_lcs_open_preflight_plan *plan,
	struct pkm_lcs_hive_route_result *route)
{
	long ret;

	if (!plan || !route)
		return -EINVAL;

	memset(route, 0, sizeof(*route));
	ret = pkm_lcs_open_preflight(desired_access, flags, plan);
	if (ret)
		return ret;

	return pkm_lcs_route_user_absolute_path_for_token(
		token, ops, upath, rewrite_current_user, scope_guids,
		scope_count, route);
}

long pkm_lcs_open_user_relative_path_preflight(
	const struct pkm_lcs_usercopy_ops *ops, int parent_fd,
	const char __user *upath, u32 desired_access, u32 flags,
	struct pkm_lcs_relative_open_preflight *result)
{
	struct pkm_lcs_syscall_path_copy copy = { };
	struct pkm_lcs_runtime_limits limits;
	long ret;

	if (!result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	ret = pkm_lcs_open_preflight(desired_access, flags, &result->access);
	if (ret)
		return ret;

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_validate_syscall_relative_path_with_limits(
		copy.path, copy.path_len, &limits, &result->path);
	if (ret)
		goto out_destroy_copy;

	ret = pkm_lcs_key_fd_relative_base(parent_fd, &result->parent);
	if (ret)
		goto out_destroy_copy;

	ret = pkm_lcs_validate_relative_open_depth_counts(
		result->parent.parent_depth, result->path.component_count,
		limits.max_key_depth);
	if (ret)
		memset(&result->parent, 0, sizeof(result->parent));

out_destroy_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_open_user_absolute_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, u32 desired_access, u32 flags,
	const u8 (*scope_guids)[16], u32 scope_count,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_open_preflight_plan preflight = { };
	struct pkm_lcs_resolved_key_path resolved = { };
	struct pkm_lcs_hive_route_result route = { };
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_syscall_path_copy copy = { };
	const u8 *final_sd;
	long ret;

	if (!token)
		return -EACCES;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;

	ret = pkm_lcs_open_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_route_absolute_path_for_token_with_limits(
		token, copy.path, copy.path_len, true, scope_guids,
		scope_count, &limits, &route);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_materialize_absolute_path_components_for_token_with_limits(
		token, copy.path, copy.path_len, true, &limits, &components);
	if (ret)
		goto out_copy;

	ret = pkm_lcs_walk_absolute_components_for_open_with_limits(
		route.source_id, 0, route.root_guid, components.components,
		components.component_count, (flags & REG_OPEN_LINK) != 0,
		scope_guids, scope_count, layers, layer_count,
		private_layers, private_layer_count, -1, &limits, &resolved);
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
	ret = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count, &limits);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_open_user_relative_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_rsi_private_layer_view *private_layers,
	u32 private_layer_count)
{
	struct pkm_lcs_key_fd_parent_snapshot parent = { };
	struct pkm_lcs_materialized_path components = { };
	struct pkm_lcs_open_preflight_plan preflight = { };
	struct pkm_lcs_path_validation_result path = { };
	struct pkm_lcs_resolved_key_path resolved = { };
	struct pkm_lcs_runtime_limits limits;
	struct pkm_lcs_syscall_path_copy copy = { };
	const u8 *final_sd;
	long ret;

	if (!token)
		return -EACCES;
	if ((layer_count && !layers) ||
	    (private_layer_count && !private_layers))
		return -EINVAL;

	ret = pkm_lcs_open_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
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

	ret = pkm_lcs_walk_relative_components_for_open_with_limits(
		&parent, 0, components.components, components.component_count,
		(flags & REG_OPEN_LINK) != 0, NULL, 0, layers, layer_count,
		private_layers, private_layer_count, -1, &limits, &resolved);
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
	ret = pkm_lcs_publish_open_key_for_token(
		token, resolved.source_id, resolved.key_guid, final_sd,
		resolved.final_sd_len, desired_access,
		(const char * const *)resolved.resolved_path,
		resolved.ancestor_guids, resolved.component_count, &limits);

out_resolved:
	pkm_lcs_resolved_key_path_destroy(&resolved);
out_components:
	pkm_lcs_materialized_path_destroy(&components);
out_parent:
	pkm_lcs_key_fd_parent_snapshot_destroy(&parent);
out_copy:
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_reg_open_key_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	int parent_fd, const char __user *upath, u32 desired_access, u32 flags)
{
	struct pkm_lcs_private_credential_view private_view = { };
	struct pkm_lcs_layer_snapshot snapshot = { };
	struct pkm_lcs_open_preflight_plan preflight = { };
	struct pkm_lcs_runtime_limits limits;
	long ret;

	if (!token)
		return -EACCES;

	ret = pkm_lcs_open_preflight(desired_access, flags, &preflight);
	if (ret)
		return ret;
	ret = pkm_lcs_source_layer_snapshot_acquire(&snapshot);
	if (ret)
		return ret;
	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_private_credentials_acquire_for_token(token, &limits,
							   &private_view);
	if (ret)
		goto out_snapshot;

	if (parent_fd == -1)
		ret = pkm_lcs_open_user_absolute_path_for_token(
			token, ops, upath, desired_access, flags,
			private_view.scope_guids, private_view.scope_count,
			snapshot.layers, snapshot.layer_count,
			private_view.private_layers,
			private_view.private_layer_count);
	else
		ret = pkm_lcs_open_user_relative_path_for_token(
			token, ops, parent_fd, upath, desired_access, flags,
			snapshot.layers, snapshot.layer_count,
			private_view.private_layers,
			private_view.private_layer_count);

	pkm_lcs_private_credentials_release(&private_view);
out_snapshot:
	pkm_lcs_source_layer_snapshot_release(&snapshot);
	return ret;
}

SYSCALL_DEFINE4(reg_open_key, int, parent_fd, const char __user *, path,
		u32, desired_access, u32, flags)
{
	return pkm_lcs_reg_open_key_for_token(
		pkm_kacs_current_effective_token_ptr(), NULL, parent_fd, path,
		desired_access, flags);
}
