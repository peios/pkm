// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS path validation and component materialization helpers.
 */

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../kacs/token_runtime.h"
#include "source_device.h"

extern int lcs_rust_materialize_absolute_path_components_with_token_sid(
	const u8 *path, u32 path_len, bool rewrite_current_user,
	const u8 *current_user_sid, size_t current_user_sid_len,
	struct pkm_lcs_path_component_view *components,
	size_t component_capacity, u8 *string_buf, size_t string_capacity,
	struct pkm_lcs_path_component_materialization *result,
	const struct pkm_lcs_runtime_limits *limits);
extern int lcs_rust_materialize_symlink_target_components(
	const u8 *target, u32 target_len,
	struct pkm_lcs_path_component_view *components,
	size_t component_capacity, u8 *string_buf, size_t string_capacity,
	struct pkm_lcs_path_component_materialization *result,
	const struct pkm_lcs_runtime_limits *limits);
extern int lcs_rust_materialize_relative_path_components(
	const u8 *path, u32 path_len,
	struct pkm_lcs_path_component_view *components,
	size_t component_capacity, u8 *string_buf, size_t string_capacity,
	struct pkm_lcs_path_component_materialization *result,
	const struct pkm_lcs_runtime_limits *limits);
extern int lcs_rust_validate_syscall_relative_path(
	const u8 *path, u32 path_len,
	struct pkm_lcs_path_validation_result *result,
	const struct pkm_lcs_runtime_limits *limits);

long pkm_lcs_validate_syscall_relative_path(
	const char *path, u32 path_len,
	struct pkm_lcs_path_validation_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_validate_syscall_relative_path_with_limits(
		path, path_len, &limits, result);
}

long pkm_lcs_validate_syscall_relative_path_with_limits(
	const char *path, u32 path_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_path_validation_result *result)
{
	if (!path || !result || !limits)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	return lcs_rust_validate_syscall_relative_path((const u8 *)path,
						      path_len, result,
						      limits);
}

void pkm_lcs_materialized_path_destroy(struct pkm_lcs_materialized_path *path)
{
	if (!path)
		return;

	kfree(path->components);
	kfree(path->strings);
	memset(path, 0, sizeof(*path));
}

long pkm_lcs_materialize_absolute_path_components_for_token_with_limits(
	const void *token, const char *path, u32 path_len,
	bool rewrite_current_user, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_materialized_path *result)
{
	const u8 *current_user_sid = NULL;
	size_t current_user_sid_len = 0;
	struct pkm_lcs_path_component_materialization shape = { };
	struct pkm_lcs_path_component_materialization filled = { };
	struct pkm_lcs_path_component_view *components;
	char *strings;
	long ret;

	if (!path || !result || !limits)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	if (rewrite_current_user) {
		ret = kacs_rust_token_user_sid(token, &current_user_sid,
					       &current_user_sid_len);
		if (ret)
			return ret;
	}

	ret = lcs_rust_materialize_absolute_path_components_with_token_sid(
		(const u8 *)path, path_len, rewrite_current_user,
		current_user_sid, current_user_sid_len, NULL, 0, NULL, 0,
		&shape, limits);
	if (ret)
		return ret;
	if (!shape.component_count || !shape.string_bytes)
		return -EINVAL;

	components = kcalloc(shape.component_count, sizeof(*components),
			     GFP_KERNEL);
	if (!components)
		return -ENOMEM;
	strings = kmalloc(shape.string_bytes, GFP_KERNEL);
	if (!strings) {
		kfree(components);
		return -ENOMEM;
	}

	ret = lcs_rust_materialize_absolute_path_components_with_token_sid(
		(const u8 *)path, path_len, rewrite_current_user,
		current_user_sid, current_user_sid_len, components,
		shape.component_count, (u8 *)strings, shape.string_bytes, &filled,
		limits);
	if (ret)
		goto out_free;
	if (filled.component_count != shape.component_count ||
	    filled.string_bytes != shape.string_bytes) {
		ret = -EIO;
		goto out_free;
	}

	result->components = components;
	result->strings = strings;
	result->component_count = filled.component_count;
	result->string_bytes = filled.string_bytes;
	return 0;

out_free:
	kfree(components);
	kfree(strings);
	return ret;
}

long pkm_lcs_materialize_absolute_path_components_for_token(
	const void *token, const char *path, u32 path_len,
	bool rewrite_current_user, struct pkm_lcs_materialized_path *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_materialize_absolute_path_components_for_token_with_limits(
		token, path, path_len, rewrite_current_user, &limits, result);
}

long pkm_lcs_materialize_relative_path_components_with_limits(
	const char *path, u32 path_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_materialized_path *result)
{
	struct pkm_lcs_path_component_materialization shape = { };
	struct pkm_lcs_path_component_materialization filled = { };
	struct pkm_lcs_path_component_view *components;
	char *strings;
	long ret;

	if (!path || !result || !limits)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	ret = lcs_rust_materialize_relative_path_components(
		(const u8 *)path, path_len, NULL, 0, NULL, 0, &shape, limits);
	if (ret)
		return ret;
	if (!shape.component_count || !shape.string_bytes)
		return -EINVAL;

	components = kcalloc(shape.component_count, sizeof(*components),
			     GFP_KERNEL);
	if (!components)
		return -ENOMEM;
	strings = kmalloc(shape.string_bytes, GFP_KERNEL);
	if (!strings) {
		kfree(components);
		return -ENOMEM;
	}

	ret = lcs_rust_materialize_relative_path_components(
		(const u8 *)path, path_len, components, shape.component_count,
		(u8 *)strings, shape.string_bytes, &filled, limits);
	if (ret)
		goto out_free;
	if (filled.component_count != shape.component_count ||
	    filled.string_bytes != shape.string_bytes) {
		ret = -EIO;
		goto out_free;
	}

	result->components = components;
	result->strings = strings;
	result->component_count = filled.component_count;
	result->string_bytes = filled.string_bytes;
	return 0;

out_free:
	kfree(components);
	kfree(strings);
	return ret;
}

long pkm_lcs_materialize_relative_path_components(
	const char *path, u32 path_len,
	struct pkm_lcs_materialized_path *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_materialize_relative_path_components_with_limits(
		path, path_len, &limits, result);
}

long pkm_lcs_materialize_symlink_target_components_with_limits(
	const char *target, u32 target_len,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_materialized_path *result)
{
	struct pkm_lcs_path_component_materialization shape = { };
	struct pkm_lcs_path_component_materialization filled = { };
	struct pkm_lcs_path_component_view *components;
	char *strings;
	long ret;

	if (!target || !limits || !result)
		return -EINVAL;

	memset(result, 0, sizeof(*result));
	ret = lcs_rust_materialize_symlink_target_components(
		(const u8 *)target, target_len, NULL, 0, NULL, 0, &shape,
		limits);
	if (ret)
		return ret;
	if (!shape.component_count || !shape.string_bytes)
		return -EINVAL;

	components = kcalloc(shape.component_count, sizeof(*components),
			     GFP_KERNEL);
	if (!components)
		return -ENOMEM;
	strings = kmalloc(shape.string_bytes, GFP_KERNEL);
	if (!strings) {
		kfree(components);
		return -ENOMEM;
	}

	ret = lcs_rust_materialize_symlink_target_components(
		(const u8 *)target, target_len, components,
		shape.component_count, (u8 *)strings, shape.string_bytes,
		&filled, limits);
	if (ret)
		goto out_free;
	if (filled.component_count != shape.component_count ||
	    filled.string_bytes != shape.string_bytes) {
		ret = -EIO;
		goto out_free;
	}

	result->components = components;
	result->strings = strings;
	result->component_count = filled.component_count;
	result->string_bytes = filled.string_bytes;
	return 0;

out_free:
	kfree(components);
	kfree(strings);
	return ret;
}

long pkm_lcs_materialize_symlink_target_components(
	const char *target, u32 target_len,
	struct pkm_lcs_materialized_path *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_materialize_symlink_target_components_with_limits(
		target, target_len, &limits, result);
}

void pkm_lcs_symlink_target_resolution_destroy(
	struct pkm_lcs_symlink_target_resolution *resolution)
{
	if (!resolution)
		return;

	pkm_lcs_materialized_path_destroy(&resolution->components);
	memset(resolution, 0, sizeof(*resolution));
}
