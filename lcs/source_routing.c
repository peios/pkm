// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source-table routing helpers.
 */

#include <linux/errno.h>
#include <linux/string.h>

#include "../kacs/token_runtime.h"
#include "source_internal.h"

extern int lcs_rust_route_hive_from_source_slots(
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	const u8 *hive_name, u32 hive_name_len,
	const u8 (*scope_guids)[16], size_t scope_count,
	struct pkm_lcs_hive_route_result *result,
	const struct pkm_lcs_runtime_limits *limits);
extern int lcs_rust_route_absolute_path_from_source_slots(
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	const u8 *path, u32 path_len, bool rewrite_current_user,
	const u8 *current_user_sid_component,
	u32 current_user_sid_component_len, const u8 (*scope_guids)[16],
	size_t scope_count, struct pkm_lcs_hive_route_result *result,
	const struct pkm_lcs_runtime_limits *limits);
extern int lcs_rust_route_absolute_path_from_source_slots_with_token_sid(
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	const u8 *path, u32 path_len, bool rewrite_current_user,
	const u8 *current_user_sid, size_t current_user_sid_len,
	const u8 (*scope_guids)[16], size_t scope_count,
	struct pkm_lcs_hive_route_result *result,
	const struct pkm_lcs_runtime_limits *limits);
extern int lcs_rust_route_symlink_target_from_source_slots(
	const struct pkm_lcs_source_slot_view_copy *slots, size_t slot_count,
	const u8 *target, u32 target_len, const u8 (*scope_guids)[16],
	size_t scope_count, struct pkm_lcs_hive_route_result *result,
	const struct pkm_lcs_runtime_limits *limits);

long pkm_lcs_route_hive_name(const char *hive_name, u32 hive_name_len,
			     const u8 (*scope_guids)[16], u32 scope_count,
			     struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_source_slot_view_buffer view_buffer;
	struct pkm_lcs_runtime_limits limits;
	u32 slot_count;
	long ret;

	if (!hive_name || !result)
		return -EINVAL;

	pkm_lcs_source_slot_view_buffer_init(&view_buffer);
	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	memset(result, 0, sizeof(*result));
	pkm_lcs_source_table_lock();
	ret = pkm_lcs_source_slot_view_buffer_prepare_locked(&view_buffer,
							     &slot_count);
	if (ret)
		goto out_unlock;
	ret = lcs_rust_route_hive_from_source_slots(
		view_buffer.views, slot_count, hive_name, hive_name_len,
		scope_guids, scope_count, result, &limits);
out_unlock:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_slot_view_buffer_destroy(&view_buffer);
	return ret;
}

long pkm_lcs_route_absolute_path(const char *path, u32 path_len,
				 bool rewrite_current_user,
				 const char *current_user_sid_component,
				 u32 current_user_sid_component_len,
				 const u8 (*scope_guids)[16], u32 scope_count,
				 struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_source_slot_view_buffer view_buffer;
	struct pkm_lcs_runtime_limits limits;
	u32 slot_count;
	long ret;

	if (!path || !result)
		return -EINVAL;

	pkm_lcs_source_slot_view_buffer_init(&view_buffer);
	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	memset(result, 0, sizeof(*result));
	pkm_lcs_source_table_lock();
	ret = pkm_lcs_source_slot_view_buffer_prepare_locked(&view_buffer,
							     &slot_count);
	if (ret)
		goto out_unlock;
	ret = lcs_rust_route_absolute_path_from_source_slots(
		view_buffer.views, slot_count, path, path_len,
		rewrite_current_user, current_user_sid_component,
		current_user_sid_component_len, scope_guids, scope_count,
		result, &limits);
out_unlock:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_slot_view_buffer_destroy(&view_buffer);
	return ret;
}

long pkm_lcs_route_absolute_path_for_token_with_limits(
	const void *token, const char *path, u32 path_len,
	bool rewrite_current_user, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_source_slot_view_buffer view_buffer;
	const u8 *current_user_sid = NULL;
	size_t current_user_sid_len = 0;
	u32 slot_count;
	long ret;

	if (!path || !result || !limits)
		return -EINVAL;

	pkm_lcs_source_slot_view_buffer_init(&view_buffer);
	memset(result, 0, sizeof(*result));
	if (rewrite_current_user) {
		ret = kacs_rust_token_user_sid(token, &current_user_sid,
					       &current_user_sid_len);
		if (ret) {
			pkm_lcs_source_slot_view_buffer_destroy(&view_buffer);
			return ret;
		}
	}

	pkm_lcs_source_table_lock();
	ret = pkm_lcs_source_slot_view_buffer_prepare_locked(&view_buffer,
							     &slot_count);
	if (ret)
		goto out_unlock;
	ret = lcs_rust_route_absolute_path_from_source_slots_with_token_sid(
		view_buffer.views, slot_count, path, path_len,
		rewrite_current_user, current_user_sid, current_user_sid_len,
		scope_guids, scope_count, result, limits);
out_unlock:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_slot_view_buffer_destroy(&view_buffer);
	return ret;
}

long pkm_lcs_route_absolute_path_for_token(const void *token, const char *path,
					   u32 path_len,
					   bool rewrite_current_user,
					   const u8 (*scope_guids)[16],
					   u32 scope_count,
					   struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_route_absolute_path_for_token_with_limits(
		token, path, path_len, rewrite_current_user, scope_guids,
		scope_count, &limits, result);
}

long pkm_lcs_route_current_absolute_path(const char *path, u32 path_len,
					 bool rewrite_current_user,
					 const u8 (*scope_guids)[16],
					 u32 scope_count,
					 struct pkm_lcs_hive_route_result *result)
{
	return pkm_lcs_route_absolute_path_for_token(
		pkm_kacs_current_effective_token_ptr(), path, path_len,
		rewrite_current_user, scope_guids, scope_count, result);
}

long pkm_lcs_route_user_absolute_path_for_token(
	const void *token, const struct pkm_lcs_usercopy_ops *ops,
	const char __user *upath, bool rewrite_current_user,
	const u8 (*scope_guids)[16], u32 scope_count,
	struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_syscall_path_copy copy = { };
	struct pkm_lcs_runtime_limits limits;
	long ret;

	if (!result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));

	ret = pkm_lcs_syscall_path_copy_from_user(ops, upath, &copy);
	if (ret)
		return ret;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	ret = pkm_lcs_route_absolute_path_for_token_with_limits(
		token, copy.path, copy.path_len, rewrite_current_user,
		scope_guids, scope_count, &limits, result);
	pkm_lcs_syscall_path_copy_destroy(&copy);
	return ret;
}

long pkm_lcs_route_symlink_target_with_limits(
	const char *target, u32 target_len, const u8 (*scope_guids)[16],
	u32 scope_count, const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_source_slot_view_buffer view_buffer;
	u32 slot_count;
	long ret;

	if (!target || !limits || !result)
		return -EINVAL;

	pkm_lcs_source_slot_view_buffer_init(&view_buffer);
	memset(result, 0, sizeof(*result));
	pkm_lcs_source_table_lock();
	ret = pkm_lcs_source_slot_view_buffer_prepare_locked(&view_buffer,
							     &slot_count);
	if (ret)
		goto out_unlock;
	ret = lcs_rust_route_symlink_target_from_source_slots(
		view_buffer.views, slot_count, (const u8 *)target, target_len,
		scope_guids, scope_count, result, limits);
out_unlock:
	pkm_lcs_source_table_unlock();
	pkm_lcs_source_slot_view_buffer_destroy(&view_buffer);
	return ret;
}

long pkm_lcs_route_symlink_target(
	const char *target, u32 target_len, const u8 (*scope_guids)[16],
	u32 scope_count, struct pkm_lcs_hive_route_result *result)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_route_symlink_target_with_limits(
		target, target_len, scope_guids, scope_count, &limits, result);
}
