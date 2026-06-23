// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS syscall input copying and target preparation.
 */

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "source_device.h"

extern int lcs_rust_admit_layer_target(
	const u8 *layer_name, u32 layer_name_len,
	const struct pkm_lcs_rsi_layer_view *layers, size_t layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_layer_target_admission_plan *plan);

static bool pkm_lcs_default_copy_from_user(void *ctx, void *dst,
					   const void __user *src, size_t len)
{
	(void)ctx;

	return copy_from_user(dst, src, len) == 0;
}

static size_t pkm_lcs_default_strnlen_user(void *ctx,
					   const char __user *src, size_t max)
{
	(void)ctx;

	return strnlen_user(src, max);
}

static bool pkm_lcs_default_copy_to_user(void *ctx, void __user *dst,
					 const void *src, size_t len)
{
	(void)ctx;

	return copy_to_user(dst, src, len) == 0;
}

static const struct pkm_lcs_usercopy_ops pkm_lcs_default_usercopy = {
	.read = pkm_lcs_default_copy_from_user,
	.write = pkm_lcs_default_copy_to_user,
	.strnlen = pkm_lcs_default_strnlen_user,
};

const struct pkm_lcs_usercopy_ops *pkm_lcs_default_usercopy_ops(void)
{
	return &pkm_lcs_default_usercopy;
}

void pkm_lcs_syscall_path_copy_destroy(struct pkm_lcs_syscall_path_copy *copy)
{
	if (!copy)
		return;

	kfree(copy->path);
	memset(copy, 0, sizeof(*copy));
}

long pkm_lcs_syscall_path_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *upath,
	struct pkm_lcs_syscall_path_copy *out)
{
	char *path;
	size_t path_len;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	if (!ops)
		ops = pkm_lcs_default_usercopy_ops();
	if (!ops->read || !ops->strnlen)
		return -EINVAL;
	if (!upath)
		return -EFAULT;

	path_len = ops->strnlen(ops->ctx, upath,
				PKM_LCS_MAX_SYSCALL_PATH_BYTES_HARD);
	if (!path_len)
		return -EFAULT;
	if (path_len > PKM_LCS_MAX_SYSCALL_PATH_BYTES_HARD)
		return -ENAMETOOLONG;

	path = kmalloc(path_len, GFP_KERNEL);
	if (!path)
		return -ENOMEM;
	if (!ops->read(ops->ctx, path, upath, path_len)) {
		kfree(path);
		return -EFAULT;
	}

	out->path = path;
	out->path_len = (u32)path_len;
	return 0;
}

void pkm_lcs_create_layer_target_destroy(
	struct pkm_lcs_create_layer_target *target)
{
	if (!target)
		return;

	kfree(target->owned_name);
	memset(target, 0, sizeof(*target));
}

long pkm_lcs_create_layer_target_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *ulayer,
	struct pkm_lcs_create_layer_target *target)
{
	char *layer;
	size_t user_len;

	if (!target)
		return -EINVAL;
	memset(target, 0, sizeof(*target));

	if (!ulayer) {
		pkm_lcs_create_layer_target_set_base(target);
		return 0;
	}

	if (!ops)
		ops = pkm_lcs_default_usercopy_ops();
	if (!ops->read || !ops->strnlen)
		return -EINVAL;

	user_len = ops->strnlen(ops->ctx, ulayer,
				PKM_LCS_MAX_SYSCALL_LAYER_BYTES_HARD);
	if (!user_len)
		return -EFAULT;
	if (user_len > PKM_LCS_MAX_SYSCALL_LAYER_BYTES_HARD)
		return -ENAMETOOLONG;

	layer = kmalloc(user_len, GFP_KERNEL);
	if (!layer)
		return -ENOMEM;
	if (!ops->read(ops->ctx, layer, ulayer, user_len)) {
		kfree(layer);
		return -EFAULT;
	}
	if (layer[user_len - 1] != '\0') {
		kfree(layer);
		return -EFAULT;
	}

	target->owned_name = layer;
	target->name = layer;
	target->name_len = (u32)user_len - 1U;
	return 0;
}

long pkm_lcs_create_layer_target_admit(
	const struct pkm_lcs_create_layer_target *target,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	struct pkm_lcs_layer_target_admission_plan *plan)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_create_layer_target_admit_with_limits(
		target, layers, layer_count, &limits, plan);
}

long pkm_lcs_create_layer_target_admit_with_limits(
	const struct pkm_lcs_create_layer_target *target,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_layer_target_admission_plan *plan)
{
	const struct pkm_lcs_rsi_layer_view *active_layers = layers;
	const struct pkm_lcs_rsi_private_layer_view *private_layers = NULL;
	u32 active_layer_count = layer_count;
	u32 private_layer_count = 0;
	long ret;

	if (!target || !target->name || !limits || !plan)
		return -EINVAL;
	memset(plan, 0, sizeof(*plan));

	ret = pkm_lcs_normalize_layer_inputs(
		&active_layers, &active_layer_count, &private_layers,
		&private_layer_count);
	if (ret)
		return ret;

	return lcs_rust_admit_layer_target(
		(const u8 *)target->name, target->name_len, active_layers,
		active_layer_count, limits, plan);
}

long pkm_lcs_create_layer_target_prepare(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *ulayer,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	struct pkm_lcs_create_layer_target *target,
	struct pkm_lcs_layer_target_admission_plan *plan)
{
	struct pkm_lcs_runtime_limits limits;

	pkm_lcs_runtime_limits_snapshot_or_default(&limits);
	return pkm_lcs_create_layer_target_prepare_with_limits(
		ops, ulayer, layers, layer_count, &limits, target, plan);
}

long pkm_lcs_create_layer_target_prepare_with_limits(
	const struct pkm_lcs_usercopy_ops *ops, const char __user *ulayer,
	const struct pkm_lcs_rsi_layer_view *layers, u32 layer_count,
	const struct pkm_lcs_runtime_limits *limits,
	struct pkm_lcs_create_layer_target *target,
	struct pkm_lcs_layer_target_admission_plan *plan)
{
	long ret;

	if (!limits || !target || !plan)
		return -EINVAL;

	ret = pkm_lcs_create_layer_target_copy_from_user(ops, ulayer, target);
	if (ret)
		return ret;

	ret = pkm_lcs_create_layer_target_admit_with_limits(
		target, layers, layer_count, limits, plan);
	if (ret) {
		pkm_lcs_create_layer_target_destroy(target);
		memset(plan, 0, sizeof(*plan));
	}
	return ret;
}
