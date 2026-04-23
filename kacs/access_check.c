// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM AccessCheck kernel ingress helper.
 *
 * This file provides the public AccessCheck syscalls and the internal
 * kernel usercopy/writeback seam above the closed pure Slice 15 ABI bridge.
 * Public syscalls intentionally reuse the token-fd-aware ingress path instead
 * of growing a parallel AccessCheck implementation.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "access_check.h"
#include "caap_cache.h"
#include "token_fd.h"
#include "token_runtime.h"

#define PKM_KACS_ACCESS_CHECK_ARGS_SIZE 136U
#define PKM_KACS_ACCESS_CHECK_ARGS_V1_SIZE 40U
#define PKM_KACS_ACCESS_CHECK_TOKEN_FD_OFFSET 4U

extern long kacs_rust_access_check_ingress_scalar(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

extern long kacs_rust_access_check_ingress_list(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	u64 results_ptr,
	u32 results_count,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary);

static bool pkm_kacs_read_user(void *ctx, u64 user_ptr, void *dst, size_t len)
{
	void __user *src = (void __user *)(uintptr_t)user_ptr;

	(void)ctx;
	return copy_from_user(dst, src, len) == 0;
}

static bool pkm_kacs_write_user(void *ctx, u64 user_ptr, const void *src, size_t len)
{
	void __user *dst = (void __user *)(uintptr_t)user_ptr;

	(void)ctx;
	return copy_to_user(dst, src, len) == 0;
}

struct pkm_kacs_token_resolution {
	struct pkm_kacs_resolved_ctx ctx;
	const void *cloned_token;
	const struct pkm_kacs_usercopy_ops *outer_ops;
	struct pkm_kacs_usercopy_ops copied_ops;
	u64 args_ptr;
	size_t args_len;
	u8 args_copy[PKM_KACS_ACCESS_CHECK_ARGS_SIZE];
};

static void pkm_kacs_release_token_resolution(
	struct pkm_kacs_token_resolution *resolution)
{
	if (resolution->cloned_token) {
		kacs_rust_token_drop(resolution->cloned_token);
		resolution->cloned_token = NULL;
	}
}

static u32 pkm_kacs_read_le32(const u8 *bytes)
{
	return (u32)bytes[0] | ((u32)bytes[1] << 8) |
	       ((u32)bytes[2] << 16) | ((u32)bytes[3] << 24);
}

static bool pkm_kacs_copied_args_read(void *ctx, u64 user_ptr, void *dst,
				      size_t len)
{
	struct pkm_kacs_token_resolution *resolution = ctx;
	u64 offset64;
	size_t offset;

	if (user_ptr >= resolution->args_ptr) {
		offset64 = user_ptr - resolution->args_ptr;
		if (offset64 <= resolution->args_len) {
			offset = (size_t)offset64;
			if (len <= resolution->args_len - offset) {
				memcpy(dst, resolution->args_copy + offset, len);
				return true;
			}
		}
	}

	return resolution->outer_ops->read_bytes(resolution->outer_ops->ctx,
						 user_ptr, dst, len);
}

static bool pkm_kacs_copied_args_write(void *ctx, u64 user_ptr,
				       const void *src, size_t len)
{
	struct pkm_kacs_token_resolution *resolution = ctx;

	return resolution->outer_ops->write_bytes(resolution->outer_ops->ctx,
						  user_ptr, src, len);
}

static long pkm_kacs_copy_args_prefix(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	struct pkm_kacs_token_resolution *resolution,
	s32 *token_fd)
{
	u8 size_bytes[4];
	size_t copied_len;
	u32 size;

	if (!ops || !ops->read_bytes || !ops->write_bytes || !resolution ||
	    !token_fd)
		return -EINVAL;
	if (!ops->read_bytes(ops->ctx, args_ptr, size_bytes,
			     sizeof(size_bytes)))
		return -EFAULT;
	size = pkm_kacs_read_le32(size_bytes);
	if (size < PKM_KACS_ACCESS_CHECK_ARGS_V1_SIZE)
		return -EINVAL;

	copied_len = size;
	if (copied_len > PKM_KACS_ACCESS_CHECK_ARGS_SIZE)
		copied_len = PKM_KACS_ACCESS_CHECK_ARGS_SIZE;
	if (!ops->read_bytes(ops->ctx, args_ptr, resolution->args_copy,
			     copied_len))
		return -EFAULT;

	resolution->outer_ops = ops;
	resolution->args_ptr = args_ptr;
	resolution->args_len = copied_len;
	resolution->copied_ops.ctx = resolution;
	resolution->copied_ops.read_bytes = pkm_kacs_copied_args_read;
	resolution->copied_ops.write_bytes = pkm_kacs_copied_args_write;
	*token_fd = (s32)pkm_kacs_read_le32(
		&resolution->args_copy[PKM_KACS_ACCESS_CHECK_TOKEN_FD_OFFSET]);

	return 0;
}

static long pkm_kacs_begin_token_resolution(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	struct pkm_kacs_token_resolution *resolution)
{
	s32 token_fd;
	long ret;

	if (!resolution)
		return -EINVAL;

	memset(resolution, 0, sizeof(*resolution));

	ret = pkm_kacs_copy_args_prefix(ops, args_ptr, resolution, &token_fd);
	if (ret)
		return ret;

	if (token_fd == -1)
		return pkm_kacs_resolve_current_effective_ctx(&resolution->ctx);
	if (token_fd < -1)
		return -EINVAL;

	ret = pkm_kacs_token_fd_clone_token(token_fd, &resolution->cloned_token,
					    NULL);
	if (ret)
		return ret;

	ret = pkm_kacs_resolve_ctx_from_token(resolution->cloned_token,
					      &resolution->ctx);
	if (ret) {
		pkm_kacs_release_token_resolution(resolution);
		return ret;
	}

	return 0;
}

long pkm_kacs_access_check_ingress_scalar(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary)
{
	return kacs_rust_access_check_ingress_scalar(ops, args_ptr, resolved_ctx,
						     event_sinks, summary);
}

long pkm_kacs_access_check_ingress_list(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	u64 results_ptr,
	u32 results_count,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary)
{
	return kacs_rust_access_check_ingress_list(ops, args_ptr, results_ptr,
						   results_count, resolved_ctx,
						   event_sinks, summary);
}

long pkm_kacs_access_check_user_scalar(
	const void __user *uargs,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary)
{
	static const struct pkm_kacs_usercopy_ops ops = {
		.read_bytes = pkm_kacs_read_user,
		.write_bytes = pkm_kacs_write_user,
	};

	return pkm_kacs_access_check_ingress_scalar(
		&ops, (u64)(uintptr_t)uargs, resolved_ctx, event_sinks, summary);
}

long pkm_kacs_access_check_user_list(
	const void __user *uargs,
	struct kacs_node_result __user *results,
	u32 results_count,
	const struct pkm_kacs_resolved_ctx *resolved_ctx,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary)
{
	static const struct pkm_kacs_usercopy_ops ops = {
		.read_bytes = pkm_kacs_read_user,
		.write_bytes = pkm_kacs_write_user,
	};

	return pkm_kacs_access_check_ingress_list(
		&ops, (u64)(uintptr_t)uargs, (u64)(uintptr_t)results,
		results_count, resolved_ctx, event_sinks, summary);
}

long pkm_kacs_access_check_ingress_scalar_with_token_fd(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary)
{
	struct pkm_kacs_token_resolution resolution;
	const void *caap_cache;
	long ret;

	if (summary)
		memset(summary, 0, sizeof(*summary));

	ret = pkm_kacs_begin_token_resolution(ops, args_ptr, &resolution);
	if (ret)
		return ret;

	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret) {
		pkm_kacs_release_token_resolution(&resolution);
		return ret;
	}
	resolution.ctx.caap_cache = caap_cache;
	ret = pkm_kacs_access_check_ingress_scalar(&resolution.copied_ops,
						   args_ptr, &resolution.ctx,
						   event_sinks, summary);
	pkm_kacs_caap_cache_unlock();
	pkm_kacs_release_token_resolution(&resolution);
	return ret;
}

long pkm_kacs_access_check_ingress_list_with_token_fd(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	u64 results_ptr,
	u32 results_count,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary)
{
	struct pkm_kacs_token_resolution resolution;
	const void *caap_cache;
	long ret;

	if (summary)
		memset(summary, 0, sizeof(*summary));

	ret = pkm_kacs_begin_token_resolution(ops, args_ptr, &resolution);
	if (ret)
		return ret;

	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret) {
		pkm_kacs_release_token_resolution(&resolution);
		return ret;
	}
	resolution.ctx.caap_cache = caap_cache;
	ret = pkm_kacs_access_check_ingress_list(&resolution.copied_ops, args_ptr,
						 results_ptr, results_count,
						 &resolution.ctx,
						 event_sinks, summary);
	pkm_kacs_caap_cache_unlock();
	pkm_kacs_release_token_resolution(&resolution);
	return ret;
}

long pkm_kacs_access_check_user_scalar_with_token_fd(
	const void __user *uargs,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary)
{
	static const struct pkm_kacs_usercopy_ops ops = {
		.read_bytes = pkm_kacs_read_user,
		.write_bytes = pkm_kacs_write_user,
	};

	return pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, (u64)(uintptr_t)uargs, event_sinks, summary);
}

long pkm_kacs_access_check_user_list_with_token_fd(
	const void __user *uargs,
	struct kacs_node_result __user *results,
	u32 results_count,
	const struct pkm_kacs_event_sink_ops *event_sinks,
	struct pkm_kacs_ingress_summary *summary)
{
	static const struct pkm_kacs_usercopy_ops ops = {
		.read_bytes = pkm_kacs_read_user,
		.write_bytes = pkm_kacs_write_user,
	};

	return pkm_kacs_access_check_ingress_list_with_token_fd(
		&ops, (u64)(uintptr_t)uargs, (u64)(uintptr_t)results,
		results_count, event_sinks, summary);
}

static long pkm_kacs_access_check_syscall_scalar_with_ops(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr)
{
	return pkm_kacs_access_check_ingress_scalar_with_token_fd(
		ops, args_ptr, NULL, NULL);
}

static long pkm_kacs_access_check_syscall_list_with_ops(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	u64 results_ptr,
	u32 results_count)
{
	return pkm_kacs_access_check_ingress_list_with_token_fd(
		ops, args_ptr, results_ptr, results_count, NULL, NULL);
}

SYSCALL_DEFINE1(kacs_access_check, const void __user *, uargs)
{
	static const struct pkm_kacs_usercopy_ops ops = {
		.read_bytes = pkm_kacs_read_user,
		.write_bytes = pkm_kacs_write_user,
	};

	return pkm_kacs_access_check_syscall_scalar_with_ops(
		&ops, (u64)(uintptr_t)uargs);
}

SYSCALL_DEFINE3(kacs_access_check_list, const void __user *, uargs,
		struct kacs_node_result __user *, results, u32, results_count)
{
	static const struct pkm_kacs_usercopy_ops ops = {
		.read_bytes = pkm_kacs_read_user,
		.write_bytes = pkm_kacs_write_user,
	};

	return pkm_kacs_access_check_syscall_list_with_ops(
		&ops, (u64)(uintptr_t)uargs, (u64)(uintptr_t)results,
		results_count);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_access_check_syscall_scalar(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr)
{
	return pkm_kacs_access_check_syscall_scalar_with_ops(ops, args_ptr);
}

long pkm_kacs_kunit_access_check_syscall_list(
	const struct pkm_kacs_usercopy_ops *ops,
	u64 args_ptr,
	u64 results_ptr,
	u32 results_count)
{
	return pkm_kacs_access_check_syscall_list_with_ops(
		ops, args_ptr, results_ptr, results_count);
}
#endif
