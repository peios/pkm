// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM AccessCheck kernel ingress helper.
 *
 * This file deliberately stays below public syscall registration. It provides
 * only the first internal kernel usercopy/writeback seam above the closed pure
 * Slice 15 ABI bridge, keeping token resolution and transport work deferred.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "access_check.h"

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
