// SPDX-License-Identifier: GPL-2.0-only

#include <linux/errno.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "lsm_internal.h"
#include "token_runtime.h"

struct pkm_kacs_process_sd *pkm_kacs_process_sd_get(
	struct pkm_kacs_process_sd *process_sd)
{
	if (process_sd)
		refcount_inc(&process_sd->refs);
	return process_sd;
}

struct pkm_kacs_process_sd *pkm_kacs_process_sd_wrap_bytes(
	const u8 *bytes, size_t len)
{
	struct pkm_kacs_process_sd *process_sd;

	if (!bytes || !len)
		return NULL;

	process_sd = kzalloc(sizeof(*process_sd), GFP_KERNEL);
	if (!process_sd) {
		/*
		 * `bytes` is an owned Rust allocation that only this wrapper can
		 * hand to pkm_kacs_process_sd_put; free it here rather than
		 * orphan it when the wrapper struct cannot be allocated.
		 */
		pkm_kacs_free((void *)bytes);
		return NULL;
	}

	refcount_set(&process_sd->refs, 1);
	process_sd->bytes = bytes;
	process_sd->len = len;
	return process_sd;
}

struct pkm_kacs_process_sd *pkm_kacs_process_sd_alloc(const void *token)
{
	size_t len = 0;
	const u8 *bytes;

	if (!token)
		return NULL;

	bytes = kacs_rust_create_default_process_sd(token, &len);
	if (!bytes || len == 0)
		return NULL;

	return pkm_kacs_process_sd_wrap_bytes(bytes, len);
}

struct pkm_kacs_process_sd *pkm_kacs_socket_sd_alloc(const void *token)
{
	size_t len = 0;
	const u8 *bytes;

	if (!token)
		return NULL;

	bytes = kacs_rust_create_default_socket_sd(token, &len);
	if (!bytes || len == 0)
		return NULL;

	return pkm_kacs_process_sd_wrap_bytes(bytes, len);
}

void pkm_kacs_process_sd_put(struct pkm_kacs_process_sd *process_sd)
{
	if (!process_sd)
		return;
	if (!refcount_dec_and_test(&process_sd->refs))
		return;

	if (process_sd->bytes)
		pkm_kacs_free((void *)process_sd->bytes);
	kfree(process_sd);
}
