// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM CAAP policy cache.
 *
 * This is intentionally an internal kernel-memory cache seam. Public
 * kacs_set_caap syscall registration and privilege gating remain deferred.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include "caap_cache.h"

extern void *kacs_rust_caap_cache_create(void);
extern void kacs_rust_caap_cache_destroy(void *cache);
extern int kacs_rust_caap_cache_set(void *cache, const u8 *policy_sid_ptr,
				    size_t policy_sid_len, const u8 *spec_ptr,
				    size_t spec_len);
extern size_t kacs_rust_caap_cache_len(const void *cache);

static DEFINE_MUTEX(pkm_kacs_caap_mutex);
static void *pkm_kacs_caap_cache;

int pkm_kacs_caap_cache_init(void)
{
	void *cache;

	mutex_lock(&pkm_kacs_caap_mutex);
	if (pkm_kacs_caap_cache) {
		mutex_unlock(&pkm_kacs_caap_mutex);
		return 0;
	}

	cache = kacs_rust_caap_cache_create();
	if (!cache) {
		mutex_unlock(&pkm_kacs_caap_mutex);
		return -ENOMEM;
	}

	pkm_kacs_caap_cache = cache;
	mutex_unlock(&pkm_kacs_caap_mutex);
	return 0;
}

int pkm_kacs_set_caap_internal(const void *policy_sid, u32 policy_sid_len,
			       const void *spec, u32 spec_len)
{
	int ret;

	if (!policy_sid && policy_sid_len)
		return -EINVAL;

	mutex_lock(&pkm_kacs_caap_mutex);
	if (!pkm_kacs_caap_cache) {
		ret = -EACCES;
		goto out;
	}

	ret = kacs_rust_caap_cache_set(pkm_kacs_caap_cache, policy_sid,
				       policy_sid_len, spec, spec_len);

out:
	mutex_unlock(&pkm_kacs_caap_mutex);
	return ret;
}

int pkm_kacs_caap_cache_lock(const void **cache)
{
	if (!cache)
		return -EINVAL;

	mutex_lock(&pkm_kacs_caap_mutex);
	if (!pkm_kacs_caap_cache) {
		mutex_unlock(&pkm_kacs_caap_mutex);
		return -EACCES;
	}

	*cache = pkm_kacs_caap_cache;
	return 0;
}

void pkm_kacs_caap_cache_unlock(void)
{
	mutex_unlock(&pkm_kacs_caap_mutex);
}

size_t pkm_kacs_caap_cache_len(void)
{
	size_t len = 0;

	mutex_lock(&pkm_kacs_caap_mutex);
	if (pkm_kacs_caap_cache)
		len = kacs_rust_caap_cache_len(pkm_kacs_caap_cache);
	mutex_unlock(&pkm_kacs_caap_mutex);
	return len;
}
