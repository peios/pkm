// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM CAAP policy cache.
 *
 * Slice 27 exposes the bounded public kacs_set_caap syscall surface above the
 * Slice 26 internal cache.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <pkm/token.h>

#include "caap_cache.h"
#include "token_runtime.h"

#define PKM_KACS_MIN_SID_LEN 8U
#define PKM_KACS_MAX_SID_LEN 68U
#define PKM_KACS_MAX_CAAP_SPEC_LEN (256U * 1024U)

extern void *kacs_rust_caap_cache_create(void);
extern void kacs_rust_caap_cache_destroy(void *cache);
extern int kacs_rust_caap_cache_set(void *cache, const u8 *policy_sid_ptr,
				    size_t policy_sid_len, const u8 *spec_ptr,
				    size_t spec_len);
extern size_t kacs_rust_caap_cache_len(const void *cache);

static DEFINE_MUTEX(pkm_kacs_caap_mutex);
static void *pkm_kacs_caap_cache;

static int pkm_kacs_require_tcb(const void *token)
{
	if (!token)
		return -EACCES;
	if (!kacs_rust_token_has_enabled_privilege(token,
						  KACS_SE_TCB_PRIVILEGE))
		return -EACCES;
	if (!kacs_rust_token_mark_privileges_used(token,
						 KACS_SE_TCB_PRIVILEGE))
		return -EACCES;

	return 0;
}

static int pkm_kacs_copy_user_required_blob(const void __user *user_ptr,
					    u32 len, u32 max_len, u8 **out)
{
	u8 *copy;

	if (!out)
		return -EINVAL;

	*out = NULL;
	if (!user_ptr || !len || len > max_len)
		return -EINVAL;

	copy = kmalloc(len, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	if (copy_from_user(copy, user_ptr, len)) {
		kfree(copy);
		return -EFAULT;
	}

	*out = copy;
	return 0;
}

static int pkm_kacs_copy_user_optional_spec(const void __user *user_ptr,
					    u32 len, u8 **out, u32 *len_out)
{
	u8 *copy;

	if (!out || !len_out)
		return -EINVAL;

	*out = NULL;
	*len_out = 0;
	if (!user_ptr || !len)
		return 0;
	if (len > PKM_KACS_MAX_CAAP_SPEC_LEN)
		return -EINVAL;

	copy = kmalloc(len, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	if (copy_from_user(copy, user_ptr, len)) {
		kfree(copy);
		return -EFAULT;
	}

	*out = copy;
	*len_out = len;
	return 0;
}

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

void pkm_kacs_caap_cache_destroy(void)
{
	void *cache;

	mutex_lock(&pkm_kacs_caap_mutex);
	cache = pkm_kacs_caap_cache;
	pkm_kacs_caap_cache = NULL;
	mutex_unlock(&pkm_kacs_caap_mutex);

	if (cache)
		kacs_rust_caap_cache_destroy(cache);
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

static __maybe_unused int pkm_kacs_set_caap_for_token(const void *token, const void *policy_sid,
				       u32 policy_sid_len, const void *spec,
				       u32 spec_len)
{
	int ret;

	ret = pkm_kacs_require_tcb(token);
	if (ret)
		return ret;

	return pkm_kacs_set_caap_internal(policy_sid, policy_sid_len, spec,
					  spec_len);
}

static long pkm_kacs_set_caap_user_for_token(
	const void *token, const void __user *policy_sid, u32 policy_sid_len,
	const void __user *spec, u32 spec_len)
{
	u8 *policy_sid_copy = NULL;
	u8 *spec_copy = NULL;
	u32 copied_spec_len = 0;
	long ret;

	ret = pkm_kacs_require_tcb(token);
	if (ret)
		return ret;
	if (policy_sid_len < PKM_KACS_MIN_SID_LEN ||
	    policy_sid_len > PKM_KACS_MAX_SID_LEN)
		return -EINVAL;

	ret = pkm_kacs_copy_user_required_blob(policy_sid, policy_sid_len,
					       PKM_KACS_MAX_SID_LEN,
					       &policy_sid_copy);
	if (ret)
		return ret;

	ret = pkm_kacs_copy_user_optional_spec(spec, spec_len, &spec_copy,
					       &copied_spec_len);
	if (ret)
		goto out;

	ret = pkm_kacs_set_caap_internal(policy_sid_copy, policy_sid_len,
					 spec_copy, copied_spec_len);

out:
	kfree(spec_copy);
	kfree(policy_sid_copy);
	return ret;
}

SYSCALL_DEFINE4(kacs_set_caap, const void __user *, policy_sid, u32,
		policy_sid_len, const void __user *, spec, u32, spec_len)
{
	return pkm_kacs_set_caap_user_for_token(
		pkm_kacs_current_effective_token_ptr(), policy_sid,
		policy_sid_len, spec, spec_len);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kacs_kunit_set_caap_for_token(const void *token, const void *policy_sid,
				      u32 policy_sid_len, const void *spec,
				      u32 spec_len)
{
	return pkm_kacs_set_caap_for_token(token, policy_sid, policy_sid_len,
					   spec, spec_len);
}

long pkm_kacs_kunit_set_caap_user_for_token(
	const void *token, const void __user *policy_sid, u32 policy_sid_len,
	const void __user *spec, u32 spec_len)
{
	return pkm_kacs_set_caap_user_for_token(token, policy_sid,
						policy_sid_len, spec,
						spec_len);
}
#endif

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
