/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_CAAP_CACHE_H
#define _SECURITY_PKM_KACS_CAAP_CACHE_H

#include <linux/compiler_types.h>
#include <linux/types.h>

int pkm_kacs_caap_cache_init(void);
void pkm_kacs_caap_cache_destroy(void);
/*
 * Raw cache mutation. Public callers must go through the SeTcb-gated syscall
 * wrapper in caap_cache.c.
 */
int pkm_kacs_set_caap_internal(const void *policy_sid, u32 policy_sid_len,
			       const void *spec, u32 spec_len);
int pkm_kacs_caap_cache_lock(const void **cache);
void pkm_kacs_caap_cache_unlock(void);
size_t pkm_kacs_caap_cache_len(void);

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kacs_kunit_set_caap_for_token(const void *token, const void *policy_sid,
				      u32 policy_sid_len, const void *spec,
				      u32 spec_len);
long pkm_kacs_kunit_set_caap_user_for_token(
	const void *token, const void __user *policy_sid, u32 policy_sid_len,
	const void __user *spec, u32 spec_len);
#endif

#endif /* _SECURITY_PKM_KACS_CAAP_CACHE_H */
