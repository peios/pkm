/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_CAAP_CACHE_H
#define _SECURITY_PKM_KACS_CAAP_CACHE_H

#include <linux/types.h>

int pkm_kacs_caap_cache_init(void);
int pkm_kacs_set_caap_internal(const void *policy_sid, u32 policy_sid_len,
			       const void *spec, u32 spec_len);
int pkm_kacs_caap_cache_lock(const void **cache);
void pkm_kacs_caap_cache_unlock(void);
size_t pkm_kacs_caap_cache_len(void);

#endif /* _SECURITY_PKM_KACS_CAAP_CACHE_H */
