/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PKM_KACS_KMES_RATE_H
#define PKM_KACS_KMES_RATE_H

#include <linux/types.h>

struct pkm_kmes_rate_bucket;

struct pkm_kmes_rate_bucket *pkm_kmes_rate_bucket_alloc(void);
void pkm_kmes_rate_bucket_put(struct pkm_kmes_rate_bucket *bucket);
int pkm_kmes_rate_bucket_reserve(struct pkm_kmes_rate_bucket *bucket,
				 u32 count);
void pkm_kmes_rate_bucket_refund(struct pkm_kmes_rate_bucket *bucket,
				 u32 count);

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kmes_rate_bucket_kunit_set_tokens(
	struct pkm_kmes_rate_bucket *bucket, u32 tokens);
int pkm_kmes_rate_bucket_kunit_set_refill_frozen(
	struct pkm_kmes_rate_bucket *bucket, bool frozen);
int pkm_kmes_rate_bucket_kunit_get_tokens(
	struct pkm_kmes_rate_bucket *bucket, u32 *tokens_out);
#endif

#endif /* PKM_KACS_KMES_RATE_H */
