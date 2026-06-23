// SPDX-License-Identifier: GPL-2.0-only

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/math64.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>
#include <linux/types.h>

#include "../kmes/kmes.h"
#include "kmes_rate.h"
#include "lsm_internal.h"
#include "process_state.h"
#include "token_runtime.h"

struct pkm_kmes_rate_bucket {
	refcount_t refs;
	spinlock_t lock;
	struct list_head list;
	u64 last_refill_ns;
	u32 tokens;
#ifdef CONFIG_SECURITY_PKM_KUNIT
	bool kunit_freeze_refill;
#endif
};

static LIST_HEAD(pkm_kmes_rate_bucket_list);
static DEFINE_SPINLOCK(pkm_kmes_rate_bucket_list_lock);

struct pkm_kmes_rate_bucket *pkm_kmes_rate_bucket_alloc(void)
{
	struct pkm_kmes_rate_bucket *bucket;
	unsigned long flags;

	bucket = kzalloc(sizeof(*bucket), GFP_KERNEL);
	if (!bucket)
		return NULL;

	refcount_set(&bucket->refs, 1);
	spin_lock_init(&bucket->lock);
	INIT_LIST_HEAD(&bucket->list);
	bucket->last_refill_ns = ktime_get_ns();
	bucket->tokens = pkm_kmes_runtime_max_emit_rate_per_process();
	spin_lock_irqsave(&pkm_kmes_rate_bucket_list_lock, flags);
	list_add(&bucket->list, &pkm_kmes_rate_bucket_list);
	spin_unlock_irqrestore(&pkm_kmes_rate_bucket_list_lock, flags);
	return bucket;
}

void pkm_kmes_rate_bucket_put(struct pkm_kmes_rate_bucket *bucket)
{
	unsigned long flags;

	if (!bucket)
		return;
	if (refcount_dec_and_test(&bucket->refs)) {
		spin_lock_irqsave(&pkm_kmes_rate_bucket_list_lock, flags);
		list_del_init(&bucket->list);
		spin_unlock_irqrestore(&pkm_kmes_rate_bucket_list_lock, flags);
		kfree(bucket);
	}
}

static void pkm_kmes_rate_bucket_refill(struct pkm_kmes_rate_bucket *bucket,
					u64 now_ns, u32 rate)
{
	u64 elapsed_ns;
	u64 added;
	u64 consumed_ns;
	u64 tokens;

	if (!bucket || rate == 0)
		return;
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (bucket->kunit_freeze_refill)
		return;
#endif
	if (bucket->tokens >= rate) {
		bucket->tokens = rate;
		bucket->last_refill_ns = now_ns;
		return;
	}

	elapsed_ns = now_ns - bucket->last_refill_ns;
	if (elapsed_ns == 0)
		return;

	added = div_u64(elapsed_ns * (u64)rate, NSEC_PER_SEC);
	if (added == 0)
		return;

	tokens = bucket->tokens + added;
	if (tokens > rate)
		tokens = rate;
	bucket->tokens = (u32)tokens;

	consumed_ns = div_u64(added * NSEC_PER_SEC, rate);
	if (consumed_ns > elapsed_ns)
		consumed_ns = elapsed_ns;
	bucket->last_refill_ns += consumed_ns;
}

int pkm_kmes_rate_bucket_reserve(struct pkm_kmes_rate_bucket *bucket,
				 u32 count)
{
	unsigned long flags;
	u64 now_ns;

	if (!bucket || count == 0)
		return -EPERM;

	now_ns = ktime_get_ns();
	spin_lock_irqsave(&bucket->lock, flags);
	pkm_kmes_rate_bucket_refill(
		bucket, now_ns, pkm_kmes_runtime_max_emit_rate_per_process());
	if (bucket->tokens < count) {
		spin_unlock_irqrestore(&bucket->lock, flags);
		return -EAGAIN;
	}
	bucket->tokens -= count;
	spin_unlock_irqrestore(&bucket->lock, flags);
	return 0;
}

void pkm_kmes_rate_bucket_refund(struct pkm_kmes_rate_bucket *bucket,
				 u32 count)
{
	unsigned long flags;
	u64 tokens;

	if (!bucket || count == 0)
		return;

	spin_lock_irqsave(&bucket->lock, flags);
	tokens = bucket->tokens + (u64)count;
	if (tokens > pkm_kmes_runtime_max_emit_rate_per_process())
		tokens = pkm_kmes_runtime_max_emit_rate_per_process();
	bucket->tokens = (u32)tokens;
	spin_unlock_irqrestore(&bucket->lock, flags);
}

int pkm_kmes_current_process_rate_reserve(u32 count)
{
	struct pkm_kacs_process_state *state;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EPERM;

	return pkm_kmes_rate_bucket_reserve(state->kmes_rate_bucket, count);
}

void pkm_kmes_current_process_rate_refund(u32 count)
{
	struct pkm_kacs_process_state *state;

	if (count == 0)
		return;

	state = pkm_kacs_current_process_state();
	if (!state)
		return;

	pkm_kmes_rate_bucket_refund(state->kmes_rate_bucket, count);
}

void pkm_kmes_rate_buckets_reconfigure(u32 rate)
{
	struct pkm_kmes_rate_bucket *bucket;
	unsigned long list_flags;

	if (rate == 0)
		return;

	spin_lock_irqsave(&pkm_kmes_rate_bucket_list_lock, list_flags);
	list_for_each_entry(bucket, &pkm_kmes_rate_bucket_list, list) {
		unsigned long bucket_flags;

		spin_lock_irqsave(&bucket->lock, bucket_flags);
		if (bucket->tokens > rate)
			bucket->tokens = rate;
		spin_unlock_irqrestore(&bucket->lock, bucket_flags);
	}
	spin_unlock_irqrestore(&pkm_kmes_rate_bucket_list_lock, list_flags);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kmes_rate_bucket_kunit_set_tokens(
	struct pkm_kmes_rate_bucket *bucket, u32 tokens)
{
	unsigned long flags;

	if (!bucket)
		return -EACCES;

	spin_lock_irqsave(&bucket->lock, flags);
	bucket->tokens = tokens;
	bucket->last_refill_ns = ktime_get_ns();
	spin_unlock_irqrestore(&bucket->lock, flags);
	return 0;
}

int pkm_kmes_rate_bucket_kunit_set_refill_frozen(
	struct pkm_kmes_rate_bucket *bucket, bool frozen)
{
	unsigned long flags;

	if (!bucket)
		return -EACCES;

	spin_lock_irqsave(&bucket->lock, flags);
	bucket->kunit_freeze_refill = frozen;
	spin_unlock_irqrestore(&bucket->lock, flags);
	return 0;
}

int pkm_kmes_rate_bucket_kunit_get_tokens(
	struct pkm_kmes_rate_bucket *bucket, u32 *tokens_out)
{
	unsigned long flags;

	if (!tokens_out)
		return -EINVAL;
	if (!bucket)
		return -EACCES;

	spin_lock_irqsave(&bucket->lock, flags);
	*tokens_out = bucket->tokens;
	spin_unlock_irqrestore(&bucket->lock, flags);
	return 0;
}
#endif
