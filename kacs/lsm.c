// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM boot token/session substrate.
 *
 * Slices 21, 22, and 25 add the first live credential blob, boot SYSTEM token
 * attachment, narrow public token-open surface, and the PSB PIP fields needed
 * by AccessCheck defaulting. Wider token syscalls, impersonation
 * install/revert, and broader process/object security plumbing remain
 * deliberately out of scope here.
 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/lsm_hooks.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>

#include "caap_cache.h"
#include "kmes.h"
#include "token_runtime.h"

#define PKM_KACS_UNMAPPED_ID 65534U
#define PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS 10000U

struct pkm_kmes_rate_bucket {
	refcount_t refs;
	spinlock_t lock;
	u64 last_refill_ns;
	u32 tokens;
#ifdef CONFIG_SECURITY_PKM_KUNIT
	bool kunit_freeze_refill;
#endif
};

struct pkm_kacs_cred_security {
	const void *token;
	u32 projected_uid;
	u32 projected_gid;
};

struct pkm_kacs_task_security {
	u32 pip_type;
	u32 pip_trust;
	struct pkm_kmes_rate_bucket *kmes_rate_bucket;
};

extern int kacs_rust_init(void);

static const struct lsm_id pkm_lsmid = {
	.name = "pkm",
	.id = 1000,
};
static const void *pkm_kacs_boot_system_token;

static struct lsm_blob_sizes pkm_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct pkm_kacs_cred_security),
	.lbs_task = sizeof(struct pkm_kacs_task_security),
};

static inline struct pkm_kacs_cred_security *pkm_kacs_cred(const struct cred *cred)
{
	return (struct pkm_kacs_cred_security *)((char *)cred->security +
						 pkm_blob_sizes.lbs_cred);
}

static inline struct pkm_kacs_task_security *pkm_kacs_task(
	const struct task_struct *task)
{
	return (struct pkm_kacs_task_security *)((char *)task->security +
						 pkm_blob_sizes.lbs_task);
}

static struct pkm_kmes_rate_bucket *pkm_kmes_rate_bucket_alloc(void)
{
	struct pkm_kmes_rate_bucket *bucket;

	bucket = kzalloc(sizeof(*bucket), GFP_KERNEL);
	if (!bucket)
		return NULL;

	refcount_set(&bucket->refs, 1);
	spin_lock_init(&bucket->lock);
	bucket->last_refill_ns = ktime_get_ns();
	bucket->tokens = PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS;
	return bucket;
}

static struct pkm_kmes_rate_bucket *pkm_kmes_rate_bucket_get(
	struct pkm_kmes_rate_bucket *bucket)
{
	if (bucket)
		refcount_inc(&bucket->refs);
	return bucket;
}

static void pkm_kmes_rate_bucket_put(struct pkm_kmes_rate_bucket *bucket)
{
	if (!bucket)
		return;
	if (refcount_dec_and_test(&bucket->refs))
		kfree(bucket);
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

static int pkm_kmes_rate_bucket_reserve(struct pkm_kmes_rate_bucket *bucket,
					u32 count)
{
	unsigned long flags;
	u64 now_ns;

	if (!bucket || count == 0)
		return -EPERM;

	now_ns = ktime_get_ns();
	spin_lock_irqsave(&bucket->lock, flags);
	pkm_kmes_rate_bucket_refill(bucket, now_ns,
				    PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS);
	if (bucket->tokens < count) {
		spin_unlock_irqrestore(&bucket->lock, flags);
		return -EAGAIN;
	}
	bucket->tokens -= count;
	spin_unlock_irqrestore(&bucket->lock, flags);
	return 0;
}

static void pkm_kmes_rate_bucket_refund(struct pkm_kmes_rate_bucket *bucket,
					 u32 count)
{
	unsigned long flags;
	u64 tokens;

	if (!bucket || count == 0)
		return;

	spin_lock_irqsave(&bucket->lock, flags);
	tokens = bucket->tokens + (u64)count;
	if (tokens > PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS)
		tokens = PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS;
	bucket->tokens = (u32)tokens;
	spin_unlock_irqrestore(&bucket->lock, flags);
}

static void pkm_kacs_assert_boot_caps(struct cred *cred)
{
	kernel_cap_t caps = CAP_EMPTY_SET;

	cap_raise(caps, CAP_CHOWN);
	cap_raise(caps, CAP_DAC_OVERRIDE);
	cap_raise(caps, CAP_DAC_READ_SEARCH);
	cap_raise(caps, CAP_FOWNER);
	cap_raise(caps, CAP_FSETID);
	cap_raise(caps, CAP_KILL);
	cap_raise(caps, CAP_SETGID);
	cap_raise(caps, CAP_SETUID);
	cap_raise(caps, CAP_NET_BROADCAST);
	cap_raise(caps, CAP_IPC_OWNER);
	cap_raise(caps, CAP_LEASE);

	cred->cap_effective = caps;
	cred->cap_permitted = caps;
	cred->cap_inheritable = caps;
	cap_clear(cred->cap_ambient);
}

static void pkm_kacs_stamp_projected_ids(struct pkm_kacs_cred_security *sec)
{
	if (!sec->token) {
		sec->projected_uid = PKM_KACS_UNMAPPED_ID;
		sec->projected_gid = PKM_KACS_UNMAPPED_ID;
		return;
	}

	sec->projected_uid = kacs_rust_token_projected_uid(sec->token);
	sec->projected_gid = kacs_rust_token_projected_gid(sec->token);
}

static int pkm_kacs_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	struct pkm_kacs_cred_security *new_sec = pkm_kacs_cred(new);
	const struct pkm_kacs_cred_security *old_sec = pkm_kacs_cred(old);

	(void)gfp;
	if (old_sec->token)
		new_sec->token = kacs_rust_token_deep_copy(old_sec->token);
	else
		new_sec->token = NULL;

	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_assert_boot_caps(new);
	return 0;
}

static void pkm_kacs_cred_transfer(struct cred *new, const struct cred *old)
{
	struct pkm_kacs_cred_security *new_sec = pkm_kacs_cred(new);
	const struct pkm_kacs_cred_security *old_sec = pkm_kacs_cred(old);

	if (old_sec->token)
		new_sec->token = kacs_rust_token_deep_copy(old_sec->token);
	else
		new_sec->token = NULL;

	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_assert_boot_caps(new);
}

static int pkm_kacs_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct pkm_kacs_cred_security *sec = pkm_kacs_cred(cred);

	(void)gfp;
	sec->token = NULL;
	sec->projected_uid = PKM_KACS_UNMAPPED_ID;
	sec->projected_gid = PKM_KACS_UNMAPPED_ID;
	return 0;
}

static void pkm_kacs_cred_free(struct cred *cred)
{
	struct pkm_kacs_cred_security *sec = pkm_kacs_cred(cred);

	if (sec->token)
		kacs_rust_token_drop(sec->token);
}

static int pkm_kacs_task_alloc(struct task_struct *task, u64 clone_flags)
{
	struct pkm_kacs_task_security *new_sec;
	struct pkm_kacs_task_security *parent_sec;
	struct pkm_kmes_rate_bucket *bucket;

	(void)clone_flags;
	if (!task || !task->security)
		return -EACCES;

	new_sec = pkm_kacs_task(task);
	new_sec->pip_type = 0;
	new_sec->pip_trust = 0;
	new_sec->kmes_rate_bucket = NULL;

	if (current && current->security) {
		parent_sec = pkm_kacs_task(current);
		new_sec->pip_type = parent_sec->pip_type;
		new_sec->pip_trust = parent_sec->pip_trust;
		if ((clone_flags & CLONE_THREAD) != 0)
			bucket = pkm_kmes_rate_bucket_get(
				parent_sec->kmes_rate_bucket);
		else
			bucket = pkm_kmes_rate_bucket_alloc();
	} else {
		bucket = pkm_kmes_rate_bucket_alloc();
	}
	if (!bucket)
		return -ENOMEM;
	new_sec->kmes_rate_bucket = bucket;
	return 0;
}

static void pkm_kacs_task_free(struct task_struct *task)
{
	struct pkm_kacs_task_security *sec;

	if (!task || !task->security)
		return;

	sec = pkm_kacs_task(task);
	pkm_kmes_rate_bucket_put(sec->kmes_rate_bucket);
	sec->kmes_rate_bucket = NULL;
}

static struct security_hook_list pkm_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, pkm_kacs_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, pkm_kacs_cred_transfer),
	LSM_HOOK_INIT(cred_alloc_blank, pkm_kacs_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, pkm_kacs_cred_free),
	LSM_HOOK_INIT(task_alloc, pkm_kacs_task_alloc),
	LSM_HOOK_INIT(task_free, pkm_kacs_task_free),
};

void *pkm_kacs_zalloc(size_t size)
{
	return kzalloc(size, GFP_KERNEL);
}

void pkm_kacs_free(void *ptr)
{
	kfree(ptr);
}

const void *pkm_kacs_current_effective_token_ptr(void)
{
	return pkm_kacs_cred(current_cred())->token;
}

const void *pkm_kacs_current_primary_token_ptr(void)
{
	return pkm_kacs_cred(current_real_cred())->token;
}

const void *pkm_kacs_boot_system_token_ptr(void)
{
	return pkm_kacs_boot_system_token;
}

int pkm_kacs_current_pip_context(u32 *pip_type, u32 *pip_trust)
{
	struct pkm_kacs_task_security *sec;

	if (!pip_type || !pip_trust)
		return -EINVAL;
	if (!current || !current->security)
		return -EACCES;

	sec = pkm_kacs_task(current);
	*pip_type = sec->pip_type;
	*pip_trust = sec->pip_trust;
	return 0;
}

int pkm_kmes_current_process_rate_reserve(u32 count)
{
	struct pkm_kacs_task_security *sec;

	if (!current || !current->security)
		return -EPERM;
	sec = pkm_kacs_task(current);
	return pkm_kmes_rate_bucket_reserve(sec->kmes_rate_bucket, count);
}

void pkm_kmes_current_process_rate_refund(u32 count)
{
	struct pkm_kacs_task_security *sec;

	if (!current || !current->security || count == 0)
		return;
	sec = pkm_kacs_task(current);
	pkm_kmes_rate_bucket_refund(sec->kmes_rate_bucket, count);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
void pkm_kacs_kunit_set_current_pip_context(u32 pip_type, u32 pip_trust)
{
	struct pkm_kacs_task_security *sec;

	if (!current || !current->security)
		return;

	sec = pkm_kacs_task(current);
	sec->pip_type = pip_type;
	sec->pip_trust = pip_trust;
}

int pkm_kmes_kunit_set_current_process_rate_tokens(u32 tokens)
{
	struct pkm_kacs_task_security *sec;
	unsigned long flags;

	if (!current || !current->security)
		return -EACCES;
	if (tokens > PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS)
		return -EINVAL;

	sec = pkm_kacs_task(current);
	if (!sec->kmes_rate_bucket)
		return -EACCES;

	spin_lock_irqsave(&sec->kmes_rate_bucket->lock, flags);
	sec->kmes_rate_bucket->tokens = tokens;
	sec->kmes_rate_bucket->last_refill_ns = ktime_get_ns();
	spin_unlock_irqrestore(&sec->kmes_rate_bucket->lock, flags);
	return 0;
}

int pkm_kmes_kunit_set_current_process_rate_refill_frozen(bool frozen)
{
	struct pkm_kacs_task_security *sec;
	unsigned long flags;

	if (!current || !current->security)
		return -EACCES;

	sec = pkm_kacs_task(current);
	if (!sec->kmes_rate_bucket)
		return -EACCES;

	spin_lock_irqsave(&sec->kmes_rate_bucket->lock, flags);
	sec->kmes_rate_bucket->kunit_freeze_refill = frozen;
	spin_unlock_irqrestore(&sec->kmes_rate_bucket->lock, flags);
	return 0;
}

int pkm_kmes_kunit_get_current_process_rate_tokens(u32 *tokens_out)
{
	struct pkm_kacs_task_security *sec;
	unsigned long flags;

	if (!tokens_out)
		return -EINVAL;
	if (!current || !current->security)
		return -EACCES;

	sec = pkm_kacs_task(current);
	if (!sec->kmes_rate_bucket)
		return -EACCES;

	spin_lock_irqsave(&sec->kmes_rate_bucket->lock, flags);
	*tokens_out = sec->kmes_rate_bucket->tokens;
	spin_unlock_irqrestore(&sec->kmes_rate_bucket->lock, flags);
	return 0;
}
#endif

int pkm_kacs_resolve_ctx_from_token(const void *token,
				    struct pkm_kacs_resolved_ctx *out)
{
	u32 pip_type;
	u32 pip_trust;
	int ret;

	if (!out)
		return -EINVAL;
	if (!token)
		return -EACCES;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	out->kind = PKM_KACS_RESOLVED_CTX_TOKEN;
	out->_reserved = 0;
	out->token = token;
	out->caap_cache = NULL;
	out->default_pip_type = pip_type;
	out->default_pip_trust = pip_trust;
	return 0;
}

int pkm_kacs_resolve_current_effective_ctx(struct pkm_kacs_resolved_ctx *out)
{
	return pkm_kacs_resolve_ctx_from_token(
		pkm_kacs_current_effective_token_ptr(), out);
}

int pkm_kacs_resolve_current_primary_ctx(struct pkm_kacs_resolved_ctx *out)
{
	return pkm_kacs_resolve_ctx_from_token(
		pkm_kacs_current_primary_token_ptr(), out);
}

static int __init pkm_init(void)
{
	const void *system_token;
	struct pkm_kacs_cred_security *sec;
	struct pkm_kacs_task_security *task_sec;
	int ret;

	if (IS_ENABLED(CONFIG_SECURITY_SELINUX) ||
	    IS_ENABLED(CONFIG_SECURITY_APPARMOR) ||
	    IS_ENABLED(CONFIG_SECURITY_SMACK) ||
	    IS_ENABLED(CONFIG_SECURITY_TOMOYO) ||
	    IS_ENABLED(CONFIG_BPF_LSM)) {
		pr_err("pkm: conflicting MAC or BPF LSM detected\n");
		return -EINVAL;
	}

	security_add_hooks(pkm_hooks, ARRAY_SIZE(pkm_hooks), &pkm_lsmid);

	ret = kacs_rust_init();
	if (ret) {
		pr_err("pkm: slow-track Rust init failed (%d)\n", ret);
		return ret;
	}

	ret = pkm_kacs_caap_cache_init();
	if (ret) {
		pr_err("pkm: CAAP cache init failed (%d)\n", ret);
		return ret;
	}

	ret = pkm_kmes_init();
	if (ret) {
		pr_err("pkm: KMES init failed (%d)\n", ret);
		return ret;
	}

	system_token = kacs_rust_create_boot_system_token();
	if (!system_token)
		return -ENOMEM;
	pkm_kacs_boot_system_token = system_token;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->kmes_rate_bucket) {
		task_sec->kmes_rate_bucket = pkm_kmes_rate_bucket_alloc();
		if (!task_sec->kmes_rate_bucket)
			return -ENOMEM;
	}

	sec = pkm_kacs_cred(current_cred());
	sec->token = system_token;
	pkm_kacs_stamp_projected_ids(sec);
	pkm_kacs_assert_boot_caps((struct cred *)current_cred());

	if (current_cred() != current_real_cred()) {
		struct pkm_kacs_cred_security *real_sec =
			pkm_kacs_cred(current_real_cred());

		real_sec->token = kacs_rust_token_clone(system_token);
		pkm_kacs_stamp_projected_ids(real_sec);
		pkm_kacs_assert_boot_caps((struct cred *)current_real_cred());
	}

	pr_info("pkm: slow-track kernel scaffold initialized\n");
	return 0;
}

DEFINE_LSM(pkm) = {
	.id = &pkm_lsmid,
	.init = pkm_init,
	.blobs = &pkm_blob_sizes,
};
