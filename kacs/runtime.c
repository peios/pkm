// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include <pkm/token.h>

#include "lsm_internal.h"
#include "process_state.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

void pkm_kacs_fill_uuid_v4(u8 out[KACS_UUID_BYTES])
{
	if (!out)
		return;

	/*
	 * PCDS GUID layout (MS-DTYP mixed-endian): Data3 is little-endian
	 * in bytes 6-7, so the version-4 nibble is the high nibble of byte 7,
	 * not byte 6 as in RFC 4122 network order (PEI-238).  Data4 is raw,
	 * so the variant bits sit in byte 8 in both layouts.
	 */
	get_random_bytes(out, KACS_UUID_BYTES);
	out[7] = (out[7] & 0x0f) | 0x40;
	out[8] = (out[8] & 0x3f) | 0x80;
}

void *pkm_kacs_zalloc(size_t size)
{
	return kzalloc(size, GFP_KERNEL);
}

void pkm_kacs_free(void *ptr)
{
	kfree(ptr);
}

struct pkm_kacs_deferred_free {
	struct rcu_head rcu;
	void *ptr;
};

static void pkm_kacs_free_after_rcu_cb(struct rcu_head *rcu)
{
	struct pkm_kacs_deferred_free *deferred;

	deferred = container_of(rcu, struct pkm_kacs_deferred_free, rcu);
	kfree(deferred->ptr);
	kfree(deferred);
}

void pkm_kacs_rcu_read_lock(void)
{
	rcu_read_lock();
}

void pkm_kacs_rcu_read_unlock(void)
{
	rcu_read_unlock();
}

void pkm_kacs_free_after_rcu(void *ptr)
{
	struct pkm_kacs_deferred_free *deferred;

	if (!ptr)
		return;

	deferred = kmalloc(sizeof(*deferred), GFP_KERNEL);
	if (!deferred) {
		trace_kacs_privilege(0, KACS_PRIV_RCU_ENOMEM_FALLBACK, -ENOMEM);
		synchronize_rcu();
		kfree(ptr);
		return;
	}

	deferred->ptr = ptr;
	call_rcu(&deferred->rcu, pkm_kacs_free_after_rcu_cb);
}

unsigned long pkm_kacs_local_irq_save(void)
{
	unsigned long flags;

	local_irq_save(flags);
	return flags;
}

void pkm_kacs_local_irq_restore(unsigned long flags)
{
	local_irq_restore(flags);
}

bool pkm_kacs_subjective_cred_context_allowed(bool task_context,
					      bool has_cred,
					      bool has_security_blob,
					      bool has_token)
{
	return task_context && has_cred && has_security_blob && has_token;
}

bool pkm_kacs_current_token_eval_context_allowed(void)
{
	const struct pkm_kacs_cred_security *sec;
	const struct cred *cred;
	bool has_token;

	if (!current || !in_task())
		return false;

	cred = current_cred();
	sec = cred && cred->security ? pkm_kacs_cred(cred) : NULL;
	has_token = sec && sec->token;
	return pkm_kacs_subjective_cred_context_allowed(true, cred != NULL,
							sec != NULL, has_token);
}

const void *pkm_kacs_current_effective_token_ptr(void)
{
	const struct pkm_kacs_cred_security *sec;
	const struct cred *cred;

	if (pkm_kacs_current_token_eval_context_allowed()) {
		cred = current_cred();
		if (!cred || !cred->security)
			return NULL;
		sec = pkm_kacs_cred(cred);
		return sec ? sec->token : NULL;
	}

	return NULL;
}

const void *pkm_kacs_current_primary_token_ptr(void)
{
	return pkm_kacs_cred(current_real_cred())->token;
}

static kacs_uuid_t pkm_kacs_null_uuid(void)
{
	kacs_uuid_t uuid = { };

	return uuid;
}

static kacs_uuid_t pkm_kacs_token_guid_or_null(const void *token)
{
	kacs_uuid_t uuid = { };

	if (!token)
		return uuid;
	if (kacs_rust_token_guid(token, uuid.bytes))
		return pkm_kacs_null_uuid();
	return uuid;
}

kacs_uuid_t kacs_effective_token_guid(void)
{
	return pkm_kacs_token_guid_or_null(
		pkm_kacs_current_effective_token_ptr());
}

kacs_uuid_t kacs_primary_token_guid(void)
{
	const struct pkm_kacs_cred_security *sec;
	const struct cred *cred;

	if (!current || !in_task())
		return pkm_kacs_null_uuid();

	cred = current_real_cred();
	sec = cred && cred->security ? pkm_kacs_cred(cred) : NULL;
	return pkm_kacs_token_guid_or_null(sec ? sec->token : NULL);
}

kacs_uuid_t kacs_process_guid(void)
{
	struct pkm_kacs_process_state *state;
	kacs_uuid_t uuid = { };

	/*
	 * The same guard the other two identity-stamp accessors carry.
	 *
	 * In softirq or hardirq-deferred work `current` is whatever task was
	 * interrupted, so without this the stamp names a process that had
	 * nothing to do with the event.  KMES captures all three stamps
	 * together, and the token pair already nulls out here -- which made the
	 * result read as "no token identity, but process X", a plausible shape
	 * for a kernel-originated event and therefore not obviously wrong to a
	 * consumer.  The stamps are the part of an event a consumer is told it
	 * may trust absolutely, so misattribution is the worst failure this
	 * path has.
	 */
	if (!current || !in_task())
		return uuid;

	state = pkm_kacs_current_process_state();
	if (!state)
		return uuid;

	memcpy(uuid.bytes, state->process_guid, KACS_UUID_BYTES);
	return uuid;
}

int pkm_kacs_current_pip_context(u32 *pip_type, u32 *pip_trust)
{
	struct pkm_kacs_process_state *state;

	if (!pip_type || !pip_trust)
		return -EINVAL;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	*pip_type = READ_ONCE(state->pip_type);
	*pip_trust = READ_ONCE(state->pip_trust);
	return 0;
}

long pkm_kacs_require_enabled_privilege(const void *subject_token,
					u64 privilege)
{
	if (!subject_token || privilege == 0) {
		trace_kacs_privilege(privilege, KACS_PRIV_NULL_OR_ZERO, -EPERM);
		return -EPERM;
	}
	if (!kacs_rust_token_has_enabled_privilege(subject_token, privilege)) {
		trace_kacs_privilege(privilege, KACS_PRIV_NOT_ENABLED, -EPERM);
		return -EPERM;
	}
	if (!kacs_rust_token_mark_privileges_used(subject_token, privilege)) {
		trace_kacs_privilege(privilege, KACS_PRIV_USE_MARK_FAIL, -EPERM);
		return -EPERM;
	}

	return 0;
}

int pkm_kacs_open_by_handle_at(void)
{
	int ret = (int)pkm_kacs_require_enabled_privilege(
		pkm_kacs_current_effective_token_ptr(),
		KACS_SE_CHANGE_NOTIFY_PRIVILEGE);

	trace_kacs_privilege(KACS_SE_CHANGE_NOTIFY_PRIVILEGE,
			     KACS_PRIV_CHANGE_NOTIFY, ret);
	return ret;
}
