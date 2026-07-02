// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <pkm/psb.h>

#include "kmes_rate.h"
#include "lsm_internal.h"
#include "process_state.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

void pkm_kacs_set_cred_process_state(struct cred *cred,
				     struct pkm_kacs_process_state *state)
{
	struct pkm_kacs_cred_security *sec;

	if (!cred)
		return;

	sec = pkm_kacs_cred(cred);
	if (sec->process_state == state)
		return;
	if (sec->process_state)
		pkm_kacs_process_state_put(sec->process_state);
	sec->process_state = state ? pkm_kacs_process_state_get(state) : NULL;
}

struct pkm_kacs_process_sd *pkm_kacs_process_state_get_sd(
	struct pkm_kacs_process_state *state)
{
	struct pkm_kacs_process_sd *process_sd;
	unsigned long flags;

	if (!state)
		return NULL;

	spin_lock_irqsave(&state->mitigation_lock, flags);
	process_sd = pkm_kacs_process_sd_get(state->process_sd);
	spin_unlock_irqrestore(&state->mitigation_lock, flags);
	return process_sd;
}

void pkm_kacs_process_state_replace_sd_locked(
	struct pkm_kacs_process_state *state, struct pkm_kacs_process_sd *new_sd)
{
	struct pkm_kacs_process_sd *old_sd;
	unsigned long flags;

	if (!state || !new_sd)
		return;

	spin_lock_irqsave(&state->mitigation_lock, flags);
	old_sd = state->process_sd;
	state->process_sd = new_sd;
	spin_unlock_irqrestore(&state->mitigation_lock, flags);

	pkm_kacs_process_sd_put(old_sd);
	trace_kacs_process_state((u64)(uintptr_t)state,
				 READ_ONCE(state->pip_type),
				 READ_ONCE(state->pip_trust),
				 KACS_PST_SD_REPLACE, 0);
}

void pkm_kacs_process_state_replace_sd(
	struct pkm_kacs_process_state *state, struct pkm_kacs_process_sd *new_sd)
{
	if (!state || !new_sd)
		return;

	mutex_lock(&state->sd_lock);
	pkm_kacs_process_state_replace_sd_locked(state, new_sd);
	mutex_unlock(&state->sd_lock);
}

struct pkm_kacs_process_state *pkm_kacs_process_state_alloc(
	const void *primary_token, u32 pip_type, u32 pip_trust,
	u32 mitigation_bits)
{
	struct pkm_kacs_process_state *state;
	struct pkm_kmes_rate_bucket *bucket;
	struct pkm_kacs_process_sd *process_sd;

	if (!primary_token)
		return NULL;

	bucket = pkm_kmes_rate_bucket_alloc();
	if (!bucket) {
		trace_kacs_process_state(0, pip_type, pip_trust,
					 KACS_PST_ALLOC_FAIL, -ENOMEM);
		return NULL;
	}

	process_sd = pkm_kacs_process_sd_alloc(primary_token);
	if (!process_sd) {
		trace_kacs_process_state(0, pip_type, pip_trust,
					 KACS_PST_ALLOC_FAIL, -ENOMEM);
		pkm_kmes_rate_bucket_put(bucket);
		return NULL;
	}

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		trace_kacs_process_state(0, pip_type, pip_trust,
					 KACS_PST_ALLOC_FAIL, -ENOMEM);
		pkm_kacs_process_sd_put(process_sd);
		pkm_kmes_rate_bucket_put(bucket);
		return NULL;
	}

	refcount_set(&state->refs, 1);
	spin_lock_init(&state->mitigation_lock);
	mutex_init(&state->sd_lock);
	pkm_kacs_fill_uuid_v4(state->process_guid);
	state->pip_type = pip_type;
	state->pip_trust = pip_trust;
	state->mitigation_bits = mitigation_bits;
	state->kmes_rate_bucket = bucket;
	state->process_sd = process_sd;
	trace_kacs_process_state((u64)(uintptr_t)state, pip_type, pip_trust,
				 KACS_PST_ALLOC, 0);
	return state;
}

struct pkm_kacs_process_state *pkm_kacs_process_state_get(
	struct pkm_kacs_process_state *state)
{
	if (state)
		refcount_inc(&state->refs);
	return state;
}

void pkm_kacs_process_state_put(struct pkm_kacs_process_state *state)
{
	if (!state)
		return;
	if (!refcount_dec_and_test(&state->refs))
		return;

	trace_kacs_process_state((u64)(uintptr_t)state,
				 READ_ONCE(state->pip_type),
				 READ_ONCE(state->pip_trust), KACS_PST_FREE, 0);
	pkm_kacs_process_sd_put(state->process_sd);
	pkm_kmes_rate_bucket_put(state->kmes_rate_bucket);
	kfree(state);
}

struct pkm_kacs_process_state *pkm_kacs_current_process_state(void)
{
	if (!current || !current->security)
		return NULL;

	return pkm_kacs_task(current)->process_state;
}

void pkm_kacs_clear_pending_exec_pip(void)
{
	struct pkm_kacs_task_security *sec;

	if (!current || !current->security)
		return;

	sec = pkm_kacs_task(current);
	sec->pending_exec_pip_type = 0;
	sec->pending_exec_pip_trust = 0;
	sec->pending_exec_pip_valid = 0;
}

void pkm_kacs_stage_pending_exec_pip(u32 pip_type, u32 pip_trust)
{
	struct pkm_kacs_task_security *sec;

	if (!current || !current->security)
		return;

	sec = pkm_kacs_task(current);
	sec->pending_exec_pip_type = pip_type;
	sec->pending_exec_pip_trust = pip_trust;
	sec->pending_exec_pip_valid = 1;
	trace_kacs_process_state((u64)(uintptr_t)sec->process_state, pip_type,
				 pip_trust, KACS_PST_EXEC_PIP_STAGE, 0);
}

int pkm_kacs_exec_dumpable_after_pip(u32 pip_type, int current_dumpable)
{
	if (pip_type != 0)
		return SUID_DUMP_DISABLE;

	return current_dumpable;
}

void pkm_kacs_apply_pending_exec_dumpable(void)
{
	struct pkm_kacs_task_security *sec;
	int dumpable;
	int hardened;

	if (!current || !current->security || !current->mm)
		return;

	sec = pkm_kacs_task(current);
	if (!sec->pending_exec_pip_valid)
		return;

	dumpable = get_dumpable(current->mm);
	hardened = pkm_kacs_exec_dumpable_after_pip(sec->pending_exec_pip_type,
						    dumpable);
	if (hardened != dumpable) {
		set_dumpable(current->mm, hardened);
		trace_kacs_process_state((u64)(uintptr_t)sec->process_state,
					 sec->pending_exec_pip_type,
					 sec->pending_exec_pip_trust,
					 KACS_PST_DUMPABLE, 0);
	}
}

void pkm_kacs_commit_pending_exec_pip(void)
{
	struct pkm_kacs_task_security *sec;
	struct pkm_kacs_process_state *state;

	if (!current || !current->security)
		return;

	sec = pkm_kacs_task(current);
	if (!sec->pending_exec_pip_valid)
		return;

	state = sec->process_state;
	if (state) {
		WRITE_ONCE(state->pip_type, sec->pending_exec_pip_type);
		WRITE_ONCE(state->pip_trust, sec->pending_exec_pip_trust);
		trace_kacs_process_state((u64)(uintptr_t)state,
					 sec->pending_exec_pip_type,
					 sec->pending_exec_pip_trust,
					 KACS_PST_EXEC_PIP_COMMIT, 0);
	}
	pkm_kacs_clear_pending_exec_pip();
}

u32 pkm_kacs_process_state_mitigation_bits(
	const struct pkm_kacs_process_state *state)
{
	if (!state)
		return 0;

	return READ_ONCE(state->mitigation_bits);
}

bool pkm_kacs_clone_is_blocked_by_no_child(u32 mitigation_bits, u64 clone_flags)
{
	if ((clone_flags & CLONE_THREAD) != 0)
		return false;

	if ((mitigation_bits & KACS_MIT_NO_CHILD) == 0)
		return false;

	trace_kacs_process_state(0, 0, 0, KACS_PST_CLONE_BLOCKED_NOCHILD,
				 -EPERM);
	return true;
}

struct pkm_kacs_process_state *pkm_kacs_inherit_process_state(u64 clone_flags)
{
	struct pkm_kacs_process_state *parent_state;
	struct pkm_kacs_process_state *child_state;
	const void *primary_token;
	u32 mitigation_bits;

	parent_state = pkm_kacs_current_process_state();
	if (!parent_state)
		return NULL;

	mitigation_bits = pkm_kacs_process_state_mitigation_bits(parent_state);

	if ((clone_flags & CLONE_THREAD) != 0) {
		trace_kacs_process_state((u64)(uintptr_t)parent_state,
					 READ_ONCE(parent_state->pip_type),
					 READ_ONCE(parent_state->pip_trust),
					 KACS_PST_INHERIT_SHARE, 0);
		return pkm_kacs_process_state_get(parent_state);
	}

	primary_token = pkm_kacs_current_primary_token_ptr();
	if (!primary_token)
		return NULL;

	child_state = pkm_kacs_process_state_alloc(
		primary_token, READ_ONCE(parent_state->pip_type),
		READ_ONCE(parent_state->pip_trust), mitigation_bits);
	trace_kacs_process_state((u64)(uintptr_t)child_state,
				 READ_ONCE(parent_state->pip_type),
				 READ_ONCE(parent_state->pip_trust),
				 KACS_PST_INHERIT_FORK,
				 child_state ? 0 : -ENOMEM);
	return child_state;
}
