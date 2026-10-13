// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/types.h>

#include "../kmes/event_policy.h"
#include "access_check.h"
#include "capability.h"
#include "cred_lifecycle.h"
#include "lsm_internal.h"
#include "primary_token.h"
#include "process_state.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

struct pkm_kacs_primary_install_prepare {
	struct cred *new_real;
	struct cred *new_effective;
};

struct pkm_kacs_primary_install_work {
	struct callback_head twork;
	const void *token;
	struct task_struct *task;
	u64 epoch;
};

struct pkm_kacs_primary_install_batch {
	struct pkm_kacs_primary_install_work **works;
	size_t count;
};

static long pkm_kacs_revert_current_impersonation(void);

#if IS_ENABLED(CONFIG_SECURITY_PKM_KUNIT)
/* Fault injection is limited to the requesting KUnit task and consumed once. */
static struct task_struct *pkm_kacs_primary_fail_prepare_task;
#endif

long pkm_kacs_prepare_current_token_cred(const void *token, struct cred **out)
{
	struct pkm_kacs_cred_security *new_sec;
	const void *token_ref;
	struct cred *new;
	long ret;

	if (!token || !out)
		return -EINVAL;

	*out = NULL;
	token_ref = kacs_rust_token_clone(token);
	if (!token_ref)
		return -EACCES;

	new = prepare_creds();
	if (!new) {
		kacs_rust_token_drop(token_ref);
		return -ENOMEM;
	}

	new_sec = pkm_kacs_cred(new);
	ret = pkm_kacs_project_linux_cred_from_token(new, token_ref);
	if (ret) {
		abort_creds(new);
		kacs_rust_token_drop(token_ref);
		return ret;
	}
	if (new_sec->token)
		kacs_rust_token_drop(new_sec->token);
	new_sec->token = token_ref;
	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_raise_allow_compat_caps(new);
	*out = new;
	return 0;
}

static void pkm_kacs_abort_primary_install_prepare(
	struct pkm_kacs_primary_install_prepare *prepared)
{
	if (!prepared)
		return;

	if (prepared->new_effective)
		abort_creds(prepared->new_effective);
	if (prepared->new_real)
		abort_creds(prepared->new_real);
	prepared->new_effective = NULL;
	prepared->new_real = NULL;
}

static long pkm_kacs_prepare_current_primary_install(
	const void *new_primary_token,
	struct pkm_kacs_primary_install_prepare *prepared)
{
	struct pkm_kacs_task_security *task_sec;
	long ret;

	if (!new_primary_token || !prepared || !current || !current->security)
		return -EACCES;

	memset(prepared, 0, sizeof(*prepared));
#if IS_ENABLED(CONFIG_SECURITY_PKM_KUNIT)
	if (cmpxchg(&pkm_kacs_primary_fail_prepare_task, current, NULL) == current)
		return -ENOMEM;
#endif
	task_sec = pkm_kacs_task(current);

	ret = pkm_kacs_prepare_current_token_cred(new_primary_token,
						  &prepared->new_real);
	if (ret)
		return ret;

	if (!task_sec->impersonation_saved_cred)
		return 0;

	ret = pkm_kacs_prepare_current_token_cred(
		pkm_kacs_current_effective_token_ptr(),
		&prepared->new_effective);
	if (ret) {
		pkm_kacs_abort_primary_install_prepare(prepared);
		return ret;
	}

	return 0;
}

static long pkm_kacs_apply_current_primary_install(
	struct pkm_kacs_primary_install_prepare *prepared)
{
	struct pkm_kacs_task_security *task_sec;
	u64 new_id;

	if (!prepared || !prepared->new_real || !current || !current->security)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	new_id = (u64)(uintptr_t)pkm_kacs_cred(prepared->new_real)->token;
	if (prepared->new_effective) {
		long ret;

		ret = pkm_kacs_revert_current_impersonation();
		if (ret)
			return ret;
	}

	commit_creds(prepared->new_real);
	prepared->new_real = NULL;

	if (prepared->new_effective) {
		task_sec->impersonation_saved_cred =
			override_creds(prepared->new_effective);
		prepared->new_effective = NULL;
	}

	trace_kacs_primary_install(0, new_id, KACS_PRIM_APPLY_COMMIT, 0);
	return 0;
}

/*
 * Why an impersonation ended, for kacs.impersonation.reverted's
 * operation.name. SILENT is the primary-token install, which takes the
 * impersonation down only to put it straight back over the new real cred
 * (impersonation survives it), so nothing has ended and nothing is written.
 */
#define PKM_KACS_REVERT_SILENT 0U
#define PKM_KACS_REVERT_SYSCALL 1U
#define PKM_KACS_REVERT_EXEC 2U
#define PKM_KACS_REVERT_REPLACED 3U

static long pkm_kacs_revert_current_impersonation_for(u32 cause);

static long pkm_kacs_revert_current_impersonation(void)
{
	return pkm_kacs_revert_current_impersonation_for(PKM_KACS_REVERT_SILENT);
}

/*
 * kacs.impersonation.reverted (PKM §3.5): the thread acts as `subject` again
 * and gave up `dropped`. Best effort.
 */
static void pkm_kacs_audit_impersonation_reverted(const void *dropped,
						  u32 cause, long err)
{
	const void *subject;
	u32 pip_type = 0;
	u32 pip_trust = 0;

	if (!pkm_kmes_event_enabled(PKM_KMES_EV_KACS_IMPERSONATION_REVERTED))
		return;
	subject = pkm_kacs_current_effective_token_ptr();
	if (!subject || !dropped)
		return;
	if (pkm_kacs_current_pip_context(&pip_type, &pip_trust)) {
		pip_type = 0;
		pip_trust = 0;
	}
	(void)kacs_rust_emit_impersonation_reverted(
		subject, dropped, cause, (s32)err, (u64)task_pid_nr(current),
		pip_type, pip_trust);
}

static long pkm_kacs_revert_current_impersonation_for(u32 cause)
{
	struct pkm_kacs_task_security *task_sec;
	const void *dropped = NULL;

	if (!current || !current->security)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->impersonation_saved_cred)
		return 0;

	/*
	 * Hold the impersonation token across the revert: dropping the
	 * override cred below can free it, and the record names it. The hold
	 * is for the record alone, so the emission policy is asked first.
	 */
	if (cause != PKM_KACS_REVERT_SILENT &&
	    pkm_kmes_event_enabled(PKM_KMES_EV_KACS_IMPERSONATION_REVERTED))
		dropped = kacs_rust_token_clone(
			pkm_kacs_current_effective_token_ptr());

	trace_kacs_primary_install(
		(u64)(uintptr_t)pkm_kacs_cred(task_sec->impersonation_saved_cred)
			->token,
		0, KACS_PRIM_IMPERSONATE_REVERT, 0);
	/*
	 * override_creds() and revert_creds() take and drop no references:
	 * the impersonation cred's one reference passed to current->cred at
	 * impersonate time and comes back here. Dropping it is what frees
	 * the impersonation token and, with its last token, its logon
	 * session; it was once discarded, leaking a cred and a token on
	 * every revert (PEI-1313).
	 */
	put_cred(revert_creds(task_sec->impersonation_saved_cred));
	task_sec->impersonation_saved_cred = NULL;
	if (dropped) {
		pkm_kacs_audit_impersonation_reverted(dropped, cause, 0);
		kacs_rust_token_drop(dropped);
	}
	return 0;
}

static void pkm_kacs_free_primary_install_work(
	struct pkm_kacs_primary_install_work *work)
{
	if (!work)
		return;

	if (work->token)
		kacs_rust_token_drop(work->token);
	if (work->task)
		put_task_struct(work->task);
	kfree(work);
}

static void pkm_kacs_discard_prepared_primary_installs(
	struct pkm_kacs_primary_install_batch *batch)
{
	size_t i;

	if (!batch)
		return;

	for (i = 0; i < batch->count; i++)
		pkm_kacs_free_primary_install_work(batch->works[i]);
	kfree(batch->works);
	batch->works = NULL;
	batch->count = 0;
}

/* Caller holds primary_lock across the epoch check and credential commit. */
static long pkm_kacs_apply_primary_epoch(struct pkm_kacs_process_state *state,
					const void *token, u64 epoch)
{
	struct pkm_kacs_primary_install_prepare prepared = { };
	struct pkm_kacs_task_security *sec = pkm_kacs_task(current);
	long ret;

	lockdep_assert_held(&state->primary_lock);
	if (!state->desired_primary_token || epoch != state->primary_epoch ||
	    sec->primary_epoch >= epoch)
		return 0;

	ret = pkm_kacs_prepare_current_primary_install(token, &prepared);
	if (!ret)
		ret = pkm_kacs_apply_current_primary_install(&prepared);
	if (ret)
		pkm_kacs_abort_primary_install_prepare(&prepared);
	else
		sec->primary_epoch = epoch;
	return ret;
}

static void pkm_kacs_primary_install_task_work(struct callback_head *twork)
{
	struct pkm_kacs_primary_install_work *work =
		container_of(twork, struct pkm_kacs_primary_install_work, twork);
	struct pkm_kacs_process_state *state = pkm_kacs_current_process_state();
	long ret;

	mutex_lock(&state->primary_lock);
	ret = pkm_kacs_apply_primary_epoch(state, work->token, work->epoch);
	mutex_unlock(&state->primary_lock);
	/* Requeued work must pass the epoch check again, never replay its token. */
	if (ret == -ENOMEM &&
	    task_work_add(current, &work->twork, TWA_SIGNAL) == 0) {
		trace_kacs_primary_install(0, (u64)(uintptr_t)work->token,
					   KACS_PRIM_SIBLING_REQUEUE, ret);
		return;
	}
	if (ret) {
		trace_kacs_primary_install(0, (u64)(uintptr_t)work->token,
					   KACS_PRIM_SIBLING_FAILED, ret);
		pr_warn("pkm: queued primary-token install failed (%ld)\n", ret);
	}

	pkm_kacs_free_primary_install_work(work);
}

static void pkm_kacs_primary_enroll_task_work(struct callback_head *twork)
{
	struct pkm_kacs_process_state *state = pkm_kacs_current_process_state();
	long ret;

	mutex_lock(&state->primary_lock);
	ret = pkm_kacs_apply_primary_epoch(state, state->desired_primary_token,
					state->primary_epoch);
	mutex_unlock(&state->primary_lock);
	if (ret == -ENOMEM && task_work_add(current, twork, TWA_SIGNAL) == 0)
		return;
	if (ret)
		pr_warn("pkm: primary-token enrollment failed (%ld)\n", ret);
}

/*
 * copy_process() calls this after thread-list publication and task_works
 * initialization, but before the child can run. An install either sees the
 * published child or precedes this callback's read of the desired epoch.
 * Queueing in security_task_alloc() would be erased by task_works = NULL.
 * The embedded callback needs no allocation or task reference and is never
 * queued on a failed clone. It also covers create_io_thread().
 */
void pkm_kacs_primary_thread_enroll(struct task_struct *task)
{
	struct pkm_kacs_task_security *sec = pkm_kacs_task(task);

	init_task_work(&sec->primary_enroll_work, pkm_kacs_primary_enroll_task_work);
	WARN_ON_ONCE(task_work_add(task, &sec->primary_enroll_work, TWA_SIGNAL));
}

/*
 * Exec holds cred_guard_mutex until after committed_creds. @pending reports
 * that the selected token is an install this thread has not yet serviced, so
 * exec must also give the new cred that token's Linux identity.
 */
const void *pkm_kacs_primary_token_for_exec(bool *pending)
{
	struct pkm_kacs_process_state *state = pkm_kacs_current_process_state();
	const void *token;

	*pending = false;
	if (!state || !current->signal)
		return NULL;
	lockdep_assert_held(&current->signal->cred_guard_mutex);
	mutex_lock(&state->primary_lock);
	if (state->desired_primary_token &&
	    pkm_kacs_task(current)->primary_epoch < state->primary_epoch) {
		token = state->desired_primary_token;
		*pending = true;
	} else {
		token = pkm_kacs_current_primary_token_ptr();
	}
	token = kacs_rust_token_clone(token);
	mutex_unlock(&state->primary_lock);
	return token;
}

void pkm_kacs_primary_exec_committed(void)
{
	struct pkm_kacs_process_state *state = pkm_kacs_current_process_state();
	const void *old;

	if (!state)
		return;
	/* de_thread() has removed siblings. Exec's derived token supersedes any
	 * queued pre-exec install, including a retry on this surviving task.
	 */
	mutex_lock(&state->primary_lock);
	old = state->desired_primary_token;
	state->desired_primary_token = NULL;
	pkm_kacs_task(current)->primary_epoch = state->primary_epoch;
	mutex_unlock(&state->primary_lock);
	kacs_rust_token_drop(old);
}

static long pkm_kacs_prepare_sibling_primary_installs(
	const void *token,
	struct pkm_kacs_primary_install_batch *batch)
{
	struct task_struct **tasks = NULL;
	struct task_struct *leader;
	struct task_struct *task;
	unsigned int capacity;
	size_t count = 0;
	size_t i;
	long ret = 0;

	if (!token || !batch || !current || !current->signal)
		return -EACCES;

	memset(batch, 0, sizeof(*batch));
	capacity = READ_ONCE(current->signal->nr_threads);
	if (capacity <= 1)
		return 0;

	tasks = kcalloc(capacity - 1, sizeof(*tasks), GFP_KERNEL);
	if (!tasks)
		return -ENOMEM;

	leader = current->group_leader;
	rcu_read_lock();
	if (leader && leader != current &&
	    (READ_ONCE(leader->flags) & PF_EXITING) == 0) {
		get_task_struct(leader);
		tasks[count++] = leader;
	}
	for_each_thread(leader, task) {
		if (task == current || task == leader)
			continue;
		if ((READ_ONCE(task->flags) & PF_EXITING) != 0)
			continue;
		if (count >= capacity - 1) {
			ret = -EAGAIN;
			break;
		}
		get_task_struct(task);
		tasks[count++] = task;
	}
	rcu_read_unlock();
	if (ret)
		goto out_cleanup_tasks;

	batch->works = kcalloc(count, sizeof(*batch->works), GFP_KERNEL);
	if (!batch->works) {
		ret = -ENOMEM;
		goto out_cleanup_tasks;
	}

	for (i = 0; i < count; i++) {
		struct pkm_kacs_primary_install_work *work;
		const void *token_ref;

		work = kzalloc(sizeof(*work), GFP_KERNEL);
		if (!work) {
			ret = -ENOMEM;
			goto out_cleanup_batch;
		}

		token_ref = kacs_rust_token_clone(token);
		if (!token_ref) {
			kfree(work);
			ret = -ENOMEM;
			goto out_cleanup_batch;
		}

		init_task_work(&work->twork, pkm_kacs_primary_install_task_work);
		work->token = token_ref;
		work->task = tasks[i];
		tasks[i] = NULL;
		batch->works[i] = work;
	}

	batch->count = count;
	kfree(tasks);
	return 0;

out_cleanup_batch:
	batch->count = count;
	pkm_kacs_discard_prepared_primary_installs(batch);
out_cleanup_tasks:
	for (i = 0; i < count; i++) {
		if (tasks[i])
			put_task_struct(tasks[i]);
	}
	kfree(tasks);
	return ret;
}

static void pkm_kacs_queue_prepared_primary_installs(
	struct pkm_kacs_primary_install_batch *batch, u64 epoch)
{
	size_t i;

	if (!batch)
		return;

	for (i = 0; i < batch->count; i++) {
		struct pkm_kacs_primary_install_work *work = batch->works[i];
		long ret;

		if (!work)
			continue;
		if ((READ_ONCE(work->task->flags) & PF_EXITING) != 0) {
			pkm_kacs_free_primary_install_work(work);
			batch->works[i] = NULL;
			continue;
		}

		work->epoch = epoch;
		ret = task_work_add(work->task, &work->twork, TWA_SIGNAL);
		if (ret < 0) {
			pr_warn("pkm: sibling primary-token queue failed (%ld)\n",
				ret);
			pkm_kacs_free_primary_install_work(work);
			batch->works[i] = NULL;
			continue;
		}

		batch->works[i] = NULL;
	}

	kfree(batch->works);
	batch->works = NULL;
	batch->count = 0;
}

int pkm_kacs_install_current_primary_token(const void *token)
{
	struct pkm_kacs_primary_install_prepare prepared = { };
	struct pkm_kacs_primary_install_batch sibling_batch = { };
	struct pkm_kacs_process_state *state;
	struct pkm_kacs_process_sd *new_sd = NULL;
	const void *old_primary_token;
	const void *token_ref = NULL;
	const void *old_desired;
	u64 old_id;
	long ret;

	if (!token || !current || !current->security || !current->signal)
		return -EACCES;

	state = pkm_kacs_current_process_state();
	if (!state || !pkm_kacs_current_primary_token_ptr())
		return -EACCES;

	/*
	 * Exec holds this through de_thread() and credential commit. A sibling
	 * waiting here must be killable so exec can reap it, never deadlock
	 * waiting for an installer blocked on the mutex exec itself holds.
	 * Match exec's ordering: cred_guard_mutex before primary_lock.
	 */
	ret = mutex_lock_killable(&current->signal->cred_guard_mutex);
	if (ret)
		return ret;
	mutex_lock(&state->primary_lock);
	if (state->primary_epoch == U64_MAX) {
		ret = -EOVERFLOW;
		goto out;
	}
	/* A lagging installer must compare the process's last published identity,
	 * not its still-old local cred, when deciding whether to replace the SD.
	 */
	old_primary_token = state->desired_primary_token ?
		state->desired_primary_token : pkm_kacs_current_primary_token_ptr();
	old_id = (u64)(uintptr_t)old_primary_token;
	ret = pkm_kacs_prepare_sibling_primary_installs(token, &sibling_batch);
	if (ret)
		goto out;
	ret = pkm_kacs_prepare_current_primary_install(token, &prepared);
	if (ret)
		goto out;

	token_ref = kacs_rust_token_clone(token);
	if (!token_ref) {
		ret = -ENOMEM;
		goto out;
	}
	if (!kacs_rust_token_same_user_sid(old_primary_token, token)) {
		new_sd = pkm_kacs_process_sd_alloc(token);
		if (!new_sd) {
			trace_kacs_primary_install(old_id, (u64)(uintptr_t)token,
						  KACS_PRIM_SD_ALLOC_FAIL, -ENOMEM);
			ret = -ENOMEM;
			goto out;
		}
	}

	ret = pkm_kacs_apply_current_primary_install(&prepared);
	if (ret)
		goto out;

	old_desired = state->desired_primary_token;
	state->desired_primary_token = token_ref;
	token_ref = NULL;
	state->primary_epoch++;
	pkm_kacs_task(current)->primary_epoch = state->primary_epoch;
	kacs_rust_token_drop(old_desired);
	if (new_sd) {
		pkm_kacs_process_state_replace_sd(state, new_sd);
		new_sd = NULL;
		trace_kacs_primary_install(old_id, (u64)(uintptr_t)token,
					   KACS_PRIM_SD_REALLOC, 0);
	}

	pkm_kacs_queue_prepared_primary_installs(&sibling_batch,
						state->primary_epoch);
	trace_kacs_primary_install(old_id, (u64)(uintptr_t)token,
				   KACS_PRIM_INSTALL_OK, 0);
out:
	pkm_kacs_abort_primary_install_prepare(&prepared);
	pkm_kacs_process_sd_put(new_sd);
	pkm_kacs_discard_prepared_primary_installs(&sibling_batch);
	kacs_rust_token_drop(token_ref);
	mutex_unlock(&state->primary_lock);
	mutex_unlock(&current->signal->cred_guard_mutex);
	return ret;
}

int pkm_kacs_install_impersonation_token(const void *token)
{
	struct pkm_kacs_task_security *task_sec;
	struct pkm_kacs_cred_security *new_sec;
	struct cred *new;
	long ret;

	if (!token || !current || !current->security)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	ret = pkm_kacs_revert_current_impersonation_for(PKM_KACS_REVERT_REPLACED);
	if (ret)
		return ret;

	new = prepare_creds();
	if (!new) {
		trace_kacs_primary_install(0, (u64)(uintptr_t)token,
					   KACS_PRIM_IMPERSONATE_INSTALL,
					   -ENOMEM);
		return -ENOMEM;
	}

	new_sec = pkm_kacs_cred(new);
	ret = pkm_kacs_project_linux_cred_from_token(new, token);
	if (ret) {
		trace_kacs_primary_install(0, (u64)(uintptr_t)token,
					   KACS_PRIM_IMPERSONATE_INSTALL, ret);
		abort_creds(new);
		return ret;
	}
	if (new_sec->token)
		kacs_rust_token_drop(new_sec->token);
	new_sec->token = token;
	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_raise_allow_compat_caps(new);

	task_sec->impersonation_saved_cred = override_creds(new);
	trace_kacs_primary_install(0, (u64)(uintptr_t)token,
				   KACS_PRIM_IMPERSONATE_INSTALL, 0);
	return 0;
}

int pkm_kacs_revert_impersonation(void)
{
	return pkm_kacs_revert_current_impersonation_for(PKM_KACS_REVERT_SYSCALL);
}

/* The revert exec performs before it commits the new image's creds. */
int pkm_kacs_revert_impersonation_for_exec(void)
{
	return pkm_kacs_revert_current_impersonation_for(PKM_KACS_REVERT_EXEC);
}

SYSCALL_DEFINE0(kacs_revert)
{
	return pkm_kacs_revert_impersonation();
}

#if IS_ENABLED(CONFIG_SECURITY_PKM_KUNIT)
#include <kunit/test.h>
#include <kunit/resource.h>
#include <linux/completion.h>
#include <linux/debug_locks.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched/user.h>

#include "exec.h"
#include "kunit_common.h"

struct pkm_kacs_primary_epoch_fixture {
	const void *original;
	const void *a;
	const void *b;
	u64 initial_epoch;
};

static int pkm_kacs_primary_epoch_test_init(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	test->priv = f;
	f->original = kacs_rust_token_clone(pkm_kacs_current_primary_token_ptr());
	f->a = kacs_rust_token_deep_copy(f->original);
	f->b = kacs_rust_token_deep_copy(f->original);
	f->initial_epoch = pkm_kacs_task(current)->primary_epoch;
	if (!f->original || !f->a || !f->b) {
		kacs_rust_token_drop(f->b);
		kacs_rust_token_drop(f->a);
		kacs_rust_token_drop(f->original);
		return -ENOMEM;
	}
	return 0;
}

static void pkm_kacs_primary_epoch_test_exit(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;

	WRITE_ONCE(pkm_kacs_primary_fail_prepare_task, NULL);
	task_work_run();
	KUNIT_EXPECT_EQ(test, pkm_kacs_install_current_primary_token(f->original), 0);
	kacs_rust_token_drop(f->b);
	kacs_rust_token_drop(f->a);
	kacs_rust_token_drop(f->original);
}

/* Model a sibling that has not yet serviced its pending propagation work. */
static long pkm_kacs_primary_epoch_lag(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	struct pkm_kacs_primary_install_prepare prepared = { };
	long ret;

	ret = pkm_kacs_prepare_current_primary_install(f->original, &prepared);
	if (!ret)
		ret = pkm_kacs_apply_current_primary_install(&prepared);
	pkm_kacs_abort_primary_install_prepare(&prepared);
	if (!ret)
		pkm_kacs_task(current)->primary_epoch = f->initial_epoch;
	return ret;
}

static struct pkm_kacs_primary_install_work *
pkm_kacs_primary_epoch_work(const void *token, u64 epoch)
{
	struct pkm_kacs_primary_install_work *work;

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work)
		return NULL;
	init_task_work(&work->twork, pkm_kacs_primary_install_task_work);
	work->token = kacs_rust_token_clone(token);
	get_task_struct(current);
	work->task = current;
	work->epoch = epoch;
	return work;
}

static void pkm_kacs_primary_epoch_lifo(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	struct pkm_kacs_primary_install_work *a, *b;
	u64 epoch_a, epoch_b;

	KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(f->a), 0);
	epoch_a = pkm_kacs_current_process_state()->primary_epoch;
	KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(f->b), 0);
	epoch_b = pkm_kacs_current_process_state()->primary_epoch;
	KUNIT_ASSERT_GT(test, epoch_b, epoch_a);
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_epoch_lag(test), 0L);
	a = pkm_kacs_primary_epoch_work(f->a, epoch_a);
	KUNIT_ASSERT_NOT_NULL(test, a);
	KUNIT_ASSERT_EQ(test, task_work_add(current, &a->twork, TWA_NONE), 0);
	b = pkm_kacs_primary_epoch_work(f->b, epoch_b);
	KUNIT_ASSERT_NOT_NULL(test, b);
	KUNIT_ASSERT_EQ(test, task_work_add(current, &b->twork, TWA_NONE), 0);
	/* Actual Linux task_work_run executes B then A. A must not undo B. */
	task_work_run();
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(), f->b);
	KUNIT_EXPECT_EQ(test, pkm_kacs_task(current)->primary_epoch, epoch_b);
}

static void pkm_kacs_primary_epoch_retry(struct kunit *test, bool supersede)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	struct pkm_kacs_primary_install_work *a;
	u64 epoch;

	KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(f->a), 0);
	epoch = pkm_kacs_current_process_state()->primary_epoch;
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_epoch_lag(test), 0L);
	a = pkm_kacs_primary_epoch_work(f->a, epoch);
	KUNIT_ASSERT_NOT_NULL(test, a);
	WRITE_ONCE(pkm_kacs_primary_fail_prepare_task, current);
	pkm_kacs_primary_install_task_work(&a->twork);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(), f->original);
	KUNIT_EXPECT_TRUE(test, task_work_pending(current));
	if (supersede)
		KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(f->b), 0);
	task_work_run();
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    supersede ? f->b : f->a);
}

static void pkm_kacs_primary_epoch_retry_current(struct kunit *test)
{
	pkm_kacs_primary_epoch_retry(test, false);
}

static void pkm_kacs_primary_epoch_retry_obsolete(struct kunit *test)
{
	pkm_kacs_primary_epoch_retry(test, true);
}

static void pkm_kacs_primary_epoch_enroll(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;

	KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(f->a), 0);
	KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(f->b), 0);
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_epoch_lag(test), 0L);
	/* A clone missed both sibling snapshots; enrollment must read latest. */
	pkm_kacs_primary_thread_enroll(current);
	task_work_run();
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(), f->b);
}

static void pkm_kacs_primary_epoch_exec(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	struct pkm_kacs_primary_install_work *a;
	struct pkm_kacs_primary_install_prepare prepared = { };

	KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(f->a), 0);
	a = pkm_kacs_primary_epoch_work(f->a,
		pkm_kacs_current_process_state()->primary_epoch);
	KUNIT_ASSERT_NOT_NULL(test, a);
	KUNIT_ASSERT_EQ(test, task_work_add(current, &a->twork, TWA_NONE), 0);
	/* Exec derives and commits a token without an INSTALL operation. */
	KUNIT_ASSERT_EQ(test, pkm_kacs_prepare_current_primary_install(f->b, &prepared), 0L);
	KUNIT_ASSERT_EQ(test, pkm_kacs_apply_current_primary_install(&prepared), 0L);
	pkm_kacs_primary_exec_committed();
	task_work_run();
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(), f->b);
}

struct pkm_kacs_install_exec_guard_test {
	/* The installing task's real signal_struct exec guard. */
	struct mutex *guard;
	struct task_struct *installer;
	const void *original;
	struct completion locked;
	bool blocked;
	bool unchanged;
};

static int pkm_kacs_install_exec_guard_holder(void *data)
{
	struct pkm_kacs_install_exec_guard_test *f = data;
	unsigned long deadline = jiffies + msecs_to_jiffies(2000);

	mutex_lock(f->guard);
	complete(&f->locked);
	while (!kthread_should_stop() && time_before(jiffies, deadline)) {
		if (READ_ONCE(f->installer->__state) == TASK_KILLABLE) {
			const struct cred *cred = get_task_cred(f->installer);

			f->blocked = true;
			f->unchanged = pkm_kacs_cred(cred)->token == f->original;
			put_cred(cred);
			break;
		}
		usleep_range(1000, 2000);
	}
	mutex_unlock(f->guard);
	/* Keep the task alive until the test has joined it with kthread_stop. */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

static void pkm_kacs_primary_install_waits_for_exec(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	struct pkm_kacs_install_exec_guard_test race = {
		.guard = &current->signal->cred_guard_mutex,
		.installer = current,
		.original = pkm_kacs_current_primary_token_ptr(),
	};
	struct task_struct *holder;
	long ret;

	init_completion(&race.locked);
	holder = kthread_run(pkm_kacs_install_exec_guard_holder, &race,
			     "pkm-install-exec");
	KUNIT_ASSERT_FALSE(test, IS_ERR(holder));
	if (!wait_for_completion_timeout(&race.locked, msecs_to_jiffies(5000))) {
		kthread_stop(holder);
		KUNIT_FAIL(test, "exec guard holder did not start");
		return;
	}
	ret = pkm_kacs_install_current_primary_token(f->b);
	kthread_stop(holder);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_TRUE(test, race.blocked);
	KUNIT_EXPECT_TRUE(test, race.unchanged);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(), f->b);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static void pkm_kacs_primary_install_error_releases_exec_guard(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	struct pkm_kacs_process_state *state = pkm_kacs_current_process_state();
	u64 epoch;
	bool unlocked;
	long ret;

	mutex_lock(&state->primary_lock);
	epoch = state->primary_epoch;
	state->primary_epoch = U64_MAX;
	mutex_unlock(&state->primary_lock);
	ret = pkm_kacs_install_current_primary_token(f->b);
	mutex_lock(&state->primary_lock);
	state->primary_epoch = epoch;
	mutex_unlock(&state->primary_lock);
	KUNIT_EXPECT_EQ(test, ret, -EOVERFLOW);
	unlocked = mutex_trylock(&current->signal->cred_guard_mutex);
	if (unlocked)
		mutex_unlock(&current->signal->cred_guard_mutex);
	KUNIT_ASSERT_TRUE(test, unlocked);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(), f->original);

	WRITE_ONCE(pkm_kacs_primary_fail_prepare_task, current);
	ret = pkm_kacs_install_current_primary_token(f->b);
	KUNIT_EXPECT_EQ(test, ret, -ENOMEM);
	unlocked = mutex_trylock(&current->signal->cred_guard_mutex);
	if (unlocked)
		mutex_unlock(&current->signal->cred_guard_mutex);
	KUNIT_ASSERT_TRUE(test, unlocked);
	KUNIT_EXPECT_EQ(test, state->primary_epoch, epoch);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(), f->original);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static void pkm_kacs_primary_exec_selects_pending_install(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	const void *selected;
	bool pending;

	mutex_lock(&current->signal->cred_guard_mutex);
	selected = pkm_kacs_primary_token_for_exec(&pending);
	mutex_unlock(&current->signal->cred_guard_mutex);
	KUNIT_EXPECT_PTR_EQ(test, selected, f->original);
	KUNIT_EXPECT_FALSE(test, pending);
	kacs_rust_token_drop(selected);

	KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(f->b), 0);
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_epoch_lag(test), 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(), f->original);
	mutex_lock(&current->signal->cred_guard_mutex);
	selected = pkm_kacs_primary_token_for_exec(&pending);
	mutex_unlock(&current->signal->cred_guard_mutex);
	KUNIT_EXPECT_PTR_EQ(test, selected, f->b);
	KUNIT_EXPECT_TRUE(test, pending);
	kacs_rust_token_drop(selected);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

/*
 * Derive exec credentials from the current cred as bprm would, with a
 * supplementary group the pending token does not project and, when @setuid
 * or @setgid is nonzero, the effective id a setuid or setgid binary would
 * have given it.
 */
static long pkm_kacs_primary_exec_derive(const void *subject,
					 const void *primary, bool project,
					 u32 setuid, u32 setgid,
					 struct cred **out)
{
	struct group_info *groups;
	struct cred *new;
	long ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	groups = groups_alloc(1);
	if (!groups) {
		abort_creds(new);
		return -ENOMEM;
	}
	groups->gid[0] = KGIDT_INIT(4321);
	set_groups(new, groups);
	put_group_info(groups);
	if (setuid)
		new->euid = KUIDT_INIT(setuid);
	if (setgid)
		new->egid = KGIDT_INIT(setgid);
	ret = pkm_kacs_bprm_creds_from_file_core(subject, primary, NULL, new,
						 current_cred(), false, false,
						 false, 0, project);
	if (ret) {
		abort_creds(new);
		return ret;
	}
	*out = new;
	return 0;
}

static void pkm_kacs_primary_exec_pending_install_projects_ids(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	const void *installed;
	const void *selected;
	struct cred *new;
	u32 replaced_uid;
	bool pending;

	installed =
		kacs_rust_kunit_create_impersonation_variant_token(PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
								   KACS_TOKEN_TYPE_PRIMARY,
								   KACS_IMLEVEL_DELEGATION,
								   PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, installed);
	/* The fixture owns the replacement through all assertion exits. */
	kacs_rust_token_drop(f->b);
	f->b = installed;
	KUNIT_ASSERT_EQ(test, kacs_rust_token_projected_uid(installed), 65534U);
	KUNIT_ASSERT_EQ(test, kacs_rust_token_projected_gid(installed), 65534U);
	KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(installed), 0);
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_epoch_lag(test), 0L);
	replaced_uid = __kuid_val(current_real_cred()->uid);
	KUNIT_ASSERT_NE(test, replaced_uid, 65534U);

	mutex_lock(&current->signal->cred_guard_mutex);
	selected = pkm_kacs_primary_token_for_exec(&pending);
	mutex_unlock(&current->signal->cred_guard_mutex);
	KUNIT_EXPECT_TRUE(test, pending);
	KUNIT_EXPECT_PTR_EQ(test, selected, installed);
	kacs_rust_token_drop(selected);

	/* Control: without projection the replaced token's identity survives. */
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_exec_derive(installed, installed,
							   false, 0U, 0U, &new), 0L);
	KUNIT_EXPECT_EQ(test, __kuid_val(new->uid), replaced_uid);
	KUNIT_EXPECT_EQ(test, new->group_info->ngroups, 1);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_cred(new)->token, installed);
	abort_creds(new);

	/* A lagging exec runs as the pending token's projection. */
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_exec_derive(installed, installed,
							   true, 0U, 0U, &new), 0L);
	pkm_kunit_expect_linux_cred_projection(test, new, 65534U, 65534U);
	KUNIT_EXPECT_EQ(test, __kuid_val(new->user->uid), 65534U);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_cred(new)->token, installed);
	abort_creds(new);

	/* A setuid binary's uid applies on top; the rest stays projected. */
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_exec_derive(installed, installed,
							   true, 4242U, 0U, &new), 0L);
	KUNIT_EXPECT_EQ(test, __kuid_val(new->uid), 4242U);
	KUNIT_EXPECT_EQ(test, __kuid_val(new->euid), 4242U);
	KUNIT_EXPECT_EQ(test, __kuid_val(new->suid), 4242U);
	KUNIT_EXPECT_EQ(test, __kuid_val(new->fsuid), 65534U);
	KUNIT_EXPECT_EQ(test, __kgid_val(new->gid), 65534U);
	KUNIT_EXPECT_EQ(test, __kgid_val(new->egid), 65534U);
	KUNIT_EXPECT_EQ(test, __kgid_val(new->fsgid), 65534U);
	KUNIT_EXPECT_EQ(test, new->group_info->ngroups, 0);
	KUNIT_EXPECT_EQ(test, __kuid_val(new->user->uid), 65534U);
	abort_creds(new);

	/* Likewise a setgid binary's gid. */
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_exec_derive(installed, installed,
							   true, 0U, 4343U, &new), 0L);
	KUNIT_EXPECT_EQ(test, __kuid_val(new->uid), 65534U);
	KUNIT_EXPECT_EQ(test, __kgid_val(new->gid), 4343U);
	KUNIT_EXPECT_EQ(test, __kgid_val(new->egid), 4343U);
	KUNIT_EXPECT_EQ(test, __kgid_val(new->sgid), 4343U);
	KUNIT_EXPECT_EQ(test, __kgid_val(new->fsgid), 65534U);
	KUNIT_EXPECT_EQ(test, new->group_info->ngroups, 0);
	abort_creds(new);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

/*
 * The setuid gate runs only for a real change from the pending projection: a
 * subject holding SeAssignPrimaryToken is refused a setuid to another uid but
 * not one to the projected uid itself, which is no change.
 */
static void pkm_kacs_primary_exec_pending_install_projected_setuid_is_no_change(
	struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	const void *installed;
	const void *subject;
	struct cred *new = NULL;
	long ret;

	installed =
		kacs_rust_kunit_create_impersonation_variant_token(PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
								   KACS_TOKEN_TYPE_PRIMARY,
								   KACS_IMLEVEL_DELEGATION,
								   PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, installed);
	/* The fixture owns the replacement through all assertion exits. */
	kacs_rust_token_drop(f->b);
	f->b = installed;
	KUNIT_ASSERT_NE(test, __kuid_val(current_real_cred()->uid), 65534U);

	subject = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_DELEGATION, PKM_KUNIT_IL_SYSTEM, 0U,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, subject);

	ret = pkm_kacs_primary_exec_derive(subject, installed, true, 65534U, 0U,
					   &new);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (!ret) {
		KUNIT_EXPECT_EQ(test, __kuid_val(new->uid), 65534U);
		KUNIT_EXPECT_EQ(test, __kuid_val(new->euid), 65534U);
		abort_creds(new);
	}
	ret = pkm_kacs_primary_exec_derive(subject, installed, true, 4242U, 0U,
					   &new);
	KUNIT_EXPECT_EQ(test, ret, (long)-EOPNOTSUPP);
	if (!ret)
		abort_creds(new);
	kacs_rust_token_drop(subject);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static void pkm_kacs_primary_exec_pending_install_keeps_npm(struct kunit *test)
{
	struct pkm_kacs_primary_epoch_fixture *f = test->priv;
	struct pkm_kacs_kunit_exec_new_process_min_args args = { };
	struct pkm_kacs_boot_snapshot before = { }, after = { };
	const void *selected;
	const void *installed;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 changed = 0;
	bool pending;
	long ret;

	installed =
		kacs_rust_kunit_create_impersonation_variant_token(PKM_KUNIT_USER_KIND_SYSTEM,
								   KACS_TOKEN_TYPE_PRIMARY,
								   KACS_IMLEVEL_DELEGATION,
								   PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, installed);
	/* The fixture owns the replacement through all assertion exits. */
	kacs_rust_token_drop(f->b);
	f->b = installed;
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(installed, &before));
	KUNIT_ASSERT_TRUE(test, before.mandatory_policy &
			 KACS_TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN);
	KUNIT_ASSERT_EQ(test, pkm_kacs_install_current_primary_token(installed), 0);
	KUNIT_ASSERT_EQ(test, pkm_kacs_primary_epoch_lag(test), 0L);
	file_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_LOW,
							 &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	mutex_lock(&current->signal->cred_guard_mutex);
	selected = pkm_kacs_primary_token_for_exec(&pending);
	args.subject_token = f->original;
	args.primary_token = selected;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;
	ret = pkm_kacs_kunit_check_exec_new_process_min(&args, &after, &changed);
	mutex_unlock(&current->signal->cred_guard_mutex);
	KUNIT_EXPECT_PTR_EQ(test, selected, installed);
	KUNIT_EXPECT_TRUE(test, pending);
	kacs_rust_token_drop(selected);
	pkm_kacs_free((void *)file_sd);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, changed, 1U);
	KUNIT_EXPECT_EQ(test, after.integrity_level, PKM_KUNIT_IL_LOW);
	KUNIT_EXPECT_NE(test, after.token_id, before.token_id);
	KUNIT_EXPECT_EQ(test, after.logon_session_id, before.logon_session_id);
	KUNIT_EXPECT_EQ(test, after.mandatory_policy, before.mandatory_policy);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled, before.privileges_enabled);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static struct kunit_case pkm_kacs_primary_epoch_cases[] = {
	KUNIT_CASE(pkm_kacs_primary_epoch_lifo),
	KUNIT_CASE(pkm_kacs_primary_epoch_retry_current),
	KUNIT_CASE(pkm_kacs_primary_epoch_retry_obsolete),
	KUNIT_CASE(pkm_kacs_primary_epoch_enroll),
	KUNIT_CASE(pkm_kacs_primary_epoch_exec),
	KUNIT_CASE(pkm_kacs_primary_install_waits_for_exec),
	KUNIT_CASE(pkm_kacs_primary_install_error_releases_exec_guard),
	KUNIT_CASE(pkm_kacs_primary_exec_selects_pending_install),
	KUNIT_CASE(pkm_kacs_primary_exec_pending_install_keeps_npm),
	KUNIT_CASE(pkm_kacs_primary_exec_pending_install_projects_ids),
	KUNIT_CASE(pkm_kacs_primary_exec_pending_install_projected_setuid_is_no_change),
	{ }
};

static struct kunit_suite pkm_kacs_primary_epoch_suite = {
	.name = "pkm_kunit_primary_epoch",
	.init = pkm_kacs_primary_epoch_test_init,
	.exit = pkm_kacs_primary_epoch_test_exit,
	.test_cases = pkm_kacs_primary_epoch_cases,
};
kunit_test_suite(pkm_kacs_primary_epoch_suite);
#endif
