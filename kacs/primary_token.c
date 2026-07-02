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
};

struct pkm_kacs_primary_install_batch {
	struct pkm_kacs_primary_install_work **works;
	size_t count;
};

static long pkm_kacs_revert_current_impersonation(void);

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

static long pkm_kacs_revert_current_impersonation(void)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->impersonation_saved_cred)
		return 0;

	trace_kacs_primary_install(
		(u64)(uintptr_t)pkm_kacs_cred(task_sec->impersonation_saved_cred)
			->token,
		0, KACS_PRIM_IMPERSONATE_REVERT, 0);
	revert_creds(task_sec->impersonation_saved_cred);
	task_sec->impersonation_saved_cred = NULL;
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

static void pkm_kacs_primary_install_task_work(struct callback_head *twork)
{
	struct pkm_kacs_primary_install_prepare prepared = { };
	struct pkm_kacs_primary_install_work *work =
		container_of(twork, struct pkm_kacs_primary_install_work, twork);
	long ret;

	ret = pkm_kacs_prepare_current_primary_install(work->token, &prepared);
	if (!ret)
		ret = pkm_kacs_apply_current_primary_install(&prepared);
	if (ret)
		pkm_kacs_abort_primary_install_prepare(&prepared);
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
	struct pkm_kacs_primary_install_batch *batch)
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
	long ret;

	if (!token || !current || !current->security)
		return -EACCES;

	state = pkm_kacs_current_process_state();
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	if (!state || !old_primary_token)
		return -EACCES;

	ret = pkm_kacs_prepare_sibling_primary_installs(token, &sibling_batch);
	if (ret)
		return ret;

	ret = pkm_kacs_prepare_current_primary_install(token, &prepared);
	if (ret) {
		pkm_kacs_discard_prepared_primary_installs(&sibling_batch);
		return ret;
	}

	if (!kacs_rust_token_same_user_sid(old_primary_token, token)) {
		new_sd = pkm_kacs_process_sd_alloc(token);
		if (!new_sd) {
			trace_kacs_primary_install(
				(u64)(uintptr_t)old_primary_token,
				(u64)(uintptr_t)token,
				KACS_PRIM_SD_ALLOC_FAIL, -ENOMEM);
			pkm_kacs_abort_primary_install_prepare(&prepared);
			pkm_kacs_discard_prepared_primary_installs(&sibling_batch);
			return -ENOMEM;
		}
	}

	ret = pkm_kacs_apply_current_primary_install(&prepared);
	if (ret) {
		pkm_kacs_abort_primary_install_prepare(&prepared);
		pkm_kacs_process_sd_put(new_sd);
		pkm_kacs_discard_prepared_primary_installs(&sibling_batch);
		return ret;
	}

	if (new_sd) {
		pkm_kacs_process_state_replace_sd(state, new_sd);
		trace_kacs_primary_install((u64)(uintptr_t)old_primary_token,
					   (u64)(uintptr_t)token,
					   KACS_PRIM_SD_REALLOC, 0);
	}

	pkm_kacs_queue_prepared_primary_installs(&sibling_batch);
	trace_kacs_primary_install((u64)(uintptr_t)old_primary_token,
				   (u64)(uintptr_t)token, KACS_PRIM_INSTALL_OK, 0);
	return 0;
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
	ret = pkm_kacs_revert_current_impersonation();
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
	return pkm_kacs_revert_current_impersonation();
}

SYSCALL_DEFINE0(kacs_revert)
{
	return pkm_kacs_revert_impersonation();
}
