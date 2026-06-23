// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/pidfd.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>
#include <linux/types.h>

#include <pkm/token.h>

#include "lsm_internal.h"
#include "process_access.h"
#include "process_state.h"
#include "process_token.h"
#include "token_fd.h"
#include "token_runtime.h"

static long pkm_kacs_open_process_token_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *target_state,
	const void *target_token, u32 caller_pip_type, u32 caller_pip_trust,
	u32 access_mask)
{
	long ret;

	ret = pkm_kacs_validate_token_open_access_mask(access_mask);
	if (ret)
		return ret;
	if (!target_token)
		return -EACCES;

	ret = pkm_kacs_authorize_process_access_core(
		subject_token, target_state, caller_pip_type, caller_pip_trust,
		KACS_PROCESS_QUERY_INFORMATION);
	if (ret)
		return ret;

	return pkm_kacs_open_token_fd_for_subject_checked_with_pip(
		subject_token, target_token, access_mask, caller_pip_type,
		caller_pip_trust);
}

static long pkm_kacs_authorize_process_token_inspection_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	bool self_target)
{
	if (!subject_token || !caller_state || !target_state)
		return -EACCES;
	if (self_target)
		return 0;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust),
		KACS_PROCESS_QUERY_INFORMATION);
}

static long pkm_kacs_open_process_token_inspection_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	const void *target_token, bool self_target)
{
	long ret;

	if (!target_token)
		return -EACCES;

	ret = pkm_kacs_authorize_process_token_inspection_core(
		subject_token, caller_state, target_state, self_target);
	if (ret)
		return ret;

	return pkm_kacs_open_token_fd_with_fixed_access(target_token,
							KACS_TOKEN_QUERY);
}

static int pkm_kacs_bind_process_token_inspection_file(
	struct file *file,
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	const void *target_token, bool self_target)
{
	long ret;

	ret = pkm_kacs_authorize_process_token_inspection_core(
		subject_token, caller_state, target_state, self_target);
	if (ret)
		return (int)ret;

	return pkm_kacs_bind_query_token_file(file, target_token);
}

long pkm_kacs_open_process_token_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task, u32 access_mask)
{
	const struct cred *target_real_cred;
	struct pkm_kacs_process_state *target_state;
	const void *target_token;
	long ret;

	if (!subject_token || !caller_state || !task || !task->security)
		return -EACCES;

	target_state = pkm_kacs_task(task)->process_state;
	if (!target_state)
		return -EACCES;

	target_real_cred = get_task_cred(task);
	target_token = pkm_kacs_cred(target_real_cred)->token;
	if (!target_token) {
		put_cred(target_real_cred);
		return -EACCES;
	}

	ret = pkm_kacs_open_process_token_core(
		subject_token, target_state, target_token,
		READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), access_mask);
	put_cred(target_real_cred);
	return ret;
}

static long __maybe_unused pkm_kacs_open_process_token_inspection_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task)
{
	const struct cred *target_real_cred;
	struct pkm_kacs_process_state *target_state;
	const void *target_token;
	long ret;
	bool self_target;

	if (!subject_token || !caller_state || !task || !task->security)
		return -EACCES;

	target_state = pkm_kacs_task(task)->process_state;
	if (!target_state)
		return -EACCES;
	self_target = caller_state == target_state;

	target_real_cred = get_task_cred(task);
	target_token = pkm_kacs_cred(target_real_cred)->token;
	if (!target_token) {
		put_cred(target_real_cred);
		return -EACCES;
	}

	ret = pkm_kacs_open_process_token_inspection_core(
		subject_token, caller_state, target_state, target_token,
		self_target);
	put_cred(target_real_cred);
	return ret;
}

static const struct cred *pkm_kacs_get_task_effective_cred(
	struct task_struct *task)
{
	const struct cred *cred;

	if (!task)
		return NULL;

	rcu_read_lock();
	cred = rcu_dereference(task->cred);
	if (cred)
		get_cred(cred);
	rcu_read_unlock();
	return cred;
}

long pkm_kacs_open_thread_token_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task, u32 access_mask)
{
	const struct cred *target_effective_cred;
	struct pkm_kacs_process_state *target_state;
	const void *target_token;
	long ret;

	if (!subject_token || !caller_state || !task || !task->security)
		return -EACCES;

	target_state = pkm_kacs_task(task)->process_state;
	if (!target_state)
		return -EACCES;

	target_effective_cred = pkm_kacs_get_task_effective_cred(task);
	if (!target_effective_cred)
		return -EACCES;

	target_token = pkm_kacs_cred(target_effective_cred)->token;
	if (!target_token) {
		put_cred(target_effective_cred);
		return -EACCES;
	}

	ret = pkm_kacs_open_process_token_core(
		subject_token, target_state, target_token,
		READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), access_mask);
	put_cred(target_effective_cred);
	return ret;
}

static long __maybe_unused pkm_kacs_open_thread_token_inspection_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task)
{
	const struct cred *target_effective_cred;
	struct pkm_kacs_process_state *target_state;
	const void *target_token;
	long ret;
	bool self_target;

	if (!subject_token || !caller_state || !task || !task->security)
		return -EACCES;

	target_state = pkm_kacs_task(task)->process_state;
	if (!target_state)
		return -EACCES;
	self_target = caller_state == target_state;

	target_effective_cred = pkm_kacs_get_task_effective_cred(task);
	if (!target_effective_cred)
		return -EACCES;

	target_token = pkm_kacs_cred(target_effective_cred)->token;
	if (!target_token) {
		put_cred(target_effective_cred);
		return -EACCES;
	}

	ret = pkm_kacs_open_process_token_inspection_core(
		subject_token, caller_state, target_state, target_token,
		self_target);
	put_cred(target_effective_cred);
	return ret;
}

int pkm_kacs_proc_open_process_token_file(struct file *file,
					  struct task_struct *task)
{
	struct pkm_kacs_process_state *caller_state;
	const struct cred *target_real_cred;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	const void *target_token;
	int ret;
	bool self_target;

	if (!file || !task || !task->security)
		return -EACCES;

	caller_state = pkm_kacs_current_process_state();
	subject_token = pkm_kacs_current_effective_token_ptr();
	target_state = pkm_kacs_task(task)->process_state;
	if (!caller_state || !subject_token || !target_state)
		return -EACCES;
	self_target = caller_state == target_state;

	target_real_cred = get_task_cred(task);
	target_token = pkm_kacs_cred(target_real_cred)->token;
	if (!target_token) {
		put_cred(target_real_cred);
		return -EACCES;
	}

	ret = pkm_kacs_bind_process_token_inspection_file(
		file, subject_token, caller_state, target_state, target_token,
		self_target);
	put_cred(target_real_cred);
	return ret;
}

int pkm_kacs_proc_open_thread_token_file(struct file *file,
					 struct task_struct *task)
{
	struct pkm_kacs_process_state *caller_state;
	const struct cred *target_effective_cred;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	const void *target_token;
	int ret;
	bool self_target;

	if (!file || !task || !task->security)
		return -EACCES;

	caller_state = pkm_kacs_current_process_state();
	subject_token = pkm_kacs_current_effective_token_ptr();
	target_state = pkm_kacs_task(task)->process_state;
	if (!caller_state || !subject_token || !target_state)
		return -EACCES;
	self_target = caller_state == target_state;

	target_effective_cred = pkm_kacs_get_task_effective_cred(task);
	if (!target_effective_cred)
		return -EACCES;

	target_token = pkm_kacs_cred(target_effective_cred)->token;
	if (!target_token) {
		put_cred(target_effective_cred);
		return -EACCES;
	}

	ret = pkm_kacs_bind_process_token_inspection_file(
		file, subject_token, caller_state, target_state, target_token,
		self_target);
	put_cred(target_effective_cred);
	return ret;
}

SYSCALL_DEFINE2(kacs_open_process_token, int, pidfd, u32, access_mask)
{
	struct pkm_kacs_process_state *caller_state;
	const void *subject_token;
	struct task_struct *task;
	struct pid *pid;
	unsigned int pidfd_flags = 0;
	long ret;

	ret = pkm_kacs_validate_token_open_access_mask(access_mask);
	if (ret)
		return ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	caller_state = pkm_kacs_current_process_state();
	if (!subject_token || !caller_state)
		return -EACCES;

	pid = pidfd_get_pid(pidfd, &pidfd_flags);
	if (IS_ERR(pid))
		return PTR_ERR(pid);
	(void)pidfd_flags;

	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!task)
		return -ESRCH;

	ret = pkm_kacs_open_process_token_task(subject_token, caller_state, task,
					       access_mask);
	put_task_struct(task);
	return ret;
}

SYSCALL_DEFINE3(kacs_open_thread_token, int, pidfd, int, tid, u32, access_mask)
{
	struct pkm_kacs_process_state *caller_state;
	const void *subject_token;
	struct task_struct *process_task;
	struct task_struct *thread_task;
	struct pid *pid;
	struct pid *thread_pid;
	unsigned int pidfd_flags = 0;
	long ret;

	ret = pkm_kacs_validate_token_open_access_mask(access_mask);
	if (ret)
		return ret;
	if (tid <= 0)
		return -EINVAL;

	subject_token = pkm_kacs_current_effective_token_ptr();
	caller_state = pkm_kacs_current_process_state();
	if (!subject_token || !caller_state)
		return -EACCES;

	pid = pidfd_get_pid(pidfd, &pidfd_flags);
	if (IS_ERR(pid))
		return PTR_ERR(pid);
	(void)pidfd_flags;

	process_task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!process_task)
		return -ESRCH;

	thread_pid = find_get_pid(tid);
	if (!thread_pid) {
		put_task_struct(process_task);
		return -ESRCH;
	}

	thread_task = get_pid_task(thread_pid, PIDTYPE_PID);
	put_pid(thread_pid);
	if (!thread_task) {
		put_task_struct(process_task);
		return -ESRCH;
	}

	if (!same_thread_group(process_task, thread_task)) {
		put_task_struct(thread_task);
		put_task_struct(process_task);
		return -ESRCH;
	}

	ret = pkm_kacs_open_thread_token_task(subject_token, caller_state,
					      thread_task, access_mask);
	put_task_struct(thread_task);
	put_task_struct(process_task);
	return ret;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_open_process_token_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_open_process_token_core(
		args->subject_token, &target_state, args->target_token,
		args->caller_pip_type, args->caller_pip_trust,
		args->access_mask);
}

long pkm_kacs_kunit_open_process_token_inspection_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_open_process_token_inspection_core(
		args->subject_token, &caller_state, &target_state,
		args->target_token, args->self_target != 0);
}

long pkm_kacs_kunit_open_thread_token_inspection_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args)
{
	return pkm_kacs_kunit_open_process_token_inspection_for_subject(args);
}

long pkm_kacs_kunit_open_self_token_inspection_for_subject(void)
{
	const void *subject_token = pkm_kacs_current_effective_token_ptr();

	if (!subject_token)
		return -EACCES;

	return pkm_kacs_open_token_fd_with_fixed_access(subject_token,
							KACS_TOKEN_QUERY);
}

long pkm_kacs_kunit_open_current_thread_token_for_subject(
	const void *subject_token, u32 access_mask)
{
	struct pkm_kacs_process_state *caller_state;

	if (!subject_token)
		return -EINVAL;

	caller_state = pkm_kacs_current_process_state();
	if (!caller_state)
		return -EACCES;

	return pkm_kacs_open_thread_token_task(subject_token, caller_state,
					       current, access_mask);
}
#endif /* CONFIG_SECURITY_PKM_KUNIT */
