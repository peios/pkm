// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/types.h>

#include <pkm/token.h>

#include "lsm_internal.h"
#include "process_access.h"
#include "process_state.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

#define PKM_KACS_LSM_PRLIMIT_READ 1U
#define PKM_KACS_LSM_PRLIMIT_WRITE 2U

#ifndef PTRACE_MODE_GETFD
#define PTRACE_MODE_GETFD 0x20
#endif

#ifndef PTRACE_MODE_PIDFD_OPEN
#define PTRACE_MODE_PIDFD_OPEN 0x40
#endif

#ifndef PTRACE_MODE_PROC_QUERY_LIMITED
#define PTRACE_MODE_PROC_QUERY_LIMITED 0x80
#endif

#ifndef PTRACE_MODE_PROC_QUERY_INFORMATION
#define PTRACE_MODE_PROC_QUERY_INFORMATION 0x100
#endif

bool pkm_kacs_pip_dominates(u32 caller_pip_type, u32 caller_pip_trust,
				   u32 target_pip_type, u32 target_pip_trust)
{
	if (target_pip_type == 0)
		return true;

	return caller_pip_type >= target_pip_type &&
	       caller_pip_trust >= target_pip_trust;
}

long pkm_kacs_authorize_process_sd_access(
	const void *subject_token,
	const struct pkm_kacs_process_sd *process_sd, u32 desired_access,
	u32 pip_type, u32 pip_trust)
{
	u32 granted = 0;
	u32 pip_denied = 0;
	int ret;

	if (!subject_token || !process_sd || !process_sd->bytes || !process_sd->len) {
		trace_kacs_process_access(pip_type, pip_trust, 0, 0,
					  desired_access, KACS_PA_BAD_ARGS,
					  -EACCES);
		return -EACCES;
	}

	ret = kacs_rust_check_process_sd_with_intent_status(
		subject_token, process_sd->bytes, process_sd->len,
		desired_access, 0, pip_type, pip_trust, &granted,
		&pip_denied);
	if (!ret) {
		trace_kacs_process_access(pip_type, pip_trust, 0, 0,
					  desired_access, KACS_PA_ALLOW, 0);
		return 0;
	}
	if (ret != -EACCES) {
		trace_kacs_process_access(pip_type, pip_trust, 0, 0,
					  desired_access, KACS_PA_SD_ERROR, ret);
		return ret;
	}
	if (pip_denied) {
		trace_kacs_process_access(pip_type, pip_trust, 0, 0,
					  desired_access, KACS_PA_PIP_DENIED,
					  -EACCES);
		return -EACCES;
	}
	if (!kacs_rust_token_has_enabled_privilege(subject_token,
						   KACS_SE_DEBUG_PRIVILEGE)) {
		trace_kacs_process_access(pip_type, pip_trust, 0, 0,
					  desired_access, KACS_PA_DEBUG_DENIED,
					  -EACCES);
		return -EACCES;
	}
	if (!kacs_rust_token_mark_privileges_used(
		    subject_token, KACS_SE_DEBUG_PRIVILEGE)) {
		trace_kacs_process_access(pip_type, pip_trust, 0, 0,
					  desired_access, KACS_PA_DEBUG_DENIED,
					  -EACCES);
		return -EACCES;
	}

	trace_kacs_process_access(pip_type, pip_trust, 0, 0, desired_access,
				  KACS_PA_DEBUG_RESCUE, 0);
	return 0;
}

long pkm_kacs_authorize_process_sd_access_nondebug(
	const void *subject_token,
	const struct pkm_kacs_process_sd *process_sd, u32 desired_access,
	u32 privilege_intent, u32 pip_type, u32 pip_trust)
{
	u32 granted = 0;

	if (!subject_token || !process_sd || !process_sd->bytes || !process_sd->len)
		return -EACCES;

	return kacs_rust_check_process_sd_with_intent(
		subject_token, process_sd->bytes, process_sd->len,
		desired_access, privilege_intent, pip_type, pip_trust, &granted);
}

long pkm_kacs_enforce_cross_process_pip(
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state, bool self_target)
{
	if (self_target)
		return 0;
	if (!caller_state || !target_state)
		return -EACCES;
	if (!pkm_kacs_pip_dominates(READ_ONCE(caller_state->pip_type),
				    READ_ONCE(caller_state->pip_trust),
				    READ_ONCE(target_state->pip_type),
				    READ_ONCE(target_state->pip_trust)))
		return -EACCES;

	return 0;
}

long pkm_kacs_authorize_process_access_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *target_state, u32 caller_pip_type,
	u32 caller_pip_trust, u32 desired_process_access)
{
	struct pkm_kacs_process_sd *process_sd;
	long ret;

	if (!subject_token || !target_state) {
		trace_kacs_process_access(caller_pip_type, caller_pip_trust, 0,
					  0, desired_process_access,
					  KACS_PA_BAD_ARGS, -EACCES);
		return -EACCES;
	}

	process_sd = pkm_kacs_process_state_get_sd(
		(struct pkm_kacs_process_state *)target_state);
	if (!process_sd) {
		trace_kacs_process_access(caller_pip_type, caller_pip_trust,
					  READ_ONCE(target_state->pip_type),
					  READ_ONCE(target_state->pip_trust),
					  desired_process_access, KACS_PA_NO_SD,
					  -EACCES);
		return -EACCES;
	}

	ret = pkm_kacs_authorize_process_sd_access(subject_token, process_sd,
						   desired_process_access,
						   caller_pip_type,
						   caller_pip_trust);
	pkm_kacs_process_sd_put(process_sd);
	if (ret)
		return ret;
	if (!pkm_kacs_pip_dominates(caller_pip_type, caller_pip_trust,
				    READ_ONCE(target_state->pip_type),
				    READ_ONCE(target_state->pip_trust))) {
		trace_kacs_process_access(caller_pip_type, caller_pip_trust,
					  READ_ONCE(target_state->pip_type),
					  READ_ONCE(target_state->pip_trust),
					  desired_process_access,
					  KACS_PA_PIP_DOMINANCE, -EACCES);
		return -EACCES;
	}

	trace_kacs_process_access(caller_pip_type, caller_pip_trust,
				  READ_ONCE(target_state->pip_type),
				  READ_ONCE(target_state->pip_trust),
				  desired_process_access, KACS_PA_ALLOW, 0);
	return 0;
}

long pkm_kacs_signal_to_process_access(int sig, u32 *desired_access)
{
	if (!desired_access)
		return -EINVAL;
	if (sig < 0 || sig > SIGRTMAX)
		return -EINVAL;
	if (sig == 0) {
		*desired_access = KACS_PROCESS_QUERY_LIMITED;
		return 0;
	}

	switch (sig) {
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGILL:
	case SIGTRAP:
	case SIGABRT:
	case SIGBUS:
	case SIGFPE:
	case SIGKILL:
	case SIGUSR1:
	case SIGSEGV:
	case SIGUSR2:
	case SIGPIPE:
	case SIGALRM:
	case SIGTERM:
	case SIGSTKFLT:
	case SIGXCPU:
	case SIGXFSZ:
	case SIGVTALRM:
	case SIGPROF:
	case SIGIO:
	case SIGPWR:
	case SIGSYS:
		*desired_access = KACS_PROCESS_TERMINATE;
		return 0;
	case SIGCONT:
	case SIGSTOP:
	case SIGTSTP:
	case SIGTTIN:
	case SIGTTOU:
		*desired_access = KACS_PROCESS_SUSPEND_RESUME;
		return 0;
	case SIGCHLD:
	case SIGURG:
	case SIGWINCH:
		*desired_access = KACS_PROCESS_SIGNAL;
		return 0;
	default:
		if (sig >= SIGRTMIN) {
			*desired_access = KACS_PROCESS_TERMINATE;
			return 0;
		}
		return -EACCES;
	}
}

bool pkm_kacs_signal_is_kernel_originated(
	const struct kernel_siginfo *info, const struct cred *cred)
{
	if (cred)
		return false;
	if (info == SEND_SIG_PRIV)
		return true;
	if (info == SEND_SIG_NOINFO)
		return false;
	if (!info)
		return false;

	return SI_FROMKERNEL(info);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_signal_origin_is_kernel(u32 origin_kind)
{
	struct kernel_siginfo info = {};
	const struct cred *cred = NULL;
	const struct kernel_siginfo *info_ptr = &info;

	switch (origin_kind) {
	case PKM_KUNIT_SIGNAL_ORIGIN_NOINFO:
		info_ptr = SEND_SIG_NOINFO;
		break;
	case PKM_KUNIT_SIGNAL_ORIGIN_PRIV:
		info_ptr = SEND_SIG_PRIV;
		break;
	case PKM_KUNIT_SIGNAL_ORIGIN_USER:
		info.si_code = SI_USER;
		break;
	case PKM_KUNIT_SIGNAL_ORIGIN_TKILL:
		info.si_code = SI_TKILL;
		break;
	case PKM_KUNIT_SIGNAL_ORIGIN_KERNEL:
		info.si_code = SI_KERNEL;
		break;
	case PKM_KUNIT_SIGNAL_ORIGIN_STORED_CRED:
		info.si_code = SI_KERNEL;
		cred = current_cred();
		break;
	default:
		return -EINVAL;
	}

	return pkm_kacs_signal_is_kernel_originated(info_ptr, cred) ? 1L : 0L;
}
#endif

long pkm_kacs_ptrace_mode_to_process_access(unsigned int mode,
						   u32 *desired_access)
{
	bool is_pidfd_open_mode;
	bool is_getfd_mode;
	bool is_proc_query_limited_mode;
	bool is_proc_query_information_mode;
	bool is_read_mode;
	bool is_attach_mode;

	if (!desired_access)
		return -EINVAL;

	is_pidfd_open_mode = (mode & PTRACE_MODE_PIDFD_OPEN) != 0;
	is_getfd_mode = (mode & PTRACE_MODE_GETFD) != 0;
	is_proc_query_limited_mode =
		(mode & PTRACE_MODE_PROC_QUERY_LIMITED) != 0;
	is_proc_query_information_mode =
		(mode & PTRACE_MODE_PROC_QUERY_INFORMATION) != 0;
	is_read_mode = (mode & PTRACE_MODE_READ) != 0;
	is_attach_mode = (mode & PTRACE_MODE_ATTACH) != 0;
	if (is_pidfd_open_mode) {
		if (!is_read_mode || is_attach_mode || is_getfd_mode)
			return -EACCES;
		*desired_access = KACS_PROCESS_QUERY_LIMITED;
		return 0;
	}
	if (is_getfd_mode) {
		if (is_read_mode || !is_attach_mode)
			return -EACCES;
		*desired_access = KACS_PROCESS_DUP_HANDLE;
		return 0;
	}
	if (is_proc_query_limited_mode || is_proc_query_information_mode) {
		if (is_proc_query_limited_mode &&
		    is_proc_query_information_mode)
			return -EACCES;
		if (!is_read_mode || is_attach_mode || is_getfd_mode ||
		    is_pidfd_open_mode)
			return -EACCES;

		*desired_access = is_proc_query_information_mode ?
					  KACS_PROCESS_QUERY_INFORMATION :
					  KACS_PROCESS_QUERY_LIMITED;
		return 0;
	}
	if (is_read_mode == is_attach_mode)
		return -EACCES;

	*desired_access = is_attach_mode ? KACS_PROCESS_VM_WRITE :
					     KACS_PROCESS_VM_READ;
	return 0;
}

long pkm_kacs_check_process_capget_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state)
{
	if (!caller_state || !target_state)
		return -EACCES;
	if (caller_state == target_state)
		return 0;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust),
		KACS_PROCESS_QUERY_INFORMATION);
}

long pkm_kacs_validate_process_attribute_access(u32 desired_access)
{
	switch (desired_access) {
	case KACS_PROCESS_QUERY_LIMITED:
	case KACS_PROCESS_QUERY_INFORMATION:
	case KACS_PROCESS_SET_INFORMATION:
		return 0;
	default:
		return -EACCES;
	}
}

long pkm_kacs_check_process_attribute_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	u32 desired_access)
{
	long ret;

	ret = pkm_kacs_validate_process_attribute_access(desired_access);
	if (ret)
		return ret;
	if (!subject_token || !caller_state || !target_state)
		return -EACCES;
	if (caller_state == target_state)
		return 0;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), desired_access);
}

static int pkm_kacs_task_process_attribute_access(struct task_struct *task,
						  u32 desired_access)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;

	if (!task || !task->security)
		return -EACCES;

	caller_state = pkm_kacs_current_process_state();
	target_state = pkm_kacs_task(task)->process_state;
	subject_token = pkm_kacs_current_effective_token_ptr();
	return (int)pkm_kacs_check_process_attribute_core(
		subject_token, caller_state, target_state, desired_access);
}

long pkm_kacs_prlimit_flags_to_process_access(unsigned int flags,
						     u32 *desired_access)
{
	if (!desired_access)
		return -EINVAL;

	switch (flags) {
	case PKM_KACS_LSM_PRLIMIT_READ:
		*desired_access = KACS_PROCESS_QUERY_INFORMATION;
		return 0;
	case PKM_KACS_LSM_PRLIMIT_WRITE:
		*desired_access = KACS_PROCESS_SET_INFORMATION;
		return 0;
	default:
		return -EACCES;
	}
}

long pkm_kacs_check_process_setinfo_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state)
{
	return pkm_kacs_check_process_attribute_core(
		subject_token, caller_state, target_state,
		KACS_PROCESS_SET_INFORMATION);
}

long pkm_kacs_proc_process_setinfo(struct task_struct *task)
{
	return pkm_kacs_task_process_attribute_access(
		task, KACS_PROCESS_SET_INFORMATION);
}

long pkm_kacs_check_process_affinity_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state)
{
	if (!subject_token || !caller_state || !target_state)
		return -EACCES;
	if (caller_state == target_state)
		return 0;
	if (!kacs_rust_token_has_enabled_privilege(
		    subject_token,
		    KACS_SE_INCREASE_BASE_PRIORITY_PRIVILEGE))
		return -EACCES;
	if (!kacs_rust_token_mark_privileges_used(
		    subject_token,
		    KACS_SE_INCREASE_BASE_PRIORITY_PRIVILEGE))
		return -EACCES;

	return pkm_kacs_check_process_setinfo_core(subject_token, caller_state,
						   target_state);
}

long pkm_kacs_check_process_perf_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	bool self_target)
{
	long ret;

	if (!caller_state || !target_state)
		return -EACCES;

	ret = pkm_kacs_require_enabled_privilege(
		subject_token, KACS_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE);
	if (ret)
		return ret;
	if (self_target)
		return 0;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust),
		KACS_PROCESS_QUERY_INFORMATION);
}

long pkm_kacs_sched_setaffinity(struct task_struct *task)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;

	if (!task || !task->security)
		return -EACCES;

	caller_state = pkm_kacs_current_process_state();
	target_state = pkm_kacs_task(task)->process_state;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;

	return pkm_kacs_check_process_affinity_core(subject_token, caller_state,
						    target_state);
}

long pkm_kacs_perf_event_open(struct task_struct *task)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;

	if (!task || !task->security)
		return -EACCES;

	caller_state = pkm_kacs_current_process_state();
	target_state = pkm_kacs_task(task)->process_state;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;

	return pkm_kacs_check_process_perf_core(subject_token, caller_state,
						target_state,
						caller_state == target_state);
}

int pkm_kacs_task_kill(struct task_struct *target,
			      struct kernel_siginfo *info, int sig,
			      const struct cred *cred)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const struct cred *subject_cred;
	const void *subject_token;
	u32 desired_access;
	long ret;

	if (!target || !target->security)
		return -EACCES;
	if (pkm_kacs_signal_is_kernel_originated(info, cred))
		return 0;

	if (cred) {
		if (!cred->security)
			return -EACCES;
		subject_cred = cred;
		caller_state = pkm_kacs_cred(cred)->process_state;
	} else {
		if (!pkm_kacs_current_token_eval_context_allowed())
			return -EACCES;
		subject_cred = current_cred();
		caller_state = pkm_kacs_current_process_state();
	}
	if (!subject_cred || !subject_cred->security)
		return -EACCES;

	target_state = pkm_kacs_task(target)->process_state;
	subject_token = pkm_kacs_cred(subject_cred)->token;
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;

	/*
	 * Structural, not SD-based: raise()/abort()/pthread_kill() must work
	 * even when the caller's restricted token fails AccessCheck against
	 * its own process SD.
	 */
	if (caller_state == target_state)
		return 0;

	ret = pkm_kacs_signal_to_process_access(sig, &desired_access);
	if (ret)
		return ret;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), desired_access);
}

int pkm_kacs_ptrace_access_check(struct task_struct *child,
					unsigned int mode)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	u32 desired_access;
	long ret;

	if (!child || !child->security)
		return -EACCES;
	if (child == current)
		return 0;

	caller_state = pkm_kacs_current_process_state();
	target_state = pkm_kacs_task(child)->process_state;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;

	ret = pkm_kacs_ptrace_mode_to_process_access(mode, &desired_access);
	if (ret)
		return ret;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), desired_access);
}

int pkm_kacs_ptrace_traceme(struct task_struct *parent)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const struct cred *parent_cred;
	const void *subject_token;
	long ret;

	if (!parent || !parent->security)
		return -EACCES;
	if (parent == current)
		return 0;
	if (!pkm_kacs_current_token_eval_context_allowed())
		return -EACCES;

	parent_cred = get_task_cred(parent);
	if (!parent_cred)
		return -EACCES;
	if (!parent_cred->security) {
		put_cred(parent_cred);
		return -EACCES;
	}

	caller_state = pkm_kacs_task(parent)->process_state;
	target_state = pkm_kacs_current_process_state();
	subject_token = pkm_kacs_cred(parent_cred)->token;
	if (!caller_state || !target_state || !subject_token) {
		ret = -EACCES;
		goto out_put;
	}
	if (caller_state == target_state) {
		ret = 0;
		goto out_put;
	}

	ret = pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), KACS_PROCESS_VM_WRITE);

out_put:
	put_cred(parent_cred);
	return ret;
}

int pkm_kacs_task_setnice(struct task_struct *task, int nice)
{
	(void)nice;

	return pkm_kacs_task_process_attribute_access(
		task, KACS_PROCESS_SET_INFORMATION);
}

int pkm_kacs_task_setscheduler(struct task_struct *task)
{
	return pkm_kacs_task_setnice(task, 0);
}

int pkm_kacs_task_setioprio(struct task_struct *task, int ioprio)
{
	(void)ioprio;
	return pkm_kacs_task_setnice(task, 0);
}

int pkm_kacs_task_setpgid(struct task_struct *task, pid_t pgid)
{
	(void)pgid;
	return pkm_kacs_task_process_attribute_access(
		task, KACS_PROCESS_SET_INFORMATION);
}

int pkm_kacs_task_getpgid(struct task_struct *task)
{
	return pkm_kacs_task_process_attribute_access(
		task, KACS_PROCESS_QUERY_LIMITED);
}

int pkm_kacs_task_getsid(struct task_struct *task)
{
	return pkm_kacs_task_process_attribute_access(
		task, KACS_PROCESS_QUERY_LIMITED);
}

int pkm_kacs_task_getscheduler(struct task_struct *task)
{
	return pkm_kacs_task_process_attribute_access(
		task, KACS_PROCESS_QUERY_INFORMATION);
}

int pkm_kacs_task_getioprio(struct task_struct *task)
{
	return pkm_kacs_task_process_attribute_access(
		task, KACS_PROCESS_QUERY_INFORMATION);
}

int pkm_kacs_task_movememory(struct task_struct *task)
{
	return pkm_kacs_task_process_attribute_access(
		task, KACS_PROCESS_SET_INFORMATION);
}

int pkm_kacs_task_prlimit(const struct cred *cred,
				 const struct cred *tcred,
				 unsigned int flags)
{
	const struct pkm_kacs_cred_security *caller_sec;
	const struct pkm_kacs_cred_security *target_sec;
	const struct pkm_kacs_process_state *caller_state;
	const struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	u32 desired_access;
	long ret;

	if (!cred || !tcred)
		return -EACCES;
	if (!pkm_kacs_current_token_eval_context_allowed())
		return -EACCES;

	caller_sec = pkm_kacs_cred(cred);
	target_sec = pkm_kacs_cred(tcred);
	caller_state = caller_sec->process_state;
	target_state = target_sec->process_state;
	subject_token = caller_sec->token;
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;
	if (caller_state == target_state)
		return 0;

	ret = pkm_kacs_prlimit_flags_to_process_access(flags, &desired_access);
	if (ret)
		return ret;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), desired_access);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
bool pkm_kacs_kunit_pip_dominates(u32 caller_pip_type, u32 caller_pip_trust,
				  u32 target_pip_type, u32 target_pip_trust)
{
	return pkm_kacs_pip_dominates(caller_pip_type, caller_pip_trust,
				      target_pip_type, target_pip_trust);
}

long pkm_kacs_kunit_check_signal_for_subject(
	const struct pkm_kacs_kunit_process_signal_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state target_state = {};
	u32 desired_access;
	long ret;

	if (!args)
		return -EINVAL;
	if (args->kernel_originated)
		return 0;

	ret = pkm_kacs_signal_to_process_access(args->sig, &desired_access);
	if (ret)
		return ret;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_authorize_process_access_core(
		args->subject_token, &target_state, args->caller_pip_type,
		args->caller_pip_trust, desired_access);
}

long pkm_kacs_kunit_check_signal_for_current(
	const struct pkm_kacs_kunit_process_signal_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state target_state = {};
	const void *subject_token;
	u32 desired_access;
	long ret;

	if (!args)
		return -EINVAL;
	if (args->kernel_originated)
		return 0;

	ret = pkm_kacs_signal_to_process_access(args->sig, &desired_access);
	if (ret)
		return ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	caller_state = pkm_kacs_current_process_state();
	if (!subject_token || !caller_state)
		return -EACCES;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_authorize_process_access_core(
		subject_token, &target_state,
		READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), desired_access);
}

long pkm_kacs_kunit_check_ptrace_for_subject(
	const struct pkm_kacs_kunit_process_ptrace_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state target_state = {};
	u32 desired_access;
	long ret;

	if (!args)
		return -EINVAL;

	ret = pkm_kacs_ptrace_mode_to_process_access(args->mode,
						     &desired_access);
	if (ret)
		return ret;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_authorize_process_access_core(
		args->subject_token, &target_state, args->caller_pip_type,
		args->caller_pip_trust, desired_access);
}

long pkm_kacs_kunit_check_ptrace_traceme_for_subject(
	const struct pkm_kacs_kunit_process_ptrace_check_args *args)
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

	return pkm_kacs_authorize_process_access_core(
		args->subject_token, &target_state, args->caller_pip_type,
		args->caller_pip_trust, KACS_PROCESS_VM_WRITE);
}

long pkm_kacs_kunit_check_process_setinfo_for_subject(
	const struct pkm_kacs_kunit_process_setinfo_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;
	if (args->self_target)
		return 0;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_check_process_setinfo_core(args->subject_token,
						   &caller_state,
						   &target_state);
}

long pkm_kacs_kunit_check_process_affinity_for_subject(
	const struct pkm_kacs_kunit_process_affinity_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;
	if (args->same_process)
		return 0;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_check_process_affinity_core(args->subject_token,
						    &caller_state,
						    &target_state);
}

long pkm_kacs_kunit_check_prlimit_for_subject(
	const struct pkm_kacs_kunit_process_prlimit_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state target_state = {};
	u32 desired_access;
	long ret;

	if (!args)
		return -EINVAL;
	if (args->self_target)
		return 0;

	ret = pkm_kacs_prlimit_flags_to_process_access(args->flags,
						       &desired_access);
	if (ret)
		return ret;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_authorize_process_access_core(
		args->subject_token, &target_state, args->caller_pip_type,
		args->caller_pip_trust, desired_access);
}

long pkm_kacs_kunit_check_process_attribute_for_subject(
	const struct pkm_kacs_kunit_process_access_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;
	if (args->self_target)
		return pkm_kacs_validate_process_attribute_access(
			args->desired_access);

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_check_process_attribute_core(
		args->subject_token, &caller_state, &target_state,
		args->desired_access);
}

long pkm_kacs_kunit_check_perf_event_for_subject(
	const struct pkm_kacs_kunit_process_perf_check_args *args)
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

	return pkm_kacs_check_process_perf_core(args->subject_token,
						&caller_state,
						&target_state,
						args->self_target != 0);
}
#endif /* CONFIG_SECURITY_PKM_KUNIT */
