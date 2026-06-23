/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_PROCESS_ACCESS_H
#define _SECURITY_PKM_KACS_PROCESS_ACCESS_H

#include <linux/types.h>

struct cred;
struct kernel_siginfo;
struct pkm_kacs_process_sd;
struct pkm_kacs_process_state;
struct task_struct;

bool pkm_kacs_pip_dominates(u32 caller_pip_type, u32 caller_pip_trust,
			    u32 target_pip_type, u32 target_pip_trust);
long pkm_kacs_authorize_process_sd_access(
	const void *subject_token, const struct pkm_kacs_process_sd *process_sd,
	u32 desired_access, u32 pip_type, u32 pip_trust);
long pkm_kacs_authorize_process_sd_access_nondebug(
	const void *subject_token, const struct pkm_kacs_process_sd *process_sd,
	u32 desired_access, u32 privilege_intent, u32 pip_type, u32 pip_trust);
long pkm_kacs_enforce_cross_process_pip(
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state, bool self_target);
long pkm_kacs_authorize_process_access_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *target_state, u32 caller_pip_type,
	u32 caller_pip_trust, u32 desired_process_access);

long pkm_kacs_signal_to_process_access(int sig, u32 *desired_access);
bool pkm_kacs_signal_is_kernel_originated(
	const struct kernel_siginfo *info, const struct cred *cred);
long pkm_kacs_ptrace_mode_to_process_access(unsigned int mode,
					    u32 *desired_access);
long pkm_kacs_check_process_capget_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state);
long pkm_kacs_validate_process_attribute_access(u32 desired_access);
long pkm_kacs_check_process_attribute_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	u32 desired_access);
long pkm_kacs_prlimit_flags_to_process_access(unsigned int flags,
					      u32 *desired_access);
long pkm_kacs_check_process_setinfo_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state);
long pkm_kacs_check_process_affinity_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state);
long pkm_kacs_check_process_perf_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	bool self_target);

long pkm_kacs_proc_process_setinfo(struct task_struct *task);
long pkm_kacs_sched_setaffinity(struct task_struct *task);
long pkm_kacs_perf_event_open(struct task_struct *task);
int pkm_kacs_task_kill(struct task_struct *target,
		       struct kernel_siginfo *info, int sig,
		       const struct cred *cred);
int pkm_kacs_ptrace_access_check(struct task_struct *child,
				 unsigned int mode);
int pkm_kacs_ptrace_traceme(struct task_struct *parent);
int pkm_kacs_task_setnice(struct task_struct *task, int nice);
int pkm_kacs_task_setscheduler(struct task_struct *task);
int pkm_kacs_task_setioprio(struct task_struct *task, int ioprio);
int pkm_kacs_task_setpgid(struct task_struct *task, pid_t pgid);
int pkm_kacs_task_getpgid(struct task_struct *task);
int pkm_kacs_task_getsid(struct task_struct *task);
int pkm_kacs_task_getscheduler(struct task_struct *task);
int pkm_kacs_task_getioprio(struct task_struct *task);
int pkm_kacs_task_movememory(struct task_struct *task);
int pkm_kacs_task_prlimit(const struct cred *cred, const struct cred *tcred,
			  unsigned int flags);

#endif /* _SECURITY_PKM_KACS_PROCESS_ACCESS_H */
