/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_PROCESS_TOKEN_H
#define _SECURITY_PKM_KACS_PROCESS_TOKEN_H

#include <linux/types.h>

struct pkm_kacs_process_state;
struct task_struct;

long pkm_kacs_open_process_token_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task, u32 access_mask);
long pkm_kacs_open_thread_token_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task, u32 access_mask);

#endif /* _SECURITY_PKM_KACS_PROCESS_TOKEN_H */
