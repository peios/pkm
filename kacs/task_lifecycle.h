/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_TASK_LIFECYCLE_H
#define _SECURITY_PKM_KACS_TASK_LIFECYCLE_H

#include <linux/types.h>

struct task_struct;

int pkm_kacs_task_alloc(struct task_struct *task, u64 clone_flags);
void pkm_kacs_task_free(struct task_struct *task);

#endif /* _SECURITY_PKM_KACS_TASK_LIFECYCLE_H */
