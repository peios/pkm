// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "cred_lifecycle.h"
#include "lsm_internal.h"
#include "process_state.h"
#include "task_lifecycle.h"

#include <trace/events/kacs.h>

int pkm_kacs_task_alloc(struct task_struct *task, u64 clone_flags)
{
	const struct cred *child_cred;
	const struct cred *child_real_cred;
	struct pkm_kacs_task_security *new_sec;
	struct pkm_kacs_process_state *state;
	struct pkm_kacs_process_state *parent_state;
	long ret;

	if (!task || !task->security)
		return -EACCES;

	new_sec = pkm_kacs_task(task);
	new_sec->process_state = NULL;
	new_sec->impersonation_saved_cred = NULL;
	new_sec->native_open.expected_dentry = NULL;
	new_sec->native_open.expected_mnt = NULL;
	new_sec->native_open.desired_access = 0;
	new_sec->native_open.create_options = 0;
	new_sec->native_open.active = false;
	new_sec->native_create.expected_parent_inode = NULL;
	new_sec->native_create.sd_bytes = NULL;
	new_sec->native_create.sd_len = 0;
	new_sec->native_create.directory = false;
	new_sec->native_create.active = false;
	new_sec->metadata_decision.inode = NULL;
	new_sec->metadata_decision.op_class = PKM_KACS_METADATA_OP_NONE;
	new_sec->metadata_decision.active = 0;
	new_sec->pending_exec_pip_type = 0;
	new_sec->pending_exec_pip_trust = 0;
	new_sec->pending_exec_pip_valid = 0;

	parent_state = pkm_kacs_current_process_state();
	if (parent_state &&
	    pkm_kacs_clone_is_blocked_by_no_child(
		    pkm_kacs_process_state_mitigation_bits(parent_state),
		    clone_flags)) {
		trace_kacs_task(clone_flags, (u64)(uintptr_t)parent_state,
				KACS_TASK_ALLOC_NO_CHILD_BLOCKED, -EACCES);
		return -EACCES;
	}

	child_cred = task->cred;
	child_real_cred = task->real_cred;
	ret = pkm_kacs_apply_clone_token_lifecycle(&child_cred,
						   &child_real_cred,
						   clone_flags);
	if (ret)
		return (int)ret;
	rcu_assign_pointer(task->cred, child_cred);
	rcu_assign_pointer(task->real_cred, child_real_cred);

	state = pkm_kacs_inherit_process_state(clone_flags);
	if (!state) {
		trace_kacs_task(clone_flags, 0,
				KACS_TASK_ALLOC_INHERIT_ENOMEM, -ENOMEM);
		return -ENOMEM;
	}

	new_sec->process_state = state;
	pkm_kacs_set_cred_process_state((struct cred *)task->real_cred, state);
	if (task->cred != task->real_cred)
		pkm_kacs_set_cred_process_state((struct cred *)task->cred,
						state);
	trace_kacs_task(clone_flags, (u64)(uintptr_t)state, KACS_TASK_ALLOC, 0);
	return 0;
}

void pkm_kacs_task_free(struct task_struct *task)
{
	struct pkm_kacs_task_security *sec;

	if (!task || !task->security)
		return;

	sec = pkm_kacs_task(task);
	trace_kacs_task(0, (u64)(uintptr_t)sec->process_state,
			KACS_TASK_FREE, 0);
	pkm_kacs_process_state_put(sec->process_state);
	sec->process_state = NULL;
	sec->impersonation_saved_cred = NULL;
	sec->pending_exec_pip_type = 0;
	sec->pending_exec_pip_trust = 0;
	sec->pending_exec_pip_valid = 0;
}
