/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_PRIMARY_TOKEN_H
#define _SECURITY_PKM_KACS_PRIMARY_TOKEN_H

struct cred;
struct task_struct;

long pkm_kacs_prepare_current_token_cred(const void *token, struct cred **out);

void pkm_kacs_primary_thread_enroll(struct task_struct *task);
void pkm_kacs_primary_exec_committed(void);
/* Owned reference; caller holds current->signal->cred_guard_mutex. */
const void *pkm_kacs_primary_token_for_exec(void);

#endif /* _SECURITY_PKM_KACS_PRIMARY_TOKEN_H */
