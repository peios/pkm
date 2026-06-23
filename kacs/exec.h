/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_EXEC_H
#define _SECURITY_PKM_KACS_EXEC_H

#include <linux/types.h>

struct cred;
struct file;
struct linux_binprm;

int pkm_kacs_bprm_check_security(struct linux_binprm *bprm);
int pkm_kacs_bprm_creds_from_file(struct linux_binprm *bprm,
				  const struct file *file);
void pkm_kacs_bprm_committing_creds(const struct linux_binprm *bprm);
void pkm_kacs_bprm_committed_creds(const struct linux_binprm *bprm);
long pkm_kacs_bprm_creds_from_file_core(const void *subject_token,
					const void *primary_token,
					const struct file *file,
					struct cred *new,
					const struct cred *old,
					bool require_file_for_npm,
					bool stage_exec_pip);

#endif /* _SECURITY_PKM_KACS_EXEC_H */
