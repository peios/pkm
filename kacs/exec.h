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
					bool stage_exec_pip,
					bool usermodehelper,
					unsigned int bprm_unsafe);
bool pkm_kacs_exec_pip_cap_for_unsafe(unsigned int bprm_unsafe,
				      u32 current_pip_type,
				      u32 current_pip_trust,
				      u32 *exec_pip_type,
				      u32 *exec_pip_trust);

/*
 * Called from kernel/umh.c on a usermodehelper child immediately before it
 * execs, so the exec path can tell a kernel-initiated exec from any other one.
 * See kernel/patches/kernel/umh-mark-usermodehelper.patch.
 */
void pkm_kacs_mark_usermodehelper(void);
bool pkm_kacs_current_is_usermodehelper(void);

/*
 * The PeiosTcb floor itself, as a predicate: true when this exec must be
 * refused. Split out so the rule is testable without standing up creds, tokens
 * and a mounted file.
 */
bool pkm_kacs_umh_exec_denied(bool usermodehelper, u32 exec_pip_trust);

#endif /* _SECURITY_PKM_KACS_EXEC_H */
