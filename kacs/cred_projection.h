/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_CRED_PROJECTION_H
#define _SECURITY_PKM_KACS_CRED_PROJECTION_H

#include <linux/types.h>
#include <linux/uidgid.h>

struct cred;

long pkm_kacs_task_fix_setuid_core(const void *subject_token,
				   struct cred *new, const struct cred *old,
				   int flags);
long pkm_kacs_task_fix_setgid_core(const void *subject_token,
				   struct cred *new, const struct cred *old,
				   int flags);
long pkm_kacs_task_fix_setgroups_core(const void *subject_token,
				      struct cred *new,
				      const struct cred *old);
int pkm_kacs_task_fix_setuid(struct cred *new, const struct cred *old,
			     int flags);
int pkm_kacs_task_fix_setgid(struct cred *new, const struct cred *old,
			     int flags);
int pkm_kacs_task_fix_setgroups(struct cred *new, const struct cred *old);

kuid_t pkm_kacs_current_fsuid_kuid(void);
kgid_t pkm_kacs_current_fsgid_kgid(void);
void pkm_kacs_current_fsuid_fsgid(kuid_t *fsuid, kgid_t *fsgid);
void pkm_kacs_project_cred_uid_gid(const struct cred *cred, kuid_t *uid,
				   kgid_t *gid);

#endif /* _SECURITY_PKM_KACS_CRED_PROJECTION_H */
