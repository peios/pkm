// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <linux/sched/user.h>
#include <linux/uidgid.h>

#include <pkm/token.h>

#include "cred_projection.h"
#include "lsm_internal.h"
#include "token_runtime.h"

static void pkm_kacs_restore_capability_sets(struct cred *new,
					     const struct cred *old)
{
	if (!new || !old)
		return;

	new->cap_inheritable = old->cap_inheritable;
	new->cap_permitted = old->cap_permitted;
	new->cap_effective = old->cap_effective;
	new->cap_bset = old->cap_bset;
	new->cap_ambient = old->cap_ambient;
}

static void pkm_kacs_restore_uid_state(struct cred *new,
				       const struct cred *old)
{
	struct user_struct *old_user;

	if (!new || !old)
		return;

	new->uid = old->uid;
	new->euid = old->euid;
	new->suid = old->suid;
	new->fsuid = old->fsuid;
	pkm_kacs_restore_capability_sets(new, old);

	if (new->user == old->user)
		return;

	old_user = get_uid(old->user);
	free_uid(new->user);
	new->user = old_user;
}

static void pkm_kacs_restore_gid_state(struct cred *new,
				       const struct cred *old)
{
	if (!new || !old)
		return;

	new->gid = old->gid;
	new->egid = old->egid;
	new->sgid = old->sgid;
	new->fsgid = old->fsgid;
	pkm_kacs_restore_capability_sets(new, old);
}

static void pkm_kacs_restore_groups_state(struct cred *new,
					  const struct cred *old)
{
	if (!new || !old)
		return;

	set_groups(new, old->group_info);
	pkm_kacs_restore_capability_sets(new, old);
}

static long pkm_kacs_task_fix_setid_common(const void *subject_token)
{
	if (!subject_token)
		return -EACCES;
	if (kacs_rust_token_has_enabled_privilege(
		    subject_token, KACS_SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE))
		return -EOPNOTSUPP;

	return 0;
}

long pkm_kacs_task_fix_setuid_core(const void *subject_token,
				   struct cred *new,
				   const struct cred *old,
				   int flags)
{
	long ret;

	if (!new || !old)
		return -EINVAL;

	switch (flags) {
	case LSM_SETID_RE:
	case LSM_SETID_ID:
	case LSM_SETID_RES:
	case LSM_SETID_FS:
		break;
	default:
		return -EINVAL;
	}

	ret = pkm_kacs_task_fix_setid_common(subject_token);
	if (ret)
		return ret;

	pkm_kacs_restore_uid_state(new, old);
	return 0;
}

long pkm_kacs_task_fix_setgid_core(const void *subject_token,
				   struct cred *new,
				   const struct cred *old,
				   int flags)
{
	long ret;

	if (!new || !old)
		return -EINVAL;

	switch (flags) {
	case LSM_SETID_RE:
	case LSM_SETID_ID:
	case LSM_SETID_RES:
	case LSM_SETID_FS:
		break;
	default:
		return -EINVAL;
	}

	ret = pkm_kacs_task_fix_setid_common(subject_token);
	if (ret)
		return ret;

	pkm_kacs_restore_gid_state(new, old);
	return 0;
}

long pkm_kacs_task_fix_setgroups_core(const void *subject_token,
				      struct cred *new,
				      const struct cred *old)
{
	long ret;

	if (!new || !old)
		return -EINVAL;

	ret = pkm_kacs_task_fix_setid_common(subject_token);
	if (ret)
		return ret;

	pkm_kacs_restore_groups_state(new, old);
	return 0;
}

int pkm_kacs_task_fix_setuid(struct cred *new, const struct cred *old,
			     int flags)
{
	return (int)pkm_kacs_task_fix_setuid_core(
		pkm_kacs_current_effective_token_ptr(), new, old, flags);
}

int pkm_kacs_task_fix_setgid(struct cred *new, const struct cred *old,
			     int flags)
{
	return (int)pkm_kacs_task_fix_setgid_core(
		pkm_kacs_current_effective_token_ptr(), new, old, flags);
}

int pkm_kacs_task_fix_setgroups(struct cred *new, const struct cred *old)
{
	return (int)pkm_kacs_task_fix_setgroups_core(
		pkm_kacs_current_effective_token_ptr(), new, old);
}

kuid_t pkm_kacs_current_fsuid_kuid(void)
{
	const struct cred *cred = current_cred();
	const struct pkm_kacs_cred_security *sec;

	if (!cred || !cred->security)
		return cred ? cred->fsuid : GLOBAL_ROOT_UID;

	sec = pkm_kacs_cred(cred);
	if (!sec->token)
		return cred->fsuid;

	return KUIDT_INIT(sec->projected_uid);
}
EXPORT_SYMBOL_GPL(pkm_kacs_current_fsuid_kuid);

kgid_t pkm_kacs_current_fsgid_kgid(void)
{
	const struct cred *cred = current_cred();
	const struct pkm_kacs_cred_security *sec;

	if (!cred || !cred->security)
		return cred ? cred->fsgid : GLOBAL_ROOT_GID;

	sec = pkm_kacs_cred(cred);
	if (!sec->token)
		return cred->fsgid;

	return KGIDT_INIT(sec->projected_gid);
}
EXPORT_SYMBOL_GPL(pkm_kacs_current_fsgid_kgid);

void pkm_kacs_current_fsuid_fsgid(kuid_t *fsuid, kgid_t *fsgid)
{
	if (fsuid)
		*fsuid = pkm_kacs_current_fsuid_kuid();
	if (fsgid)
		*fsgid = pkm_kacs_current_fsgid_kgid();
}
EXPORT_SYMBOL_GPL(pkm_kacs_current_fsuid_fsgid);

void pkm_kacs_project_cred_uid_gid(const struct cred *cred, kuid_t *uid,
				   kgid_t *gid)
{
	const struct pkm_kacs_cred_security *sec;
	kuid_t projected_uid;
	kgid_t projected_gid;

	if (!cred)
		return;

	projected_uid = cred->euid;
	projected_gid = cred->egid;
	if (cred->security) {
		sec = pkm_kacs_cred(cred);
		if (sec->token) {
			projected_uid = KUIDT_INIT(sec->projected_uid);
			projected_gid = KGIDT_INIT(sec->projected_gid);
		}
	}

	if (uid)
		*uid = projected_uid;
	if (gid)
		*gid = projected_gid;
}
EXPORT_SYMBOL_GPL(pkm_kacs_project_cred_uid_gid);
