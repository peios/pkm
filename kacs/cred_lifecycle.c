// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/sched/user.h>
#include <linux/types.h>
#include <linux/uidgid.h>

#include "capability.h"
#include "cred_lifecycle.h"
#include "lsm_internal.h"
#include "process_state.h"
#include "token_runtime.h"

void pkm_kacs_stamp_projected_ids(struct pkm_kacs_cred_security *sec)
{
	if (!sec->token) {
		sec->projected_uid = PKM_KACS_UNMAPPED_ID;
		sec->projected_gid = PKM_KACS_UNMAPPED_ID;
		return;
	}

	sec->projected_uid = kacs_rust_token_projected_uid(sec->token);
	sec->projected_gid = kacs_rust_token_projected_gid(sec->token);
}

long pkm_kacs_project_linux_cred_from_token(struct cred *cred,
					    const void *token)
{
	struct group_info *groups;
	struct user_struct *new_user;
	size_t group_count;
	size_t i;
	u32 projected_uid;
	u32 projected_gid;
	long ret;

	if (!cred || !token)
		return -EINVAL;

	projected_uid = kacs_rust_token_projected_uid(token);
	if (projected_uid == 0 && !kacs_rust_token_allows_uid0_projection(token))
		return -EACCES;

	projected_gid = kacs_rust_token_projected_gid(token);
	group_count = kacs_rust_token_projected_supplementary_gid_count(token);
	if (group_count > NGROUPS_MAX)
		return -E2BIG;

	groups = groups_alloc((int)group_count);
	if (!groups)
		return -ENOMEM;

	for (i = 0; i < group_count; i++) {
		u32 gid;

		ret = kacs_rust_token_projected_supplementary_gid(token, i,
								  &gid);
		if (ret) {
			put_group_info(groups);
			return ret;
		}
		groups->gid[i] = KGIDT_INIT(gid);
	}
	groups_sort(groups);

	new_user = alloc_uid(KUIDT_INIT(projected_uid));
	if (!new_user) {
		put_group_info(groups);
		return -EAGAIN;
	}

	cred->uid = KUIDT_INIT(projected_uid);
	cred->euid = KUIDT_INIT(projected_uid);
	cred->suid = KUIDT_INIT(projected_uid);
	cred->fsuid = KUIDT_INIT(projected_uid);
	cred->gid = KGIDT_INIT(projected_gid);
	cred->egid = KGIDT_INIT(projected_gid);
	cred->sgid = KGIDT_INIT(projected_gid);
	cred->fsgid = KGIDT_INIT(projected_gid);
	free_uid(cred->user);
	cred->user = new_user;

	ret = set_cred_ucounts(cred);
	if (ret) {
		put_group_info(groups);
		return ret;
	}

	set_groups(cred, groups);
	put_group_info(groups);
	return 0;
}

int pkm_kacs_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	struct pkm_kacs_cred_security *new_sec = pkm_kacs_cred(new);
	const struct pkm_kacs_cred_security *old_sec = pkm_kacs_cred(old);

	(void)gfp;
	if (old_sec->token) {
		new_sec->token = kacs_rust_token_clone(old_sec->token);
		if (!new_sec->token)
			return -ENOMEM;
	} else {
		new_sec->token = NULL;
	}
	if (old_sec->process_state)
		new_sec->process_state =
			pkm_kacs_process_state_get(old_sec->process_state);
	else
		new_sec->process_state = NULL;

	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_raise_allow_compat_caps(new);
	return 0;
}

void pkm_kacs_cred_transfer(struct cred *new, const struct cred *old)
{
	struct pkm_kacs_cred_security *new_sec = pkm_kacs_cred(new);
	const struct pkm_kacs_cred_security *old_sec = pkm_kacs_cred(old);

	if (old_sec->token)
		new_sec->token = kacs_rust_token_clone(old_sec->token);
	else
		new_sec->token = NULL;
	if (old_sec->process_state)
		new_sec->process_state =
			pkm_kacs_process_state_get(old_sec->process_state);
	else
		new_sec->process_state = NULL;

	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_raise_allow_compat_caps(new);
}

int pkm_kacs_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct pkm_kacs_cred_security *sec = pkm_kacs_cred(cred);

	(void)gfp;
	sec->token = NULL;
	sec->process_state = NULL;
	sec->projected_uid = PKM_KACS_UNMAPPED_ID;
	sec->projected_gid = PKM_KACS_UNMAPPED_ID;
	return 0;
}

void pkm_kacs_cred_free(struct cred *cred)
{
	struct pkm_kacs_cred_security *sec = pkm_kacs_cred(cred);

	if (sec->token)
		kacs_rust_token_drop(sec->token);
	if (sec->process_state)
		pkm_kacs_process_state_put(sec->process_state);
}

static bool pkm_kacs_cred_is_current_shared(const struct cred *cred)
{
	return cred == current_cred() || cred == current_real_cred();
}

long pkm_kacs_install_primary_on_child_cred_pair(
	const struct cred *child_cred, const struct cred *child_real_cred,
	const void *source_primary_token, bool deep_copy_primary)
{
	const void *child_primary;
	const void *child_effective;
	long ret;

	if (!child_cred || !child_real_cred || !source_primary_token)
		return -EACCES;
	if (pkm_kacs_cred_is_current_shared(child_cred) ||
	    pkm_kacs_cred_is_current_shared(child_real_cred))
		return -EACCES;

	child_primary = deep_copy_primary ?
				kacs_rust_token_deep_copy(source_primary_token) :
				kacs_rust_token_clone(source_primary_token);
	if (!child_primary)
		return -ENOMEM;

	ret = pkm_kacs_install_token_ref_on_cred((struct cred *)child_real_cred,
						child_primary, false);
	if (ret) {
		kacs_rust_token_drop(child_primary);
		return ret;
	}

	if (child_cred == child_real_cred)
		return 0;

	child_effective = kacs_rust_token_clone(
		pkm_kacs_cred(child_real_cred)->token);
	if (!child_effective)
		return -ENOMEM;

	ret = pkm_kacs_install_token_ref_on_cred((struct cred *)child_cred,
						child_effective, false);
	if (ret) {
		kacs_rust_token_drop(child_effective);
		return ret;
	}
	return 0;
}

long pkm_kacs_apply_clone_token_lifecycle(
	const struct cred **child_credp, const struct cred **child_real_credp,
	u64 clone_flags)
{
	const struct cred *child_cred;
	const struct cred *child_real_cred;
	const struct cred *parent_effective_cred;
	const struct cred *parent_primary_cred;
	const void *parent_primary_token;

	if (!child_credp || !child_real_credp)
		return -EACCES;

	child_cred = *child_credp;
	child_real_cred = *child_real_credp;
	parent_effective_cred = current_cred();
	parent_primary_cred = current_real_cred();
	parent_primary_token = pkm_kacs_current_primary_token_ptr();
	if (!child_cred || !child_real_cred || !parent_primary_token)
		return -EACCES;

	if ((clone_flags & CLONE_THREAD) != 0) {
		if (parent_effective_cred != parent_primary_cred &&
		    (child_cred == parent_effective_cred ||
		     child_real_cred == parent_effective_cred)) {
			get_cred_many(parent_primary_cred, 2);
			put_cred(child_cred);
			put_cred(child_real_cred);
			*child_credp = parent_primary_cred;
			*child_real_credp = parent_primary_cred;
			return 0;
		}

		if (child_cred == parent_primary_cred &&
		    child_real_cred == parent_primary_cred)
			return 0;

		return pkm_kacs_install_primary_on_child_cred_pair(
			child_cred, child_real_cred, parent_primary_token,
			false);
	}

	return pkm_kacs_install_primary_on_child_cred_pair(
		child_cred, child_real_cred, parent_primary_token, true);
}

long pkm_kacs_install_token_ref_on_cred(struct cred *cred,
					const void *token_ref,
					bool project_linux_ids)
{
	struct pkm_kacs_cred_security *sec;
	long ret;

	if (!cred || !cred->security || !token_ref)
		return -EACCES;

	if (project_linux_ids) {
		ret = pkm_kacs_project_linux_cred_from_token(cred, token_ref);
		if (ret)
			return ret;
	}

	sec = pkm_kacs_cred(cred);
	if (sec->token)
		kacs_rust_token_drop(sec->token);
	sec->token = token_ref;
	pkm_kacs_stamp_projected_ids(sec);
	pkm_kacs_raise_allow_compat_caps(cred);
	return 0;
}
