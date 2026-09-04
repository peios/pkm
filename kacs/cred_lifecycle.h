/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_CRED_LIFECYCLE_H
#define _SECURITY_PKM_KACS_CRED_LIFECYCLE_H

#include <linux/gfp_types.h>
#include <linux/types.h>

#define PKM_KACS_UNMAPPED_ID 65534U

struct cred;
struct pkm_kacs_cred_security;

void pkm_kacs_stamp_projected_ids(struct pkm_kacs_cred_security *sec);
void pkm_kacs_cred_set_projected_ids(struct cred *cred, u32 uid, u32 gid);
long pkm_kacs_project_linux_cred_from_token(struct cred *cred,
					    const void *token);
int pkm_kacs_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);
void pkm_kacs_cred_transfer(struct cred *new, const struct cred *old);
int pkm_kacs_cred_alloc_blank(struct cred *cred, gfp_t gfp);
void pkm_kacs_cred_free(struct cred *cred);
long pkm_kacs_install_primary_on_child_cred_pair(
	const struct cred *child_cred, const struct cred *child_real_cred,
	const void *source_primary_token, bool deep_copy_primary);
long pkm_kacs_apply_clone_token_lifecycle(
	const struct cred **child_credp, const struct cred **child_real_credp,
	u64 clone_flags);
long pkm_kacs_install_token_ref_on_cred(struct cred *cred,
					const void *token_ref,
					bool project_linux_ids);

#endif /* _SECURITY_PKM_KACS_CRED_LIFECYCLE_H */
