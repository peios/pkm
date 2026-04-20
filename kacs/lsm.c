// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM boot token/session substrate.
 *
 * Slice 21 adds only the first live credential blob and boot SYSTEM token
 * attachment. It intentionally stops short of public token syscalls,
 * impersonation install/revert, or broader process/object security plumbing.
 */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/slab.h>

#include "token_runtime.h"

#define PKM_KACS_UNMAPPED_ID 65534U

struct pkm_kacs_cred_security {
	const void *token;
	u32 projected_uid;
	u32 projected_gid;
};

extern int kacs_rust_init(void);

static const struct lsm_id pkm_lsmid = {
	.name = "pkm",
	.id = 1000,
};
static const void *pkm_kacs_boot_system_token;

static struct lsm_blob_sizes pkm_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct pkm_kacs_cred_security),
};

static inline struct pkm_kacs_cred_security *pkm_kacs_cred(const struct cred *cred)
{
	return (struct pkm_kacs_cred_security *)((char *)cred->security +
						 pkm_blob_sizes.lbs_cred);
}

static void pkm_kacs_assert_boot_caps(struct cred *cred)
{
	kernel_cap_t caps = CAP_EMPTY_SET;

	cap_raise(caps, CAP_CHOWN);
	cap_raise(caps, CAP_DAC_OVERRIDE);
	cap_raise(caps, CAP_DAC_READ_SEARCH);
	cap_raise(caps, CAP_FOWNER);
	cap_raise(caps, CAP_FSETID);
	cap_raise(caps, CAP_KILL);
	cap_raise(caps, CAP_SETGID);
	cap_raise(caps, CAP_SETUID);
	cap_raise(caps, CAP_NET_BROADCAST);
	cap_raise(caps, CAP_IPC_OWNER);
	cap_raise(caps, CAP_LEASE);

	cred->cap_effective = caps;
	cred->cap_permitted = caps;
	cred->cap_inheritable = caps;
	cap_clear(cred->cap_ambient);
}

static void pkm_kacs_stamp_projected_ids(struct pkm_kacs_cred_security *sec)
{
	if (!sec->token) {
		sec->projected_uid = PKM_KACS_UNMAPPED_ID;
		sec->projected_gid = PKM_KACS_UNMAPPED_ID;
		return;
	}

	sec->projected_uid = kacs_rust_token_projected_uid(sec->token);
	sec->projected_gid = kacs_rust_token_projected_gid(sec->token);
}

static int pkm_kacs_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	struct pkm_kacs_cred_security *new_sec = pkm_kacs_cred(new);
	const struct pkm_kacs_cred_security *old_sec = pkm_kacs_cred(old);

	(void)gfp;
	if (old_sec->token)
		new_sec->token = kacs_rust_token_deep_copy(old_sec->token);
	else
		new_sec->token = NULL;

	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_assert_boot_caps(new);
	return 0;
}

static void pkm_kacs_cred_transfer(struct cred *new, const struct cred *old)
{
	struct pkm_kacs_cred_security *new_sec = pkm_kacs_cred(new);
	const struct pkm_kacs_cred_security *old_sec = pkm_kacs_cred(old);

	if (old_sec->token)
		new_sec->token = kacs_rust_token_deep_copy(old_sec->token);
	else
		new_sec->token = NULL;

	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_assert_boot_caps(new);
}

static int pkm_kacs_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct pkm_kacs_cred_security *sec = pkm_kacs_cred(cred);

	(void)gfp;
	sec->token = NULL;
	sec->projected_uid = PKM_KACS_UNMAPPED_ID;
	sec->projected_gid = PKM_KACS_UNMAPPED_ID;
	return 0;
}

static void pkm_kacs_cred_free(struct cred *cred)
{
	struct pkm_kacs_cred_security *sec = pkm_kacs_cred(cred);

	if (sec->token)
		kacs_rust_token_drop(sec->token);
}

static struct security_hook_list pkm_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, pkm_kacs_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, pkm_kacs_cred_transfer),
	LSM_HOOK_INIT(cred_alloc_blank, pkm_kacs_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, pkm_kacs_cred_free),
};

void *pkm_kacs_zalloc(size_t size)
{
	return kzalloc(size, GFP_KERNEL);
}

void pkm_kacs_free(void *ptr)
{
	kfree(ptr);
}

const void *pkm_kacs_current_effective_token_ptr(void)
{
	return pkm_kacs_cred(current_cred())->token;
}

const void *pkm_kacs_current_primary_token_ptr(void)
{
	return pkm_kacs_cred(current_real_cred())->token;
}

const void *pkm_kacs_boot_system_token_ptr(void)
{
	return pkm_kacs_boot_system_token;
}

int pkm_kacs_resolve_ctx_from_token(const void *token,
				    struct pkm_kacs_resolved_ctx *out)
{
	if (!out)
		return -EINVAL;
	if (!token)
		return -EACCES;

	out->kind = PKM_KACS_RESOLVED_CTX_TOKEN;
	out->_reserved = 0;
	out->token = token;
	return 0;
}

int pkm_kacs_resolve_current_effective_ctx(struct pkm_kacs_resolved_ctx *out)
{
	return pkm_kacs_resolve_ctx_from_token(
		pkm_kacs_current_effective_token_ptr(), out);
}

int pkm_kacs_resolve_current_primary_ctx(struct pkm_kacs_resolved_ctx *out)
{
	return pkm_kacs_resolve_ctx_from_token(
		pkm_kacs_current_primary_token_ptr(), out);
}

static int __init pkm_init(void)
{
	const void *system_token;
	struct pkm_kacs_cred_security *sec;
	int ret;

	if (IS_ENABLED(CONFIG_SECURITY_SELINUX) ||
	    IS_ENABLED(CONFIG_SECURITY_APPARMOR) ||
	    IS_ENABLED(CONFIG_SECURITY_SMACK) ||
	    IS_ENABLED(CONFIG_SECURITY_TOMOYO) ||
	    IS_ENABLED(CONFIG_BPF_LSM)) {
		pr_err("pkm: conflicting MAC or BPF LSM detected\n");
		return -EINVAL;
	}

	security_add_hooks(pkm_hooks, ARRAY_SIZE(pkm_hooks), &pkm_lsmid);

	ret = kacs_rust_init();
	if (ret) {
		pr_err("pkm: slow-track Rust init failed (%d)\n", ret);
		return ret;
	}

	system_token = kacs_rust_create_boot_system_token();
	if (!system_token)
		return -ENOMEM;
	pkm_kacs_boot_system_token = system_token;

	sec = pkm_kacs_cred(current_cred());
	sec->token = system_token;
	pkm_kacs_stamp_projected_ids(sec);
	pkm_kacs_assert_boot_caps((struct cred *)current_cred());

	if (current_cred() != current_real_cred()) {
		struct pkm_kacs_cred_security *real_sec =
			pkm_kacs_cred(current_real_cred());

		real_sec->token = kacs_rust_token_clone(system_token);
		pkm_kacs_stamp_projected_ids(real_sec);
		pkm_kacs_assert_boot_caps((struct cred *)current_real_cred());
	}

	pr_info("pkm: slow-track kernel scaffold initialized\n");
	return 0;
}

DEFINE_LSM(pkm) = {
	.id = &pkm_lsmid,
	.init = pkm_init,
	.blobs = &pkm_blob_sizes,
};
