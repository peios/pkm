// SPDX-License-Identifier: GPL-2.0-only
/*
 * Mount namespaces as KACS objects.
 *
 * Linux decides who may change a mount table with CAP_SYS_ADMIN in the user
 * namespace that owns it, and lets an unprivileged process manufacture that
 * capability by creating a user namespace first. Under KACS a user namespace
 * confers nothing (the capability switchboard discards it), so that route
 * leads nowhere, and until this object existed only SeManageVolumePrivilege
 * or SeTcbPrivilege could reshape any mount table at all.
 *
 * This file gives every mount namespace other than the initial one a
 * security descriptor, minted from the creating token at copy_mnt_ns(), and
 * answers may_mount() from it: the privilege first, as before, and otherwise
 * an access check for KACS_MNTNS_MOUNT against the caller's own namespace.
 * Creating a namespace needs no privilege. The initial namespace carries no
 * descriptor, so the root table is reachable only through the privilege,
 * exactly as it was.
 *
 * Only a bind mount, an unmount and pivot_root can be admitted by the
 * descriptor. Everything else — a filesystem type, a remount, a move, a
 * propagation change, the new mount API — still needs the privilege, so a
 * private table never puts a filesystem parser in reach of an unprivileged
 * caller. The other Linux reasons for gating a private table do not apply
 * here: the token never changes at exec, and every file access is decided on
 * the real object's descriptor, so a bind mount shows a name and denies at
 * open.
 */

#include <linux/errno.h>
#include <linux/kacs_mntns.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <pkm/mntns.h>
#include <pkm/token.h>
#include <pkm/trace.h>

#include "access_check.h"
#include "capability.h"
#include "lsm_internal.h"
#include "mnt_namespace.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

#define PKM_KACS_MNTNS_PRIVILEGE_MASK \
	(KACS_SE_MANAGE_VOLUME_PRIVILEGE | KACS_SE_TCB_PRIVILEGE)

struct pkm_kacs_process_sd *pkm_kacs_mntns_sd_alloc(const void *token)
{
	struct pkm_kacs_process_sd *sd;
	size_t len = 0;
	const u8 *bytes;

	if (!token)
		return NULL;

	bytes = kacs_rust_create_default_mnt_ns_sd(token, &len);
	if (!bytes || len == 0) {
		trace_kacs_mntns(0, 0, KACS_MNTNS_SD_ALLOC_FAIL, -ENOMEM);
		return NULL;
	}

	sd = pkm_kacs_process_sd_wrap_bytes(bytes, len);
	trace_kacs_mntns(0, 0, sd ? KACS_MNTNS_SD_ALLOC : KACS_MNTNS_SD_ALLOC_FAIL,
			 sd ? 0 : -ENOMEM);
	return sd;
}

struct pkm_kacs_mntns_security *pkm_kacs_mntns_security_create(void)
{
	struct pkm_kacs_mntns_security *sec;
	const void *token = pkm_kacs_current_effective_token_ptr();

	/*
	 * A task with no token is a kernel thread or the boot path; it can
	 * only be reshaping tables through the privilege rung anyway, and a
	 * namespace it creates has no creator to name.
	 */
	if (!token)
		return NULL;

	sec = kzalloc(sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return ERR_PTR(-ENOMEM);

	sec->sd = pkm_kacs_mntns_sd_alloc(token);
	if (!sec->sd) {
		kfree(sec);
		return ERR_PTR(-ENOMEM);
	}
	return sec;
}

void pkm_kacs_mntns_security_free(struct pkm_kacs_mntns_security *sec)
{
	if (!sec)
		return;
	pkm_kacs_process_sd_put(sec->sd);
	kfree(sec);
}

bool pkm_kacs_mntns_creator_privileged(void)
{
	const void *token = pkm_kacs_current_effective_token_ptr();

	if (!token)
		return false;
	return kacs_rust_token_enabled_privileges_in_mask(
		       token, PKM_KACS_MNTNS_PRIVILEGE_MASK) != 0;
}

static bool pkm_kacs_mntns_op_admissible(unsigned int op)
{
	switch (op) {
	case PKM_KACS_MNTNS_OP_BIND:
	case PKM_KACS_MNTNS_OP_UMOUNT:
	case PKM_KACS_MNTNS_OP_PIVOT_ROOT:
		return true;
	default:
		return false;
	}
}

bool pkm_kacs_may_mount_op_for_token(const void *subject_token,
				     const struct pkm_kacs_process_sd *sd,
				     unsigned int op)
{
	u32 granted = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	int ret;

	if (!subject_token)
		return pkm_kacs_may_manage_volumes_for_token(NULL);

	/*
	 * The privilege rung is decided first and alone: a token that holds
	 * the privilege is answered by it, including its use-mark, and never
	 * reaches the descriptor. Asking whether it is held before asking the
	 * gate keeps an unprivileged caller's routine bind mount from logging
	 * a privilege refusal it was never relying on.
	 */
	if (kacs_rust_token_enabled_privileges_in_mask(
		    subject_token, PKM_KACS_MNTNS_PRIVILEGE_MASK)) {
		bool allowed = pkm_kacs_may_manage_volumes_for_token(
			subject_token);

		trace_kacs_mntns(op, 0, KACS_MNTNS_GATE_PRIVILEGE,
				 allowed ? 0 : -EPERM);
		return allowed;
	}

	if (!sd || !sd->bytes || !sd->len) {
		trace_kacs_mntns(op, 0, KACS_MNTNS_GATE_NO_SD, -EPERM);
		return false;
	}

	if (!pkm_kacs_mntns_op_admissible(op)) {
		trace_kacs_mntns(op, 0, KACS_MNTNS_GATE_OP_NOT_ADMITTED, -EPERM);
		return false;
	}

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret) {
		trace_kacs_mntns(op, KACS_MNTNS_MOUNT, KACS_MNTNS_GATE_PIP_CONTEXT,
				 ret);
		return false;
	}

	ret = kacs_rust_check_mnt_ns_sd(subject_token, sd->bytes, sd->len,
					KACS_MNTNS_MOUNT, pip_type, pip_trust,
					&granted);
	trace_kacs_mntns(op, KACS_MNTNS_MOUNT, KACS_MNTNS_GATE_SD_DECISION, ret);
	return ret == 0;
}

bool pkm_kacs_may_mount_op(const struct pkm_kacs_mntns_security *sec,
			   unsigned int op)
{
	return pkm_kacs_may_mount_op_for_token(
		pkm_kacs_current_effective_token_ptr(), sec ? sec->sd : NULL,
		op);
}
