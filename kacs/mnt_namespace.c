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
 * A bind mount, an unmount, pivot_root, and a new tmpfs, proc or stratafs
 * can be admitted by the descriptor. Everything else — any other filesystem
 * type, a remount, a move, a propagation change, the new mount API — still
 * needs the privilege, so a private table never puts a filesystem parser that
 * reads an untrusted image in reach of an unprivileged caller. The allowlist
 * is a kernel attack-surface list, never a policy knob: who may change a
 * table is decided by the table's descriptor alone. The other Linux reasons for gating
 * a private table do not apply here: the token never changes at exec, and
 * every file access is decided on the real object's descriptor, so a bind
 * mount shows a name and denies at open.
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kacs_mntns.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include <pkm/mntns.h>
#include <pkm/token.h>
#include <pkm/trace.h>

#include "access_check.h"
#include "capability.h"
#include "lsm_internal.h"
#include "mnt_namespace.h"
#include "mount_policy.h"
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
	case PKM_KACS_MNTNS_OP_NEW_FS:
		return true;
	default:
		return false;
	}
}

/*
 * The filesystem types an unprivileged caller may bring into being in a
 * table it holds the mount right on. All three read nothing but the
 * caller's own mount options: tmpfs has no backing image, proc is a view of
 * the kernel's own state, and stratafs is a view of directories the caller
 * can already traverse, every access through it decided on the providing
 * object. A stratafs stack with a create stratum is refused by stratafs
 * itself (its get_tree demands the initial user namespace and
 * CAP_SYS_ADMIN, which is SeTcb here), so an unprivileged caller gets
 * read-only and absent-tolerant stacks only. A type that parses an image
 * (ext4, squashfs, iso9660, ntfs3 ...) is not here and stays privileged
 * whatever a descriptor grants.
 */
static bool pkm_kacs_mntns_fs_type_admissible(const char *fstype)
{
	return fstype && (!strcmp(fstype, "tmpfs") || !strcmp(fstype, "proc") ||
			  !strcmp(fstype, "stratafs"));
}

bool pkm_kacs_may_mount_op_for_token(const void *subject_token,
				     const struct pkm_kacs_process_sd *sd,
				     unsigned int op, const char *fstype)
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

	if (op == PKM_KACS_MNTNS_OP_NEW_FS &&
	    !pkm_kacs_mntns_fs_type_admissible(fstype)) {
		trace_kacs_mntns(op, 0, KACS_MNTNS_GATE_FS_NOT_ADMITTED, -EPERM);
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
			   unsigned int op, const char *fstype)
{
	return pkm_kacs_may_mount_op_for_token(
		pkm_kacs_current_effective_token_ptr(), sec ? sec->sd : NULL,
		op, fstype);
}

long pkm_kacs_mntns_stamp_superblock_for_token(struct super_block *sb,
					       const void *token)
{
	struct pkm_kacs_superblock_security *sec;
	const u8 *template_bytes;
	size_t template_len = 0;
	u32 generation;

	if (!sb || !sb->s_security || !token)
		return 0;
	if (sb->s_magic != TMPFS_MAGIC)
		return 0;
	/*
	 * A privileged mounter's tmpfs keeps the magic default (deny-missing)
	 * and the mounter seeds it, as the system's own overlays are seeded.
	 * Only a mount the descriptor rung admitted reaches the stamp.
	 */
	if (kacs_rust_token_enabled_privileges_in_mask(
		    token, PKM_KACS_MNTNS_PRIVILEGE_MASK))
		return 0;

	template_bytes = kacs_rust_create_default_mnt_ns_sd(token, &template_len);
	if (!template_bytes || template_len == 0) {
		trace_kacs_mntns(PKM_KACS_MNTNS_OP_NEW_FS, 0,
				 KACS_MNTNS_SB_STAMP_FAIL, -ENOMEM);
		return -ENOMEM;
	}

	sec = pkm_kacs_sb(sb);
	mutex_lock(&sec->lock);
	/*
	 * A generation above zero means kacs_set_mount_policy has already
	 * spoken for this superblock; the lazily cached magic default has not,
	 * and is what the root inode's creation during fill_super leaves
	 * behind. Bumping the generation retires anything cached under it.
	 */
	if (READ_ONCE(sec->policy_generation) != 0) {
		mutex_unlock(&sec->lock);
		pkm_kacs_free((void *)template_bytes);
		return 0;
	}
	generation = pkm_kacs_next_mount_policy_generation(0);
	sec->template_sd_bytes = template_bytes;
	sec->template_sd_len = template_len;
	WRITE_ONCE(sec->mount_policy, KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);
	WRITE_ONCE(sec->policy_generation, generation);
	mutex_unlock(&sec->lock);

	trace_kacs_mntns(PKM_KACS_MNTNS_OP_NEW_FS, 0, KACS_MNTNS_SB_STAMP, 0);
	return 0;
}

int pkm_kacs_sb_kern_mount(const struct super_block *sb)
{
	long ret = pkm_kacs_mntns_stamp_superblock_for_token(
		(struct super_block *)sb,
		pkm_kacs_current_effective_token_ptr());

	return ret < 0 ? (int)ret : 0;
}
