// SPDX-License-Identifier: GPL-2.0-only

#include <linux/fs.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/magic.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <pkm/token.h>

#include "lsm_internal.h"
#include "mount_policy.h"
#include "token_runtime.h"

u32 pkm_kacs_mount_policy_for_magic(unsigned long magic)
{
	switch (magic) {
	case PROC_SUPER_MAGIC:
	case SYSFS_MAGIC:
		return KACS_MOUNT_POLICY_UNMANAGED;
	case NULL_FS_MAGIC:
		/*
		 * nullfs (NULL_FS_MAGIC, 0x4E554C4C) — the immutable,
		 * permanently-empty namespace root that Linux 7.0+ mounts
		 * unconditionally beneath the mutable rootfs (init_mount_tree
		 * in fs/namespace.c). It sets s_xattr = NULL, so it can NEVER
		 * store an SD, and its single root inode is S_IMMUTABLE +
		 * make_empty_dir_inode (no children possible, SB_NOUSER,
		 * NOEXEC, NODEV). DENY_MISSING here would be a permanent boot
		 * landmine on an inode that is, by construction, incapable of
		 * holding state. This is NOT a paper-over like tmpfs/squashfs
		 * would be — there is nothing to stamp and nothing to protect,
		 * exactly as for proc/sysfs above.
		 */
		return KACS_MOUNT_POLICY_UNMANAGED;
	case RAMFS_MAGIC:
		/*
		 * rootfs / ramfs ONLY (RAMFS_MAGIC, 0x858458f6) — the initial
		 * ramfs the kernel populates from the boot cpio and runs before
		 * switch_root. It has no SD storage and its cpio-extracted
		 * inodes are not stamped, so DENY_MISSING would block prelude
		 * itself; synthesize an ephemeral SD from the mount template
		 * instead. The trust chain is the kernel image it ships with.
		 *
		 * Deliberately NOT tmpfs or squashfs: those are distinct magics
		 * (TMPFS_MAGIC 0x01021994, SQUASHFS_MAGIC 0x73717368) and fall
		 * through to DENY_MISSING below — by design. The squashfs root
		 * is SD-stamped at build time and the tmpfs overlay upper is
		 * seed-sd'd and inherits, so a missing SD on either is a bug to
		 * catch, not to paper over. Do NOT add TMPFS_MAGIC or
		 * SQUASHFS_MAGIC to this case.
		 */
		return KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
	case NFS_SUPER_MAGIC:
	case MSDOS_SUPER_MAGIC:
	case EXFAT_SUPER_MAGIC:
		return KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
	default:
		return KACS_MOUNT_POLICY_DENY_MISSING;
	}
}

u32 pkm_kacs_superblock_mount_policy(const struct super_block *sb)
{
	struct pkm_kacs_superblock_security *sec;
	u32 policy;
	u32 resolved;

	if (!sb)
		return KACS_MOUNT_POLICY_DENY_MISSING;
	if (!sb->s_security)
		return pkm_kacs_mount_policy_for_magic(sb->s_magic);

	sec = pkm_kacs_sb(sb);
	policy = READ_ONCE(sec->mount_policy);
	switch (policy) {
	case KACS_MOUNT_POLICY_UNMANAGED:
	case KACS_MOUNT_POLICY_DENY_MISSING:
	case KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL:
	case KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT:
		return policy;
	}

	/*
	 * Lazy resolution: sb_alloc_security cannot capture the magic-derived
	 * policy because s_magic is still zero at that point in alloc_super().
	 * Defer resolution to the first read that observes a populated magic,
	 * then cache it so subsequent reads are O(1).
	 *
	 * If s_magic is still unresolved here (extremely unusual — would mean
	 * the filesystem type hasn't initialized at all yet), fall back to
	 * DENY_MISSING. That matches the !sb branch above and avoids returning
	 * a value outside the documented policy set. We do NOT cache that
	 * fallback, so a later read with a populated magic still gets the
	 * correct value.
	 */
	if (sb->s_magic == 0)
		return KACS_MOUNT_POLICY_DENY_MISSING;

	resolved = pkm_kacs_mount_policy_for_magic(sb->s_magic);
	WRITE_ONCE(sec->mount_policy, resolved);
	return resolved;
}

u32 pkm_kacs_superblock_policy_generation(const struct super_block *sb)
{
	struct pkm_kacs_superblock_security *sec;

	if (!sb || !sb->s_security)
		return 0;

	sec = pkm_kacs_sb(sb);
	return READ_ONCE(sec->policy_generation);
}

bool pkm_kacs_mount_policy_is_managed(u32 mount_policy)
{
	return mount_policy == KACS_MOUNT_POLICY_DENY_MISSING ||
	       mount_policy == KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL ||
	       mount_policy == KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT;
}

bool pkm_kacs_inode_is_ntfs(const struct inode *inode)
{
	return inode && inode->i_sb && inode->i_sb->s_type &&
	       inode->i_sb->s_type->name &&
	       strcmp(inode->i_sb->s_type->name, "ntfs3") == 0;
}

const char *pkm_kacs_inode_sd_xattr_name(const struct inode *inode)
{
	if (pkm_kacs_inode_is_ntfs(inode))
		return "system.ntfs_security";

	return "security.peios.sd";
}

bool pkm_kacs_is_canonical_sd_xattr(const struct inode *inode,
				    const char *name)
{
	if (!name)
		return false;
	if (strcmp(name, "security.peios.sd") == 0)
		return true;
	if (pkm_kacs_inode_is_ntfs(inode) &&
	    strcmp(name, "system.ntfs_security") == 0)
		return true;

	return false;
}

long pkm_kacs_copy_mount_policy_args_from_user(
	struct kacs_mount_policy_args *out,
	const struct kacs_mount_policy_args __user *uargs, size_t argsize)
{
	int ret;

	if (!out || !uargs)
		return -EINVAL;
	if (argsize < KACS_MOUNT_POLICY_ARGS_MIN_SIZE)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	ret = copy_struct_from_user(out, sizeof(*out), uargs, argsize);
	if (ret == -E2BIG)
		return -EINVAL;
	return ret;
}

static bool pkm_kacs_mount_policy_user_settable(u32 policy)
{
	return policy == KACS_MOUNT_POLICY_DENY_MISSING ||
	       policy == KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL ||
	       policy == KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT;
}

static bool pkm_kacs_mount_policy_uses_template(u32 policy)
{
	return policy == KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL ||
	       policy == KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT;
}

long pkm_kacs_validate_mount_policy_args(
	const struct kacs_mount_policy_args *args)
{
	if (!args)
		return -EINVAL;
	if (!pkm_kacs_mount_policy_user_settable(args->policy))
		return -EINVAL;
	if (args->flags != 0 || args->generation != 0 || args->__pad0 != 0 ||
	    args->__pad1 != 0)
		return -EINVAL;
	if (args->template_sd_ptr == 0 && args->template_sd_len != 0)
		return -EINVAL;
	if (args->template_sd_ptr != 0 && args->template_sd_len == 0)
		return -EINVAL;
	if (args->template_sd_len > PKM_KACS_MAX_SD_BYTES)
		return -EINVAL;
	if (!pkm_kacs_mount_policy_uses_template(args->policy) &&
	    args->template_sd_len != 0)
		return -EINVAL;

	return 0;
}

long pkm_kacs_copy_mount_template_from_user(
	const struct kacs_mount_policy_args *args, const u8 **template_out)
{
	const void __user *template_user;
	u8 *template_bytes;

	if (!args || !template_out)
		return -EINVAL;

	*template_out = NULL;
	if (args->template_sd_len == 0)
		return 0;

	template_user = (const void __user *)(unsigned long)args->template_sd_ptr;
	template_bytes = memdup_user(template_user, args->template_sd_len);
	if (IS_ERR(template_bytes))
		return PTR_ERR(template_bytes);
	if (kacs_rust_validate_stored_sd_bytes(template_bytes,
					       args->template_sd_len) != 0) {
		kfree(template_bytes);
		return -EINVAL;
	}

	*template_out = template_bytes;
	return 0;
}

u32 pkm_kacs_next_mount_policy_generation(u32 generation)
{
	generation++;
	if (generation == 0)
		generation = 1;
	return generation;
}

long pkm_kacs_set_mount_policy_core(
	const void *subject_token, struct super_block *sb,
	const struct kacs_mount_policy_args *args, const u8 *template_bytes)
{
	struct pkm_kacs_superblock_security *sec;
	const u8 *old_template;

	if (!subject_token || !sb || !args)
		return -EINVAL;
	if (!sb->s_security)
		return -EOPNOTSUPP;
	if (pkm_kacs_mount_policy_for_magic(sb->s_magic) ==
	    KACS_MOUNT_POLICY_UNMANAGED)
		return -EOPNOTSUPP;

	if (pkm_kacs_validate_mount_policy_args(args))
		return -EINVAL;
	if (template_bytes &&
	    kacs_rust_validate_stored_sd_bytes(template_bytes,
					       args->template_sd_len) != 0)
		return -EINVAL;

	if (pkm_kacs_require_enabled_privilege(
		    subject_token, KACS_SE_TCB_PRIVILEGE))
		return -EPERM;

	sec = pkm_kacs_sb(sb);
	mutex_lock(&sec->lock);
	old_template = sec->template_sd_bytes;
	sec->template_sd_bytes = template_bytes;
	sec->template_sd_len = args->template_sd_len;
	WRITE_ONCE(sec->mount_policy, args->policy);
	WRITE_ONCE(sec->policy_generation,
		   pkm_kacs_next_mount_policy_generation(
			   READ_ONCE(sec->policy_generation)));
	mutex_unlock(&sec->lock);

	pkm_kacs_free((void *)old_template);
	return 0;
}

long pkm_kacs_get_mount_policy_snapshot(
	const struct super_block *sb, struct kacs_mount_policy_args *snapshot,
	const u8 **template_out)
{
	struct pkm_kacs_superblock_security *sec;
	const u8 *template_copy = NULL;

	if (!sb || !snapshot || !template_out)
		return -EINVAL;

	memset(snapshot, 0, sizeof(*snapshot));
	*template_out = NULL;

	if (!sb->s_security) {
		snapshot->policy = pkm_kacs_mount_policy_for_magic(sb->s_magic);
		return 0;
	}

	sec = pkm_kacs_sb(sb);
	mutex_lock(&sec->lock);
	snapshot->policy = pkm_kacs_superblock_mount_policy(sb);
	snapshot->generation = READ_ONCE(sec->policy_generation);
	snapshot->template_sd_len = sec->template_sd_len;
	if (sec->template_sd_bytes && sec->template_sd_len != 0) {
		template_copy = kmemdup(sec->template_sd_bytes,
					sec->template_sd_len, GFP_KERNEL);
		if (!template_copy) {
			mutex_unlock(&sec->lock);
			return -ENOMEM;
		}
	}
	mutex_unlock(&sec->lock);

	*template_out = template_copy;
	return 0;
}

long pkm_kacs_mount_policy_fd_superblock(int fd, struct file **file_out,
					 struct super_block **sb_out)
{
	struct file *file;
	struct inode *inode;

	if (!file_out || !sb_out)
		return -EINVAL;

	file = fget_raw(fd);
	if (!file)
		return -EBADF;

	inode = file_inode(file);
	if (!inode || !inode->i_sb) {
		fput(file);
		return -EOPNOTSUPP;
	}

	*file_out = file;
	*sb_out = inode->i_sb;
	return 0;
}

SYSCALL_DEFINE3(kacs_get_mount_policy, int, fd,
		struct kacs_mount_policy_args __user *, uargs, size_t, argsize)
{
	struct kacs_mount_policy_args args = {};
	struct kacs_mount_policy_args snapshot = {};
	struct super_block *sb = NULL;
	struct file *file = NULL;
	const void *subject_token;
	const u8 *template_bytes = NULL;
	void __user *template_user;
	size_t out_size;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;
	ret = pkm_kacs_require_enabled_privilege(
		subject_token, KACS_SE_TCB_PRIVILEGE);
	if (ret)
		return ret;

	ret = pkm_kacs_copy_mount_policy_args_from_user(&args, uargs, argsize);
	if (ret)
		return ret;
	if (args.flags != 0 || args.__pad0 != 0 || args.__pad1 != 0)
		return -EINVAL;

	ret = pkm_kacs_mount_policy_fd_superblock(fd, &file, &sb);
	if (ret)
		return ret;

	ret = pkm_kacs_get_mount_policy_snapshot(sb, &snapshot,
						 &template_bytes);
	if (ret)
		goto out;

	if (template_bytes && args.template_sd_ptr != 0 &&
	    args.template_sd_len >= snapshot.template_sd_len) {
		template_user =
			(void __user *)(unsigned long)args.template_sd_ptr;
		if (copy_to_user(template_user, template_bytes,
				 snapshot.template_sd_len)) {
			ret = -EFAULT;
			goto out;
		}
	}
	snapshot.template_sd_ptr = args.template_sd_ptr;
	out_size = min_t(size_t, argsize, sizeof(snapshot));
	if (copy_to_user(uargs, &snapshot, out_size)) {
		ret = -EFAULT;
		goto out;
	}

	ret = 0;

out:
	pkm_kacs_free((void *)template_bytes);
	if (file)
		fput(file);
	return ret;
}

SYSCALL_DEFINE3(kacs_set_mount_policy, int, fd,
		struct kacs_mount_policy_args __user *, uargs, size_t, argsize)
{
	struct kacs_mount_policy_args args = {};
	struct super_block *sb = NULL;
	struct file *file = NULL;
	const void *subject_token;
	const u8 *template_bytes = NULL;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	ret = pkm_kacs_copy_mount_policy_args_from_user(&args, uargs, argsize);
	if (ret)
		return ret;
	ret = pkm_kacs_validate_mount_policy_args(&args);
	if (ret)
		return ret;

	if (!kacs_rust_token_has_enabled_privilege(
		    subject_token, KACS_SE_TCB_PRIVILEGE))
		return -EPERM;

	ret = pkm_kacs_copy_mount_template_from_user(&args, &template_bytes);
	if (ret)
		return ret;

	ret = pkm_kacs_mount_policy_fd_superblock(fd, &file, &sb);
	if (ret)
		goto out;

	ret = pkm_kacs_set_mount_policy_core(subject_token, sb, &args,
					     template_bytes);
	if (!ret)
		template_bytes = NULL;

out:
	pkm_kacs_free((void *)template_bytes);
	if (file)
		fput(file);
	return ret;
}
