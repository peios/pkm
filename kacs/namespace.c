// SPDX-License-Identifier: GPL-2.0-only
/*
 * Namespace and inode hook authorization for PKM KACS.
 */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/xattr.h>

#include <pkm/file.h>
#include <pkm/sd.h>
#include <pkm/token.h>

#include "file_access.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "namespace.h"
#include "native_open.h"
#include "token_runtime.h"
#include "trace.h"

int pkm_kacs_inode_permission(struct inode *inode, int mask)
{
	return (int)pkm_kacs_check_inode_permission_live_for_subject(
		pkm_kacs_current_effective_token_ptr(), inode, NULL, mask);
}

static bool pkm_kacs_inode_permission_is_traverse(struct inode *inode, int mask)
{
	int permission_mask = mask & ~MAY_NOT_BLOCK;

	if (!inode || !S_ISDIR(inode->i_mode))
		return false;
	if ((permission_mask & MAY_EXEC) == 0)
		return false;
	if ((permission_mask & (MAY_OPEN | MAY_ACCESS)) != 0)
		return false;

	return true;
}

static bool pkm_kacs_inode_permission_is_pathname_socket_write(
	struct inode *inode, int mask)
{
	int permission_mask = mask & ~MAY_NOT_BLOCK;

	if (!inode || !S_ISSOCK(inode->i_mode))
		return false;
	if ((permission_mask & MAY_WRITE) == 0)
		return false;
	if ((permission_mask & ~(MAY_WRITE)) != 0)
		return false;

	return true;
}

static long pkm_kacs_authorize_inode_file_access_core(
	const void *subject_token, struct inode *inode, struct dentry *dentry,
	u32 desired_access)
{
	struct vfsmount mnt = {};
	struct dentry *alias = NULL;
	struct path path = {};
	struct file file = {};
	long ret;

	if (!subject_token || !inode || desired_access == 0) {
		if (inode)
			pr_debug(
				"kacs: deny inode_file_access EINVAL ino=%lu sb_magic=0x%lx desired=0x%x has_token=%d comm=%s pid=%d\n",
				inode->i_ino,
				(unsigned long)inode->i_sb->s_magic,
				desired_access, subject_token != NULL,
				current->comm, current->pid);
		PKM_KACS_TRACE("inode_file_access", "bad-args", inode,
			       desired_access, -EINVAL);
		return -EINVAL;
	}
	if (!inode->i_security) {
		pr_debug(
			"kacs: deny inode_file_access NO_SEC ino=%lu sb_magic=0x%lx desired=0x%x comm=%s pid=%d\n",
			inode->i_ino,
			(unsigned long)inode->i_sb->s_magic,
			desired_access, current->comm, current->pid);
		PKM_KACS_TRACE("inode_file_access", "no-i_security", inode,
			       desired_access, -EACCES);
		return -EACCES;
	}

	if (!dentry) {
		alias = d_find_any_alias(inode);
		if (!alias) {
			pr_debug(
				"kacs: deny inode_file_access NO_ALIAS ino=%lu sb_magic=0x%lx desired=0x%x comm=%s pid=%d\n",
				inode->i_ino,
				(unsigned long)inode->i_sb->s_magic,
				desired_access, current->comm, current->pid);
			/*
			 * No dentry alias yet — can happen if an inode is
			 * permission-checked mid-mount, before its dentry is
			 * wired up. A prime suspect for SD-less-fs mount denials.
			 */
			PKM_KACS_TRACE("inode_file_access", "no-dentry-alias",
				       inode, desired_access, -EACCES);
			return -EACCES;
		}
		dentry = alias;
	}

	mnt.mnt_root = dentry;
	mnt.mnt_sb = inode->i_sb;
	mnt.mnt_idmap = &nop_mnt_idmap;
	path.mnt = &mnt;
	path.dentry = dentry;
	pkm_kacs_init_path_anchor_file(&file, &path);

	ret = pkm_kacs_authorize_live_file_access_core(subject_token, &file,
						       desired_access);
	if (alias)
		dput(alias);
	PKM_KACS_TRACE("inode_file_access", "decision", inode, desired_access,
		       ret);
	return ret;
}

long pkm_kacs_check_inode_permission_live_for_subject(
	const void *subject_token, struct inode *inode, struct dentry *dentry,
	int mask)
{
	bool explicit_chdir;
	u32 desired_access = 0;

	if (pkm_kacs_inode_permission_is_traverse(inode, mask)) {
		desired_access = KACS_FILE_TRAVERSE;
	} else if (pkm_kacs_inode_permission_is_pathname_socket_write(inode,
								      mask)) {
		desired_access = KACS_FILE_WRITE_DATA;
	} else {
		return 0;
	}
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return 0;
	if (!subject_token) {
		PKM_KACS_TRACE("inode_permission", "no-token", inode,
			       desired_access, -EACCES);
		return -EACCES;
	}

	if (desired_access == KACS_FILE_WRITE_DATA) {
		if ((mask & MAY_NOT_BLOCK) != 0)
			return -ECHILD;
		return pkm_kacs_authorize_inode_file_access_core(
			subject_token, inode, dentry, desired_access);
	}

	explicit_chdir = (mask & MAY_CHDIR) != 0;
	if (!explicit_chdir &&
	    kacs_rust_token_has_enabled_privilege(
		    subject_token, KACS_SE_CHANGE_NOTIFY_PRIVILEGE)) {
		if (!kacs_rust_token_mark_privileges_used(
			    subject_token, KACS_SE_CHANGE_NOTIFY_PRIVILEGE)) {
			PKM_KACS_TRACE("inode_permission",
				       "change-notify-priv-exhausted", inode,
				       desired_access, -EACCES);
			return -EACCES;
		}
		PKM_KACS_TRACE("inode_permission", "change-notify-priv", inode,
			       desired_access, 0);
		return 0;
	}

	if ((mask & MAY_NOT_BLOCK) != 0)
		return -ECHILD;

	return pkm_kacs_authorize_inode_file_access_core(
		subject_token, inode, dentry, desired_access);
}

bool pkm_kacs_inode_on_unmanaged_mount(const struct inode *inode)
{
	return inode &&
	       pkm_kacs_superblock_mount_policy(inode->i_sb) ==
		       KACS_MOUNT_POLICY_UNMANAGED;
}

bool pkm_kacs_inode_on_sysfs_mount(const struct inode *inode)
{
	return inode && inode->i_sb && inode->i_sb->s_magic == SYSFS_MAGIC;
}

static struct dentry *pkm_kacs_parent_dentry_for_inode(
	struct inode *parent_inode, struct dentry *child_dentry)
{
	struct dentry *parent_dentry;

	if (!parent_inode || !child_dentry)
		return NULL;

	parent_dentry = child_dentry->d_parent;
	if (!parent_dentry || d_inode(parent_dentry) != parent_inode)
		return NULL;

	return parent_dentry;
}

long pkm_kacs_authorize_inode_namespace_access_for_subject(
	const void *subject_token, struct inode *inode, struct dentry *dentry,
	u32 desired_access)
{
	if (!inode || desired_access == 0)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return 0;
	if (!subject_token) {
		pr_debug(
			"kacs: deny ns_access NO_TOKEN ino=%lu sb_magic=0x%lx desired=0x%x comm=%s pid=%d\n",
			inode->i_ino,
			(unsigned long)inode->i_sb->s_magic,
			desired_access, current->comm, current->pid);
		return -EACCES;
	}

	return pkm_kacs_authorize_inode_file_access_core(
		subject_token, inode, dentry, desired_access);
}

static long pkm_kacs_authorize_parent_namespace_access_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *child_dentry, u32 desired_access)
{
	struct dentry *parent_dentry;

	if (!parent_inode || desired_access == 0)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(parent_inode))
		return 0;

	parent_dentry = pkm_kacs_parent_dentry_for_inode(parent_inode,
							  child_dentry);
	return pkm_kacs_authorize_inode_namespace_access_for_subject(
		subject_token, parent_inode, parent_dentry, desired_access);
}

long pkm_kacs_authorize_namespace_delete_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *target_dentry)
{
	struct inode *target_inode;
	long ret;

	if (!target_dentry)
		return -EACCES;

	target_inode = d_inode(target_dentry);
	if (!target_inode)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(target_inode) &&
	    pkm_kacs_inode_on_unmanaged_mount(parent_inode))
		return 0;

	ret = pkm_kacs_authorize_inode_namespace_access_for_subject(
		subject_token, target_inode, target_dentry, KACS_ACCESS_DELETE);
	if (ret != -EACCES)
		return ret;

	return pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, parent_inode, target_dentry,
		KACS_FILE_DELETE_CHILD);
}

long pkm_kacs_authorize_namespace_create_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *child_dentry, bool directory)
{
	u32 desired_access = directory ? KACS_FILE_ADD_SUBDIRECTORY :
					 KACS_FILE_ADD_FILE;

	return pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, parent_inode, child_dentry, desired_access);
}

long pkm_kacs_authorize_namespace_symlink_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *child_dentry)
{
	long ret;

	ret = pkm_kacs_authorize_namespace_create_for_subject(
		subject_token, parent_inode, child_dentry, false);
	if (ret)
		return ret;
	if (pkm_kacs_inode_on_unmanaged_mount(parent_inode))
		return 0;

	return pkm_kacs_require_enabled_privilege(
		subject_token, KACS_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE);
}

long pkm_kacs_authorize_namespace_link_for_subject(
	const void *subject_token, struct dentry *old_dentry, struct inode *dir,
	struct dentry *new_dentry)
{
	struct inode *source_inode;
	long ret;

	if (!old_dentry || !dir || !new_dentry)
		return -EACCES;

	ret = pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, dir, new_dentry, KACS_FILE_ADD_FILE);
	if (ret)
		return ret;

	source_inode = d_inode(old_dentry);
	if (!source_inode)
		return -EACCES;

	return pkm_kacs_authorize_inode_namespace_access_for_subject(
		subject_token, source_inode, old_dentry,
		KACS_FILE_WRITE_ATTRIBUTES);
}

long pkm_kacs_authorize_namespace_rename_for_subject(
	const void *subject_token, struct inode *old_dir,
	struct dentry *old_dentry, struct inode *new_dir,
	struct dentry *new_dentry)
{
	struct inode *source_inode;
	u32 add_access;
	long ret;

	if (!old_dir || !old_dentry || !new_dir || !new_dentry)
		return -EACCES;

	source_inode = d_inode(old_dentry);
	if (!source_inode)
		return -EACCES;

	ret = pkm_kacs_authorize_namespace_delete_for_subject(
		subject_token, old_dir, old_dentry);
	if (ret)
		return ret;

	add_access = S_ISDIR(source_inode->i_mode) ?
			     KACS_FILE_ADD_SUBDIRECTORY :
			     KACS_FILE_ADD_FILE;
	ret = pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, new_dir, new_dentry, add_access);
	if (ret)
		return ret;

	if (d_is_positive(new_dentry)) {
		ret = pkm_kacs_authorize_namespace_delete_for_subject(
			subject_token, new_dir, new_dentry);
		if (ret)
			return ret;
	}

	return 0;
}

long pkm_kacs_build_legacy_created_file_sd_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *parent_dentry, bool directory, const u8 **out_sd_ptr,
	size_t *out_sd_len)
{
	struct vfsmount mnt = {};
	struct dentry *alias = NULL;
	struct path parent_path = {};
	struct file parent_file = {};
	long ret;

	if (!subject_token || !parent_inode || !out_sd_ptr || !out_sd_len)
		return -EINVAL;
	if (pkm_kacs_inode_on_unmanaged_mount(parent_inode))
		return -EOPNOTSUPP;

	if (!parent_dentry) {
		alias = d_find_any_alias(parent_inode);
		if (!alias)
			return -EACCES;
		parent_dentry = alias;
	}
	if (d_inode(parent_dentry) != parent_inode) {
		ret = -EACCES;
		goto out;
	}

	mnt.mnt_root = parent_dentry;
	mnt.mnt_sb = parent_inode->i_sb;
	mnt.mnt_idmap = &nop_mnt_idmap;
	parent_path.mnt = &mnt;
	parent_path.dentry = parent_dentry;
	pkm_kacs_init_path_anchor_file(&parent_file, &parent_path);

	ret = pkm_kacs_build_created_file_sd_for_subject(
		subject_token, &parent_file, NULL, 0, directory, 0,
		out_sd_ptr, out_sd_len, NULL);
out:
	if (alias)
		dput(alias);
	return ret;
}

int pkm_kacs_inode_rename_flags(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry,
				unsigned int flags)
{
	(void)new_dentry;

	if ((flags & RENAME_WHITEOUT) == 0)
		return 0;
	if (pkm_kacs_inode_on_unmanaged_mount(old_dir) &&
	    pkm_kacs_inode_on_unmanaged_mount(new_dir))
		return 0;

	/*
	 * RENAME_WHITEOUT leaves a chrdev(0,0) whiteout sentinel at the source
	 * name in old_dir once the renamed entry moves to new_dir. The native
	 * in-FS path (e.g. shmem_whiteout -> shmem_mknod) creates that sentinel
	 * without firing security_inode_mknod, so recover that hook's two
	 * remaining duties here: authorize FILE_ADD_FILE on the source parent
	 * and emit the special-node creation audit record. This fails closed,
	 * so a caller lacking FILE_ADD_FILE on old_dir gets the whole rename
	 * denied before any inode is touched.
	 *
	 * SD stamping needs no help: every in-tree filesystem that natively
	 * implements RENAME_WHITEOUT allocates the whiteout as a real inode and
	 * therefore still runs security_inode_init_security, where KACS stamps
	 * the inherited SD like any other new node. A chrdev(0,0) addresses no
	 * driver, so no device-creation privilege beyond FILE_ADD_FILE applies.
	 */
	return (int)pkm_kacs_authorize_namespace_create_for_subject(
		pkm_kacs_current_effective_token_ptr(), old_dir, old_dentry,
		false);
}

int pkm_kacs_inode_create(struct inode *dir, struct dentry *dentry,
			  umode_t mode)
{
	(void)mode;
	return (int)pkm_kacs_authorize_namespace_create_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry, false);
}

int pkm_kacs_inode_mkdir(struct inode *dir, struct dentry *dentry,
			 umode_t mode)
{
	(void)mode;
	return (int)pkm_kacs_authorize_namespace_create_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry, true);
}

int pkm_kacs_inode_mknod(struct inode *dir, struct dentry *dentry,
			 umode_t mode, dev_t dev)
{
	(void)dev;

	if (!pkm_kacs_inode_on_unmanaged_mount(dir) &&
	    !pkm_kacs_special_node_mode_supported(mode))
		return -EOPNOTSUPP;

	return (int)pkm_kacs_authorize_namespace_create_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry, false);
}

int pkm_kacs_inode_symlink(struct inode *dir, struct dentry *dentry,
			   const char *old_name)
{
	(void)old_name;
	return (int)pkm_kacs_authorize_namespace_symlink_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry);
}

int pkm_kacs_inode_link(struct dentry *old_dentry, struct inode *dir,
			struct dentry *new_dentry)
{
	return (int)pkm_kacs_authorize_namespace_link_for_subject(
		pkm_kacs_current_effective_token_ptr(), old_dentry, dir,
		new_dentry);
}

int pkm_kacs_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return (int)pkm_kacs_authorize_namespace_delete_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry);
}

int pkm_kacs_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return (int)pkm_kacs_authorize_namespace_delete_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry);
}

int pkm_kacs_inode_rename(struct inode *old_dir,
			  struct dentry *old_dentry,
			  struct inode *new_dir,
			  struct dentry *new_dentry)
{
	return (int)pkm_kacs_authorize_namespace_rename_for_subject(
		pkm_kacs_current_effective_token_ptr(), old_dir, old_dentry,
		new_dir, new_dentry);
}

int pkm_kacs_inode_readlink(struct dentry *dentry)
{
	struct inode *inode;

	if (!dentry)
		return -EACCES;

	inode = d_inode(dentry);
	return (int)pkm_kacs_authorize_inode_namespace_access_for_subject(
		pkm_kacs_current_effective_token_ptr(), inode, dentry,
		KACS_FILE_READ_DATA);
}

int pkm_kacs_authorize_path_metadata_access(const struct path *path,
					    u32 desired_access)
{
	const void *subject_token;

	if (!path || !path->dentry || desired_access == 0)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(d_inode(path->dentry)))
		return 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	return (int)pkm_kacs_authorize_path_file_access_core(
		subject_token, path, desired_access);
}

int pkm_kacs_authorize_dentry_metadata_access(struct dentry *dentry,
					      u32 desired_access)
{
	struct vfsmount mnt = {};
	struct path path = {};
	struct file file = {};
	const void *subject_token;
	struct inode *inode;

	if (!dentry || desired_access == 0)
		return -EACCES;

	inode = d_inode(dentry);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	mnt.mnt_root = dentry;
	mnt.mnt_sb = inode->i_sb;
	mnt.mnt_idmap = &nop_mnt_idmap;
	path.mnt = &mnt;
	path.dentry = dentry;
	pkm_kacs_init_path_anchor_file(&file, &path);

	return (int)pkm_kacs_authorize_live_file_access_core(
		subject_token, &file, desired_access);
}

int pkm_kacs_inode_init_security(struct inode *inode, struct inode *dir,
				 const struct qstr *qstr,
				 struct xattr *xattrs,
				 int *xattr_count)
{
	struct xattr *xattr;
	const void *subject_token;
	const u8 *sd_bytes = NULL;
	size_t sd_len = 0;
	u8 *copied_bytes;
	bool allocated_sd = false;
	long ret;

	(void)qstr;
	if (!inode || !dir || !xattrs || !xattr_count)
		return -EOPNOTSUPP;
	if (pkm_kacs_inode_is_ntfs(inode))
		return -EOPNOTSUPP;
	if (!pkm_kacs_current_native_create_request_matches(
		    dir, S_ISDIR(inode->i_mode), &sd_bytes, &sd_len)) {
		subject_token = pkm_kacs_current_effective_token_ptr();
		if (!subject_token) {
			pr_debug(
				"kacs: deny inode_init_security NO_TOKEN dir_ino=%lu sb_magic=0x%lx mode=0%o comm=%s pid=%d\n",
				dir->i_ino,
				(unsigned long)dir->i_sb->s_magic,
				inode->i_mode, current->comm, current->pid);
			return -EACCES;
		}
		ret = pkm_kacs_build_legacy_created_file_sd_for_subject(
			subject_token, dir, NULL, S_ISDIR(inode->i_mode),
			&sd_bytes, &sd_len);
		if (ret) {
			pr_debug(
				"kacs: deny inode_init_security BUILD_FAIL dir_ino=%lu sb_magic=0x%lx mode=0%o comm=%s pid=%d ret=%ld\n",
				dir->i_ino,
				(unsigned long)dir->i_sb->s_magic,
				inode->i_mode, current->comm, current->pid, ret);
			return ret;
		}
		allocated_sd = true;
	}
	if (!sd_bytes || sd_len == 0) {
		if (allocated_sd)
			pr_debug(
				"kacs: deny inode_init_security NO_SD_BYTES dir_ino=%lu sb_magic=0x%lx mode=0%o comm=%s pid=%d\n",
				dir->i_ino,
				(unsigned long)dir->i_sb->s_magic,
				inode->i_mode, current->comm, current->pid);
		return allocated_sd ? -EACCES : -EOPNOTSUPP;
	}

	copied_bytes = kmemdup(sd_bytes, sd_len, GFP_NOFS);
	if (allocated_sd)
		pkm_kacs_free((void *)sd_bytes);
	if (!copied_bytes)
		return -ENOMEM;

	xattr = lsm_get_xattr_slot(xattrs, xattr_count);
	if (!xattr) {
		kfree(copied_bytes);
		return -ENOMEM;
	}

	xattr->name = "peios.sd";
	xattr->value = copied_bytes;
	xattr->value_len = sd_len;
	return 0;
}
