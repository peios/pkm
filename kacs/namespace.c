// SPDX-License-Identifier: GPL-2.0-only
/*
 * Namespace and inode hook authorization for PKM KACS.
 */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kacs_stratafs.h>
#include <linux/lsm_hooks.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/xattr.h>

#ifdef CONFIG_SECURITY_PKM_KUNIT
#include <kunit/test.h>
#endif

#include <pkm/file.h>
#include <pkm/sd.h>
#include <pkm/token.h>

#include "file_access.h"
#include "copy_up.h"
#include "file_sd_cache.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "namespace.h"
#include "native_open.h"
#include "token_runtime.h"
#include <trace/events/kacs.h>

#define PKM_KACS_STRATAFS_SUPERSEDE_BOUND 2
#define PKM_KACS_STRATAFS_SUPERSEDE_UNLINK 1
#define PKM_KACS_STRATAFS_SUPERSEDE_RENAME 2

void pkm_kacs_stratafs_end_supersede_phase(void)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return;
	task_sec = pkm_kacs_task(current);
	task_sec->stratafs_supersede_old_parent = NULL;
	task_sec->stratafs_supersede_old_dentry = NULL;
	task_sec->stratafs_supersede_old_inode = NULL;
	task_sec->stratafs_supersede_new_parent = NULL;
	task_sec->stratafs_supersede_new_dentry = NULL;
	task_sec->stratafs_supersede_new_inode = NULL;
	task_sec->stratafs_supersede_phase = 0;
}

void pkm_kacs_stratafs_end_supersede(void)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return;
	task_sec = pkm_kacs_task(current);
	pkm_kacs_stratafs_end_supersede_phase();
	task_sec->stratafs_supersede_subject = NULL;
	task_sec->stratafs_supersede_target = NULL;
	task_sec->stratafs_supersede_target_inode = NULL;
	task_sec->stratafs_supersede_source = NULL;
	task_sec->stratafs_supersede_source_inode = NULL;
	task_sec->stratafs_supersede_file = NULL;
	task_sec->stratafs_supersede_state = 0;
}

int pkm_kacs_stratafs_begin_supersede(const struct dentry *outer_target)
{
	struct pkm_kacs_task_security *task_sec;
	const void *subject;

	if (!current || !current->security || !outer_target ||
	    outer_target->d_sb->s_magic != STRATAFS_SUPER_MAGIC ||
	    !d_really_is_positive((struct dentry *)outer_target))
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_supersede_state)
		return -EBUSY;
	subject = pkm_kacs_current_effective_token_ptr();
	if (!subject)
		return -EACCES;
	task_sec->stratafs_supersede_subject = subject;
	task_sec->stratafs_supersede_target = outer_target;
	task_sec->stratafs_supersede_target_inode = d_inode(outer_target);
	task_sec->stratafs_supersede_state = 1;
	return 0;
}

int pkm_kacs_stratafs_bind_supersede_file(
	const struct dentry *outer_source, const struct dentry *outer_target,
	const struct file *outer_file)
{
	struct pkm_kacs_task_security *task_sec;

	if (!outer_file || !pkm_kacs_stratafs_supersede_active(
				 outer_source, outer_target) ||
	    file_dentry((struct file *)outer_file) == NULL ||
	    file_inode((struct file *)outer_file) == NULL ||
	    file_inode((struct file *)outer_file)->i_sb != outer_source->d_sb)
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_supersede_file)
		return -EBUSY;
	task_sec->stratafs_supersede_file = outer_file;
	return 0;
}

const struct file *pkm_kacs_stratafs_supersede_file(
	const struct dentry *outer_source, const struct dentry *outer_target)
{
	struct pkm_kacs_task_security *task_sec;

	if (!pkm_kacs_stratafs_supersede_active(outer_source, outer_target))
		return NULL;
	task_sec = pkm_kacs_task(current);
	return task_sec->stratafs_supersede_file;
}

int pkm_kacs_stratafs_bind_supersede_source(
	const struct dentry *outer_target, const struct dentry *outer_source)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !outer_target || !outer_source ||
	    !d_really_is_positive((struct dentry *)outer_source))
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_supersede_state != 1 ||
	    task_sec->stratafs_supersede_subject !=
		pkm_kacs_current_effective_token_ptr() ||
	    task_sec->stratafs_supersede_target != outer_target ||
	    task_sec->stratafs_supersede_target_inode != d_inode(outer_target) ||
	    outer_source->d_sb != outer_target->d_sb)
		return -EACCES;
	task_sec->stratafs_supersede_source = outer_source;
	task_sec->stratafs_supersede_source_inode = d_inode(outer_source);
	task_sec->stratafs_supersede_state =
		PKM_KACS_STRATAFS_SUPERSEDE_BOUND;
	return 0;
}

bool pkm_kacs_stratafs_supersede_active(
	const struct dentry *outer_source, const struct dentry *outer_target)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !outer_source || !outer_target)
		return false;
	task_sec = pkm_kacs_task(current);
	return task_sec->stratafs_supersede_state ==
		       PKM_KACS_STRATAFS_SUPERSEDE_BOUND &&
	       task_sec->stratafs_supersede_phase == 0 &&
	       task_sec->stratafs_supersede_subject ==
		       pkm_kacs_current_effective_token_ptr() &&
	       task_sec->stratafs_supersede_source == outer_source &&
	       task_sec->stratafs_supersede_source_inode ==
		       d_inode(outer_source) &&
	       task_sec->stratafs_supersede_target == outer_target &&
	       task_sec->stratafs_supersede_target_inode ==
		       d_inode(outer_target);
}

int pkm_kacs_stratafs_begin_supersede_unlink(
	const struct inode *parent, const struct dentry *target)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !parent || !target ||
	    !d_really_is_positive((struct dentry *)target) ||
	    target->d_parent == NULL || d_inode(target->d_parent) != parent)
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_supersede_state !=
		    PKM_KACS_STRATAFS_SUPERSEDE_BOUND ||
	    task_sec->stratafs_supersede_phase ||
	    task_sec->stratafs_supersede_subject !=
		    pkm_kacs_current_effective_token_ptr())
		return -EACCES;
	task_sec->stratafs_supersede_old_parent = parent;
	task_sec->stratafs_supersede_old_dentry = target;
	task_sec->stratafs_supersede_old_inode = d_inode(target);
	task_sec->stratafs_supersede_phase =
		PKM_KACS_STRATAFS_SUPERSEDE_UNLINK;
	return 0;
}

int pkm_kacs_stratafs_begin_supersede_rename(
	const struct inode *old_parent, const struct dentry *old_dentry,
	const struct inode *new_parent, const struct dentry *new_dentry)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !old_parent || !old_dentry ||
	    !new_parent || !new_dentry ||
	    !d_really_is_positive((struct dentry *)old_dentry) ||
	    old_dentry->d_parent == NULL ||
	    d_inode(old_dentry->d_parent) != old_parent ||
	    new_dentry->d_parent == NULL ||
	    d_inode(new_dentry->d_parent) != new_parent)
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_supersede_state !=
		    PKM_KACS_STRATAFS_SUPERSEDE_BOUND ||
	    task_sec->stratafs_supersede_phase ||
	    task_sec->stratafs_supersede_subject !=
		    pkm_kacs_current_effective_token_ptr())
		return -EACCES;
	task_sec->stratafs_supersede_old_parent = old_parent;
	task_sec->stratafs_supersede_old_dentry = old_dentry;
	task_sec->stratafs_supersede_old_inode = d_inode(old_dentry);
	task_sec->stratafs_supersede_new_parent = new_parent;
	task_sec->stratafs_supersede_new_dentry = new_dentry;
	task_sec->stratafs_supersede_new_inode = d_inode(new_dentry);
	task_sec->stratafs_supersede_phase =
		PKM_KACS_STRATAFS_SUPERSEDE_RENAME;
	return 0;
}

static bool pkm_kacs_stratafs_supersede_allows_unlink(
	const struct inode *parent, const struct dentry *target)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return false;
	task_sec = pkm_kacs_task(current);
	return task_sec->stratafs_supersede_phase ==
		       PKM_KACS_STRATAFS_SUPERSEDE_UNLINK &&
	       task_sec->stratafs_supersede_state ==
		       PKM_KACS_STRATAFS_SUPERSEDE_BOUND &&
	       task_sec->stratafs_supersede_subject ==
			       pkm_kacs_current_effective_token_ptr() &&
	       task_sec->stratafs_supersede_old_parent == parent &&
	       task_sec->stratafs_supersede_old_dentry == target &&
	       task_sec->stratafs_supersede_old_inode == d_inode(target);
}

static bool pkm_kacs_stratafs_supersede_allows_rename(
	const struct inode *old_parent, const struct dentry *old_dentry,
	const struct inode *new_parent, const struct dentry *new_dentry)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return false;
	task_sec = pkm_kacs_task(current);
	return task_sec->stratafs_supersede_phase ==
		       PKM_KACS_STRATAFS_SUPERSEDE_RENAME &&
	       task_sec->stratafs_supersede_state ==
		       PKM_KACS_STRATAFS_SUPERSEDE_BOUND &&
	       task_sec->stratafs_supersede_subject ==
			       pkm_kacs_current_effective_token_ptr() &&
	       task_sec->stratafs_supersede_old_parent == old_parent &&
	       task_sec->stratafs_supersede_old_dentry == old_dentry &&
	       task_sec->stratafs_supersede_old_inode == d_inode(old_dentry) &&
	       task_sec->stratafs_supersede_new_parent == new_parent &&
	       task_sec->stratafs_supersede_new_dentry == new_dentry &&
	       task_sec->stratafs_supersede_new_inode == d_inode(new_dentry);
}

void pkm_kacs_stratafs_end_created_cleanup(void)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return;
	task_sec = pkm_kacs_task(current);
	task_sec->stratafs_cleanup_parent = NULL;
	task_sec->stratafs_cleanup_dentry = NULL;
	task_sec->stratafs_cleanup_inode = NULL;
	task_sec->stratafs_cleanup_outer = NULL;
	task_sec->stratafs_cleanup_outer_inode = NULL;
	task_sec->stratafs_cleanup_subject = NULL;
}

int pkm_kacs_stratafs_arm_created_cleanup(const struct dentry *outer)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !outer ||
	    outer->d_sb->s_magic != STRATAFS_SUPER_MAGIC ||
	    !d_really_is_positive((struct dentry *)outer))
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_cleanup_outer ||
	    task_sec->stratafs_cleanup_parent)
		return -EBUSY;
	task_sec->stratafs_cleanup_subject =
		pkm_kacs_current_effective_token_ptr();
	if (!task_sec->stratafs_cleanup_subject)
		return -EACCES;
	task_sec->stratafs_cleanup_outer = outer;
	task_sec->stratafs_cleanup_outer_inode = d_inode(outer);
	return 0;
}

bool pkm_kacs_stratafs_created_cleanup_active(const struct dentry *outer)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !outer)
		return false;
	task_sec = pkm_kacs_task(current);
	return task_sec->stratafs_cleanup_outer == outer &&
	       task_sec->stratafs_cleanup_outer_inode == d_inode(outer) &&
	       task_sec->stratafs_cleanup_subject ==
		       pkm_kacs_current_effective_token_ptr();
}

int pkm_kacs_stratafs_begin_created_cleanup(
	const struct inode *parent, const struct dentry *target)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !parent || !target ||
	    !d_really_is_positive((struct dentry *)target) ||
	    target->d_parent == NULL || d_inode(target->d_parent) != parent)
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_cleanup_parent ||
	    task_sec->stratafs_cleanup_dentry)
		return -EBUSY;
	if (task_sec->stratafs_cleanup_subject) {
		if (task_sec->stratafs_cleanup_subject !=
		    pkm_kacs_current_effective_token_ptr())
			return -EACCES;
	} else {
		task_sec->stratafs_cleanup_subject =
			pkm_kacs_current_effective_token_ptr();
		if (!task_sec->stratafs_cleanup_subject)
			return -EACCES;
	}
	task_sec->stratafs_cleanup_parent = parent;
	task_sec->stratafs_cleanup_dentry = target;
	task_sec->stratafs_cleanup_inode = d_inode(target);
	return 0;
}

static bool pkm_kacs_stratafs_created_cleanup_allows(
	const struct inode *parent, const struct dentry *target)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return false;
	task_sec = pkm_kacs_task(current);
	return task_sec->stratafs_cleanup_subject ==
			       pkm_kacs_current_effective_token_ptr() &&
	       task_sec->stratafs_cleanup_parent == parent &&
	       task_sec->stratafs_cleanup_dentry == target &&
	       task_sec->stratafs_cleanup_inode == d_inode(target);
}

int pkm_kacs_inode_permission(struct inode *inode, int mask)
{
	if (inode && inode->i_sb &&
	    inode->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;
	if (pkm_kacs_copy_up_allows_inode_permission(inode, mask))
		return 0;
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
		trace_kacs_inode_file_access(inode, desired_access, -EINVAL,
					     KACS_TR_BAD_ARGS);
		return -EINVAL;
	}
	if (!inode->i_security) {
		pr_debug(
			"kacs: deny inode_file_access NO_SEC ino=%lu sb_magic=0x%lx desired=0x%x comm=%s pid=%d\n",
			inode->i_ino,
			(unsigned long)inode->i_sb->s_magic,
			desired_access, current->comm, current->pid);
		trace_kacs_inode_file_access(inode, desired_access, -EACCES,
					     KACS_TR_NO_ISEC);
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
			trace_kacs_inode_file_access(inode, desired_access,
						     -EACCES,
						     KACS_TR_NO_DENTRY_ALIAS);
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
	trace_kacs_inode_file_access(inode, desired_access, ret,
				     KACS_TR_DECISION);
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
		trace_kacs_inode_permission(inode, desired_access, -EACCES,
					    KACS_TR_NO_TOKEN);
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
			trace_kacs_inode_permission(
				inode, desired_access, -EACCES,
				KACS_TR_CHANGE_NOTIFY_PRIV_EXHAUSTED);
			return -EACCES;
		}
		trace_kacs_inode_permission(inode, desired_access, 0,
					    KACS_TR_CHANGE_NOTIFY_PRIV);
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
	struct pkm_kacs_task_security *task_sec;
	bool preauthorized = false;

	if (!parent_inode || desired_access == 0)
		return -EACCES;
	if (current && current->security) {
		task_sec = pkm_kacs_task(current);
		if (task_sec->stratafs_create_state == 2) {
			preauthorized =
				task_sec->stratafs_create_subject == subject_token &&
				task_sec->stratafs_create_parent == parent_inode &&
				(!task_sec->stratafs_create_dentry ||
				 task_sec->stratafs_create_dentry == child_dentry) &&
				task_sec->stratafs_create_access == desired_access;
			pkm_kacs_stratafs_end_create_decision();
			if (preauthorized)
				return 0;
		}
	}
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
	struct pkm_kacs_task_security *task_sec;
	bool unnamed_link = false;
	long ret;

	if (!old_dentry || !dir || !new_dentry)
		return -EACCES;

	if (current && current->security) {
		task_sec = pkm_kacs_task(current);
		unnamed_link = task_sec->stratafs_create_state == 2 &&
			task_sec->stratafs_create_subject == subject_token &&
			task_sec->stratafs_create_parent == dir &&
			task_sec->stratafs_create_dentry == new_dentry &&
			task_sec->stratafs_create_access == KACS_FILE_ADD_FILE &&
			task_sec->stratafs_create_link_source == old_dentry &&
			task_sec->stratafs_create_link_inode == d_inode(old_dentry);
	}
	ret = pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, dir, new_dentry, KACS_FILE_ADD_FILE);
	trace_kacs_inode_link(dir, NULL, KACS_FILE_ADD_FILE, KACS_NS_DEST, ret);
	if (ret)
		return ret;

	source_inode = d_inode(old_dentry);
	if (!source_inode)
		return -EACCES;
	if (unnamed_link)
		return 0;

	ret = pkm_kacs_authorize_inode_namespace_access_for_subject(
		subject_token, source_inode, old_dentry,
		KACS_FILE_WRITE_ATTRIBUTES);
	trace_kacs_inode_link(NULL, source_inode, KACS_FILE_WRITE_ATTRIBUTES,
			      KACS_NS_SOURCE, ret);
	return ret;
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
	trace_kacs_inode_rename(old_dir, source_inode, KACS_ACCESS_DELETE,
				KACS_NS_SOURCE, ret);
	if (ret)
		return ret;

	add_access = S_ISDIR(source_inode->i_mode) ?
			     KACS_FILE_ADD_SUBDIRECTORY :
			     KACS_FILE_ADD_FILE;
	ret = pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, new_dir, new_dentry, add_access);
	trace_kacs_inode_rename(new_dir, source_inode, add_access,
				KACS_NS_DEST, ret);
	if (ret)
		return ret;

	if (d_is_positive(new_dentry)) {
		ret = pkm_kacs_authorize_namespace_delete_for_subject(
			subject_token, new_dir, new_dentry);
		trace_kacs_inode_rename(new_dir, d_inode(new_dentry),
					KACS_ACCESS_DELETE,
					KACS_NS_DELETE_EXISTING, ret);
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
	if (old_dir && old_dir->i_sb &&
	    old_dir->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;
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
	long ret;
	if (dir && dir->i_sb && dir->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;

	if (pkm_kacs_copy_up_allows_create(dir, dentry, S_IFREG))
		return 0;
	(void)mode;
	ret = pkm_kacs_authorize_namespace_create_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry, false);
	trace_kacs_inode_create(dir, dentry ? d_inode(dentry) : NULL,
				KACS_FILE_ADD_FILE, KACS_NS_PRIMARY, ret);
	return (int)ret;
}

int pkm_kacs_inode_mkdir(struct inode *dir, struct dentry *dentry,
			 umode_t mode)
{
	long ret;
	if (dir && dir->i_sb && dir->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;

	if (pkm_kacs_copy_up_allows_create(dir, dentry, S_IFDIR))
		return 0;
	(void)mode;
	ret = pkm_kacs_authorize_namespace_create_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry, true);
	trace_kacs_inode_mkdir(dir, dentry ? d_inode(dentry) : NULL,
			       KACS_FILE_ADD_SUBDIRECTORY, KACS_NS_PRIMARY, ret);
	return (int)ret;
}

int pkm_kacs_inode_mknod(struct inode *dir, struct dentry *dentry,
			 umode_t mode, dev_t dev)
{
	long ret;
	if (dir && dir->i_sb && dir->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;

	(void)dev;

	if (!pkm_kacs_inode_on_unmanaged_mount(dir) &&
	    !pkm_kacs_special_node_mode_supported(mode))
		ret = -EOPNOTSUPP;
	else
		ret = pkm_kacs_authorize_namespace_create_for_subject(
			pkm_kacs_current_effective_token_ptr(), dir, dentry,
			false);
	trace_kacs_inode_mknod(dir, dentry ? d_inode(dentry) : NULL,
			       KACS_FILE_ADD_FILE, KACS_NS_PRIMARY, ret);
	return (int)ret;
}

int pkm_kacs_inode_symlink(struct inode *dir, struct dentry *dentry,
			   const char *old_name)
{
	long ret;
	if (dir && dir->i_sb && dir->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;

	if (pkm_kacs_copy_up_allows_create(dir, dentry, S_IFLNK))
		return 0;
	(void)old_name;
	ret = pkm_kacs_authorize_namespace_symlink_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry);
	trace_kacs_inode_symlink(dir, dentry ? d_inode(dentry) : NULL,
				 KACS_FILE_ADD_FILE, KACS_NS_PRIMARY, ret);
	return (int)ret;
}

int pkm_kacs_inode_link(struct dentry *old_dentry, struct inode *dir,
			struct dentry *new_dentry)
{
	if (dir && dir->i_sb && dir->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;
	if (pkm_kacs_copy_up_allows_link(old_dentry, dir, new_dentry))
		return 0;
	return (int)pkm_kacs_authorize_namespace_link_for_subject(
		pkm_kacs_current_effective_token_ptr(), old_dentry, dir,
		new_dentry);
}

int pkm_kacs_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	long ret;
	if (dir && dir->i_sb && dir->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;
	if (pkm_kacs_stratafs_supersede_allows_unlink(dir, dentry))
		return 0;
	if (pkm_kacs_stratafs_created_cleanup_allows(dir, dentry))
		return 0;

	if (pkm_kacs_copy_up_allows_unlink(dir, dentry, false))
		return 0;
	if (current && current->security) {
		struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
		const struct file *file = task_sec->delete_on_close_file;

		if (file &&
		    ((file_dentry((struct file *)file) == dentry &&
		      file_inode((struct file *)file) == d_inode(dentry) &&
		      dentry->d_parent && d_inode(dentry->d_parent) == dir) ||
		     (task_sec->delete_on_close_parent_inode == dir &&
		      task_sec->delete_on_close_dentry == dentry &&
		      task_sec->delete_on_close_inode == d_inode(dentry))))
			return 0;
	}
	ret = pkm_kacs_authorize_namespace_delete_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry);
	trace_kacs_inode_unlink(dir, dentry ? d_inode(dentry) : NULL,
				KACS_ACCESS_DELETE, KACS_NS_PRIMARY, ret);
	return (int)ret;
}

int pkm_kacs_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	long ret;
	if (dir && dir->i_sb && dir->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;
	if (pkm_kacs_stratafs_created_cleanup_allows(dir, dentry))
		return 0;

	if (pkm_kacs_copy_up_allows_unlink(dir, dentry, true))
		return 0;
	ret = pkm_kacs_authorize_namespace_delete_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry);
	trace_kacs_inode_rmdir(dir, dentry ? d_inode(dentry) : NULL,
			       KACS_ACCESS_DELETE, KACS_NS_PRIMARY, ret);
	return (int)ret;
}

int pkm_kacs_inode_rename(struct inode *old_dir,
			  struct dentry *old_dentry,
			  struct inode *new_dir,
			  struct dentry *new_dentry)
{
	if (old_dir && old_dir->i_sb &&
	    old_dir->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return 0;
	if (pkm_kacs_stratafs_supersede_allows_rename(
		    old_dir, old_dentry, new_dir, new_dentry))
		return 0;
	if (pkm_kacs_copy_up_allows_rename(old_dir, old_dentry, new_dir,
					   new_dentry))
		return 0;
	return (int)pkm_kacs_authorize_namespace_rename_for_subject(
		pkm_kacs_current_effective_token_ptr(), old_dir, old_dentry,
		new_dir, new_dentry);
}

int pkm_kacs_inode_readlink(struct dentry *dentry)
{
	struct inode *inode;
	long ret;

	if (!dentry)
		return -EACCES;
	if (pkm_kacs_copy_up_allows_readlink(dentry))
		return 0;

	inode = d_inode(dentry);
	ret = pkm_kacs_authorize_inode_namespace_access_for_subject(
		pkm_kacs_current_effective_token_ptr(), inode, dentry,
		KACS_FILE_READ_DATA);
	trace_kacs_inode_readlink(NULL, inode, KACS_FILE_READ_DATA,
				  KACS_NS_PRIMARY, ret);
	return (int)ret;
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
	u8 *cache_bytes = NULL;
	struct pkm_kacs_inode_sd_cache *copy_up_cache = NULL;
	struct pkm_kacs_inode_security *inode_sec;
	bool allocated_sd = false;
	bool copy_up_sd = false;
	int copy_up_match;
	long ret;

	(void)qstr;
	if (!inode || !dir || !xattrs || !xattr_count)
		return -EOPNOTSUPP;
	if (pkm_kacs_inode_is_ntfs(inode))
		return -EOPNOTSUPP;
	copy_up_match = pkm_kacs_copy_up_init_security(
		inode, dir, qstr, &sd_bytes, &sd_len);
	if (copy_up_match < 0)
		return copy_up_match;
	if (copy_up_match > 0) {
		copy_up_sd = true;
	} else if (!pkm_kacs_current_native_create_request_matches(
		    dir, S_ISDIR(inode->i_mode), &sd_bytes, &sd_len)) {
		subject_token = pkm_kacs_current_effective_token_ptr();
		if (!subject_token) {
			pr_debug(
				"kacs: deny inode_init_security NO_TOKEN dir_ino=%lu sb_magic=0x%lx mode=0%o comm=%s pid=%d\n",
				dir->i_ino,
				(unsigned long)dir->i_sb->s_magic,
				inode->i_mode, current->comm, current->pid);
			trace_kacs_inode_init_security(dir, inode, 0,
						       KACS_NS_PRIMARY, -EACCES);
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
			trace_kacs_inode_init_security(dir, inode, 0,
						       KACS_NS_PRIMARY, ret);
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
		trace_kacs_inode_init_security(dir, inode, 0, KACS_NS_PRIMARY,
					       allocated_sd ? -EACCES :
							      -EOPNOTSUPP);
		return allocated_sd ? -EACCES : -EOPNOTSUPP;
	}

	copied_bytes = kmemdup(sd_bytes, sd_len, GFP_NOFS);
	if (allocated_sd)
		pkm_kacs_free((void *)sd_bytes);
	if (!copied_bytes)
		return -ENOMEM;
	if (copy_up_sd) {
		if (!inode->i_security) {
			kfree(copied_bytes);
			return -EACCES;
		}
		cache_bytes = kmemdup(sd_bytes, sd_len, GFP_NOFS);
		if (!cache_bytes) {
			kfree(copied_bytes);
			return -ENOMEM;
		}
		copy_up_cache = pkm_kacs_inode_sd_cache_alloc(
			PKM_KACS_INODE_SD_VALID, cache_bytes, sd_len);
		if (!copy_up_cache) {
			kfree(cache_bytes);
			kfree(copied_bytes);
			return -EACCES;
		}
	}

	xattr = lsm_get_xattr_slot(xattrs, xattr_count);
	if (!xattr) {
		pkm_kacs_inode_sd_cache_free(copy_up_cache);
		kfree(copied_bytes);
		return -ENOMEM;
	}

	xattr->name = "peios.sd";
	xattr->value = copied_bytes;
	xattr->value_len = sd_len;
	if (copy_up_cache) {
		inode_sec = pkm_kacs_inode(inode);
		mutex_lock(&inode_sec->lock);
		pkm_kacs_inode_replace_sd_cache_locked(inode_sec,
						       copy_up_cache);
		mutex_unlock(&inode_sec->lock);
	}
	trace_kacs_inode_init_security(dir, inode, 0, KACS_NS_PRIMARY, 0);
	return 0;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static void pkm_kacs_kunit_init_namespace_dentry(
	struct dentry *dentry, struct super_block *sb, struct inode *inode,
	struct dentry *parent, const char *name)
{
	struct qstr *qstr;

	memset(dentry, 0, sizeof(*dentry));
	dentry->d_sb = sb;
	dentry->d_inode = inode;
	dentry->d_parent = parent ? parent : dentry;
	qstr = (struct qstr *)&dentry->d_name;
	qstr->name = (const u8 *)name;
	qstr->len = strlen(name);
	if (inode && S_ISDIR(inode->i_mode))
		dentry->d_flags = DCACHE_DIRECTORY_TYPE;
	else if (inode)
		dentry->d_flags = DCACHE_REGULAR_TYPE;
}

static void pkm_kunit_stratafs_supersede_scope_is_exact(struct kunit *test)
{
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct super_block outer_sb = { .s_magic = STRATAFS_SUPER_MAGIC };
	struct super_block lower_sb = { .s_magic = TMPFS_MAGIC };
	struct inode outer_parent_inode = {
		.i_mode = S_IFDIR,
		.i_sb = &outer_sb,
	};
	struct inode outer_source_inode = {
		.i_mode = S_IFREG,
		.i_sb = &outer_sb,
	};
	struct inode outer_target_inode = {
		.i_mode = S_IFREG,
		.i_sb = &outer_sb,
	};
	struct inode lower_parent_inode = {
		.i_mode = S_IFDIR,
		.i_sb = &lower_sb,
	};
	struct inode lower_source_inode = {
		.i_mode = S_IFREG,
		.i_sb = &lower_sb,
	};
	struct inode lower_target_inode = {
		.i_mode = S_IFREG,
		.i_sb = &lower_sb,
	};
	struct inode replacement_inode = {
		.i_mode = S_IFREG,
		.i_sb = &lower_sb,
	};
	struct dentry outer_parent;
	struct dentry outer_source;
	struct dentry outer_target;
	struct dentry lower_parent;
	struct dentry lower_source;
	struct dentry lower_target;
	struct dentry lower_destination;
	const void *subject;

	KUNIT_ASSERT_NOT_NULL(test, current->security);
	KUNIT_ASSERT_EQ(test, task_sec->stratafs_supersede_state, (u8)0);
	pkm_kacs_kunit_init_namespace_dentry(
		&outer_parent, &outer_sb, &outer_parent_inode, NULL, "outer");
	pkm_kacs_kunit_init_namespace_dentry(
		&outer_source, &outer_sb, &outer_source_inode, &outer_parent,
		"source");
	pkm_kacs_kunit_init_namespace_dentry(
		&outer_target, &outer_sb, &outer_target_inode, &outer_parent,
		"target");
	pkm_kacs_kunit_init_namespace_dentry(
		&lower_parent, &lower_sb, &lower_parent_inode, NULL, "lower");
	pkm_kacs_kunit_init_namespace_dentry(
		&lower_source, &lower_sb, &lower_source_inode, &lower_parent,
		"stage");
	pkm_kacs_kunit_init_namespace_dentry(
		&lower_target, &lower_sb, &lower_target_inode, &lower_parent,
		"victim");
	pkm_kacs_kunit_init_namespace_dentry(
		&lower_destination, &lower_sb, NULL, &lower_parent, "published");

	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_begin_supersede(&outer_target), 0);
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_stratafs_begin_supersede(&outer_target), -EBUSY);
	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_bind_supersede_source(
			&outer_target, &outer_source), 0);
	KUNIT_EXPECT_TRUE(test, pkm_kacs_stratafs_supersede_active(
		&outer_source, &outer_target));

	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_begin_supersede_unlink(
			&lower_parent_inode, &lower_target), 0);
	KUNIT_EXPECT_TRUE(test, pkm_kacs_stratafs_supersede_allows_unlink(
		&lower_parent_inode, &lower_target));
	lower_target.d_inode = &replacement_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_stratafs_supersede_allows_unlink(
		&lower_parent_inode, &lower_target));
	lower_target.d_inode = &lower_target_inode;
	subject = task_sec->stratafs_supersede_subject;
	task_sec->stratafs_supersede_subject = &replacement_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_stratafs_supersede_allows_unlink(
		&lower_parent_inode, &lower_target));
	task_sec->stratafs_supersede_subject = subject;
	pkm_kacs_stratafs_end_supersede_phase();

	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_begin_supersede_rename(
			&lower_parent_inode, &lower_source,
			&lower_parent_inode, &lower_destination), 0);
	KUNIT_EXPECT_TRUE(test, pkm_kacs_stratafs_supersede_allows_rename(
		&lower_parent_inode, &lower_source,
		&lower_parent_inode, &lower_destination));
	lower_destination.d_inode = &replacement_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_stratafs_supersede_allows_rename(
		&lower_parent_inode, &lower_source,
		&lower_parent_inode, &lower_destination));
	lower_destination.d_inode = NULL;
	lower_source.d_inode = &replacement_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_stratafs_supersede_allows_rename(
		&lower_parent_inode, &lower_source,
		&lower_parent_inode, &lower_destination));
	lower_source.d_inode = &lower_source_inode;
	pkm_kacs_stratafs_end_supersede();
	KUNIT_EXPECT_FALSE(test, pkm_kacs_stratafs_supersede_active(
		&outer_source, &outer_target));
	KUNIT_EXPECT_EQ(test, task_sec->stratafs_supersede_state, (u8)0);
}

static void pkm_kunit_stratafs_cleanup_scope_is_exact(struct kunit *test)
{
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct super_block outer_sb = { .s_magic = STRATAFS_SUPER_MAGIC };
	struct super_block lower_sb = { .s_magic = TMPFS_MAGIC };
	struct inode outer_inode = { .i_mode = S_IFREG, .i_sb = &outer_sb };
	struct inode lower_parent_inode = {
		.i_mode = S_IFDIR,
		.i_sb = &lower_sb,
	};
	struct inode lower_inode = { .i_mode = S_IFREG, .i_sb = &lower_sb };
	struct inode replacement_inode = {
		.i_mode = S_IFREG,
		.i_sb = &lower_sb,
	};
	struct dentry outer;
	struct dentry lower_parent;
	struct dentry lower;
	const void *subject;

	KUNIT_ASSERT_NOT_NULL(test, current->security);
	KUNIT_ASSERT_NULL(test, task_sec->stratafs_cleanup_subject);
	pkm_kacs_kunit_init_namespace_dentry(
		&outer, &outer_sb, &outer_inode, NULL, "outer");
	pkm_kacs_kunit_init_namespace_dentry(
		&lower_parent, &lower_sb, &lower_parent_inode, NULL, "parent");
	pkm_kacs_kunit_init_namespace_dentry(
		&lower, &lower_sb, &lower_inode, &lower_parent, "created");

	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_arm_created_cleanup(&outer), 0);
	KUNIT_EXPECT_TRUE(test,
		pkm_kacs_stratafs_created_cleanup_active(&outer));
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_stratafs_arm_created_cleanup(&outer), -EBUSY);
	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_begin_created_cleanup(
			&lower_parent_inode, &lower), 0);
	KUNIT_EXPECT_TRUE(test, pkm_kacs_stratafs_created_cleanup_allows(
		&lower_parent_inode, &lower));
	lower.d_inode = &replacement_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_stratafs_created_cleanup_allows(
		&lower_parent_inode, &lower));
	lower.d_inode = &lower_inode;
	subject = task_sec->stratafs_cleanup_subject;
	task_sec->stratafs_cleanup_subject = &replacement_inode;
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_stratafs_created_cleanup_active(&outer));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_stratafs_created_cleanup_allows(
		&lower_parent_inode, &lower));
	task_sec->stratafs_cleanup_subject = subject;
	pkm_kacs_stratafs_end_created_cleanup();
	KUNIT_EXPECT_NULL(test, task_sec->stratafs_cleanup_subject);
	KUNIT_EXPECT_NULL(test, task_sec->stratafs_cleanup_inode);
}

static void pkm_kunit_stratafs_create_preauthorization_is_one_shot(
	struct kunit *test)
{
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct super_block sb = { .s_magic = TMPFS_MAGIC };
	struct inode parent_inode = { .i_mode = S_IFDIR, .i_sb = &sb };
	struct dentry parent;
	struct dentry target;
	struct vfsmount mnt = { .mnt_sb = &sb };
	struct path authority;
	const void *subject;

	KUNIT_ASSERT_NOT_NULL(test, current->security);
	KUNIT_ASSERT_EQ(test, task_sec->stratafs_create_state, (u8)0);
	pkm_kacs_kunit_init_namespace_dentry(
		&parent, &sb, &parent_inode, NULL, "parent");
	pkm_kacs_kunit_init_namespace_dentry(
		&target, &sb, NULL, &parent, "target");
	mnt.mnt_root = &parent;
	mnt.mnt_idmap = &nop_mnt_idmap;
	authority = (struct path){ .mnt = &mnt, .dentry = &parent };
	subject = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject);

	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_set_native_create_decision(
			&authority, KACS_FILE_ADD_FILE), 0);
	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_bind_create_decision(&parent_inode, &target), 0);
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_authorize_parent_namespace_access_for_subject(
			subject, &parent_inode, &target, KACS_FILE_ADD_FILE), 0L);
	KUNIT_EXPECT_EQ(test, task_sec->stratafs_create_state, (u8)0);
	KUNIT_EXPECT_NULL(test, task_sec->stratafs_create_subject);
}

static struct kunit_case pkm_kunit_stratafs_namespace_cases[] = {
	KUNIT_CASE(pkm_kunit_stratafs_supersede_scope_is_exact),
	KUNIT_CASE(pkm_kunit_stratafs_cleanup_scope_is_exact),
	KUNIT_CASE(pkm_kunit_stratafs_create_preauthorization_is_one_shot),
	{}
};

static struct kunit_suite pkm_kunit_stratafs_namespace_suite = {
	.name = "pkm_kunit_stratafs_namespace",
	.test_cases = pkm_kunit_stratafs_namespace_cases,
};

kunit_test_suite(pkm_kunit_stratafs_namespace_suite);
#endif
