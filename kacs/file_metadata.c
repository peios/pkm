// SPDX-License-Identifier: GPL-2.0-only

#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/xattr.h>

#include <pkm/sd.h>

#include "access_check.h"
#include "file_access.h"
#include "file_metadata.h"
#include <trace/events/kacs.h>
#include "lsm_internal.h"
#include "mount_policy.h"
#include "object_lifecycle.h"
#include "signing.h"

bool pkm_kacs_is_file_capability_xattr(const char *name)
{
	return name && strcmp(name, XATTR_NAME_CAPS) == 0;
}

static bool pkm_kacs_is_signing_xattr(const char *name)
{
	return name && strcmp(name, PKM_KACS_SIGNING_XATTR_NAME) == 0;
}

int pkm_kacs_check_signed_exec_xattr_mutation(const struct inode *inode,
					      const char *name)
{
	if (!name)
		return -EACCES;
	if (!pkm_kacs_is_signing_xattr(name))
		return 0;
	if (!inode)
		return -EACCES;

	return pkm_kacs_check_signed_exec_content_mutation_inode(inode);
}

int pkm_kacs_inode_getattr(const struct path *path)
{
	if (!path || !path->dentry) {
		pkm_kacs_clear_current_file_metadata_decision();
		return -EACCES;
	}

	if (pkm_kacs_consume_file_metadata_decision(
		    d_inode(path->dentry), PKM_KACS_METADATA_OP_GETATTR))
		return 0;

	return pkm_kacs_authorize_path_metadata_access(
		path, KACS_FILE_READ_ATTRIBUTES);
}

static u32 pkm_kacs_inode_setattr_required_access(const struct iattr *attr)
{
	u32 required = 0;
	unsigned int ia_valid;

	if (!attr)
		return 0;

	ia_valid = attr->ia_valid;
	if ((ia_valid & ATTR_MODE) != 0)
		required |= KACS_ACCESS_WRITE_DAC;
	if ((ia_valid & (ATTR_UID | ATTR_GID)) != 0)
		required |= KACS_ACCESS_WRITE_OWNER;
	if ((ia_valid & ATTR_SIZE) != 0 &&
	    (ia_valid & ATTR_FILE) == 0)
		required |= KACS_FILE_WRITE_DATA;
	if ((ia_valid & (ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET |
			 ATTR_MTIME_SET | ATTR_CTIME_SET | ATTR_TIMES_SET |
			 ATTR_TOUCH)) != 0)
		required |= KACS_FILE_WRITE_ATTRIBUTES;

	return required;
}

int pkm_kacs_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			   struct iattr *attr)
{
	u32 required_access;
	int ret;

	if (!dentry || !attr) {
		pkm_kacs_clear_current_file_metadata_decision();
		return -EACCES;
	}

	if ((attr->ia_valid & ATTR_SIZE) != 0) {
		ret = pkm_kacs_check_signed_exec_content_mutation_inode(
			d_inode(dentry));
		if (ret) {
			pkm_kacs_consume_file_metadata_decision(
				d_inode(dentry), PKM_KACS_METADATA_OP_SETATTR);
			trace_kacs_metadata(d_inode(dentry),
					    PKM_KACS_METADATA_OP_SETATTR, 0,
					    KACS_META_SIGNED_EXEC, ret);
			return ret;
		}
	}

	if (pkm_kacs_consume_file_metadata_decision(
		    d_inode(dentry), PKM_KACS_METADATA_OP_SETATTR))
		return 0;

	required_access = pkm_kacs_inode_setattr_required_access(attr);
	if (required_access == 0)
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(dentry,
							 required_access);
}

int pkm_kacs_inode_file_getattr(struct dentry *dentry, struct file_kattr *fa)
{
	if (!dentry) {
		pkm_kacs_clear_current_file_metadata_decision();
		return -EACCES;
	}

	if (pkm_kacs_has_file_metadata_decision(
		    d_inode(dentry), PKM_KACS_METADATA_OP_FILEATTR_SET))
		return 0;
	if (pkm_kacs_consume_file_metadata_decision(
		    d_inode(dentry), PKM_KACS_METADATA_OP_FILEATTR_GET))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, KACS_FILE_READ_ATTRIBUTES);
}

int pkm_kacs_inode_file_setattr(struct dentry *dentry, struct file_kattr *fa)
{
	if (!dentry) {
		pkm_kacs_clear_current_file_metadata_decision();
		return -EACCES;
	}

	if (pkm_kacs_consume_file_metadata_decision(
		    d_inode(dentry), PKM_KACS_METADATA_OP_FILEATTR_SET))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, KACS_FILE_WRITE_ATTRIBUTES);
}

int pkm_kacs_inode_xattr_skipcap(const char *name)
{
	/*
	 * FACS is authoritative for xattr metadata access. A missing name is an
	 * invalid hook shape, so leave native capability checks in place.
	 */
	return name ? 1 : 0;
}

int pkm_kacs_inode_getxattr(struct dentry *dentry, const char *name)
{
	if (dentry && pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name)) {
		/*
		 * KACS's own SD-cache populate path may re-enter this hook
		 * through a stacking FS's xattr handler (overlayfs forwards
		 * to vfs_getxattr on the real lower/upper inode). Allow the
		 * read iff we're inside one of those internal reads — the
		 * task counter is bumped by pkm_kacs_inode_read_sd_xattr_locked
		 * around its __vfs_getxattr calls. Caller-originated syscalls
		 * still get -EACCES.
		 */
		if (current && current->security &&
		    pkm_kacs_task(current)->internal_sd_read_depth > 0) {
			trace_kacs_metadata(d_inode(dentry),
					    PKM_KACS_METADATA_OP_GETXATTR, 0,
					    KACS_META_INTERNAL_SD, 0);
			return 0;
		}
		pkm_kacs_consume_file_metadata_decision(
			d_inode(dentry), PKM_KACS_METADATA_OP_GETXATTR);
		trace_kacs_metadata(d_inode(dentry),
				    PKM_KACS_METADATA_OP_GETXATTR, 0,
				    KACS_META_CANONICAL_SD, -EACCES);
		return -EACCES;
	}

	if (!name) {
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_GETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_GETXATTR, 0,
				    KACS_META_BAD_ARGS, -EACCES);
		return -EACCES;
	}

	if (pkm_kacs_consume_file_metadata_decision(
		    dentry ? d_inode(dentry) : NULL,
		    PKM_KACS_METADATA_OP_GETXATTR))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, KACS_FILE_READ_EA);
}

int pkm_kacs_inode_setxattr(struct mnt_idmap *idmap, struct dentry *dentry,
			    const char *name, const void *value, size_t size,
			    int flags)
{
	int ret;

	if (dentry && pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name)) {
		/*
		 * Mirror inode_getxattr: KACS's own SD-xattr write
		 * (__vfs_setxattr_noperm) can re-enter this hook through a
		 * stacking FS (overlayfs forwards to vfs_setxattr on the real
		 * inode). Allow the write iff we're inside one of those
		 * internal writes — caller-originated syscalls still get
		 * -EACCES.
		 */
		if (current && current->security &&
		    pkm_kacs_task(current)->internal_sd_write_depth > 0) {
			trace_kacs_metadata(d_inode(dentry),
					    PKM_KACS_METADATA_OP_SETXATTR, 0,
					    KACS_META_INTERNAL_SD, 0);
			return 0;
		}
		pkm_kacs_consume_file_metadata_decision(
			d_inode(dentry), PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(d_inode(dentry),
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_CANONICAL_SD, -EACCES);
		return -EACCES;
	}
	if (!name) {
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_BAD_ARGS, -EACCES);
		return -EACCES;
	}
	if (pkm_kacs_is_file_capability_xattr(name)) {
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_CAPS_XATTR, -EPERM);
		return -EPERM;
	}
	if (is_posix_acl_xattr(name)) {
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_ACL, -EACCES);
		return -EACCES;
	}
	ret = pkm_kacs_check_signed_exec_xattr_mutation(
		dentry ? d_inode(dentry) : NULL, name);
	if (ret) {
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_SIGNED_EXEC, ret);
		return ret;
	}

	if (pkm_kacs_consume_file_metadata_decision(
		    dentry ? d_inode(dentry) : NULL,
		    PKM_KACS_METADATA_OP_SETXATTR))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, KACS_FILE_WRITE_EA);
}

int pkm_kacs_inode_removexattr(struct mnt_idmap *idmap, struct dentry *dentry,
			       const char *name)
{
	int ret;

	if (dentry && pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name)) {
		pkm_kacs_consume_file_metadata_decision(
			d_inode(dentry), PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(d_inode(dentry),
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_CANONICAL_SD, -EACCES);
		return -EACCES;
	}
	if (!name) {
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_BAD_ARGS, -EACCES);
		return -EACCES;
	}
	if (is_posix_acl_xattr(name)) {
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_ACL, -EACCES);
		return -EACCES;
	}
	ret = pkm_kacs_check_signed_exec_xattr_mutation(
		dentry ? d_inode(dentry) : NULL, name);
	if (ret) {
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_SIGNED_EXEC, ret);
		return ret;
	}

	if (pkm_kacs_consume_file_metadata_decision(
		    dentry ? d_inode(dentry) : NULL,
		    PKM_KACS_METADATA_OP_SETXATTR))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, KACS_FILE_WRITE_EA);
}

int pkm_kacs_inode_listxattr(struct dentry *dentry)
{
	if (!dentry) {
		pkm_kacs_clear_current_file_metadata_decision();
		return -EACCES;
	}

	pkm_kacs_consume_file_metadata_decision(d_inode(dentry),
						PKM_KACS_METADATA_OP_NONE);

	return 0;
}

/*
 * On overlayfs copy-up, decline to copy the canonical SD xattr. The upper
 * inode's SD is established by KACS inheritance when overlayfs creates it,
 * so replicating the lower's SD is both redundant and impossible: the
 * lower read and upper write would each hit the deny in inode_getxattr /
 * inode_setxattr (canonical SD xattrs are not userspace-writable; SD
 * mutation is the dedicated syscall's job), failing the whole copy-up.
 *
 * -ECANCELED is the overlayfs "discard this xattr" signal; -EOPNOTSUPP
 * (the hook default) leaves every other xattr to the normal copy. This is
 * the same pattern SELinux and Smack use for their own label xattrs.
 */
int pkm_kacs_inode_copy_up_xattr(struct dentry *src, const char *name)
{
	if (src && pkm_kacs_is_canonical_sd_xattr(d_inode(src), name))
		return -ECANCELED; /* discard: do not copy the SD up */

	return -EOPNOTSUPP;
}

int pkm_kacs_inode_follow_link(struct dentry *dentry, struct inode *inode,
			       bool rcu)
{
	(void)dentry;
	(void)inode;
	(void)rcu;
	return 0;
}

int pkm_kacs_inode_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
			   const char *acl_name, struct posix_acl *kacl)
{
	(void)idmap;
	(void)dentry;
	(void)acl_name;
	(void)kacl;
	/*
	 * Peios doesn't carry POSIX ACLs — the SD lives in security.peios.sd.
	 * Return EOPNOTSUPP rather than EACCES so callers that defensively
	 * probe-then-tolerate (e.g. overlayfs's workdir setup) treat us as
	 * "this FS doesn't support ACLs" rather than as a permission failure.
	 */
	return -EOPNOTSUPP;
}

int pkm_kacs_inode_remove_acl(struct mnt_idmap *idmap, struct dentry *dentry,
			      const char *acl_name)
{
	(void)idmap;
	(void)dentry;
	(void)acl_name;
	/* See pkm_kacs_inode_set_acl above for the EOPNOTSUPP rationale. */
	return -EOPNOTSUPP;
}

int pkm_kacs_inode_getsecurity(struct mnt_idmap *idmap, struct inode *inode,
			       const char *name, void **buffer, bool alloc)
{
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache;
	void *copy;
	size_t len;

	(void)idmap;
	if (!inode || !inode->i_security || !name || strcmp(name, "peios.sd"))
		return -EOPNOTSUPP;
	if (alloc && !buffer)
		return -EINVAL;

	sec = pkm_kacs_inode(inode);
	cache = pkm_kacs_inode_sd_cache_get_current(inode, sec);
	if (!cache) {
		trace_kacs_metadata(inode, PKM_KACS_METADATA_OP_NONE, 0,
				    KACS_META_GETSECURITY, -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}
	if (cache->state != PKM_KACS_INODE_SD_VALID || !cache->bytes ||
	    cache->len == 0 || cache->len > INT_MAX) {
		pkm_kacs_inode_sd_cache_free(cache);
		trace_kacs_metadata(inode, PKM_KACS_METADATA_OP_NONE, 0,
				    KACS_META_GETSECURITY, -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}

	len = cache->len;
	if (!alloc) {
		pkm_kacs_inode_sd_cache_free(cache);
		trace_kacs_metadata(inode, PKM_KACS_METADATA_OP_NONE, 1,
				    KACS_META_GETSECURITY, (int)len);
		return (int)len;
	}

	copy = kmemdup(cache->bytes, len, GFP_KERNEL);
	pkm_kacs_inode_sd_cache_free(cache);
	if (!copy) {
		trace_kacs_metadata(inode, PKM_KACS_METADATA_OP_NONE, 0,
				    KACS_META_GETSECURITY, -ENOMEM);
		return -ENOMEM;
	}

	*buffer = copy;
	trace_kacs_metadata(inode, PKM_KACS_METADATA_OP_NONE, 1,
			    KACS_META_GETSECURITY, (int)len);
	return (int)len;
}

static void pkm_kacs_clear_file_metadata_decision(
	struct pkm_kacs_task_security *task_sec)
{
	if (!task_sec)
		return;

	task_sec->metadata_decision.inode = NULL;
	task_sec->metadata_decision.op_class = PKM_KACS_METADATA_OP_NONE;
	task_sec->metadata_decision.active = 0;
}

static int pkm_kacs_begin_file_metadata_decision(struct file *file,
						 u8 op_class)
{
	struct pkm_kacs_task_security *task_sec;
	struct inode *inode;

	if (!file || !current || !current->security ||
	    op_class == PKM_KACS_METADATA_OP_NONE)
		return -EACCES;

	inode = file_inode(file);
	if (!inode)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	if (task_sec->metadata_decision.active) {
		trace_kacs_metadata(inode, op_class, 0, KACS_META_BEGIN_BUSY,
				    -EACCES);
		return -EACCES;
	}

	task_sec->metadata_decision.inode = inode;
	task_sec->metadata_decision.op_class = op_class;
	task_sec->metadata_decision.active = 1;
	return 0;
}

static int pkm_kacs_begin_inode_metadata_decision(const struct inode *inode,
						  u8 op_class)
{
	struct pkm_kacs_task_security *task_sec;

	if (!inode || !current || !current->security ||
	    op_class == PKM_KACS_METADATA_OP_NONE)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	if (task_sec->metadata_decision.active) {
		trace_kacs_metadata(inode, op_class, 0, KACS_META_BEGIN_BUSY,
				    -EACCES);
		return -EACCES;
	}

	task_sec->metadata_decision.inode = inode;
	task_sec->metadata_decision.op_class = op_class;
	task_sec->metadata_decision.active = 1;
	return 0;
}

bool pkm_kacs_has_file_metadata_decision(const struct inode *inode,
					 u8 op_class)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !inode)
		return false;

	task_sec = pkm_kacs_task(current);
	return task_sec->metadata_decision.active &&
	       task_sec->metadata_decision.inode == inode &&
	       task_sec->metadata_decision.op_class == op_class;
}

void pkm_kacs_clear_current_file_metadata_decision(void)
{
	if (!current || !current->security)
		return;

	pkm_kacs_clear_file_metadata_decision(pkm_kacs_task(current));
}

bool pkm_kacs_consume_file_metadata_decision(const struct inode *inode,
					     u8 op_class)
{
	struct pkm_kacs_task_security *task_sec;
	bool matched;

	if (!current || !current->security)
		return false;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->metadata_decision.active)
		return false;

	matched = inode && task_sec->metadata_decision.inode == inode &&
		  task_sec->metadata_decision.op_class == op_class;

	trace_kacs_metadata(inode, op_class, matched ? 1 : 0,
			    matched ? KACS_META_CONSUME_HIT : KACS_META_DECISION,
			    0);
	pkm_kacs_clear_file_metadata_decision(task_sec);
	return matched;
}

void pkm_kacs_file_end_metadata(struct file *file)
{
	struct pkm_kacs_task_security *task_sec;
	struct inode *inode;

	if (!current || !current->security)
		return;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->metadata_decision.active)
		return;

	inode = file ? file_inode(file) : NULL;
	if (!inode || task_sec->metadata_decision.inode == inode)
		pkm_kacs_clear_file_metadata_decision(task_sec);
}

static void pkm_kacs_inode_end_metadata(const struct inode *inode)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->metadata_decision.active)
		return;

	if (!inode || task_sec->metadata_decision.inode == inode)
		pkm_kacs_clear_file_metadata_decision(task_sec);
}

static int pkm_kacs_check_file_xattr_snapshot(struct file *file,
					      const char *name,
					      u32 required_access,
					      bool write_operation,
					      u8 op_class)
{
	struct inode *inode;
	int ret;

	if (!name)
		return -EACCES;
	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;

	inode = file_inode(file);
	if (inode && pkm_kacs_is_canonical_sd_xattr(inode, name))
		return -EACCES;
	if (write_operation && is_posix_acl_xattr(name))
		return -EACCES;
	if (write_operation) {
		ret = pkm_kacs_check_signed_exec_xattr_mutation(inode, name);
		if (ret)
			return ret;
	}

	ret = pkm_kacs_check_file_snapshot_grant(file, required_access);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(file, op_class);
}

int pkm_kacs_file_sd_xattr_set(struct file *file, const char *name)
{
	if (pkm_kacs_is_file_capability_xattr(name))
		return -EPERM;

	return pkm_kacs_check_file_xattr_snapshot(
		file, name, KACS_FILE_WRITE_EA, true,
		PKM_KACS_METADATA_OP_SETXATTR);
}

int pkm_kacs_file_sd_xattr_get(struct file *file, const char *name)
{
	return pkm_kacs_check_file_xattr_snapshot(
		file, name, KACS_FILE_READ_EA, false,
		PKM_KACS_METADATA_OP_GETXATTR);
}

int pkm_kacs_file_sd_xattr_remove(struct file *file, const char *name)
{
	return pkm_kacs_check_file_xattr_snapshot(
		file, name, KACS_FILE_WRITE_EA, true,
		PKM_KACS_METADATA_OP_SETXATTR);
}

int pkm_kacs_file_getattr(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(
		file, KACS_FILE_READ_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_GETATTR);
}

int pkm_kacs_file_statfs(struct file *file)
{
	if (!file)
		return -EACCES;
	return pkm_kacs_check_file_snapshot_grant(
		file, KACS_FILE_READ_ATTRIBUTES);
}

int pkm_kacs_file_chmod(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	ret = pkm_kacs_check_file_snapshot_grant(file,
						 KACS_ACCESS_WRITE_DAC);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_SETATTR);
}

int pkm_kacs_file_chown(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	ret = pkm_kacs_check_file_snapshot_grant(file,
						 KACS_ACCESS_WRITE_OWNER);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_SETATTR);
}

int pkm_kacs_file_utimens(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(
		file, KACS_FILE_WRITE_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_SETATTR);
}

int pkm_kacs_file_fileattr_get(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	ret = pkm_kacs_check_file_snapshot_grant(
		file, KACS_FILE_READ_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_FILEATTR_GET);
}

int pkm_kacs_file_fileattr_set(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	ret = pkm_kacs_check_file_snapshot_grant(
		file, KACS_FILE_WRITE_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_FILEATTR_SET);
}

int pkm_kacs_path_fileattr_set(const struct path *path)
{
	struct inode *inode;
	int ret;

	if (!path || !path->dentry)
		return -EACCES;

	inode = d_inode(path->dentry);
	if (!inode)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return 0;

	ret = pkm_kacs_authorize_path_metadata_access(
		path, KACS_FILE_WRITE_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_inode_metadata_decision(
		inode, PKM_KACS_METADATA_OP_FILEATTR_SET);
}

void pkm_kacs_path_end_metadata(const struct path *path)
{
	pkm_kacs_inode_end_metadata(path && path->dentry ?
					    d_inode(path->dentry) :
					    NULL);
}

int pkm_kacs_file_listxattr(struct file *file)
{
	if (!file)
		return -EACCES;
	return 0;
}

int pkm_kacs_path_access(const struct path *path, int mode)
{
	u32 desired_access = 0;

	if (!path || !path->dentry)
		return -EACCES;
	if ((mode & ~(MAY_READ | MAY_WRITE | MAY_EXEC)) != 0)
		return -EINVAL;

	if ((mode & MAY_READ) != 0)
		desired_access |= KACS_FILE_READ_DATA;
	if ((mode & MAY_WRITE) != 0)
		desired_access |= KACS_FILE_WRITE_DATA;
	if ((mode & MAY_EXEC) != 0)
		desired_access |= KACS_FILE_EXECUTE;
	if (desired_access == 0)
		desired_access = KACS_FILE_READ_ATTRIBUTES;

	return pkm_kacs_authorize_path_metadata_access(path, desired_access);
}
