// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kacs_stratafs.h>
#include <linux/mnt_idmapping.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/xattr.h>

#include <pkm/sd.h>

#include "access_check.h"
#include "copy_up.h"
#include "file_access.h"
#include "file_metadata.h"
#include "file_sd_cache.h"
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
	if (pkm_kacs_copy_up_allows_path_getattr(path))
		return 0;

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
	if (pkm_kacs_copy_up_allows_setattr(dentry))
		return 0;

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
	if (pkm_kacs_copy_up_allows_getattr(dentry))
		return 0;

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
	if (pkm_kacs_copy_up_allows_setattr(dentry))
		return 0;

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
	if (pkm_kacs_copy_up_allows_getxattr(dentry, name))
		return 0;

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
	if (is_posix_acl_xattr(name)) {
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_ACL, -EACCES);
		return -EACCES;
	}
	if (pkm_kacs_is_file_capability_xattr(name)) {
		if (pkm_kacs_copy_up_allows_capability_setxattr(dentry))
			return 0;
		pkm_kacs_consume_file_metadata_decision(
			dentry ? d_inode(dentry) : NULL,
			PKM_KACS_METADATA_OP_SETXATTR);
		trace_kacs_metadata(dentry ? d_inode(dentry) : NULL,
				    PKM_KACS_METADATA_OP_SETXATTR, 0,
				    KACS_META_CAPS_XATTR, -EPERM);
		return -EPERM;
	}
	if (!strcmp(name, STRATAFS_STAGING_XATTR)) {
		if (pkm_kacs_copy_up_allows_setxattr(dentry, name))
			return 0;
		return -EPERM;
	}
	if (pkm_kacs_copy_up_allows_setxattr(dentry, name))
		return 0;
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
	if (!strcmp(name, STRATAFS_STAGING_XATTR)) {
		if (pkm_kacs_copy_up_allows_setxattr(dentry, name))
			return 0;
		return -EPERM;
	}
	if (pkm_kacs_copy_up_allows_setxattr(dentry, name))
		return 0;
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
	if (pkm_kacs_copy_up_allows_listxattr(dentry))
		return 0;

	pkm_kacs_consume_file_metadata_decision(d_inode(dentry),
						PKM_KACS_METADATA_OP_NONE);

	return 0;
}

/*
 * Capture the effective security descriptor of the object being copied up.
 *
 * `src` is the overlay dentry, so this reads through to whichever layer
 * actually answers: the lower's stored xattr, or the descriptor KACS
 * synthesized for it on an SD-less mount. Either is the descriptor the object
 * had a moment ago, and therefore the one it must still have afterwards.
 */
static int pkm_kacs_copy_up_capture_sd(struct dentry *src, u8 **bytes_out,
				       size_t *len_out)
{
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_security *inode_sec;
	struct vfsmount mnt = {};
	struct path path = {};
	struct file anchor = {};
	struct inode *inode;
	u8 *copy;
	long ret;

	if (!src || !bytes_out || !len_out)
		return -EINVAL;
	*bytes_out = NULL;
	*len_out = 0;

	inode = d_inode(src);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return -EOPNOTSUPP;

	/*
	 * Resolving an SD needs a dentry-shaped anchor: the xattr read
	 * addresses a dentry, and missing-SD synthesis walks d_parent. The hook
	 * gives us the dentry but not the mount, so the anchor carries a zeroed
	 * vfsmount -- the same shape
	 * pkm_kacs_inode_ensure_effective_cache_by_inode() builds for the
	 * inode-only callers.
	 */
	mnt.mnt_root = src;
	mnt.mnt_sb = inode->i_sb;
	mnt.mnt_idmap = &nop_mnt_idmap;
	path.mnt = &mnt;
	path.dentry = src;
	pkm_kacs_init_path_anchor_file(&anchor, &path);

	inode_sec = pkm_kacs_inode(inode);
	ret = pkm_kacs_inode_ensure_effective_cache(&anchor, inode_sec);
	if (ret)
		return (int)ret;

	cache = pkm_kacs_inode_sd_cache_get_current(inode, inode_sec);
	if (!cache)
		return -EACCES;
	if (cache->state != PKM_KACS_INODE_SD_VALID || !cache->bytes ||
	    cache->len == 0 || cache->len > PKM_KACS_MAX_SD_BYTES) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -EACCES;
	}

	copy = kmemdup(cache->bytes, cache->len, GFP_NOFS);
	if (!copy) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}
	*bytes_out = copy;
	*len_out = cache->len;
	pkm_kacs_inode_sd_cache_free(cache);
	return 0;
}

/*
 * Carry the copied-up object's own descriptor onto the upper inode, instead of
 * letting it inherit one.
 *
 * Without this the upper copy takes whatever inheritance computes from the
 * directory overlayfs creates it in -- which is the workdir, not even the
 * destination parent. A file with a deliberately narrow descriptor would be
 * widened by the act of writing to it, and a deliberately permissive one
 * narrowed, in both cases changing what *other* principals may do as a side
 * effect of somebody else's write.
 *
 * The descriptor rides on the cred because that is the lifetime the kernel
 * already provides: overlayfs installs the cred we return with
 * override_creds() around exactly one create and reverts it through a scope
 * guard on every exit path (fs/overlayfs/copy_up.c). See the field comment on
 * struct pkm_kacs_cred_security.
 *
 * This is the half of the SELinux pattern that was missing. Its
 * inode_copy_up hook stashes the source label in the cred (create_sid) and its
 * inode_copy_up_xattr then discards the label xattr *because* the cred already
 * carries it. KACS had the discard without the carry.
 *
 * A source whose descriptor cannot be read fails the copy-up. Proceeding would
 * mean silently stamping the workdir's descriptor on it, which is the failure
 * this exists to prevent, and it would be invisible afterwards.
 */
int pkm_kacs_inode_copy_up(struct dentry *src, struct cred **new)
{
	struct pkm_kacs_cred_security *sec;
	struct cred *new_creds;
	u8 *sd_bytes = NULL;
	size_t sd_len = 0;
	int ret;

	if (!src || !new)
		return -EINVAL;

	ret = pkm_kacs_copy_up_capture_sd(src, &sd_bytes, &sd_len);
	/* An unmanaged mount has no descriptor to preserve. */
	if (ret == -EOPNOTSUPP)
		return 0;
	if (ret)
		return ret;

	new_creds = *new;
	if (!new_creds) {
		new_creds = prepare_creds();
		if (!new_creds) {
			kfree(sd_bytes);
			return -ENOMEM;
		}
	}

	if (!new_creds->security) {
		if (new_creds != *new)
			put_cred(new_creds);
		kfree(sd_bytes);
		return -EACCES;
	}

	sec = pkm_kacs_cred(new_creds);
	kfree(sec->copy_up_sd);
	sec->copy_up_sd = sd_bytes;
	sec->copy_up_sd_len = sd_len;
	*new = new_creds;
	return 0;
}

/*
 * The descriptor pkm_kacs_inode_copy_up() left for the create it is wrapping,
 * or false when this create is not an overlayfs copy-up.
 *
 * The bytes stay owned by the cred, which outlives the create and is freed by
 * pkm_kacs_cred_free().
 */
bool pkm_kacs_copy_up_cred_sd(const u8 **bytes_out, size_t *len_out)
{
	const struct pkm_kacs_cred_security *sec;
	const struct cred *cred;

	if (!bytes_out || !len_out)
		return false;

	cred = current_cred();
	if (!cred || !cred->security)
		return false;

	sec = pkm_kacs_cred(cred);
	if (!sec->copy_up_sd || sec->copy_up_sd_len == 0)
		return false;

	*bytes_out = sec->copy_up_sd;
	*len_out = sec->copy_up_sd_len;
	return true;
}

/*
 * On overlayfs copy-up, decline to copy the canonical SD xattr -- the
 * descriptor is carried by pkm_kacs_inode_copy_up() above instead, on the cred
 * overlayfs creates the upper inode under, so copying the xattr as well would
 * only overwrite it with the same answer.
 *
 * It could not be copied here in any case: the lower read and upper write
 * would each hit the deny in inode_getxattr / inode_setxattr, because
 * canonical SD xattrs are not userspace-writable and SD mutation is the
 * dedicated syscall's job. That is a statement about this path, not about the
 * descriptor being unpreservable.
 *
 * -ECANCELED is the overlayfs "discard this xattr" signal; -EOPNOTSUPP (the
 * hook default) leaves every other xattr to the normal copy. This is the same
 * pattern SELinux and Smack use for their own label xattrs, and -- since the
 * cred now carries the descriptor -- for the same reason they do.
 */
int pkm_kacs_inode_copy_up_xattr(struct dentry *src, const char *name)
{
	if (src && pkm_kacs_is_canonical_sd_xattr(d_inode(src), name))
		return -ECANCELED; /* discard: the cred carries it instead */

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
	/*
	 * Resolve the effective descriptor rather than reporting only a cache
	 * that some earlier operation happens to have warmed.
	 *
	 * This hook is how a stacking filesystem reads the SD of the real inode
	 * beneath it: vfs_getxattr() routes every security.* name through
	 * security_inode_getsecurity() before the lower filesystem's own xattr
	 * handler ever sees it, so overlayfs's ovl_xattr_get() and StrataFS's
	 * stratafs_xattr_get() both land here. Answering -EOPNOTSUPP because
	 * the cache is merely cold makes the VFS fall through to the raw
	 * on-disk xattr -- which on a SYNTHESIZE mount does not exist. The
	 * stacker then sees a file with no SD and, under DENY_MISSING, locks it.
	 *
	 * That made the answer depend on whether anything had touched this
	 * inode first, which is why it surfaced as "symlinks are denied and
	 * nothing else is": overlayfs runs inode_permission on every directory
	 * it walks and probes trusted.overlay.metacopy on every regular file it
	 * looks up -- both of which warm the real inode -- but touches a
	 * symlink's real inode only when something actually traverses it.
	 *
	 * Resolving here costs nothing on a mount that stores its descriptors:
	 * the resolve reads the same xattr the fall-through would have.
	 *
	 * Only one layer of a stack ever performs the ancestor walk that
	 * synthesis needs -- a layer walks only when the layer below answered
	 * MISSING, which means that layer did not walk -- so the recursion here
	 * costs O(1) frames per stacking level on top of the single walk that
	 * PKM_KACS_MAX_SD_SYNTHESIS_DEPTH already bounds. The depth cap below is
	 * belt-and-braces against a filesystem stack deeper than Linux's own
	 * FILESYSTEM_MAX_STACK_DEPTH; past it we fail back to the old
	 * fall-through rather than risk the kernel stack.
	 */
	if (current && current->security &&
	    pkm_kacs_task(current)->internal_sd_read_depth > 8) {
		trace_kacs_metadata(inode, PKM_KACS_METADATA_OP_NONE, 0,
				    KACS_META_GETSECURITY, -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}
	if (pkm_kacs_inode_ensure_effective_cache_by_inode(inode, sec)) {
		trace_kacs_metadata(inode, PKM_KACS_METADATA_OP_NONE, 0,
				    KACS_META_GETSECURITY, -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}
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
	task_sec->metadata_decision.file = NULL;
	task_sec->metadata_decision.op_class = PKM_KACS_METADATA_OP_NONE;
	task_sec->metadata_decision.active = 0;
}

int pkm_kacs_stratafs_rebind_metadata_decision(
	const struct inode *outer, const struct inode *provider)
{
	struct pkm_kacs_task_security *task_sec;

	if (!outer || !provider || !current || !current->security)
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (!task_sec->metadata_decision.active)
		return 0;
	if (task_sec->metadata_decision.inode != outer)
		return -EACCES;

	/*
	 * VFS file-metadata entry points have already checked the immutable
	 * grant on the outer descriptor.  Rebinding only its outstanding,
	 * single-use decision preserves that authority across the stacking
	 * boundary; the provider hook consumes it immediately.
	 */
	task_sec->metadata_decision.inode = provider;
	return 0;
}

void pkm_kacs_stratafs_end_metadata_decision(const struct inode *provider)
{
	struct pkm_kacs_task_security *task_sec;

	if (!provider || !current || !current->security)
		return;
	task_sec = pkm_kacs_task(current);
	if (task_sec->metadata_decision.active &&
	    task_sec->metadata_decision.inode == provider)
		pkm_kacs_clear_file_metadata_decision(task_sec);
}

struct file *
pkm_kacs_stratafs_metadata_file(const struct inode *outer)
{
	struct pkm_kacs_task_security *task_sec;
	struct file *file;

	if (!outer || !current || !current->security)
		return NULL;
	task_sec = pkm_kacs_task(current);
	file = task_sec->metadata_decision.file;
	if (!task_sec->metadata_decision.active ||
	    task_sec->metadata_decision.inode != outer || !file ||
	    file_inode(file) != outer)
		return NULL;
	return file;
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
	task_sec->metadata_decision.file = file;
	task_sec->metadata_decision.op_class = op_class;
	task_sec->metadata_decision.active = 1;
	return 0;
}

int pkm_kacs_file_truncate_metadata(struct file *file)
{
	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_SETATTR);
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
	task_sec->metadata_decision.file = NULL;
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
	/* StrataFS must retarget the one-shot decision to its provider hook. */
	if (matched && inode->i_sb &&
	    inode->i_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return true;
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
					      bool reject_capability,
					      u8 op_class)
{
	enum pkm_kacs_copy_up_file_access copy_up;
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
	if (reject_capability && pkm_kacs_is_file_capability_xattr(name))
		return -EPERM;
	copy_up = pkm_kacs_copy_up_file_metadata(file, write_operation);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
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
	return pkm_kacs_check_file_xattr_snapshot(
		file, name, KACS_FILE_WRITE_EA, true, true,
		PKM_KACS_METADATA_OP_SETXATTR);
}

int pkm_kacs_file_sd_xattr_get(struct file *file, const char *name)
{
	return pkm_kacs_check_file_xattr_snapshot(
		file, name, KACS_FILE_READ_EA, false, false,
		PKM_KACS_METADATA_OP_GETXATTR);
}

int pkm_kacs_file_sd_xattr_remove(struct file *file, const char *name)
{
	return pkm_kacs_check_file_xattr_snapshot(
		file, name, KACS_FILE_WRITE_EA, true, false,
		PKM_KACS_METADATA_OP_SETXATTR);
}

int pkm_kacs_file_getattr(struct file *file)
{
	enum pkm_kacs_copy_up_file_access copy_up;
	int ret;

	if (!file)
		return -EACCES;
	copy_up = pkm_kacs_copy_up_file_metadata(file, false);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
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
	if (pkm_kacs_copy_up_file_is_internal(file))
		return -EACCES;
	return pkm_kacs_check_file_snapshot_grant(
		file, KACS_FILE_READ_ATTRIBUTES);
}

int pkm_kacs_file_chmod(struct file *file)
{
	enum pkm_kacs_copy_up_file_access copy_up;
	int ret;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	copy_up = pkm_kacs_copy_up_file_metadata(file, true);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(file,
						 KACS_ACCESS_WRITE_DAC);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_SETATTR);
}

int pkm_kacs_file_chown(struct file *file)
{
	enum pkm_kacs_copy_up_file_access copy_up;
	int ret;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	copy_up = pkm_kacs_copy_up_file_metadata(file, true);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(file,
						 KACS_ACCESS_WRITE_OWNER);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_SETATTR);
}

int pkm_kacs_file_utimens(struct file *file)
{
	enum pkm_kacs_copy_up_file_access copy_up;
	int ret;

	if (!file)
		return -EACCES;
	copy_up = pkm_kacs_copy_up_file_metadata(file, true);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
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
	enum pkm_kacs_copy_up_file_access copy_up;
	int ret;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	copy_up = pkm_kacs_copy_up_file_metadata(file, false);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(
		file, KACS_FILE_READ_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_FILEATTR_GET);
}

int pkm_kacs_file_fileattr_set(struct file *file)
{
	enum pkm_kacs_copy_up_file_access copy_up;
	int ret;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	copy_up = pkm_kacs_copy_up_file_metadata(file, true);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
		return -EACCES;
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
	enum pkm_kacs_copy_up_file_access copy_up;

	if (!file)
		return -EACCES;
	copy_up = pkm_kacs_copy_up_file_metadata(file, false);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
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
