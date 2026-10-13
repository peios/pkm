// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kacs_stratafs.h>
#include <linux/kernel.h>
#include <linux/lockdep.h>
#include <linux/mnt_idmapping.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/xattr.h>

#include "../kmes/kmes.h"
#include "access_check.h"
#include "file_access.h"
#include "file_sd_cache.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

#ifdef CONFIG_SECURITY_PKM_KUNIT
#include <kunit/test.h>
#include <linux/debug_locks.h>
#endif

static long pkm_kacs_superblock_synthesis_snapshot(const struct super_block *sb,
						   const u8 **sd_ptr_out,
						   size_t *sd_len_out,
						   u32 *policy, u32 *generation)
{
	struct pkm_kacs_superblock_security *sec;
	const u8 *copy;

	if (sd_ptr_out)
		*sd_ptr_out = NULL;
	if (sd_len_out)
		*sd_len_out = 0;
	*policy = pkm_kacs_superblock_mount_policy(sb);
	*generation = pkm_kacs_superblock_policy_generation(sb);
	if (!sb || !sd_ptr_out || !sd_len_out || !sb->s_security)
		return 0;

	sec = pkm_kacs_sb(sb);
	mutex_lock(&sec->lock);
	*policy = pkm_kacs_superblock_mount_policy(sb);
	*generation = pkm_kacs_superblock_policy_generation(sb);
	if (!sec->template_sd_bytes || sec->template_sd_len == 0) {
		mutex_unlock(&sec->lock);
		return 0;
	}

	copy = kmemdup(sec->template_sd_bytes, sec->template_sd_len, GFP_KERNEL);
	if (!copy) {
		mutex_unlock(&sec->lock);
		return -ENOMEM;
	}

	*sd_ptr_out = copy;
	*sd_len_out = sec->template_sd_len;
	mutex_unlock(&sec->lock);
	return 0;
}

long pkm_kacs_missing_file_sd_policy_result(
	const struct super_block *sb,
	struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct pkm_kacs_inode_sd_cache *cache;
	u32 policy;

	if (!cache_out)
		return -EINVAL;

	policy = pkm_kacs_superblock_mount_policy(sb);
	switch (policy) {
	case KACS_MOUNT_POLICY_DENY_MISSING:
	case KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL:
	case KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT:
		cache = pkm_kacs_inode_sd_cache_alloc_ex(
			PKM_KACS_INODE_SD_MISSING, NULL, 0,
			PKM_KACS_INODE_SD_SOURCE_MISSING,
			pkm_kacs_superblock_policy_generation(sb));
		if (!cache)
			return -ENOMEM;
		*cache_out = cache;
		return 0;
	case KACS_MOUNT_POLICY_UNMANAGED:
	default:
		return -EOPNOTSUPP;
	}
}

static u8 pkm_kacs_inode_sd_default_source(u8 state)
{
	switch (state) {
	case PKM_KACS_INODE_SD_VALID:
		return PKM_KACS_INODE_SD_SOURCE_XATTR;
	case PKM_KACS_INODE_SD_MISSING:
		return PKM_KACS_INODE_SD_SOURCE_MISSING;
	case PKM_KACS_INODE_SD_CORRUPT:
	default:
		return PKM_KACS_INODE_SD_SOURCE_CORRUPT;
	}
}

struct pkm_kacs_inode_sd_cache *pkm_kacs_inode_sd_cache_alloc_ex(
	u8 state, const u8 *bytes, size_t len, u8 source,
	u32 policy_generation)
{
	struct pkm_kacs_inode_sd_cache *cache;

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache)
		return NULL;

	refcount_set(&cache->refs, 1);
	if (state == PKM_KACS_INODE_SD_VALID) {
		if (!bytes || len == 0 ||
		    kacs_rust_parse_file_sd_layout(bytes, len,
						   &cache->layout) != 0) {
			kfree(cache);
			return NULL;
		}
	}

	cache->state = state;
	cache->bytes = bytes;
	cache->len = len;
	cache->source = source;
	cache->policy_generation = policy_generation;
	return cache;
}

struct pkm_kacs_inode_sd_cache *pkm_kacs_inode_sd_cache_alloc(
	u8 state, const u8 *bytes, size_t len)
{
	return pkm_kacs_inode_sd_cache_alloc_ex(
		state, bytes, len, pkm_kacs_inode_sd_default_source(state), 0);
}

bool pkm_kacs_inode_sd_cache_current(const struct super_block *sb,
					    const struct pkm_kacs_inode_sd_cache *cache)
{
	if (!cache)
		return false;

	switch (cache->source) {
	case PKM_KACS_INODE_SD_SOURCE_MISSING:
	case PKM_KACS_INODE_SD_SOURCE_SYNTHETIC:
	case PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING:
		return cache->policy_generation ==
		       pkm_kacs_superblock_policy_generation(sb);
	default:
		return true;
	}
}

/*
 * A provider's descriptor can change through a stratum without notifying the
 * outer inode (PEI-253). Re-read on each new check, including missing/corrupt
 * entries and entries installed by set_sd. The root can also change provider
 * without notification (PEI-575). This does not change a file's frozen grant.
 */
static bool pkm_kacs_inode_sd_cache_rereads_each_time(
	const struct inode *inode)
{
	return inode->i_sb->s_magic == STRATAFS_SUPER_MAGIC;
}

static void pkm_kacs_inode_sd_cache_destroy(
	struct pkm_kacs_inode_sd_cache *cache)
{
	if (!cache)
		return;
	if (cache->bytes)
		pkm_kacs_free((void *)cache->bytes);
	kfree(cache);
}

void pkm_kacs_inode_sd_cache_free(struct pkm_kacs_inode_sd_cache *cache)
{
	if (!cache)
		return;
	if (!refcount_dec_and_test(&cache->refs))
		return;

	pkm_kacs_inode_sd_cache_destroy(cache);
}

static void pkm_kacs_inode_sd_cache_free_rcu(struct rcu_head *rcu)
{
	struct pkm_kacs_inode_sd_cache *cache;

	cache = container_of(rcu, struct pkm_kacs_inode_sd_cache, rcu);
	pkm_kacs_inode_sd_cache_free(cache);
}

bool pkm_kacs_inode_try_publish_sd_cache(
	struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache *expected,
	struct pkm_kacs_inode_sd_cache *new_cache)
{
	struct pkm_kacs_inode_sd_cache *old_cache;

	lockdep_assert_held(&sec->lock);
	old_cache = cmpxchg_release(
		(struct pkm_kacs_inode_sd_cache **)&sec->sd_cache, expected,
		new_cache);
	if (old_cache != expected)
		return false;
	sec->sd_cache_epoch++;
	return true;
}

void pkm_kacs_inode_replace_sd_cache_locked(
	struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache *new_cache)
{
	struct pkm_kacs_inode_sd_cache *old_cache;

	old_cache = rcu_dereference_protected(sec->sd_cache,
					      lockdep_is_held(&sec->lock));
	sec->sd_cache_epoch++;
	rcu_assign_pointer(sec->sd_cache, new_cache);
	if (old_cache)
		call_rcu(&old_cache->rcu, pkm_kacs_inode_sd_cache_free_rcu);
}

void pkm_kacs_stratafs_invalidate_sd_cache(struct inode *inode)
{
	struct pkm_kacs_inode_security *sec;

	if (!inode || !inode->i_security ||
	    inode->i_sb->s_magic != STRATAFS_SUPER_MAGIC)
		return;
	sec = pkm_kacs_inode(inode);
	mutex_lock(&sec->lock);
	pkm_kacs_inode_replace_sd_cache_locked(sec, NULL);
	mutex_unlock(&sec->lock);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static ssize_t pkm_kacs_kunit_fake_getxattr_locked(
	struct pkm_kacs_inode_security *sec, void *buffer, size_t size)
{
	if (!sec->kunit_fake_xattr_enabled)
		return -EOPNOTSUPP;
	if (sec->kunit_fake_xattr_get_errno)
		return sec->kunit_fake_xattr_get_errno;
	if (!sec->kunit_fake_xattr_bytes || sec->kunit_fake_xattr_len == 0)
		return -ENODATA;
	if (!buffer)
		return (ssize_t)sec->kunit_fake_xattr_len;
	if (size < sec->kunit_fake_xattr_len)
		return -ERANGE;

	memcpy(buffer, sec->kunit_fake_xattr_bytes, sec->kunit_fake_xattr_len);
	return (ssize_t)sec->kunit_fake_xattr_len;
}

long pkm_kacs_kunit_fake_setxattr_locked(
	struct pkm_kacs_inode_security *sec, const u8 *sd_bytes, size_t sd_len)
{
	const u8 *copied_bytes;

	if (!sec->kunit_fake_xattr_enabled)
		return -EOPNOTSUPP;
	if (sec->kunit_fake_xattr_fail_set)
		return -EIO;
	if (!sd_bytes || sd_len == 0)
		return -EINVAL;

	copied_bytes = kmemdup(sd_bytes, sd_len, GFP_KERNEL);
	if (!copied_bytes)
		return -ENOMEM;

	kfree(sec->kunit_fake_xattr_bytes);
	sec->kunit_fake_xattr_bytes = copied_bytes;
	sec->kunit_fake_xattr_len = sd_len;
	return 0;
}
#endif

/*
 * kacs.descriptor.rejected: the subject whose access made KACS read the
 * descriptor, the file by inode and device, the stored attribute's length,
 * and outcome.reason "corrupt".
 *
 * object.file.path is left out. The descriptor read is reached through
 * path-anchor files, and the inode_getsecurity route builds its anchor on a
 * stack vfsmount that is not part of any mount tree, so d_path here could
 * walk a struct mount that does not exist. The inode and device name the
 * file instead, for as long as its filesystem stays mounted.
 */
static void pkm_kacs_emit_corrupt_sd_event(const struct inode *inode,
					   ssize_t sd_len)
{
	u32 pip_type = 0;
	u32 pip_trust = 0;

	if (!pkm_kmes_event_enabled(PKM_KMES_EV_KACS_DESCRIPTOR_REJECTED))
		return;
	if (pkm_kacs_current_pip_context(&pip_type, &pip_trust)) {
		pip_type = 0;
		pip_trust = 0;
	}
	(void)kacs_rust_emit_descriptor_rejected(
		pkm_kacs_current_effective_token_ptr(), (u64)inode->i_ino,
		(u64)new_encode_dev(inode->i_sb->s_dev),
		sd_len > 0 ? (u64)sd_len : 0, pip_type, pip_trust);
}

static long pkm_kacs_inode_alloc_corrupt_sd_cache(
	const struct inode *inode, ssize_t sd_len,
	struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct pkm_kacs_inode_sd_cache *cache;

	if (!cache_out)
		return -EINVAL;

	cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_CORRUPT, NULL,
					      0);
	if (!cache)
		return -ENOMEM;

	pkm_kacs_emit_corrupt_sd_event(inode, sd_len);
	*cache_out = cache;
	return 0;
}

static long pkm_kacs_inode_read_sd_xattr(struct file *file,
					 struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct dentry *dentry;
	struct inode *inode;
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	const char *name;
	u8 *bytes = NULL;
	ssize_t len;
	int ret;

	if (!file || !cache_out)
		return -EINVAL;

	dentry = file_dentry(file);
	inode = file_inode(file);
	if (!dentry || !inode)
		return -EACCES;
	sec = inode->i_security ? pkm_kacs_inode(inode) : NULL;

	name = pkm_kacs_inode_sd_xattr_name(inode);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec && sec->kunit_fake_xattr_enabled) {
		mutex_lock(&sec->lock);
		len = pkm_kacs_kunit_fake_getxattr_locked(sec, NULL, 0);
		mutex_unlock(&sec->lock);
	}
	else
#endif
	{
		/*
		 * __vfs_getxattr skips security_inode_getxattr for *us*, but
		 * stacking FSes (overlayfs) re-enter vfs_getxattr on the real
		 * inode inside their xattr handler, which fires our own hook
		 * again. Mark the task so the hook recognises the internal
		 * read and allows the canonical SD xattr.
		 */
		if (current && current->security)
			pkm_kacs_task(current)->internal_sd_read_depth++;
		len = __vfs_getxattr(dentry, inode, name, NULL, 0);
		if (current && current->security)
			pkm_kacs_task(current)->internal_sd_read_depth--;
	}
	/*
	 * ENOENT is ntfs3's answer for an inode with no $Secure entry (its
	 * descriptor is an inline attribute the driver never reads): no
	 * descriptor, so the mount's missing-SD policy applies (PEI-715).
	 */
	if (len == -ENODATA || len == -EOPNOTSUPP || len == -ENOENT)
		return pkm_kacs_missing_file_sd_policy_result(inode->i_sb,
							      cache_out);
	if (len < 0)
		return len;
	if (len == 0 || len > PKM_KACS_MAX_SD_BYTES) {
		trace_kacs_sd_cache_corrupt(inode,
					    KACS_SDC_CORRUPT_EMPTY_OR_OVERSIZE,
					    (u32)len);
		return pkm_kacs_inode_alloc_corrupt_sd_cache(inode, len,
							     cache_out);
	}

	bytes = pkm_kacs_zalloc(len);
	if (!bytes)
		return -ENOMEM;

#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec && sec->kunit_fake_xattr_enabled) {
		mutex_lock(&sec->lock);
		ret = pkm_kacs_kunit_fake_getxattr_locked(sec, bytes, len);
		mutex_unlock(&sec->lock);
	}
	else
#endif
	{
		if (current && current->security)
			pkm_kacs_task(current)->internal_sd_read_depth++;
		ret = __vfs_getxattr(dentry, inode, name, bytes, len);
		if (current && current->security)
			pkm_kacs_task(current)->internal_sd_read_depth--;
	}
	if (ret < 0) {
		pkm_kacs_free(bytes);
		return ret;
	}
	if (ret != len || kacs_rust_validate_stored_sd_bytes(bytes, len) != 0) {
		pkm_kacs_free(bytes);
		trace_kacs_sd_cache_corrupt(inode, KACS_SDC_CORRUPT_VALIDATE_FAIL,
					    (u32)len);
		return pkm_kacs_inode_alloc_corrupt_sd_cache(inode, len,
							     cache_out);
	}

	cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_VALID, bytes,
					      len);
	if (!cache) {
		kvfree(bytes);
		return -ENOMEM;
	}
	*cache_out = cache;
	return 0;
}

static long pkm_kacs_inode_get_or_populate_cache_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct pkm_kacs_inode_sd_cache *cache, *fresh;
	struct inode *inode = file_inode(file);
	u32 generation;
	u64 epoch;
	long ret;

	if (!inode)
		return -EACCES;
	lockdep_assert_held(&sec->lock);
retry:
	cache = rcu_dereference_protected(sec->sd_cache,
					  lockdep_is_held(&sec->lock));
	if (cache && pkm_kacs_inode_sd_cache_current(inode->i_sb, cache) &&
	    !pkm_kacs_inode_sd_cache_rereads_each_time(inode)) {
		*cache_out = cache;
		return 0;
	}

	/*
	 * A stacking filesystem can resolve a lower inode's SD from its xattr
	 * handler. Never carry this inode's mutex into that resolution. Pin
	 * the expected entry across the unlocked read so pointer comparison
	 * cannot suffer ABA. The epoch also detects NULL -> NULL invalidation
	 * and an initially empty slot populated then cleared during the read.
	 * Keep the old entry visible until the replacement is ready.
	 */
	if (cache)
		refcount_inc(&cache->refs);
	generation = pkm_kacs_superblock_policy_generation(inode->i_sb);
	epoch = sec->sd_cache_epoch;
	fresh = NULL;
	mutex_unlock(&sec->lock);
	ret = pkm_kacs_inode_read_sd_xattr(file, &fresh);
	mutex_lock(&sec->lock);
	if (rcu_dereference_protected(sec->sd_cache,
				      lockdep_is_held(&sec->lock)) != cache ||
	    epoch != sec->sd_cache_epoch ||
	    generation != pkm_kacs_superblock_policy_generation(inode->i_sb)) {
		pkm_kacs_inode_sd_cache_free(fresh);
		pkm_kacs_inode_sd_cache_free(cache);
		goto retry;
	}
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		return ret;
	}
	if (!pkm_kacs_inode_try_publish_sd_cache(sec, cache, fresh)) {
		pkm_kacs_inode_sd_cache_free(fresh);
		pkm_kacs_inode_sd_cache_free(cache);
		goto retry;
	}
	if (cache)
		call_rcu(&cache->rcu, pkm_kacs_inode_sd_cache_free_rcu);
	pkm_kacs_inode_sd_cache_free(cache);
	*cache_out = fresh;
	return 0;
}

/*
 * Preserve the documented missing-SD synthesis depth bound. Ancestors are
 * resolved without holding descendant SD mutexes; the limit bounds work and
 * recursion, rather than permitting a stack of nested mutex acquisitions.
 */
#define PKM_KACS_MAX_SD_SYNTHESIS_DEPTH 32U

long pkm_kacs_inode_resolve_effective_cache_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out, unsigned int depth);
static void pkm_kacs_inode_queue_sd_persist(
	struct file *file, struct pkm_kacs_inode_security *sec);

static long pkm_kacs_synthesize_missing_file_sd(struct file *file,
						struct pkm_kacs_inode_sd_cache **cache_out,
						unsigned int depth)
{
	struct pkm_kacs_inode_sd_cache *new_cache = NULL;
	struct pkm_kacs_inode_sd_cache *parent_cache = NULL;
	struct pkm_kacs_inode_security *parent_sec;
	struct dentry *dentry;
	struct dentry *parent_dentry = NULL;
	struct inode *inode;
	struct inode *parent_inode;
	struct file *parent_file = NULL;
	const u8 *template_sd_ptr = NULL;
	const u8 *parent_sd_ptr = NULL;
	const u8 *new_sd_bytes = NULL;
	size_t template_sd_len = 0;
	size_t parent_sd_len = 0;
	size_t new_sd_len = 0;
	u32 policy_generation;
	u32 mount_policy;
	long ret;

	if (!file || !cache_out)
		return -EINVAL;

	/* KC-00: bound the parent-to-root synthesis recursion (fail closed). */
	if (depth >= PKM_KACS_MAX_SD_SYNTHESIS_DEPTH)
		return -EACCES;

	inode = file_inode(file);
	dentry = file_dentry(file);
	if (!inode || !dentry)
		return -EACCES;

	ret = pkm_kacs_superblock_synthesis_snapshot(inode->i_sb,
						     &template_sd_ptr,
						     &template_sd_len,
						     &mount_policy,
						     &policy_generation);
	if (ret)
		return ret;
	if (mount_policy != KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL &&
	    mount_policy != KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT) {
		ret = -EACCES;
		goto out_template;
	}

	parent_dentry = dget_parent(dentry);
	if (parent_dentry && parent_dentry != dentry) {
		struct path parent_path;

		parent_inode = d_inode(parent_dentry);
		if (!parent_inode || !parent_inode->i_security) {
			ret = -EACCES;
			goto out_template;
		}

		parent_file = kzalloc(sizeof(*parent_file), GFP_KERNEL);
		if (!parent_file) {
			ret = -ENOMEM;
			goto out_template;
		}
		parent_sec = pkm_kacs_inode(parent_inode);
		parent_file->f_inode = parent_inode;
		parent_path = file->f_path;
		parent_path.dentry = parent_dentry;
		*(struct path *)&parent_file->f_path = parent_path;

		mutex_lock(&parent_sec->lock);
		ret = pkm_kacs_inode_resolve_effective_cache_locked(
			parent_file, parent_sec, &parent_cache, depth + 1);
		if (ret) {
			mutex_unlock(&parent_sec->lock);
			goto out_template;
		}
		if (parent_cache->state != PKM_KACS_INODE_SD_VALID ||
		    !parent_cache->bytes || parent_cache->len == 0) {
			mutex_unlock(&parent_sec->lock);
			ret = -EACCES;
			goto out_template;
		}
		refcount_inc(&parent_cache->refs);
		mutex_unlock(&parent_sec->lock);
		parent_sd_ptr = parent_cache->bytes;
		parent_sd_len = parent_cache->len;
		ret = kacs_rust_synthesize_file_sd(
			parent_sd_ptr, parent_sd_len, template_sd_ptr,
			template_sd_len, S_ISDIR(inode->i_mode), &new_sd_bytes,
			&new_sd_len);
		pkm_kacs_inode_sd_cache_free(parent_cache);
		if (ret)
			goto out_template;
	} else {
		ret = kacs_rust_synthesize_file_sd(
			NULL, 0, template_sd_ptr, template_sd_len,
			S_ISDIR(inode->i_mode), &new_sd_bytes, &new_sd_len);
		if (ret)
			goto out_template;
	}

	/*
	 * Both synthesize classes cache the result in the inode blob and tag it
	 * with the policy generation so a later mount-policy/template change
	 * discards and repopulates it. PERSISTENT additionally owes a write-back
	 * to the xattr, but a metadata-hook caller may already hold i_rwsem.
	 * Writing here can self-deadlock, so PERSISTENT marks
	 * the entry SYNTHETIC_PENDING and defers the write-back to a task_work
	 * (pkm_kacs_inode_queue_sd_persist) queued by the caller after sec->lock
	 * is dropped; that work runs at return-to-userspace with no FACS/VFS
	 * locks held. The decision is always correct from the cached SD the
	 * instant synthesis completes; the on-disk xattr is a recomputable
	 * cache, so a missed write-back simply re-synthesizes identically.
	 */
	new_cache = pkm_kacs_inode_sd_cache_alloc_ex(
		PKM_KACS_INODE_SD_VALID, new_sd_bytes, new_sd_len,
		mount_policy == KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT ?
			PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING :
			PKM_KACS_INODE_SD_SOURCE_SYNTHETIC,
		policy_generation);
	if (!new_cache) {
		pkm_kacs_free((void *)new_sd_bytes);
		ret = -ENOMEM;
		goto out_template;
	}

	*cache_out = new_cache;
	new_cache = NULL;
	ret = 0;

out_template:
	kfree(parent_file);
	if (parent_dentry)
		dput(parent_dentry);
	pkm_kacs_free((void *)template_sd_ptr);
	return ret;
}

/* The caller's mutex is held on entry and every return, but may be dropped. */
long pkm_kacs_inode_resolve_effective_cache_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out, unsigned int depth)
{
	struct pkm_kacs_inode_sd_cache *cache, *fresh;
	u32 mount_policy;
	u64 epoch;
	long ret;

	if (!file || !sec || !cache_out)
		return -EINVAL;

	lockdep_assert_held(&sec->lock);
retry:
	ret = pkm_kacs_inode_get_or_populate_cache_locked(file, sec, &cache);
	if (ret)
		return ret;
	mount_policy = pkm_kacs_superblock_mount_policy(file_inode(file)->i_sb);
	if (cache->state != PKM_KACS_INODE_SD_MISSING ||
	    (mount_policy != KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL &&
	     mount_policy != KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT)) {
		*cache_out = cache;
		return 0;
	}

	/*
	 * Parent resolution may sleep or recurse. Keep this cache alive, not
	 * its mutex: no descendant SD lock may be held when locking an ancestor.
	 * A competing set-security or policy change wins over this synthesis.
	 */
	refcount_inc(&cache->refs);
	epoch = sec->sd_cache_epoch;
	fresh = NULL;
	mutex_unlock(&sec->lock);
	ret = pkm_kacs_synthesize_missing_file_sd(file, &fresh, depth);
	mutex_lock(&sec->lock);
	if (rcu_dereference_protected(sec->sd_cache,
				      lockdep_is_held(&sec->lock)) != cache ||
	    epoch != sec->sd_cache_epoch ||
	    !pkm_kacs_inode_sd_cache_current(file_inode(file)->i_sb, cache) ||
	    (fresh && !pkm_kacs_inode_sd_cache_current(file_inode(file)->i_sb,
						     fresh))) {
		pkm_kacs_inode_sd_cache_free(fresh);
		pkm_kacs_inode_sd_cache_free(cache);
		goto retry;
	}
	pkm_kacs_inode_sd_cache_free(cache);
	if (ret)
		return ret;
	pkm_kacs_inode_replace_sd_cache_locked(sec, fresh);
	*cache_out = fresh;
	return 0;
}

static bool pkm_kacs_missing_cache_requires_synthesis(
	const struct inode *inode, const struct pkm_kacs_inode_sd_cache *cache)
{
	u32 mount_policy;

	if (!inode || !cache || cache->state != PKM_KACS_INODE_SD_MISSING)
		return false;

	mount_policy = pkm_kacs_superblock_mount_policy(inode->i_sb);
	return mount_policy == KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL ||
	       mount_policy == KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT;
}

static const struct pkm_kacs_inode_sd_cache *pkm_kacs_inode_current_cache_rcu(
	const struct inode *inode, const struct pkm_kacs_inode_security *sec)
{
	const struct pkm_kacs_inode_sd_cache *cache;

	if (!inode || !sec)
		return NULL;

	cache = rcu_dereference(sec->sd_cache);
	if (!pkm_kacs_inode_sd_cache_current(inode->i_sb, cache)) {
		trace_kacs_sd_cache_lookup(inode,
					   cache ? KACS_SDC_MISS_STALE_GEN :
						   KACS_SDC_MISS_NONE,
					   0);
		return NULL;
	}
	if (pkm_kacs_missing_cache_requires_synthesis(inode, cache)) {
		trace_kacs_sd_cache_lookup(inode, KACS_SDC_MISS_NEEDS_SYNTH, 0);
		return NULL;
	}

	trace_kacs_sd_cache_lookup(inode, KACS_SDC_HIT, 0);
	return cache;
}

struct pkm_kacs_inode_sd_cache *pkm_kacs_inode_sd_cache_get_current(
	const struct inode *inode, const struct pkm_kacs_inode_security *sec)
{
	const struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_sd_cache *candidate;
	struct pkm_kacs_inode_sd_cache *owned = NULL;

	rcu_read_lock();
	cache = pkm_kacs_inode_current_cache_rcu(inode, sec);
	candidate = (struct pkm_kacs_inode_sd_cache *)cache;
	if (candidate && refcount_inc_not_zero(&candidate->refs))
		owned = candidate;
	rcu_read_unlock();

	return owned;
}

long pkm_kacs_inode_ensure_effective_cache(
	struct file *file, struct pkm_kacs_inode_security *sec)
{
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_sd_cache *locked_cache = NULL;
	struct inode *inode;
	bool needs_persist = false;
	long ret;

	if (!file || !sec)
		return -EINVAL;

	inode = file_inode(file);
	if (!inode)
		return -EACCES;

	cache = pkm_kacs_inode_sd_cache_get_current(inode, sec);
	if (cache) {
		bool pending = cache->state == PKM_KACS_INODE_SD_VALID &&
			       cache->source ==
				       PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING;
		bool reread = pkm_kacs_inode_sd_cache_rereads_each_time(inode);

		pkm_kacs_inode_sd_cache_free(cache);
		if (reread)
			goto resolve;
		if (!pending)
			return 0;
		/*
		 * A current entry that is still pending belongs to an object
		 * synthesised as an ancestor -- only to supply inheritance
		 * inputs for a descendant, which queues no write-back for it --
		 * or to one whose earlier write-back never ran.  This access is
		 * on the object itself (ancestor resolution for a child goes
		 * through pkm_kacs_inode_resolve_effective_cache_locked, not
		 * here), so it persists under the same rules now (PEI-698).
		 */
		mutex_lock(&sec->lock);
		if (!sec->persist_work_queued) {
			sec->persist_work_queued = true;
			needs_persist = true;
		}
		mutex_unlock(&sec->lock);
		if (needs_persist)
			pkm_kacs_inode_queue_sd_persist(file, sec);
		return 0;
	}

resolve:
	mutex_lock(&sec->lock);
	ret = pkm_kacs_inode_resolve_effective_cache_locked(file, sec,
							    &locked_cache, 0);
	/*
	 * A freshly synthesized SD on a SYNTHESIZE_PERSISTENT mount owes a
	 * deferred write-back. Claim it under sec->lock (one in-flight persist
	 * per inode) and queue the task_work below, after the lock is dropped
	 * -- queuing must not run under sec->lock, and the write itself must not
	 * run under any FACS/VFS lock.
	 */
	if (ret == 0 && locked_cache &&
	    locked_cache->state == PKM_KACS_INODE_SD_VALID &&
	    locked_cache->source == PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING &&
	    !sec->persist_work_queued) {
		sec->persist_work_queued = true;
		needs_persist = true;
	}
	mutex_unlock(&sec->lock);

	if (needs_persist)
		pkm_kacs_inode_queue_sd_persist(file, sec);
	return ret;
}

long pkm_kacs_inode_ensure_effective_cache_by_inode(
	struct inode *inode, struct pkm_kacs_inode_security *sec)
{
	struct pkm_kacs_inode_sd_cache *cache;
	struct vfsmount mnt = {};
	struct path path = {};
	struct file file = {};
	struct dentry *alias;
	long ret;

	if (!inode || !sec)
		return -EINVAL;

	/*
	 * Already resolved: nothing to do, and in particular no dentry needed.
	 * Worth checking here rather than leaving it to
	 * pkm_kacs_inode_ensure_effective_cache() below, because the alias
	 * lookup is the one step that can fail for reasons unrelated to the SD.
	 * A current entry that still owes its write-back (a pending ancestor
	 * accessed in its own right, PEI-698) does need the dentry, so it
	 * falls through to the anchor below and queues the persist there.
	 */
	cache = pkm_kacs_inode_sd_cache_get_current(inode, sec);
	if (cache) {
		bool pending = cache->state == PKM_KACS_INODE_SD_VALID &&
			       cache->source ==
				       PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING;
		bool reread = pkm_kacs_inode_sd_cache_rereads_each_time(inode);

		pkm_kacs_inode_sd_cache_free(cache);
		if (!pending && !reread)
			return 0;
	}

	/*
	 * The caller reached us through an inode-only interface (the
	 * inode_getsecurity LSM hook), but resolving an SD needs a dentry: the
	 * xattr read addresses one, and missing-SD synthesis walks d_parent to
	 * find the descriptor to inherit from. Any alias will do -- every alias
	 * of an inode names the same object, and a hardlinked file inherits
	 * from whichever parent it is reached through in any case.
	 */
	alias = d_find_any_alias(inode);
	if (!alias)
		return -EACCES;

	mnt.mnt_root = alias;
	mnt.mnt_sb = inode->i_sb;
	mnt.mnt_idmap = &nop_mnt_idmap;
	path.mnt = &mnt;
	path.dentry = alias;
	pkm_kacs_init_path_anchor_file(&file, &path);

	ret = pkm_kacs_inode_ensure_effective_cache(&file, sec);
	dput(alias);
	return ret;
}

static long pkm_kacs_inode_write_sd_xattr_dentry_locked(
	struct mnt_idmap *idmap, struct dentry *dentry, struct inode *inode,
	const u8 *sd_bytes, size_t sd_len)
{
	struct pkm_kacs_inode_security *sec;
	int ret;

	if (!dentry || !inode || !sd_bytes || sd_len == 0)
		return -EINVAL;
	if (kacs_rust_validate_stored_sd_bytes(sd_bytes, sd_len) != 0)
		return -EINVAL;
	sec = inode->i_security ? pkm_kacs_inode(inode) : NULL;

#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec && sec->kunit_fake_xattr_enabled)
		return pkm_kacs_kunit_fake_setxattr_locked(sec, sd_bytes, sd_len);
#endif

	inode_lock(inode);
	/*
	 * __vfs_setxattr_noperm skips security_inode_setxattr for *us*, but
	 * stacking FSes (overlayfs) re-enter vfs_setxattr on the real inode
	 * inside their xattr handler, which fires our own hook again. Mark
	 * the task so the hook recognises the internal write and allows the
	 * canonical SD xattr.
	 */
	if (current && current->security)
		pkm_kacs_task(current)->internal_sd_write_depth++;
	ret = __vfs_setxattr_noperm(idmap, dentry,
				    pkm_kacs_inode_sd_xattr_name(inode),
				    sd_bytes, sd_len, 0);
	if (current && current->security)
		pkm_kacs_task(current)->internal_sd_write_depth--;
	inode_unlock(inode);
	return ret;
}

long pkm_kacs_inode_write_sd_xattr_locked(struct file *file,
						 const u8 *sd_bytes,
						 size_t sd_len)
{
	if (!file)
		return -EINVAL;
	return pkm_kacs_inode_write_sd_xattr_dentry_locked(
		file_mnt_idmap(file), file_dentry(file), file_inode(file),
		sd_bytes, sd_len);
}

/*
 * Deferred write-back of a SYNTHESIZE_PERSISTENT synthesized SD.
 *
 * Synthesis caches the SD as SOURCE_SYNTHETIC_PENDING but cannot write the
 * xattr inline: on the metadata-hook path i_rwsem is already held by the
 * VFS, so taking it for write-back would self-deadlock. We instead pin the
 * dentry and register a task_work that runs
 * at return-to-userspace with no FACS/VFS locks held, then writes the xattr
 * cleanly. The on-disk SD is a recomputable cache, so this is best-effort:
 * any failure (or a never-fired work) just leaves the entry to re-synthesize.
 */
struct pkm_kacs_sd_persist_work {
	struct callback_head cb;
	struct dentry *dentry;
};

static void pkm_kacs_inode_clear_persist_claim(
	struct pkm_kacs_inode_security *sec)
{
	mutex_lock(&sec->lock);
	sec->persist_work_queued = false;
	mutex_unlock(&sec->lock);
}

void pkm_kacs_inode_run_sd_persist(struct dentry *dentry,
					  struct inode *inode,
					  struct pkm_kacs_inode_security *sec)
{
	struct pkm_kacs_inode_sd_cache *cur;
	struct pkm_kacs_inode_sd_cache *promoted;
	u8 *snapshot = NULL;
	size_t snapshot_len = 0;

	/*
	 * Snapshot the pending SD under sec->lock, then drop the lock before
	 * the xattr write (which takes i_rwsem) to preserve i_rwsem -> sec->lock
	 * ordering. Only persist if the entry is still pending and still matches
	 * the current policy generation -- a generation change means the entry
	 * is stale and will be re-synthesized, so we must not pin stale bytes
	 * onto disk.
	 */
	mutex_lock(&sec->lock);
	sec->persist_work_queued = false;
	cur = rcu_dereference_protected(sec->sd_cache,
					lockdep_is_held(&sec->lock));
	if (cur && cur->state == PKM_KACS_INODE_SD_VALID &&
	    cur->source == PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING &&
	    cur->bytes && cur->len &&
	    cur->policy_generation ==
		    pkm_kacs_superblock_policy_generation(inode->i_sb)) {
		snapshot = kmemdup(cur->bytes, cur->len, GFP_KERNEL);
		if (snapshot)
			snapshot_len = cur->len;
	}
	mutex_unlock(&sec->lock);

	if (!snapshot)
		return;

	/*
	 * Best-effort. On failure the entry stays SYNTHETIC_PENDING and simply
	 * re-synthesizes (and is offered for write-back again) later.
	 */
	if (pkm_kacs_inode_write_sd_xattr_dentry_locked(&nop_mnt_idmap, dentry,
						       inode, snapshot,
						       snapshot_len)) {
		kfree(snapshot);
		return;
	}

	/*
	 * The on-disk xattr now exists and holds exactly these bytes, so the
	 * cached entry is promoted to a SOURCE_XATTR entry of the same bytes.
	 * Leaving it pending would offer it for write-back on every later
	 * access to the object (pkm_kacs_inode_ensure_effective_cache queues
	 * the persist of a current pending entry, PEI-698).  The promotion
	 * only replaces the entry it was snapshotted from: a concurrent
	 * set-security or generation bump has already superseded it.
	 */
	promoted = pkm_kacs_inode_sd_cache_alloc_ex(
		PKM_KACS_INODE_SD_VALID, snapshot, snapshot_len,
		PKM_KACS_INODE_SD_SOURCE_XATTR, 0);
	if (!promoted) {
		kfree(snapshot);
		return;
	}
	mutex_lock(&sec->lock);
	cur = rcu_dereference_protected(sec->sd_cache,
					lockdep_is_held(&sec->lock));
	if (cur && cur->state == PKM_KACS_INODE_SD_VALID &&
	    cur->source == PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING &&
	    cur->len == snapshot_len && cur->bytes &&
	    memcmp(cur->bytes, snapshot, snapshot_len) == 0) {
		pkm_kacs_inode_replace_sd_cache_locked(sec, promoted);
		promoted = NULL;
	}
	mutex_unlock(&sec->lock);
	/* Not installed: the entry owns the snapshot, so freeing it frees both. */
	pkm_kacs_inode_sd_cache_free(promoted);
}

static void pkm_kacs_inode_sd_persist_work_fn(struct callback_head *cb)
{
	struct pkm_kacs_sd_persist_work *work =
		container_of(cb, struct pkm_kacs_sd_persist_work, cb);
	struct dentry *dentry = work->dentry;
	struct inode *inode = d_inode(dentry);

	if (inode && inode->i_security)
		pkm_kacs_inode_run_sd_persist(dentry, inode,
					      pkm_kacs_inode(inode));

	dput(dentry);
	kfree(work);
}

static void pkm_kacs_inode_queue_sd_persist(
	struct file *file, struct pkm_kacs_inode_security *sec)
{
	struct pkm_kacs_sd_persist_work *work;
	struct dentry *dentry;

#ifdef CONFIG_SECURITY_PKM_KUNIT
	sec->kunit_persist_queue_calls++;
#endif
	/*
	 * task_work fires on return to userspace, so it is only meaningful for a
	 * user task. Kernel threads and exiting tasks fall back to lazy
	 * re-synthesis: clear the claim so a later access can retry.
	 */
	dentry = file ? file_dentry(file) : NULL;
	if (!dentry || (current->flags & PF_KTHREAD)) {
		pkm_kacs_inode_clear_persist_claim(sec);
		return;
	}

	work = kmalloc(sizeof(*work), GFP_KERNEL);
	if (!work) {
		pkm_kacs_inode_clear_persist_claim(sec);
		return;
	}

	init_task_work(&work->cb, pkm_kacs_inode_sd_persist_work_fn);
	work->dentry = dget(dentry);
	if (task_work_add(current, &work->cb, TWA_RESUME)) {
		dput(work->dentry);
		kfree(work);
		pkm_kacs_inode_clear_persist_claim(sec);
	}
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
/* Real VFS dentries and xattr dispatch, on a mount private to each test. */
#define PKM_SD_TEST_LEVELS 33

struct pkm_sd_test_fixture {
	struct vfsmount *mnt;
	struct dentry *chain[PKM_SD_TEST_LEVELS];
	struct file files[PKM_SD_TEST_LEVELS];
	const struct xattr_handler * const *old_handlers;
	struct pkm_kacs_inode_sd_cache *replacement;
	struct inode *trigger;
	struct inode *target;
	struct file *lower;
	unsigned int count;
	unsigned int interference;
	int read_error;
	bool bump_generation;
	bool empty_invalidation;
	bool empty_round_trip;
};

static int pkm_sd_test_getxattr(const struct xattr_handler *handler,
				struct dentry *dentry, struct inode *inode,
				const char *name, void *buffer, size_t size)
{
	struct pkm_sd_test_fixture *f = inode->i_sb->s_root->d_fsdata;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_security *sec;
	int ret;

	if (f->read_error)
		return f->read_error;
	if (inode == f->trigger && f->empty_invalidation) {
		if (f->interference)
			return -ENODATA;
		if (buffer) {
			if (size < f->replacement->len)
				return -ERANGE;
			sec = pkm_kacs_inode(inode);
			if (!mutex_trylock(&sec->lock))
				return -EDEADLK;
			if (f->empty_round_trip) {
				refcount_inc(&f->replacement->refs);
				pkm_kacs_inode_replace_sd_cache_locked(sec,
								       f->replacement);
			}
			pkm_kacs_inode_replace_sd_cache_locked(sec, NULL);
			mutex_unlock(&sec->lock);
			f->interference++;
			/* Bytes from before that invalidation must not be published. */
			memcpy(buffer, f->replacement->bytes, f->replacement->len);
		}
		return f->replacement->len;
	}
	if (inode == f->trigger && !f->interference && f->replacement) {
		sec = pkm_kacs_inode(f->target);
		/* A failing negative control must report, rather than deadlock. */
		if (!mutex_trylock(&sec->lock))
			return -EDEADLK;
		refcount_inc(&f->replacement->refs);
		pkm_kacs_inode_replace_sd_cache_locked(sec, f->replacement);
		mutex_unlock(&sec->lock);
		f->interference++;
	}
	if (inode == f->trigger && !f->interference && f->bump_generation) {
		struct pkm_kacs_superblock_security *sb_sec =
			pkm_kacs_sb(inode->i_sb);

		mutex_lock(&sb_sec->lock);
		sb_sec->policy_generation =
			pkm_kacs_next_mount_policy_generation(sb_sec->policy_generation);
		mutex_unlock(&sb_sec->lock);
		f->interference++;
	}
	if (inode != f->trigger || !f->lower)
		return -ENODATA;

	/* Model the real stacking-handler -> lower inode_getsecurity path. */
	sec = pkm_kacs_inode(file_inode(f->lower));
	ret = pkm_kacs_inode_ensure_effective_cache(f->lower, sec);
	if (ret)
		return ret;
	cache = pkm_kacs_inode_sd_cache_get_current(file_inode(f->lower), sec);
	if (!cache)
		return -EACCES;
	ret = cache->len;
	if (buffer) {
		if (size < cache->len)
			ret = -ERANGE;
		else
			memcpy(buffer, cache->bytes, cache->len);
	}
	pkm_kacs_inode_sd_cache_free(cache);
	return ret;
}

static const struct xattr_handler pkm_sd_test_xattr_handler = {
	.name = "security.peios.sd",
	.get = pkm_sd_test_getxattr,
};

static const struct xattr_handler * const pkm_sd_test_handlers[] = {
	&pkm_sd_test_xattr_handler,
	NULL,
};

static void pkm_sd_test_cleanup(void *data)
{
	struct pkm_sd_test_fixture *f = data;

	pkm_kacs_inode_sd_cache_free(f->replacement);
	while (f->count)
		dput(f->chain[--f->count]);
	if (!IS_ERR_OR_NULL(f->mnt)) {
		f->mnt->mnt_sb->s_xattr = f->old_handlers;
		f->mnt->mnt_root->d_fsdata = NULL;
		kern_unmount(f->mnt);
	}
}

static struct pkm_sd_test_fixture *
pkm_sd_test_fixture(struct kunit *test, unsigned int levels, u32 policy)
{
	struct pkm_sd_test_fixture *f;
	struct file_system_type *type;
	struct pkm_kacs_superblock_security *sb_sec;
	unsigned int i;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return NULL;
	if (kunit_add_action_or_reset(test, pkm_sd_test_cleanup, f))
		return NULL;
	type = get_fs_type("ramfs");
	if (!type)
		return NULL;
	f->mnt = vfs_kern_mount(type, 0, "ramfs", NULL);
	put_filesystem(type);
	if (IS_ERR(f->mnt))
		return NULL;
	f->old_handlers = f->mnt->mnt_sb->s_xattr;
	f->mnt->mnt_sb->s_xattr = pkm_sd_test_handlers;
	f->mnt->mnt_root->d_fsdata = f;
	sb_sec = pkm_kacs_sb(f->mnt->mnt_sb);
	mutex_lock(&sb_sec->lock);
	sb_sec->mount_policy = policy;
	sb_sec->policy_generation =
		pkm_kacs_next_mount_policy_generation(sb_sec->policy_generation);
	mutex_unlock(&sb_sec->lock);
	for (i = 0; i < levels; i++) {
		struct pkm_kacs_inode_security *sec;
		struct inode *inode;
		struct path path = { .mnt = f->mnt };

		if (!i) {
			f->chain[i] = dget(f->mnt->mnt_root);
		} else {
			f->chain[i] = d_alloc_name(f->chain[i - 1], "child");
			if (!f->chain[i])
				return NULL;
			inode = new_inode(f->mnt->mnt_sb);
			if (!inode) {
				dput(f->chain[i]);
				return NULL;
			}
			inode->i_mode = S_IFDIR | 0700;
			d_instantiate(f->chain[i], inode);
		}
		f->count++;
		inode = d_inode(f->chain[i]);
		inode->i_opflags |= IOP_XATTR;
		sec = pkm_kacs_inode(inode);
		mutex_lock(&sec->lock);
		pkm_kacs_inode_replace_sd_cache_locked(sec, NULL);
		mutex_unlock(&sec->lock);
		path.dentry = f->chain[i];
		pkm_kacs_init_path_anchor_file(&f->files[i], &path);
	}
	return f;
}

static long pkm_sd_test_resolve(struct pkm_sd_test_fixture *f, unsigned int index)
{
	struct file *file = &f->files[index];

	return pkm_kacs_inode_ensure_effective_cache(file,
						   pkm_kacs_inode(file_inode(file)));
}

static void pkm_sd_test_resolve_chain(struct kunit *test)
{
	struct pkm_sd_test_fixture *f = pkm_sd_test_fixture(test, 6,
		KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT);
	struct pkm_kacs_inode_security *sec;
	unsigned int i;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, pkm_sd_test_resolve(f, 5), 0L);
	for (i = 0; i < 6; i++) {
		struct inode *inode = file_inode(&f->files[i]);
		struct pkm_kacs_inode_sd_cache *cache;

		sec = pkm_kacs_inode(inode);
		cache = pkm_kacs_inode_sd_cache_get_current(inode, sec);
		KUNIT_ASSERT_NOT_NULL(test, cache);
		KUNIT_EXPECT_EQ(test, cache->source,
				(u8)PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING);
		pkm_kacs_inode_sd_cache_free(cache);
		KUNIT_EXPECT_EQ(test, sec->kunit_persist_queue_calls,
				i == 5 ? 1U : 0U);
	}
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static void pkm_sd_test_depth_bound(struct kunit *test)
{
	struct pkm_sd_test_fixture *f = pkm_sd_test_fixture(test,
		PKM_SD_TEST_LEVELS, KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_EXPECT_EQ(test, pkm_sd_test_resolve(f, 32), -EACCES);
	KUNIT_EXPECT_EQ(test, pkm_sd_test_resolve(f, 31), 0L);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static void pkm_sd_test_replacement(struct kunit *test, bool in_ancestor,
				    bool empty_invalidation, bool empty_round_trip)
{
	/* SYSTEM owner with a NULL DACL; the cache pointer identifies the winner. */
	static const u8 sd[] = {
		1, 0, 0, 128, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	struct pkm_sd_test_fixture *f = pkm_sd_test_fixture(test, 2,
		KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);
	struct pkm_kacs_inode_sd_cache *cache;
	const u8 *bytes;

	KUNIT_ASSERT_NOT_NULL(test, f);
	bytes = kmemdup(sd, sizeof(sd), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, bytes);
	f->replacement = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_VALID,
						       bytes, sizeof(sd));
	if (!f->replacement)
		kfree(bytes);
	KUNIT_ASSERT_NOT_NULL(test, f->replacement);
	f->empty_invalidation = empty_invalidation;
	f->empty_round_trip = empty_round_trip;
	f->target = file_inode(&f->files[1]);
	f->trigger = file_inode(&f->files[in_ancestor ? 0 : 1]);
	KUNIT_ASSERT_EQ(test, pkm_sd_test_resolve(f, 1), 0L);
	KUNIT_EXPECT_EQ(test, f->interference, 1U);
	cache = pkm_kacs_inode_sd_cache_get_current(f->target,
						    pkm_kacs_inode(f->target));
	if (empty_invalidation) {
		KUNIT_EXPECT_NOT_NULL(test, cache);
		if (cache)
			KUNIT_EXPECT_EQ(test, cache->source,
					(u8)PKM_KACS_INODE_SD_SOURCE_SYNTHETIC);
	} else {
		KUNIT_EXPECT_PTR_EQ(test, cache, f->replacement);
	}
	pkm_kacs_inode_sd_cache_free(cache);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static void pkm_sd_test_replacement_during_xattr(struct kunit *test)
{
	pkm_sd_test_replacement(test, false, false, false);
}

static void pkm_sd_test_replacement_during_parent(struct kunit *test)
{
	pkm_sd_test_replacement(test, true, false, false);
}

static void pkm_sd_test_empty_invalidation(struct kunit *test)
{
	pkm_sd_test_replacement(test, false, true, false);
}

static void pkm_sd_test_empty_round_trip(struct kunit *test)
{
	pkm_sd_test_replacement(test, false, true, true);
}

static void pkm_sd_test_generation_during_parent(struct kunit *test)
{
	struct pkm_sd_test_fixture *f = pkm_sd_test_fixture(test, 2,
		KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);
	struct pkm_kacs_inode_sd_cache *cache;
	struct inode *inode;

	KUNIT_ASSERT_NOT_NULL(test, f);
	f->trigger = file_inode(&f->files[0]);
	f->bump_generation = true;
	inode = file_inode(&f->files[1]);
	KUNIT_ASSERT_EQ(test, pkm_sd_test_resolve(f, 1), 0L);
	KUNIT_EXPECT_EQ(test, f->interference, 1U);
	cache = pkm_kacs_inode_sd_cache_get_current(inode, pkm_kacs_inode(inode));
	KUNIT_ASSERT_NOT_NULL(test, cache);
	KUNIT_EXPECT_EQ(test, cache->policy_generation,
			pkm_kacs_superblock_policy_generation(inode->i_sb));
	pkm_kacs_inode_sd_cache_free(cache);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static void pkm_sd_test_stale_read_error(struct kunit *test)
{
	struct pkm_sd_test_fixture *f = pkm_sd_test_fixture(test, 1,
		KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);
	struct pkm_kacs_superblock_security *sb_sec;
	struct pkm_kacs_inode_sd_cache *cache;
	struct inode *inode;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, pkm_sd_test_resolve(f, 0), 0L);
	sb_sec = pkm_kacs_sb(f->mnt->mnt_sb);
	mutex_lock(&sb_sec->lock);
	sb_sec->policy_generation =
		pkm_kacs_next_mount_policy_generation(sb_sec->policy_generation);
	mutex_unlock(&sb_sec->lock);
	f->read_error = -EIO;
	KUNIT_EXPECT_EQ(test, pkm_sd_test_resolve(f, 0), -EIO);
	inode = file_inode(&f->files[0]);
	cache = pkm_kacs_inode_sd_cache_get_current(inode, pkm_kacs_inode(inode));
	KUNIT_EXPECT_PTR_EQ(test, cache, NULL);
	pkm_kacs_inode_sd_cache_free(cache);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static void pkm_sd_test_stacked_xattr(struct kunit *test)
{
	struct pkm_sd_test_fixture *f = pkm_sd_test_fixture(test, 2,
		KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL);
	struct pkm_kacs_inode_sd_cache *cache;
	struct inode *inode;

	KUNIT_ASSERT_NOT_NULL(test, f);
	inode = file_inode(&f->files[1]);
	f->trigger = inode;
	f->lower = &f->files[0];
	KUNIT_ASSERT_EQ(test, pkm_sd_test_resolve(f, 1), 0L);
	cache = pkm_kacs_inode_sd_cache_get_current(inode, pkm_kacs_inode(inode));
	KUNIT_ASSERT_NOT_NULL(test, cache);
	KUNIT_EXPECT_EQ(test, cache->source,
			(u8)PKM_KACS_INODE_SD_SOURCE_XATTR);
	pkm_kacs_inode_sd_cache_free(cache);
	KUNIT_EXPECT_TRUE(test, debug_locks);
}

static struct kunit_case pkm_sd_cache_cases[] = {
	KUNIT_CASE(pkm_sd_test_resolve_chain),
	KUNIT_CASE(pkm_sd_test_depth_bound),
	KUNIT_CASE(pkm_sd_test_replacement_during_xattr),
	KUNIT_CASE(pkm_sd_test_replacement_during_parent),
	KUNIT_CASE(pkm_sd_test_generation_during_parent),
	KUNIT_CASE(pkm_sd_test_empty_invalidation),
	KUNIT_CASE(pkm_sd_test_empty_round_trip),
	KUNIT_CASE(pkm_sd_test_stacked_xattr),
	KUNIT_CASE(pkm_sd_test_stale_read_error),
	{}
};

static struct kunit_suite pkm_sd_cache_suite = {
	.name = "pkm_kunit_sd_cache",
	.test_cases = pkm_sd_cache_cases,
};

kunit_test_suite(pkm_sd_cache_suite);
#endif
