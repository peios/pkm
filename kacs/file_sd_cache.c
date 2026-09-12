// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
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
#include "file_access.h"
#include "file_sd_cache.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

static long pkm_kacs_superblock_template_sd_copy(const struct super_block *sb,
						 const u8 **sd_ptr_out,
						 size_t *sd_len_out)
{
	struct pkm_kacs_superblock_security *sec;
	const u8 *copy;

	if (sd_ptr_out)
		*sd_ptr_out = NULL;
	if (sd_len_out)
		*sd_len_out = 0;
	if (!sb || !sd_ptr_out || !sd_len_out || !sb->s_security)
		return 0;

	sec = pkm_kacs_sb(sb);
	mutex_lock(&sec->lock);
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

	old_cache = cmpxchg_release(
		(struct pkm_kacs_inode_sd_cache **)&sec->sd_cache, expected,
		new_cache);
	return old_cache == expected;
}

void pkm_kacs_inode_replace_sd_cache_locked(
	struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache *new_cache)
{
	struct pkm_kacs_inode_sd_cache *old_cache;

	old_cache = rcu_dereference_protected(sec->sd_cache,
					      lockdep_is_held(&sec->lock));
	rcu_assign_pointer(sec->sd_cache, new_cache);
	if (old_cache)
		call_rcu(&old_cache->rcu, pkm_kacs_inode_sd_cache_free_rcu);
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

static void pkm_kacs_emit_corrupt_sd_event(void)
{
	static const char event_type[] = "corrupt-sd";
	static const u8 payload[] = {
		0x81, /* map(1) */
		0xa6, 'r', 'e', 'a', 's', 'o', 'n',
		0xaa, 'c', 'o', 'r', 'r', 'u', 'p', 't', '-', 's', 'd',
	};

	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, event_type,
			     sizeof(event_type) - 1, payload, sizeof(payload));
}

static long pkm_kacs_inode_alloc_corrupt_sd_cache(
	struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct pkm_kacs_inode_sd_cache *cache;

	if (!cache_out)
		return -EINVAL;

	cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_CORRUPT, NULL,
					      0);
	if (!cache)
		return -ENOMEM;

	pkm_kacs_emit_corrupt_sd_event();
	*cache_out = cache;
	return 0;
}

static long pkm_kacs_inode_read_sd_xattr_locked(
	struct file *file, struct pkm_kacs_inode_sd_cache **cache_out)
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
	if (sec && sec->kunit_fake_xattr_enabled)
		len = pkm_kacs_kunit_fake_getxattr_locked(sec, NULL, 0);
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
		return pkm_kacs_inode_alloc_corrupt_sd_cache(cache_out);
	}

	bytes = pkm_kacs_zalloc(len);
	if (!bytes)
		return -ENOMEM;

#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec && sec->kunit_fake_xattr_enabled)
		ret = pkm_kacs_kunit_fake_getxattr_locked(sec, bytes, len);
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
		return pkm_kacs_inode_alloc_corrupt_sd_cache(cache_out);
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
	struct pkm_kacs_inode_sd_cache *cache;
	struct inode *inode;
	long ret;

	if (!file || !sec || !cache_out)
		return -EINVAL;
	inode = file_inode(file);
	if (!inode)
		return -EACCES;

retry:
	cache = rcu_dereference_protected(sec->sd_cache,
					  lockdep_is_held(&sec->lock));
	if (cache) {
		if (pkm_kacs_inode_sd_cache_current(inode->i_sb, cache)) {
			*cache_out = cache;
			return 0;
		}
		if (pkm_kacs_inode_try_publish_sd_cache(sec, cache, NULL))
			call_rcu(&cache->rcu, pkm_kacs_inode_sd_cache_free_rcu);
		goto retry;
	}

	ret = pkm_kacs_inode_read_sd_xattr_locked(file, &cache);
	if (ret)
		return ret;

	if (!pkm_kacs_inode_try_publish_sd_cache(sec, NULL, cache)) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto retry;
	}
	*cache_out = cache;
	return 0;
}

/*
 * KC-00: missing-SD synthesis walks parent-to-root holding one inode SD mutex
 * per level nested, with a full struct file per recursion frame. Cap the
 * ancestor depth well below lockdep's MAX_LOCK_DEPTH (48) and the VMAP_STACK
 * budget so a deeply nested directory tree on a SYNTHESIZE mount (vfat/exfat/
 * NFS/ramfs) cannot drive a kernel stack overflow or lock-depth BUG. Beyond the
 * cap, synthesis fails closed (-EACCES). 32 covers realistic nesting on those
 * mount types.
 */
#define PKM_KACS_MAX_SD_SYNTHESIS_DEPTH 32U

long pkm_kacs_inode_resolve_effective_cache_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out, unsigned int depth);
static void pkm_kacs_inode_queue_sd_persist(
	struct file *file, struct pkm_kacs_inode_security *sec);

static long pkm_kacs_synthesize_missing_file_sd_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out, unsigned int depth)
{
	struct pkm_kacs_inode_sd_cache *new_cache = NULL;
	struct pkm_kacs_inode_sd_cache *parent_cache = NULL;
	struct pkm_kacs_inode_security *parent_sec;
	struct dentry *dentry;
	struct dentry *parent_dentry;
	struct inode *inode;
	struct inode *parent_inode;
	struct file parent_file = {};
	const u8 *template_sd_ptr = NULL;
	const u8 *parent_sd_ptr = NULL;
	const u8 *new_sd_bytes = NULL;
	size_t template_sd_len = 0;
	size_t parent_sd_len = 0;
	size_t new_sd_len = 0;
	u32 policy_generation;
	u32 mount_policy;
	long ret;

	if (!file || !sec || !cache_out)
		return -EINVAL;

	/* KC-00: bound the parent-to-root synthesis recursion (fail closed). */
	if (depth >= PKM_KACS_MAX_SD_SYNTHESIS_DEPTH)
		return -EACCES;

	inode = file_inode(file);
	dentry = file_dentry(file);
	if (!inode || !dentry)
		return -EACCES;

	mount_policy = pkm_kacs_superblock_mount_policy(inode->i_sb);
	if (mount_policy != KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL &&
	    mount_policy != KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT)
		return -EACCES;
	policy_generation = pkm_kacs_superblock_policy_generation(inode->i_sb);

	ret = pkm_kacs_superblock_template_sd_copy(inode->i_sb,
						   &template_sd_ptr,
						   &template_sd_len);
	if (ret)
		return ret;

	parent_dentry = dentry->d_parent;
	if (parent_dentry && parent_dentry != dentry) {
		struct path parent_path;

		parent_inode = d_inode(parent_dentry);
		if (!parent_inode || !parent_inode->i_security) {
			ret = -EACCES;
			goto out_template;
		}

		parent_sec = pkm_kacs_inode(parent_inode);
		parent_file.f_inode = parent_inode;
		parent_path = file->f_path;
		parent_path.dentry = parent_dentry;
		*(struct path *)&parent_file.f_path = parent_path;

		mutex_lock(&parent_sec->lock);
		ret = pkm_kacs_inode_resolve_effective_cache_locked(
			&parent_file, parent_sec, &parent_cache, depth + 1);
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
		parent_sd_ptr = parent_cache->bytes;
		parent_sd_len = parent_cache->len;
		ret = kacs_rust_synthesize_file_sd(
			parent_sd_ptr, parent_sd_len, template_sd_ptr,
			template_sd_len, S_ISDIR(inode->i_mode), &new_sd_bytes,
			&new_sd_len);
		mutex_unlock(&parent_sec->lock);
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
	 * to the xattr, but synthesis runs under sec->lock and the xattr write
	 * takes i_rwsem -- writing here would re-introduce the sec->lock ->
	 * i_rwsem ordering the access path forbids, and self-deadlocks when the
	 * caller is a metadata hook already holding i_rwsem. So PERSISTENT marks
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

	pkm_kacs_inode_replace_sd_cache_locked(sec, new_cache);
	*cache_out = new_cache;
	new_cache = NULL;
	ret = 0;

out_template:
	pkm_kacs_free((void *)template_sd_ptr);
	return ret;
}

long pkm_kacs_inode_resolve_effective_cache_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out, unsigned int depth)
{
	struct pkm_kacs_inode_sd_cache *cache;
	u32 mount_policy;
	long ret;

	if (!file || !sec || !cache_out)
		return -EINVAL;

	ret = pkm_kacs_inode_get_or_populate_cache_locked(file, sec, &cache);
	if (ret)
		return ret;
	if (cache->state != PKM_KACS_INODE_SD_MISSING) {
		*cache_out = cache;
		return 0;
	}

	mount_policy = pkm_kacs_superblock_mount_policy(file_inode(file)->i_sb);
	if (mount_policy != KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL &&
	    mount_policy != KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT) {
		*cache_out = cache;
		return 0;
	}

	return pkm_kacs_synthesize_missing_file_sd_locked(file, sec, cache_out,
							  depth);
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

		pkm_kacs_inode_sd_cache_free(cache);
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

		pkm_kacs_inode_sd_cache_free(cache);
		if (!pending)
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
 * xattr inline (it runs under sec->lock, and the write takes i_rwsem; on the
 * metadata-hook path i_rwsem is already held by the VFS, which would
 * self-deadlock). We instead pin the dentry and register a task_work that runs
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
