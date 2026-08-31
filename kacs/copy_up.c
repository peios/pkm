// SPDX-License-Identifier: GPL-2.0-only
/*
 * Narrow KACS caller-authorization exemption for StrataFS copy-up.
 *
 * This is deliberately not a generic bypass.  A refcounted context is attached
 * to one task, admits one phase, and compares every hook argument available to
 * that hook against pinned paths/dentries/inodes.  Underlying filesystem and
 * non-KACS security checks are never changed.
 */

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kacs_stratafs.h>
#include <linux/list.h>
#include <linux/limits.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/user_namespace.h>
#include <linux/xattr.h>

#include "copy_up.h"
#include "cred_lifecycle.h"
#include "file_access.h"
#include "file_metadata.h"
#include "file_sd_cache.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "namespace.h"
#include "object_lifecycle.h"

#ifdef CONFIG_SECURITY_PKM_KUNIT
#include <kunit/test.h>
#include "kunit_common.h"
#endif

enum pkm_kacs_copy_up_phase {
	PKM_KACS_COPY_UP_PHASE_NONE = 0,
	PKM_KACS_COPY_UP_PHASE_SOURCE_READ,
	PKM_KACS_COPY_UP_PHASE_CREATE,
	PKM_KACS_COPY_UP_PHASE_POPULATE,
	PKM_KACS_COPY_UP_PHASE_PUBLISH_LINK,
	PKM_KACS_COPY_UP_PHASE_PUBLISH_RENAME,
	PKM_KACS_COPY_UP_PHASE_CLEANUP,
	PKM_KACS_COPY_UP_PHASE_ORPHAN_MARKER,
};

struct pkm_kacs_copy_up_created {
	struct list_head node;
	struct path path;
	struct inode *inode;
	struct path parent;
	struct inode *parent_inode;
};

struct pkm_kacs_stratafs_copy_up {
	refcount_t refs;
	atomic_t attached;
	struct mutex lock;

	struct path provider;
	struct inode *provider_inode;
	struct user_namespace *capability_user_ns;
	u8 *provider_sd;
	size_t provider_sd_len;
	u8 *provider_capability;
	size_t provider_capability_len;
	bool provider_capability_present;
	struct list_head created_objects;

	struct path staging;
	struct path staging_parent;
	struct inode *staging_inode;
	struct inode *staging_parent_inode;
	bool staging_bound;
	struct inode *pending_created_inode;
	bool capability_clone_active;
	bool capability_clone_hook_seen;

	enum pkm_kacs_copy_up_phase phase;
	u64 phase_generation;
	struct path phase_provider;
	struct inode *phase_provider_inode;
	bool phase_provider_pinned;
	u8 *phase_sd;
	size_t phase_sd_len;
	struct path phase_parent;
	struct inode *phase_parent_inode;
	bool phase_parent_pinned;
	struct dentry *phase_dentry;
	char *phase_name;
	u32 phase_name_len;
	struct inode *phase_inode;
	umode_t phase_mode;
	bool phase_anonymous;
	bool phase_directory;
	bool phase_create_seen;
	bool phase_init_security_seen;
	bool phase_stacked_create_seen;
	bool phase_stacked_sd_initialized;
};

static bool pkm_kacs_copy_up_staging_binding_valid(
	const struct pkm_kacs_stratafs_copy_up *context);
static bool pkm_kacs_copy_up_staging_path(
	const struct pkm_kacs_stratafs_copy_up *context,
	const struct path *path, const struct inode *inode);

static bool pkm_kacs_copy_up_path_valid(const struct path *path)
{
	return path && path->mnt && path->dentry && d_is_positive(path->dentry);
}

static bool pkm_kacs_copy_up_path_matches(const struct path *left,
					   const struct path *right)
{
	return left && right && left->mnt && right->mnt && left->dentry &&
	       right->dentry && path_equal(left, right);
}

static struct inode *pkm_kacs_copy_up_pin_path_inode(const struct path *path)
{
	struct inode *inode;

	if (!pkm_kacs_copy_up_path_valid(path))
		return ERR_PTR(-EINVAL);
	inode = igrab(d_inode(path->dentry));
	if (!inode)
		return ERR_PTR(-ESTALE);
	if (!d_is_positive(path->dentry) || d_inode(path->dentry) != inode) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}
	return inode;
}

static bool pkm_kacs_copy_up_path_inode_matches(
	const struct path *left, const struct path *right,
	const struct inode *pinned_inode)
{
	return pinned_inode &&
	       pkm_kacs_copy_up_path_matches(left, right) &&
	       d_inode(right->dentry) == pinned_inode;
}

static bool pkm_kacs_copy_up_dentry_matches_path(
	const struct dentry *dentry, const struct path *path)
{
	return dentry && path && path->dentry == dentry;
}

static bool pkm_kacs_copy_up_inode_matches_path(
	const struct inode *inode, const struct path *path,
	const struct inode *pinned_inode)
{
	return inode && inode == pinned_inode && path && path->dentry &&
	       d_inode(path->dentry) == pinned_inode;
}

static bool pkm_kacs_copy_up_qstr_equal(const struct qstr *left,
					 const struct qstr *right)
{
	return left && right && left->len == right->len &&
	       !memcmp(left->name, right->name, left->len);
}

static bool pkm_kacs_copy_up_mode_supported(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFLNK:
		return true;
	default:
		return false;
	}
}

static bool pkm_kacs_copy_up_read_mask_allowed(const struct inode *inode,
						int mask)
{
	int allowed = MAY_READ | MAY_OPEN | MAY_ACCESS | MAY_NOT_BLOCK;

	if (inode && S_ISDIR(inode->i_mode))
		allowed |= MAY_EXEC | MAY_CHDIR;
	return (mask & ~allowed) == 0;
}

static bool pkm_kacs_copy_up_parent_mask_allowed(int mask)
{
	const int allowed = MAY_WRITE | MAY_EXEC | MAY_OPEN | MAY_ACCESS |
			    MAY_CHDIR | MAY_NOT_BLOCK;

	return (mask & ~allowed) == 0;
}

static bool pkm_kacs_copy_up_staging_mask_allowed(const struct inode *inode,
						   int mask)
{
	int allowed = MAY_READ | MAY_WRITE | MAY_APPEND | MAY_OPEN |
		      MAY_ACCESS | MAY_NOT_BLOCK;

	if (inode && S_ISDIR(inode->i_mode))
		allowed |= MAY_EXEC | MAY_CHDIR;
	return (mask & ~allowed) == 0;
}

static int pkm_kacs_copy_up_copy_effective_sd(const struct path *path,
					       const struct inode *expected_inode,
					       u8 **bytes_out,
					       size_t *len_out)
{
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_security *inode_sec;
	struct file anchor = {};
	struct inode *inode;
	u8 *copy;
	long ret;

	if (!pkm_kacs_copy_up_path_valid(path) || !expected_inode ||
	    d_inode(path->dentry) != expected_inode || !bytes_out || !len_out)
		return -EINVAL;

	inode = d_inode(path->dentry);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return -EOPNOTSUPP;

	pkm_kacs_init_path_anchor_file(&anchor, path);
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
	if (d_inode(path->dentry) != expected_inode) {
		kfree(copy);
		*bytes_out = NULL;
		*len_out = 0;
		return -ESTALE;
	}
	return 0;
}

static int pkm_kacs_copy_up_read_capability(const struct path *path,
					     const struct inode *expected_inode,
					     u8 **bytes_out,
					     size_t *len_out,
					     bool *present_out)
{
	struct inode *inode;
	ssize_t len;
	ssize_t read;
	u8 *bytes;

	if (!pkm_kacs_copy_up_path_valid(path) || !expected_inode ||
	    d_inode(path->dentry) != expected_inode || !bytes_out || !len_out ||
	    !present_out)
		return -EINVAL;
	*bytes_out = NULL;
	*len_out = 0;
	*present_out = false;
	inode = d_inode(path->dentry);

	len = vfs_getxattr(mnt_idmap(path->mnt), path->dentry,
			   XATTR_NAME_CAPS, NULL, 0);
	if (len == -ENODATA || len == -EOPNOTSUPP)
		return 0;
	if (len < 0)
		return (int)len;
	if (!len || len > XATTR_SIZE_MAX)
		return -EACCES;

	bytes = kmalloc(len, GFP_NOFS);
	if (!bytes)
		return -ENOMEM;
	read = vfs_getxattr(mnt_idmap(path->mnt), path->dentry,
			    XATTR_NAME_CAPS, bytes, len);
	if (read < 0) {
		kfree(bytes);
		return (int)read;
	}
	if (read != len || inode != expected_inode ||
	    d_inode(path->dentry) != expected_inode) {
		kfree(bytes);
		return -ESTALE;
	}

	*bytes_out = bytes;
	*len_out = len;
	*present_out = true;
	return 0;
}

static struct pkm_kacs_stratafs_copy_up *
pkm_kacs_copy_up_current(void)
{
	if (!current || !current->security)
		return NULL;
	return pkm_kacs_task(current)->copy_up_context;
}

bool pkm_kacs_copy_up_active(void)
{
	return pkm_kacs_copy_up_current() != NULL;
}

static bool pkm_kacs_copy_up_owned(
	const struct pkm_kacs_stratafs_copy_up *context)
{
	return context && pkm_kacs_copy_up_current() == context &&
	       atomic_read(&context->attached) == 1;
}

static int pkm_kacs_copy_up_arm_phase_locked(
	struct pkm_kacs_stratafs_copy_up *context,
	enum pkm_kacs_copy_up_phase phase)
{
	if (context->phase != PKM_KACS_COPY_UP_PHASE_NONE)
		return -EBUSY;
	if (context->phase_generation == U64_MAX)
		return -EOVERFLOW;

	context->phase_generation++;
	context->phase = phase;
	return 0;
}

static void pkm_kacs_copy_up_clear_phase_locked(
	struct pkm_kacs_stratafs_copy_up *context)
{
	struct dentry *phase_dentry;

	/* Disable hook-side matching before any release can re-enter the VFS. */
	context->phase = PKM_KACS_COPY_UP_PHASE_NONE;
	if (context->phase_provider_pinned) {
		context->phase_provider_pinned = false;
		path_put(&context->phase_provider);
		memset(&context->phase_provider, 0,
		       sizeof(context->phase_provider));
	}
	if (context->phase_provider_inode) {
		iput(context->phase_provider_inode);
		context->phase_provider_inode = NULL;
	}
	if (context->phase_parent_pinned) {
		context->phase_parent_pinned = false;
		path_put(&context->phase_parent);
		memset(&context->phase_parent, 0, sizeof(context->phase_parent));
	}
	if (context->phase_parent_inode) {
		iput(context->phase_parent_inode);
		context->phase_parent_inode = NULL;
	}
	phase_dentry = context->phase_dentry;
	context->phase_dentry = NULL;
	if (phase_dentry)
		dput(phase_dentry);
	kfree(context->phase_name);
	context->phase_name = NULL;
	context->phase_name_len = 0;
	if (context->phase_inode) {
		iput(context->phase_inode);
		context->phase_inode = NULL;
	}
	kfree(context->phase_sd);
	context->phase_sd = NULL;
	context->phase_sd_len = 0;
	context->phase_mode = 0;
	context->phase_anonymous = false;
	context->phase_directory = false;
	context->phase_create_seen = false;
	context->phase_init_security_seen = false;
	context->phase_stacked_create_seen = false;
	context->phase_stacked_sd_initialized = false;
	context->capability_clone_active = false;
	context->capability_clone_hook_seen = false;
}

static void pkm_kacs_copy_up_destroy(
	struct pkm_kacs_stratafs_copy_up *context)
{
	struct pkm_kacs_copy_up_created *created;
	struct pkm_kacs_copy_up_created *next;

	if (!context)
		return;

	mutex_lock(&context->lock);
	pkm_kacs_copy_up_clear_phase_locked(context);
	if (context->staging_bound) {
		path_put(&context->staging_parent);
		path_put(&context->staging);
	}
	if (context->staging_inode)
		iput(context->staging_inode);
	if (context->staging_parent_inode)
		iput(context->staging_parent_inode);
	if (context->pending_created_inode)
		iput(context->pending_created_inode);
	list_for_each_entry_safe(created, next, &context->created_objects,
				 node) {
		list_del(&created->node);
		path_put(&created->path);
		iput(created->inode);
		path_put(&created->parent);
		iput(created->parent_inode);
		kfree(created);
	}
	path_put(&context->provider);
	if (context->provider_inode)
		iput(context->provider_inode);
	put_user_ns(context->capability_user_ns);
	mutex_unlock(&context->lock);
	mutex_destroy(&context->lock);
	kfree(context->provider_sd);
	kfree(context->provider_capability);
	kfree(context);
}

struct pkm_kacs_stratafs_copy_up *
pkm_kacs_stratafs_copy_up_get(struct pkm_kacs_stratafs_copy_up *context)
{
	if (!context || !refcount_inc_not_zero(&context->refs))
		return NULL;
	return context;
}

void pkm_kacs_stratafs_copy_up_put(
	struct pkm_kacs_stratafs_copy_up *context)
{
	if (context && refcount_dec_and_test(&context->refs))
		pkm_kacs_copy_up_destroy(context);
}

static struct pkm_kacs_stratafs_copy_up *
pkm_kacs_copy_up_alloc(const struct path *provider,
		       struct inode *provider_inode, u8 *sd_bytes, size_t sd_len)
{
	struct pkm_kacs_stratafs_copy_up *context;

	if (!pkm_kacs_copy_up_path_valid(provider) || !provider_inode ||
	    d_inode(provider->dentry) != provider_inode || !sd_bytes || !sd_len)
		return ERR_PTR(-EINVAL);

	context = kzalloc_obj(*context, GFP_NOFS);
	if (!context)
		return ERR_PTR(-ENOMEM);

	refcount_set(&context->refs, 1);
	atomic_set(&context->attached, 0);
	mutex_init(&context->lock);
	INIT_LIST_HEAD(&context->created_objects);
	context->provider = *provider;
	path_get(&context->provider);
	context->provider_inode = provider_inode;
	context->capability_user_ns = get_user_ns(current_user_ns());
	context->provider_sd = sd_bytes;
	context->provider_sd_len = sd_len;
	return context;
}

int pkm_kacs_stratafs_copy_up_enter(
	struct pkm_kacs_stratafs_copy_up *context)
{
	struct pkm_kacs_task_security *task_sec;

	if (!context || !current || !current->security)
		return -EINVAL;
	task_sec = pkm_kacs_task(current);
	if (task_sec->copy_up_context)
		return -EBUSY;
	if (atomic_cmpxchg(&context->attached, 0, 1) != 0)
		return -EBUSY;
	if (!pkm_kacs_stratafs_copy_up_get(context)) {
		atomic_set(&context->attached, 0);
		return -EINVAL;
	}
	task_sec->copy_up_context = context;
	return 0;
}

void pkm_kacs_stratafs_copy_up_leave(
	struct pkm_kacs_stratafs_copy_up *context)
{
	struct pkm_kacs_task_security *task_sec;

	if (!context || !current || !current->security)
		return;
	task_sec = pkm_kacs_task(current);
	if (task_sec->copy_up_context != context)
		return;

	mutex_lock(&context->lock);
	pkm_kacs_copy_up_clear_phase_locked(context);
	mutex_unlock(&context->lock);
	task_sec->copy_up_context = NULL;
	atomic_set(&context->attached, 0);
	pkm_kacs_stratafs_copy_up_put(context);
}

void pkm_kacs_copy_up_task_exit(struct task_struct *task)
{
	struct pkm_kacs_stratafs_copy_up *context;
	struct pkm_kacs_task_security *task_sec;

	if (!task || !task->security)
		return;
	task_sec = pkm_kacs_task(task);
	context = task_sec->copy_up_context;
	if (!context)
		return;

	mutex_lock(&context->lock);
	pkm_kacs_copy_up_clear_phase_locked(context);
	mutex_unlock(&context->lock);
	task_sec->copy_up_context = NULL;
	atomic_set(&context->attached, 0);
	pkm_kacs_stratafs_copy_up_put(context);
}

struct pkm_kacs_stratafs_copy_up *
pkm_kacs_stratafs_copy_up_begin(const struct path *provider)
{
	struct pkm_kacs_stratafs_copy_up *context;
	struct inode *provider_inode;
	u8 *capability = NULL;
	u8 *sd_bytes = NULL;
	size_t capability_len = 0;
	size_t sd_len = 0;
	bool capability_present = false;
	int ret;

	provider_inode = pkm_kacs_copy_up_pin_path_inode(provider);
	if (IS_ERR(provider_inode))
		return ERR_CAST(provider_inode);
	ret = pkm_kacs_copy_up_copy_effective_sd(
		provider, provider_inode, &sd_bytes, &sd_len);
	if (ret)
		goto out_put_provider;
	context = pkm_kacs_copy_up_alloc(
		provider, provider_inode, sd_bytes, sd_len);
	if (IS_ERR(context)) {
		kfree(sd_bytes);
		ret = PTR_ERR(context);
		goto out_put_provider;
	}
	provider_inode = NULL;
	ret = pkm_kacs_stratafs_copy_up_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_put(context);
		return ERR_PTR(ret);
	}
	ret = pkm_kacs_stratafs_copy_up_begin_source_read(context);
	if (!ret)
		ret = pkm_kacs_copy_up_read_capability(
			&context->provider, context->provider_inode,
			&capability, &capability_len,
			&capability_present);
	pkm_kacs_stratafs_copy_up_end_phase(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_leave(context);
		pkm_kacs_stratafs_copy_up_put(context);
		return ERR_PTR(ret);
	}
	context->provider_capability = capability;
	context->provider_capability_len = capability_len;
	context->provider_capability_present = capability_present;
	return context;
out_put_provider:
	iput(provider_inode);
	return ERR_PTR(ret);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
struct pkm_kacs_stratafs_copy_up *
pkm_kacs_kunit_copy_up_begin_with_sd(const struct path *provider,
				      const u8 *sd_bytes, size_t sd_len)
{
	struct pkm_kacs_stratafs_copy_up *context;
	struct inode *provider_inode;
	u8 *copy;
	int ret;

	if (!sd_bytes || !sd_len)
		return ERR_PTR(-EINVAL);
	copy = kmemdup(sd_bytes, sd_len, GFP_KERNEL);
	if (!copy)
		return ERR_PTR(-ENOMEM);
	provider_inode = pkm_kacs_copy_up_pin_path_inode(provider);
	if (IS_ERR(provider_inode)) {
		kfree(copy);
		return ERR_CAST(provider_inode);
	}
	context = pkm_kacs_copy_up_alloc(
		provider, provider_inode, copy, sd_len);
	if (IS_ERR(context)) {
		iput(provider_inode);
		kfree(copy);
		return context;
	}
	ret = pkm_kacs_stratafs_copy_up_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_put(context);
		return ERR_PTR(ret);
	}
	return context;
}
#endif

static int pkm_kacs_copy_up_begin_simple_phase(
	struct pkm_kacs_stratafs_copy_up *context,
	enum pkm_kacs_copy_up_phase phase)
{
	int ret = 0;

	if (!pkm_kacs_copy_up_owned(context))
		return -EPERM;
	mutex_lock(&context->lock);
	ret = pkm_kacs_copy_up_arm_phase_locked(context, phase);
	mutex_unlock(&context->lock);
	return ret;
}

int pkm_kacs_stratafs_copy_up_begin_source_read(
	struct pkm_kacs_stratafs_copy_up *context)
{
	return pkm_kacs_copy_up_begin_simple_phase(
		context, PKM_KACS_COPY_UP_PHASE_SOURCE_READ);
}

static int pkm_kacs_copy_up_begin_create_common(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *provider, const struct path *destination_parent,
	struct dentry *destination, umode_t mode, bool anonymous)
{
	struct inode *parent_inode;
	struct inode *provider_inode;
	u8 *sd_bytes = NULL;
	size_t sd_len = 0;
	int ret;

	if (!pkm_kacs_copy_up_owned(context) ||
	    !pkm_kacs_copy_up_path_valid(provider) ||
	    !pkm_kacs_copy_up_path_valid(destination_parent) ||
	    !S_ISDIR(d_inode(destination_parent->dentry)->i_mode) ||
	    !pkm_kacs_copy_up_mode_supported(mode))
		return -EINVAL;
	if (!anonymous &&
	    (!destination || d_inode(destination) ||
	     !d_is_negative(destination) ||
	     destination->d_parent != destination_parent->dentry))
		return -EINVAL;
	if (anonymous && destination)
		return -EINVAL;
	provider_inode = pkm_kacs_copy_up_pin_path_inode(provider);
	if (IS_ERR(provider_inode))
		return PTR_ERR(provider_inode);
	parent_inode = pkm_kacs_copy_up_pin_path_inode(destination_parent);
	if (IS_ERR(parent_inode)) {
		ret = PTR_ERR(parent_inode);
		goto out_put_provider;
	}

	if (pkm_kacs_copy_up_path_matches(provider, &context->provider)) {
		if (provider_inode != context->provider_inode ||
		    d_inode(context->provider.dentry) !=
			    context->provider_inode) {
			ret = -ESTALE;
			goto out_put_parent;
		}
		sd_bytes = kmemdup(context->provider_sd,
				     context->provider_sd_len, GFP_NOFS);
		if (!sd_bytes) {
			ret = -ENOMEM;
			goto out_put_parent;
		}
		sd_len = context->provider_sd_len;
		ret = 0;
	} else {
		ret = pkm_kacs_copy_up_copy_effective_sd(
			provider, provider_inode, &sd_bytes, &sd_len);
	}
	if (ret)
		goto out_put_parent;

	mutex_lock(&context->lock);
	ret = pkm_kacs_copy_up_arm_phase_locked(
		context, PKM_KACS_COPY_UP_PHASE_CREATE);
	if (ret)
		goto out_unlock;
	if (context->pending_created_inode) {
		iput(context->pending_created_inode);
		context->pending_created_inode = NULL;
	}
	context->phase_provider = *provider;
	path_get(&context->phase_provider);
	context->phase_provider_inode = provider_inode;
	provider_inode = NULL;
	context->phase_provider_pinned = true;
	context->phase_parent = *destination_parent;
	path_get(&context->phase_parent);
	context->phase_parent_inode = parent_inode;
	parent_inode = NULL;
	context->phase_parent_pinned = true;
	if (destination)
		context->phase_dentry = dget(destination);
	context->phase_sd = sd_bytes;
	context->phase_sd_len = sd_len;
	context->phase_mode = mode;
	context->phase_anonymous = anonymous;
	sd_bytes = NULL;
	ret = 0;
out_unlock:
	mutex_unlock(&context->lock);
	kfree(sd_bytes);
out_put_parent:
	iput(parent_inode);
out_put_provider:
	iput(provider_inode);
	return ret;
}

int pkm_kacs_stratafs_copy_up_begin_create(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *provider,
	const struct path *destination_parent, struct dentry *destination,
	umode_t mode)
{
	return pkm_kacs_copy_up_begin_create_common(
		context, provider, destination_parent, destination, mode, false);
}

int pkm_kacs_stratafs_copy_up_begin_anonymous_create(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *provider,
	const struct path *destination_parent, umode_t mode)
{
	return pkm_kacs_copy_up_begin_create_common(
		context, provider, destination_parent, NULL, mode, true);
}

/*
 * A stacking filesystem such as overlayfs creates the real inode below the
 * dentry on which StrataFS armed the create phase.  Record only the exact
 * outer create transition; inode_init_security can then stamp the real inode
 * with the provider SD without turning the phase into a filesystem-wide
 * exemption.
 */
int pkm_kacs_copy_up_dentry_create_files_as(
	struct dentry *dentry, int mode, const struct qstr *name,
	const struct cred *old, struct cred *new)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool matches;

	(void)name;
	(void)old;
	(void)new;
	if (!context || !dentry ||
	    context->phase != PKM_KACS_COPY_UP_PHASE_CREATE ||
	    !context->phase_parent_pinned ||
	    dentry->d_parent != context->phase_parent.dentry ||
	    d_inode(dentry->d_parent) != context->phase_parent_inode ||
	    (mode & S_IFMT) != (context->phase_mode & S_IFMT))
		return 0;

	matches = context->phase_anonymous ? !context->phase_dentry :
					      dentry == context->phase_dentry;
	if (!matches)
		return 0;
	if (d_inode(dentry) || !d_is_negative(dentry) ||
	    (!context->phase_anonymous && !context->phase_create_seen))
		return -EACCES;
	if (context->phase_stacked_create_seen)
		return -EACCES;
	context->phase_stacked_create_seen = true;
	return 0;
}

void pkm_kacs_copy_up_post_create_tmpfile(struct mnt_idmap *idmap,
					  struct inode *inode)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	struct inode *pending;

	(void)idmap;
	if (!context || !inode ||
	    context->phase != PKM_KACS_COPY_UP_PHASE_CREATE ||
	    !context->phase_anonymous ||
	    !context->phase_stacked_create_seen ||
	    !context->phase_stacked_sd_initialized ||
	    context->pending_created_inode ||
	    !context->phase_parent_inode ||
	    inode->i_sb != context->phase_parent_inode->i_sb ||
	    (inode->i_mode & S_IFMT) != (context->phase_mode & S_IFMT))
		return;

	/* The outer VFS post-create hook is the first exact outer inode anchor. */
	pending = igrab(inode);
	if (pending)
		context->pending_created_inode = pending;
}

static struct pkm_kacs_copy_up_created *
pkm_kacs_copy_up_created_alloc(const struct path *parent,
			       struct inode *parent_inode,
			       struct dentry *dentry, struct inode *inode)
{
	struct pkm_kacs_copy_up_created *created;

	created = kzalloc_obj(*created, GFP_NOFS);
	if (!created)
		return NULL;
	created->path.mnt = mntget(parent->mnt);
	created->path.dentry = dget(dentry);
	created->inode = igrab(inode);
	created->parent = *parent;
	path_get(&created->parent);
	created->parent_inode = igrab(parent_inode);
	if (!created->inode || !created->parent_inode) {
		path_put(&created->path);
		iput(created->inode);
		path_put(&created->parent);
		iput(created->parent_inode);
		kfree(created);
		return NULL;
	}
	return created;
}

int pkm_kacs_stratafs_copy_up_confirm_named_create(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *created_path)
{
	struct pkm_kacs_copy_up_created *created;
	struct inode *inode;

	if (!pkm_kacs_copy_up_owned(context) ||
	    !pkm_kacs_copy_up_path_valid(created_path))
		return -EINVAL;
	inode = d_inode(created_path->dentry);
	if (context->phase != PKM_KACS_COPY_UP_PHASE_CREATE ||
	    context->phase_anonymous || !context->phase_create_seen ||
	    created_path->mnt != context->phase_parent.mnt ||
	    created_path->dentry != context->phase_dentry ||
	    created_path->dentry->d_parent != context->phase_parent.dentry ||
	    d_inode(context->phase_parent.dentry) != context->phase_parent_inode ||
	    (inode->i_mode & S_IFMT) != (context->phase_mode & S_IFMT))
		return -ESTALE;

	/* A direct filesystem was already captured by inode_init_security. */
	if (context->phase_init_security_seen &&
	    context->pending_created_inode == inode &&
	    !context->phase_stacked_create_seen)
		return 0;
	if (!context->phase_stacked_create_seen ||
	    !context->phase_stacked_sd_initialized ||
	    context->pending_created_inode)
		return -EACCES;

	created = pkm_kacs_copy_up_created_alloc(
		&context->phase_parent, context->phase_parent_inode,
		created_path->dentry, inode);
	if (!created)
		return -ENOMEM;
	context->pending_created_inode = igrab(inode);
	if (!context->pending_created_inode) {
		path_put(&created->path);
		iput(created->inode);
		path_put(&created->parent);
		iput(created->parent_inode);
		kfree(created);
		return -ESTALE;
	}
	list_add_tail(&created->node, &context->created_objects);
	return 0;
}

int pkm_kacs_stratafs_copy_up_bind_staging(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *staging)
{
	struct inode *staging_parent_inode;
	struct path staging_parent;
	int ret = 0;

	if (!pkm_kacs_copy_up_owned(context) ||
	    !pkm_kacs_copy_up_path_valid(staging))
		return -EINVAL;
	if (!pkm_kacs_copy_up_mode_supported(d_inode(staging->dentry)->i_mode))
		return -EOPNOTSUPP;
	staging_parent.mnt = mntget(staging->mnt);
	staging_parent.dentry = dget_parent(staging->dentry);
	if (!pkm_kacs_copy_up_path_valid(&staging_parent)) {
		path_put(&staging_parent);
		return -ESTALE;
	}
	staging_parent_inode = pkm_kacs_copy_up_pin_path_inode(&staging_parent);
	if (IS_ERR(staging_parent_inode)) {
		ret = PTR_ERR(staging_parent_inode);
		path_put(&staging_parent);
		return ret;
	}

	mutex_lock(&context->lock);
	if (context->phase != PKM_KACS_COPY_UP_PHASE_NONE ||
	    context->staging_bound || !context->pending_created_inode ||
	    context->pending_created_inode != d_inode(staging->dentry) ||
	    staging->dentry->d_parent != staging_parent.dentry ||
	    d_inode(staging_parent.dentry) != staging_parent_inode) {
		ret = -EBUSY;
	} else {
		context->staging = *staging;
		path_get(&context->staging);
		context->staging_parent = staging_parent;
		memset(&staging_parent, 0, sizeof(staging_parent));
		context->staging_inode = context->pending_created_inode;
		context->staging_parent_inode = staging_parent_inode;
		staging_parent_inode = NULL;
		context->staging_bound = true;
		context->pending_created_inode = NULL;
	}
	mutex_unlock(&context->lock);
	if (staging_parent.dentry)
		path_put(&staging_parent);
	iput(staging_parent_inode);
	return ret;
}

int pkm_kacs_stratafs_copy_up_rebind_staging(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *published)
{
	struct inode *published_inode;
	struct dentry *published_parent;
	int ret = 0;

	if (!pkm_kacs_copy_up_owned(context) ||
	    !pkm_kacs_copy_up_path_valid(published))
		return -EINVAL;
	published_inode = igrab(d_inode(published->dentry));
	if (!published_inode)
		return -ESTALE;
	published_parent = dget_parent(published->dentry);

	mutex_lock(&context->lock);
	if (context->phase != PKM_KACS_COPY_UP_PHASE_NONE ||
	    !context->staging_bound ||
	    published_inode != context->staging_inode ||
	    published->mnt != context->staging.mnt ||
	    published_parent != context->staging_parent.dentry ||
	    d_inode(published_parent) != context->staging_parent_inode) {
		ret = -ESTALE;
		goto out;
	}
	path_put(&context->staging);
	context->staging = *published;
	path_get(&context->staging);
out:
	mutex_unlock(&context->lock);
	dput(published_parent);
	iput(published_inode);
	return ret;
}

static int pkm_kacs_copy_up_adopt_file_security(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct pkm_kacs_file_security *outer_sec,
	struct pkm_kacs_file_security *backing_sec,
	struct pkm_kacs_backing_file_security *backing_auth)
{
	struct pkm_kacs_stratafs_copy_up *file_context;

	if (!context || !outer_sec || !backing_sec || !backing_auth ||
	    !outer_sec->managed ||
	    outer_sec->copy_up_context ||
	    backing_sec->copy_up_context != context ||
	    backing_sec->copy_up_phase_generation != context->phase_generation ||
	    backing_auth->managed || backing_auth->inherited)
		return -EACCES;

	backing_sec->granted_access = outer_sec->granted_access;
	backing_sec->continuous_audit_mask = outer_sec->continuous_audit_mask;
	backing_sec->managed = 1;
	backing_auth->granted_access = outer_sec->granted_access;
	backing_auth->continuous_audit_mask = outer_sec->continuous_audit_mask;
	backing_auth->managed = 1;
	backing_auth->inherited = 1;
	file_context = backing_sec->copy_up_context;
	backing_sec->copy_up_context = NULL;
	backing_sec->copy_up_phase_generation = 0;
	pkm_kacs_stratafs_copy_up_put(file_context);
	return 0;
}

int pkm_kacs_stratafs_copy_up_adopt_backing_file(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct file *outer_file, struct file *backing_file)
{
	struct pkm_kacs_file_security *outer_sec;
	struct pkm_kacs_file_security *backing_sec;
	struct pkm_kacs_backing_file_security *backing_auth;
	const struct path *user_path;

	if (!pkm_kacs_copy_up_owned(context) || !outer_file ||
	    !backing_file || !outer_file->f_security ||
	    !backing_file->f_security ||
	    !(backing_file->f_mode & FMODE_BACKING))
		return -EINVAL;
	if (context->phase != PKM_KACS_COPY_UP_PHASE_NONE ||
	    !pkm_kacs_copy_up_staging_path(
		    context, &backing_file->f_path, file_inode(backing_file)))
		return -ESTALE;
	user_path = backing_file_user_path(backing_file);
	if (!user_path || !path_equal(user_path, &outer_file->f_path) ||
	    d_inode(user_path->dentry) != file_inode((struct file *)outer_file))
		return -ESTALE;

	outer_sec = pkm_kacs_file((struct file *)outer_file);
	backing_sec = pkm_kacs_file(backing_file);
	backing_auth = pkm_kacs_backing_file(backing_file);

	/*
	 * The outer descriptor's immutable access snapshot is the authority
	 * for the operation that caused copy-up.  The published object has the
	 * exact same descriptor, so transferring that snapshot preserves file
	 * descriptor delegation without consulting the token currently using
	 * it.  Exact staging and user-path bindings above prevent this from
	 * becoming a general snapshot-cloning primitive.
	 */
	return pkm_kacs_copy_up_adopt_file_security(
		context, outer_sec, backing_sec, backing_auth);
}

int pkm_kacs_stratafs_copy_up_begin_populate(
	struct pkm_kacs_stratafs_copy_up *context)
{
	int ret;

	if (!pkm_kacs_copy_up_owned(context))
		return -EPERM;
	mutex_lock(&context->lock);
	if (!pkm_kacs_copy_up_staging_binding_valid(context)) {
		mutex_unlock(&context->lock);
		return -EINVAL;
	}
	ret = pkm_kacs_copy_up_arm_phase_locked(
		context, PKM_KACS_COPY_UP_PHASE_POPULATE);
	mutex_unlock(&context->lock);
	return ret;
}

static int pkm_kacs_copy_up_validate_capability_clone(
	const struct pkm_kacs_stratafs_copy_up *context, const void *value,
	size_t size)
{
	if (!context || context->phase != PKM_KACS_COPY_UP_PHASE_POPULATE ||
	    current_user_ns() != context->capability_user_ns ||
	    !pkm_kacs_copy_up_staging_binding_valid(context))
		return -EPERM;
	if (!context->provider_capability_present ||
	    size != context->provider_capability_len ||
	    memcmp(value, context->provider_capability, size))
		return -ESTALE;
	return 0;
}

int pkm_kacs_stratafs_copy_up_set_capability(
	struct pkm_kacs_stratafs_copy_up *context, const void *value,
	size_t size)
{
	u8 *current_value = NULL;
	u8 *value_copy;
	size_t current_size = 0;
	bool current_present = false;
	int ret;

	if (!pkm_kacs_copy_up_owned(context) || !value || !size ||
	    size > XATTR_SIZE_MAX)
		return -EINVAL;
	value_copy = kmemdup(value, size, GFP_NOFS);
	if (!value_copy)
		return -ENOMEM;

	ret = pkm_kacs_copy_up_validate_capability_clone(
		context, value_copy, size);
	if (ret)
		goto out;

	/* Re-read immediately before installation so a revoked value is stale. */
	ret = pkm_kacs_copy_up_read_capability(
		&context->provider, context->provider_inode,
		&current_value, &current_size,
		&current_present);
	if (ret)
		goto out;
	if (!current_present || current_size != size ||
	    memcmp(current_value, value_copy, size)) {
		ret = -ESTALE;
		goto out;
	}

	context->capability_clone_hook_seen = false;
	context->capability_clone_active = true;
	ret = vfs_setxattr(mnt_idmap(context->staging.mnt),
			   context->staging.dentry, XATTR_NAME_CAPS,
			   value_copy, size, XATTR_CREATE);
	context->capability_clone_active = false;
	context->capability_clone_hook_seen = false;
out:
	kfree(current_value);
	kfree(value_copy);
	return ret;
}

static int pkm_kacs_copy_up_begin_publish(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *destination_parent, struct dentry *destination,
	enum pkm_kacs_copy_up_phase phase)
{
	struct inode *parent_inode;
	char *phase_name = NULL;
	int ret = 0;

	if (!pkm_kacs_copy_up_owned(context) ||
	    !pkm_kacs_copy_up_path_valid(destination_parent) ||
	    !S_ISDIR(d_inode(destination_parent->dentry)->i_mode) ||
	    !destination || d_inode(destination) ||
	    !d_is_negative(destination) ||
	    destination->d_parent != destination_parent->dentry)
		return -EINVAL;
	if (phase == PKM_KACS_COPY_UP_PHASE_PUBLISH_RENAME) {
		phase_name = kmemdup_nul(destination->d_name.name,
					   destination->d_name.len, GFP_NOFS);
		if (!phase_name)
			return -ENOMEM;
	}
	parent_inode = pkm_kacs_copy_up_pin_path_inode(destination_parent);
	if (IS_ERR(parent_inode)) {
		kfree(phase_name);
		return PTR_ERR(parent_inode);
	}

	mutex_lock(&context->lock);
	if (!pkm_kacs_copy_up_staging_binding_valid(context)) {
		ret = -EINVAL;
		goto out;
	}
	ret = pkm_kacs_copy_up_arm_phase_locked(context, phase);
	if (ret)
		goto out;
	context->phase_parent = *destination_parent;
	path_get(&context->phase_parent);
	context->phase_parent_inode = parent_inode;
	parent_inode = NULL;
	context->phase_parent_pinned = true;
	context->phase_dentry = dget(destination);
	context->phase_name = phase_name;
	context->phase_name_len = destination->d_name.len;
	phase_name = NULL;
out:
	mutex_unlock(&context->lock);
	iput(parent_inode);
	kfree(phase_name);
	return ret;
}

int pkm_kacs_stratafs_copy_up_begin_publish_link(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *destination_parent, struct dentry *destination)
{
	return pkm_kacs_copy_up_begin_publish(
		context, destination_parent, destination,
		PKM_KACS_COPY_UP_PHASE_PUBLISH_LINK);
}

int pkm_kacs_stratafs_copy_up_begin_publish_rename(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *destination_parent, struct dentry *destination)
{
	return pkm_kacs_copy_up_begin_publish(
		context, destination_parent, destination,
		PKM_KACS_COPY_UP_PHASE_PUBLISH_RENAME);
}

static bool pkm_kacs_copy_up_published_object_matches(
	const struct pkm_kacs_stratafs_copy_up *context,
	const struct path *published)
{
	if (!context || !published || !published->dentry)
		return false;

	if (context->phase == PKM_KACS_COPY_UP_PHASE_PUBLISH_LINK)
		return published->dentry == context->phase_dentry;
	if (context->phase != PKM_KACS_COPY_UP_PHASE_PUBLISH_RENAME)
		return false;

	/*
	 * vfs_rename() moves the source dentry to the destination name.  The
	 * destination dentry passed to vfs_rename() is only the pre-operation
	 * lookup placeholder and must never be accepted as the published object.
	 */
	return published->dentry == context->staging.dentry &&
	       context->phase_name &&
	       published->dentry->d_name.len == context->phase_name_len &&
	       !memcmp(published->dentry->d_name.name, context->phase_name,
		       context->phase_name_len);
}

int pkm_kacs_stratafs_copy_up_finish_publish(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *published)
{
	struct dentry *published_parent;
	struct inode *published_inode;
	bool object_matches;
	int ret = 0;

	if (!pkm_kacs_copy_up_owned(context) ||
	    !pkm_kacs_copy_up_path_valid(published))
		return -EINVAL;
	published_inode = d_inode(published->dentry);
	published_parent = published->dentry->d_parent;

	mutex_lock(&context->lock);
	object_matches = pkm_kacs_copy_up_published_object_matches(context,
								 published);
	if (!object_matches ||
	    !context->phase_parent_pinned || !context->phase_dentry ||
	    published->mnt != context->phase_parent.mnt ||
	    published_parent != context->phase_parent.dentry ||
	    d_inode(published_parent) != context->phase_parent_inode ||
	    published_inode != context->staging_inode ||
	    !d_is_positive(published->dentry)) {
		ret = -ESTALE;
		goto out;
	}

	/*
	 * Commit the published name while the exact publish phase is still
	 * armed.  This closes the gap in which a successful VFS link/rename had
	 * become visible but cleanup authorization was still bound only to the
	 * former staging name.
	 */
	if (context->phase == PKM_KACS_COPY_UP_PHASE_PUBLISH_LINK) {
		path_put(&context->staging);
		context->staging = *published;
		path_get(&context->staging);
	}
out:
	pkm_kacs_copy_up_clear_phase_locked(context);
	mutex_unlock(&context->lock);
	return ret;
}

static bool pkm_kacs_copy_up_cleanup_target_tracked_locked(
	const struct pkm_kacs_stratafs_copy_up *context,
	const struct path *parent, const struct inode *parent_inode,
	const struct dentry *victim, const struct inode *victim_inode)
{
	struct pkm_kacs_copy_up_created *created;
	struct path victim_path = {
		.mnt = parent->mnt,
		.dentry = (struct dentry *)victim,
	};

	if (pkm_kacs_copy_up_staging_binding_valid(context) &&
	    pkm_kacs_copy_up_path_inode_matches(
		    &context->staging_parent, parent,
		    context->staging_parent_inode) &&
	    pkm_kacs_copy_up_path_inode_matches(
		    &context->staging, &victim_path, context->staging_inode) &&
	    parent_inode == context->staging_parent_inode &&
	    victim_inode == context->staging_inode)
		return true;

	list_for_each_entry(created, &context->created_objects, node) {
		if (pkm_kacs_copy_up_path_inode_matches(
			    &created->parent, parent, created->parent_inode) &&
		    pkm_kacs_copy_up_path_inode_matches(
			    &created->path, &victim_path, created->inode) &&
		    parent_inode == created->parent_inode &&
		    victim_inode == created->inode)
			return true;
	}
	return false;
}

int pkm_kacs_stratafs_copy_up_begin_cleanup(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *parent,
	struct dentry *victim, bool directory)
{
	struct inode *parent_inode;
	struct inode *victim_inode;
	int ret = 0;

	if (!pkm_kacs_copy_up_owned(context) ||
	    !pkm_kacs_copy_up_path_valid(parent) ||
	    !S_ISDIR(d_inode(parent->dentry)->i_mode) || !victim)
		return -EINVAL;
	parent_inode = pkm_kacs_copy_up_pin_path_inode(parent);
	if (IS_ERR(parent_inode))
		return PTR_ERR(parent_inode);
	victim_inode = d_inode(victim);
	if (!victim_inode || !d_is_positive(victim)) {
		iput(parent_inode);
		return -ESTALE;
	}
	victim_inode = igrab(victim_inode);
	if (!victim_inode) {
		iput(parent_inode);
		return -ESTALE;
	}
	if (!d_is_positive(victim) || victim->d_parent != parent->dentry ||
	    d_inode(victim) != victim_inode ||
	    d_inode(parent->dentry) != parent_inode ||
	    (!!S_ISDIR(victim_inode->i_mode) != directory)) {
		iput(victim_inode);
		iput(parent_inode);
		return -ESTALE;
	}

	mutex_lock(&context->lock);
	if (!d_is_positive(victim) || victim->d_parent != parent->dentry ||
	    d_inode(victim) != victim_inode ||
	    d_inode(parent->dentry) != parent_inode ||
	    !pkm_kacs_copy_up_cleanup_target_tracked_locked(
		    context, parent, parent_inode, victim, victim_inode)) {
		ret = -ESTALE;
		goto out;
	}
	ret = pkm_kacs_copy_up_arm_phase_locked(
		context, PKM_KACS_COPY_UP_PHASE_CLEANUP);
	if (ret)
		goto out;
	context->phase_parent = *parent;
	path_get(&context->phase_parent);
	context->phase_parent_inode = parent_inode;
	parent_inode = NULL;
	context->phase_parent_pinned = true;
	context->phase_dentry = dget(victim);
	context->phase_inode = victim_inode;
	victim_inode = NULL;
	context->phase_directory = directory;
out:
	mutex_unlock(&context->lock);
	if (victim_inode)
		iput(victim_inode);
	iput(parent_inode);
	return ret;
}

int pkm_kacs_stratafs_copy_up_begin_orphan_cleanup(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *parent,
	struct dentry *victim, bool directory)
{
	struct inode *parent_inode;
	struct inode *victim_inode;
	int ret = 0;

	if (!pkm_kacs_copy_up_owned(context) ||
	    !pkm_kacs_copy_up_path_valid(parent) ||
	    !S_ISDIR(d_inode(parent->dentry)->i_mode) || !victim)
		return -EINVAL;
	parent_inode = pkm_kacs_copy_up_pin_path_inode(parent);
	if (IS_ERR(parent_inode))
		return PTR_ERR(parent_inode);
	victim_inode = pkm_kacs_copy_up_pin_path_inode(&context->provider);
	if (IS_ERR(victim_inode)) {
		ret = PTR_ERR(victim_inode);
		goto out_parent;
	}

	mutex_lock(&context->lock);
	if (context->phase != PKM_KACS_COPY_UP_PHASE_NONE ||
	    victim != context->provider.dentry ||
	    victim->d_parent != parent->dentry ||
	    d_inode(victim) != victim_inode ||
	    d_inode(parent->dentry) != parent_inode ||
	    (!!S_ISDIR(victim_inode->i_mode) != directory)) {
		ret = -ESTALE;
		goto out_unlock;
	}
	ret = pkm_kacs_copy_up_arm_phase_locked(
		context, PKM_KACS_COPY_UP_PHASE_CLEANUP);
	if (ret)
		goto out_unlock;
	context->phase_parent = *parent;
	path_get(&context->phase_parent);
	context->phase_parent_inode = parent_inode;
	parent_inode = NULL;
	context->phase_parent_pinned = true;
	context->phase_dentry = dget(victim);
	context->phase_inode = victim_inode;
	victim_inode = NULL;
	context->phase_directory = directory;
out_unlock:
	mutex_unlock(&context->lock);
	iput(victim_inode);
out_parent:
	iput(parent_inode);
	return ret;
}

int pkm_kacs_stratafs_copy_up_begin_orphan_marker_cleanup(
	struct pkm_kacs_stratafs_copy_up *context)
{
	if (!pkm_kacs_copy_up_owned(context) ||
	    !pkm_kacs_copy_up_path_valid(&context->provider) ||
	    d_inode(context->provider.dentry) != context->provider_inode)
		return -ESTALE;
	return pkm_kacs_copy_up_begin_simple_phase(
		context, PKM_KACS_COPY_UP_PHASE_ORPHAN_MARKER);
}

void pkm_kacs_stratafs_copy_up_end_phase(
	struct pkm_kacs_stratafs_copy_up *context)
{
	if (!pkm_kacs_copy_up_owned(context))
		return;
	mutex_lock(&context->lock);
	pkm_kacs_copy_up_clear_phase_locked(context);
	mutex_unlock(&context->lock);
}

/*
 * Hook-side matching is lockless.  Only the attached task may arm or end a
 * phase, so it cannot race its own hook call; transfer first detaches and clears
 * the phase.  This also keeps MAY_NOT_BLOCK inode_permission genuinely
 * non-blocking.
 */
static bool pkm_kacs_copy_up_source_dentry(
	const struct pkm_kacs_stratafs_copy_up *context,
	const struct dentry *dentry)
{
	switch (context->phase) {
	case PKM_KACS_COPY_UP_PHASE_SOURCE_READ:
	case PKM_KACS_COPY_UP_PHASE_POPULATE:
		return pkm_kacs_copy_up_dentry_matches_path(
			dentry, &context->provider) &&
		       d_inode(dentry) == context->provider_inode;
	case PKM_KACS_COPY_UP_PHASE_CREATE:
		return context->phase_provider_pinned &&
		       pkm_kacs_copy_up_dentry_matches_path(
			       dentry, &context->phase_provider) &&
		       d_inode(dentry) == context->phase_provider_inode;
	default:
		return false;
	}
}

static bool pkm_kacs_copy_up_staging_binding_valid(
	const struct pkm_kacs_stratafs_copy_up *context)
{
	return context->staging_bound && context->staging_inode &&
	       context->staging_parent_inode && context->staging.mnt &&
	       context->staging_parent.mnt == context->staging.mnt &&
	       context->staging.dentry && context->staging_parent.dentry &&
	       d_inode(context->staging.dentry) == context->staging_inode &&
	       context->staging.dentry->d_parent ==
		       context->staging_parent.dentry &&
	       d_inode(context->staging_parent.dentry) ==
		       context->staging_parent_inode;
}

static bool pkm_kacs_copy_up_staging_dentry(
	const struct pkm_kacs_stratafs_copy_up *context,
	const struct dentry *dentry)
{
	return pkm_kacs_copy_up_staging_binding_valid(context) &&
	       pkm_kacs_copy_up_dentry_matches_path(dentry, &context->staging) &&
	       d_inode(dentry) == context->staging_inode;
}

static bool pkm_kacs_copy_up_staging_path(
	const struct pkm_kacs_stratafs_copy_up *context,
	const struct path *path, const struct inode *inode)
{
	return pkm_kacs_copy_up_staging_binding_valid(context) &&
	       inode == context->staging_inode &&
	       pkm_kacs_copy_up_path_matches(path, &context->staging);
}

bool pkm_kacs_copy_up_allows_inode_permission(const struct inode *inode,
					       int mask)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed = false;

	if (!context || !inode)
		return false;
	switch (context->phase) {
	case PKM_KACS_COPY_UP_PHASE_SOURCE_READ:
		allowed = pkm_kacs_copy_up_inode_matches_path(
			inode, &context->provider, context->provider_inode) &&
			  pkm_kacs_copy_up_read_mask_allowed(inode, mask);
		break;
	case PKM_KACS_COPY_UP_PHASE_CREATE:
		if (pkm_kacs_copy_up_inode_matches_path(
			    inode, &context->phase_provider,
			    context->phase_provider_inode))
			allowed = pkm_kacs_copy_up_read_mask_allowed(inode, mask);
		else if (pkm_kacs_copy_up_inode_matches_path(
				 inode, &context->phase_parent,
				 context->phase_parent_inode))
			allowed = pkm_kacs_copy_up_parent_mask_allowed(mask);
		break;
	case PKM_KACS_COPY_UP_PHASE_POPULATE:
		if (pkm_kacs_copy_up_inode_matches_path(
			    inode, &context->provider, context->provider_inode))
			allowed = pkm_kacs_copy_up_read_mask_allowed(inode, mask);
		else if (pkm_kacs_copy_up_staging_binding_valid(context) &&
			 pkm_kacs_copy_up_inode_matches_path(
				 inode, &context->staging,
				 context->staging_inode))
			allowed = pkm_kacs_copy_up_staging_mask_allowed(inode,
							   mask);
		break;
	case PKM_KACS_COPY_UP_PHASE_PUBLISH_LINK:
	case PKM_KACS_COPY_UP_PHASE_PUBLISH_RENAME:
		if (!pkm_kacs_copy_up_staging_binding_valid(context))
			break;
		if (pkm_kacs_copy_up_inode_matches_path(
			    inode, &context->staging,
			    context->staging_inode))
			allowed = pkm_kacs_copy_up_read_mask_allowed(inode, mask);
		else if (pkm_kacs_copy_up_inode_matches_path(
				 inode, &context->phase_parent,
				 context->phase_parent_inode))
			allowed = pkm_kacs_copy_up_parent_mask_allowed(mask);
		else if (context->phase ==
			 PKM_KACS_COPY_UP_PHASE_PUBLISH_RENAME &&
			 pkm_kacs_copy_up_inode_matches_path(
				 inode, &context->staging_parent,
				 context->staging_parent_inode))
			allowed = pkm_kacs_copy_up_parent_mask_allowed(mask);
		break;
	case PKM_KACS_COPY_UP_PHASE_CLEANUP:
		allowed = pkm_kacs_copy_up_inode_matches_path(
				  inode, &context->phase_parent,
				  context->phase_parent_inode) &&
			  pkm_kacs_copy_up_parent_mask_allowed(mask);
		break;
	default:
		break;
	}
	return allowed;
}

bool pkm_kacs_copy_up_allows_create(const struct inode *dir,
				     const struct dentry *dentry,
				     umode_t mode)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed = false;

	if (!context || !dir || !dentry)
		return false;
	if (context->phase == PKM_KACS_COPY_UP_PHASE_CREATE &&
	    !context->phase_anonymous && !context->phase_create_seen &&
	    pkm_kacs_copy_up_inode_matches_path(
		    dir, &context->phase_parent, context->phase_parent_inode) &&
	    context->phase_dentry == dentry &&
	    dentry->d_parent == context->phase_parent.dentry &&
	    !d_inode(dentry) && d_is_negative(dentry) &&
	    (context->phase_mode & S_IFMT) == (mode & S_IFMT)) {
		context->phase_create_seen = true;
		allowed = true;
	}
	return allowed;
}

int pkm_kacs_copy_up_init_security(const struct inode *inode,
				    const struct inode *dir,
				    const struct qstr *qstr,
				    const u8 **sd_bytes,
				    size_t *sd_len)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	struct pkm_kacs_copy_up_created *created = NULL;
	struct inode *pending_inode = NULL;
	bool name_matches = false;
	int matched = 0;

	if (!context || !inode || !dir || !sd_bytes || !sd_len)
		return 0;
	if (context->phase != PKM_KACS_COPY_UP_PHASE_CREATE)
		goto out;
	if (context->phase_stacked_create_seen) {
		name_matches = (inode->i_mode & S_IFMT) ==
			       (context->phase_mode & S_IFMT);
	} else if (!pkm_kacs_copy_up_inode_matches_path(
			   dir, &context->phase_parent,
			   context->phase_parent_inode)) {
		goto out;
	}

	if (!context->phase_stacked_create_seen && context->phase_anonymous) {
		name_matches = (inode->i_mode & S_IFMT) ==
			       (context->phase_mode & S_IFMT);
	} else if (!context->phase_stacked_create_seen) {
		name_matches = context->phase_dentry &&
			       pkm_kacs_copy_up_qstr_equal(
				       qstr, &context->phase_dentry->d_name);
	}
	if (!name_matches)
		goto out;
	if (context->phase_init_security_seen || !context->phase_sd ||
	    !context->phase_sd_len ||
	    (inode->i_mode & S_IFMT) != (context->phase_mode & S_IFMT) ||
	    (!context->phase_anonymous && !context->phase_create_seen)) {
		matched = -EACCES;
		goto out;
	}

	if (!context->phase_stacked_create_seen) {
		pending_inode = igrab((struct inode *)inode);
		if (!pending_inode) {
			matched = -ENOMEM;
			goto out;
		}
		if (!context->phase_anonymous) {
			created = pkm_kacs_copy_up_created_alloc(
				&context->phase_parent, context->phase_parent_inode,
				context->phase_dentry, (struct inode *)inode);
			if (!created) {
				matched = -ENOMEM;
				goto out;
			}
		}
	}

	context->phase_init_security_seen = true;
	if (context->phase_stacked_create_seen) {
		context->phase_stacked_sd_initialized = true;
	} else {
		context->pending_created_inode = pending_inode;
		pending_inode = NULL;
	}
	if (created) {
		list_add_tail(&created->node, &context->created_objects);
		created = NULL;
	}
	*sd_bytes = context->phase_sd;
	*sd_len = context->phase_sd_len;
	matched = 1;
out:
	if (created) {
		path_put(&created->path);
		iput(created->inode);
		path_put(&created->parent);
		iput(created->parent_inode);
		kfree(created);
	}
	iput(pending_inode);
	return matched;
}

bool pkm_kacs_copy_up_allows_link(const struct dentry *old_dentry,
				   const struct inode *dir,
				   const struct dentry *new_dentry)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed;

	if (!context)
		return false;
	allowed = context->phase == PKM_KACS_COPY_UP_PHASE_PUBLISH_LINK &&
		  pkm_kacs_copy_up_staging_binding_valid(context) &&
		  old_dentry && new_dentry &&
		  context->staging.dentry == old_dentry &&
		  d_inode(old_dentry) == context->staging_inode &&
		  pkm_kacs_copy_up_inode_matches_path(
			  dir, &context->phase_parent,
			  context->phase_parent_inode) &&
		  context->phase_dentry == new_dentry &&
		  new_dentry->d_parent == context->phase_parent.dentry &&
		  !d_inode(new_dentry) &&
		  d_is_negative(new_dentry);
	return allowed;
}

bool pkm_kacs_copy_up_allows_unlink(const struct inode *dir,
				     const struct dentry *dentry,
				     bool directory)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed;

	if (!context)
		return false;
	allowed = context->phase == PKM_KACS_COPY_UP_PHASE_CLEANUP &&
		  dentry &&
		  context->phase_directory == directory &&
		  pkm_kacs_copy_up_inode_matches_path(
			  dir, &context->phase_parent,
			  context->phase_parent_inode) &&
		  context->phase_dentry == dentry &&
		  context->phase_inode == d_inode(dentry) &&
		  d_is_positive(dentry) &&
		  dentry->d_parent == context->phase_parent.dentry &&
		  (!!S_ISDIR(d_inode(dentry)->i_mode) == directory);
	return allowed;
}

bool pkm_kacs_copy_up_allows_rename(const struct inode *old_dir,
				     const struct dentry *old_dentry,
				     const struct inode *new_dir,
				     const struct dentry *new_dentry)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed;

	if (!context)
		return false;
	allowed = context->phase == PKM_KACS_COPY_UP_PHASE_PUBLISH_RENAME &&
		  pkm_kacs_copy_up_staging_binding_valid(context) &&
		  old_dentry && new_dentry &&
		  context->staging.dentry == old_dentry &&
		  d_inode(old_dentry) == context->staging_inode &&
		  old_dentry->d_parent == context->staging_parent.dentry &&
		  pkm_kacs_copy_up_inode_matches_path(
			  old_dir, &context->staging_parent,
			  context->staging_parent_inode) &&
		  pkm_kacs_copy_up_inode_matches_path(
			  new_dir, &context->phase_parent,
			  context->phase_parent_inode) &&
		  context->phase_dentry == new_dentry &&
		  new_dentry->d_parent == context->phase_parent.dentry &&
		  !d_inode(new_dentry) &&
		  d_is_negative(new_dentry);
	return allowed;
}

bool pkm_kacs_copy_up_allows_readlink(const struct dentry *dentry)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed;

	if (!context)
		return false;
	allowed = pkm_kacs_copy_up_source_dentry(context, dentry);
	return allowed;
}

static bool pkm_kacs_copy_up_file_path_allowed(
	const struct pkm_kacs_stratafs_copy_up *context, const struct file *file)
{
	const struct path *path;

	if (!file)
		return false;
	path = &file->f_path;
	switch (context->phase) {
	case PKM_KACS_COPY_UP_PHASE_SOURCE_READ:
		return pkm_kacs_copy_up_path_inode_matches(
			path, &context->provider, context->provider_inode) &&
		       file_inode((struct file *)file) == context->provider_inode;
	case PKM_KACS_COPY_UP_PHASE_CREATE:
		if (!context->phase_anonymous)
			return context->phase_create_seen &&
			       context->phase_init_security_seen &&
			       context->phase_dentry == path->dentry &&
			       context->phase_parent.mnt == path->mnt &&
			       d_is_positive(path->dentry) &&
			       context->pending_created_inode ==
				       file_inode((struct file *)file) &&
			       (file_inode((struct file *)file)->i_mode & S_IFMT) ==
				       (context->phase_mode & S_IFMT);
		return path->dentry && path->dentry->d_parent ==
					context->phase_parent.dentry &&
		       path->mnt == context->phase_parent.mnt &&
		       d_is_positive(path->dentry) &&
		       context->pending_created_inode == file_inode(
			       (struct file *)file) &&
		       (file_inode((struct file *)file)->i_mode & S_IFMT) ==
			       (context->phase_mode & S_IFMT);
	case PKM_KACS_COPY_UP_PHASE_POPULATE:
		return (pkm_kacs_copy_up_path_inode_matches(
				path, &context->provider, context->provider_inode) &&
			file_inode((struct file *)file) ==
				context->provider_inode) ||
		       pkm_kacs_copy_up_staging_path(
			       context, path, file_inode((struct file *)file));
	default:
		return false;
	}
}

static bool pkm_kacs_copy_up_file_mode_allowed(
	const struct pkm_kacs_stratafs_copy_up *context, const struct file *file)
{
	bool provider;

	if (!file || (file->f_mode & (FMODE_EXEC | FMODE_PATH)) != 0)
		return false;
	provider = pkm_kacs_copy_up_path_inode_matches(
			   &file->f_path, &context->provider,
			   context->provider_inode) ||
		   (context->phase_provider_pinned &&
		    pkm_kacs_copy_up_path_inode_matches(
			    &file->f_path, &context->phase_provider,
			    context->phase_provider_inode));
	if (provider && (file->f_mode & FMODE_WRITE) != 0)
		return false;
	return true;
}

int pkm_kacs_stratafs_copy_up_resume_source_directory(
	struct pkm_kacs_stratafs_copy_up *context, struct file *directory)
{
	struct pkm_kacs_file_security *file_sec;
	bool allowed;

	if (!context || !directory || !directory->f_security)
		return -EINVAL;
	if (!pkm_kacs_copy_up_owned(context))
		return -EPERM;

	file_sec = pkm_kacs_file(directory);
	mutex_lock(&context->lock);
	/*
	 * Recovery preserves a directory cursor while it temporarily detaches
	 * this context to clean one bounded batch.  Refresh only the exact
	 * read-only provider directory which this context authorized when it was
	 * opened; this is not a way to adopt a new or ordinary file.
	 */
	allowed = context->phase == PKM_KACS_COPY_UP_PHASE_SOURCE_READ &&
		  file_sec->copy_up_context == context &&
		  S_ISDIR(file_inode(directory)->i_mode) &&
		  (directory->f_mode & FMODE_READ) != 0 &&
		  pkm_kacs_copy_up_file_path_allowed(context, directory) &&
		  pkm_kacs_copy_up_file_mode_allowed(context, directory);
	if (allowed)
		file_sec->copy_up_phase_generation = context->phase_generation;
	mutex_unlock(&context->lock);
	return allowed ? 0 : -EACCES;
}

enum pkm_kacs_copy_up_file_access
pkm_kacs_copy_up_file_open(struct file *file)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	struct pkm_kacs_stratafs_copy_up *file_context;
	struct pkm_kacs_file_security *file_sec;
	bool allowed;

	if (!file || !file->f_security)
		return PKM_KACS_COPY_UP_FILE_ORDINARY;
	file_sec = pkm_kacs_file(file);
	if (file_sec->copy_up_context) {
		context = file_sec->copy_up_context;
		if (pkm_kacs_copy_up_current() != context ||
		    file_sec->copy_up_phase_generation !=
			    context->phase_generation)
			return PKM_KACS_COPY_UP_FILE_DENY;
		allowed = pkm_kacs_copy_up_file_path_allowed(context, file) &&
			  pkm_kacs_copy_up_file_mode_allowed(context, file);
		return allowed ? PKM_KACS_COPY_UP_FILE_ALLOW :
				 PKM_KACS_COPY_UP_FILE_DENY;
	}
	if (!context)
		return PKM_KACS_COPY_UP_FILE_ORDINARY;

	allowed = pkm_kacs_copy_up_file_path_allowed(context, file) &&
		  pkm_kacs_copy_up_file_mode_allowed(context, file);
	if (allowed) {
		file_context = pkm_kacs_stratafs_copy_up_get(context);
		if (!file_context)
			return PKM_KACS_COPY_UP_FILE_DENY;
		file_sec->copy_up_context = file_context;
		file_sec->copy_up_phase_generation =
			context->phase_generation;
		file_sec->managed = 1;
		file_sec->granted_access = 0;
		file_sec->continuous_audit_mask = 0;
	}
	return allowed ? PKM_KACS_COPY_UP_FILE_ALLOW :
			 PKM_KACS_COPY_UP_FILE_ORDINARY;
}

enum pkm_kacs_copy_up_file_access
pkm_kacs_copy_up_file_permission(const struct file *file, int mask)
{
	struct pkm_kacs_stratafs_copy_up *context;
	struct pkm_kacs_file_security *file_sec;
	bool allowed;

	if (!file || !file->f_security)
		return PKM_KACS_COPY_UP_FILE_ORDINARY;
	file_sec = pkm_kacs_file((struct file *)file);
	context = file_sec->copy_up_context;
	if (!context)
		return PKM_KACS_COPY_UP_FILE_ORDINARY;
	if (pkm_kacs_copy_up_current() != context ||
	    file_sec->copy_up_phase_generation != context->phase_generation)
		return PKM_KACS_COPY_UP_FILE_DENY;

	allowed = pkm_kacs_copy_up_file_path_allowed(context, file) &&
		  pkm_kacs_copy_up_file_mode_allowed(context, file);
	if (allowed && pkm_kacs_copy_up_path_inode_matches(
			       &file->f_path, &context->provider,
			       context->provider_inode))
		allowed = pkm_kacs_copy_up_read_mask_allowed(file_inode(file),
							     mask);
	else if (allowed && context->phase_provider_pinned &&
		 pkm_kacs_copy_up_path_inode_matches(
			 &file->f_path, &context->phase_provider,
			 context->phase_provider_inode))
		allowed = pkm_kacs_copy_up_read_mask_allowed(file_inode(file),
							     mask);
	else if (allowed)
		allowed = pkm_kacs_copy_up_staging_mask_allowed(file_inode(file),
								mask);
	return allowed ? PKM_KACS_COPY_UP_FILE_ALLOW :
			 PKM_KACS_COPY_UP_FILE_DENY;
}

enum pkm_kacs_copy_up_file_access
pkm_kacs_copy_up_file_metadata(const struct file *file, bool write)
{
	struct pkm_kacs_stratafs_copy_up *context;
	struct pkm_kacs_file_security *file_sec;
	bool source;
	bool staging;
	bool allowed = false;

	if (!file || !file->f_security)
		return PKM_KACS_COPY_UP_FILE_ORDINARY;
	file_sec = pkm_kacs_file((struct file *)file);
	context = file_sec->copy_up_context;
	if (!context)
		return PKM_KACS_COPY_UP_FILE_ORDINARY;
	if (pkm_kacs_copy_up_current() != context ||
	    file_sec->copy_up_phase_generation != context->phase_generation)
		return PKM_KACS_COPY_UP_FILE_DENY;

	source = pkm_kacs_copy_up_path_inode_matches(
		&file->f_path, &context->provider, context->provider_inode) &&
		 file_inode((struct file *)file) == context->provider_inode;
	staging = pkm_kacs_copy_up_staging_path(
		context, &file->f_path, file_inode((struct file *)file));
	if (context->phase == PKM_KACS_COPY_UP_PHASE_POPULATE)
		allowed = write ? staging : (source || staging);
	else if (!write &&
		 context->phase == PKM_KACS_COPY_UP_PHASE_SOURCE_READ)
		allowed = source;
	return allowed ? PKM_KACS_COPY_UP_FILE_ALLOW :
			 PKM_KACS_COPY_UP_FILE_DENY;
}

void pkm_kacs_copy_up_file_release(struct file *file)
{
	struct pkm_kacs_stratafs_copy_up *context;
	struct pkm_kacs_file_security *file_sec;

	if (!file || !file->f_security)
		return;
	file_sec = pkm_kacs_file(file);
	context = file_sec->copy_up_context;
	file_sec->copy_up_context = NULL;
	file_sec->copy_up_phase_generation = 0;
	pkm_kacs_stratafs_copy_up_put(context);
}

bool pkm_kacs_copy_up_file_is_internal(const struct file *file)
{
	return file && file->f_security &&
	       pkm_kacs_file((struct file *)file)->copy_up_context;
}

bool pkm_kacs_copy_up_allows_getattr(const struct dentry *dentry)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed;

	if (!context)
		return false;
	allowed = pkm_kacs_copy_up_source_dentry(context, dentry) ||
		  (context->phase == PKM_KACS_COPY_UP_PHASE_POPULATE &&
		   pkm_kacs_copy_up_staging_dentry(context, dentry));
	return allowed;
}

bool pkm_kacs_copy_up_allows_path_getattr(const struct path *path)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed = false;

	if (!context || !path)
		return false;
	switch (context->phase) {
	case PKM_KACS_COPY_UP_PHASE_SOURCE_READ:
		allowed = pkm_kacs_copy_up_path_inode_matches(
			path, &context->provider, context->provider_inode);
		break;
	case PKM_KACS_COPY_UP_PHASE_CREATE:
		allowed = context->phase_provider_pinned &&
			  pkm_kacs_copy_up_path_inode_matches(
				  path, &context->phase_provider,
				  context->phase_provider_inode);
		break;
	case PKM_KACS_COPY_UP_PHASE_POPULATE:
		allowed = pkm_kacs_copy_up_path_inode_matches(
				  path, &context->provider,
				  context->provider_inode) ||
			  pkm_kacs_copy_up_staging_path(
				  context, path, d_inode(path->dentry));
		break;
	default:
		break;
	}
	return allowed;
}

bool pkm_kacs_copy_up_allows_setattr(const struct dentry *dentry)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed;

	if (!context || !dentry)
		return false;
	allowed = context->phase == PKM_KACS_COPY_UP_PHASE_POPULATE &&
		  pkm_kacs_copy_up_staging_dentry(context, dentry);
	return allowed;
}

bool pkm_kacs_copy_up_allows_getxattr(const struct dentry *dentry,
				       const char *name)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed;

	if (!context || !dentry || !name ||
	    pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name))
		return false;
	allowed = pkm_kacs_copy_up_source_dentry(context, dentry);
	return allowed;
}

bool pkm_kacs_copy_up_allows_setxattr(const struct dentry *dentry,
				       const char *name)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed;

	if (!context || !dentry || !name || is_posix_acl_xattr(name) ||
	    !strcmp(name, XATTR_NAME_CAPS) ||
	    pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name))
		return false;
	allowed = (context->phase == PKM_KACS_COPY_UP_PHASE_POPULATE &&
		   pkm_kacs_copy_up_staging_dentry(context, dentry)) ||
		  (context->phase == PKM_KACS_COPY_UP_PHASE_ORPHAN_MARKER &&
		   !strcmp(name, STRATAFS_STAGING_XATTR) &&
		   pkm_kacs_copy_up_dentry_matches_path(
			   dentry, &context->provider) &&
		   d_inode(dentry) == context->provider_inode);
	return allowed;
}

bool pkm_kacs_copy_up_allows_capability_setxattr(
	const struct dentry *dentry)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();

	if (!context || !context->capability_clone_active || !dentry ||
	    context->phase != PKM_KACS_COPY_UP_PHASE_POPULATE ||
	    current_user_ns() != context->capability_user_ns ||
	    !pkm_kacs_copy_up_staging_binding_valid(context))
		return false;
	if (!context->capability_clone_hook_seen) {
		if (context->phase != PKM_KACS_COPY_UP_PHASE_POPULATE ||
		    !pkm_kacs_copy_up_staging_dentry(context, dentry))
			return false;
		context->capability_clone_hook_seen = true;
	}
	return true;
}

bool pkm_kacs_copy_up_allows_capability_use(
	const struct user_namespace *target_ns)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool namespace_matches;

	if (!context || !target_ns)
		return false;
	namespace_matches = target_ns == context->capability_user_ns ||
			    (context->staging_inode &&
			     context->staging_inode->i_sb &&
			     target_ns ==
				     context->staging_inode->i_sb->s_user_ns);

	return namespace_matches &&
	       context->phase == PKM_KACS_COPY_UP_PHASE_POPULATE &&
	       current_user_ns() == context->capability_user_ns &&
	       context->capability_clone_active &&
	       pkm_kacs_copy_up_staging_binding_valid(context);
}

bool pkm_kacs_copy_up_allows_listxattr(const struct dentry *dentry)
{
	struct pkm_kacs_stratafs_copy_up *context = pkm_kacs_copy_up_current();
	bool allowed;

	if (!context)
		return false;
	allowed = pkm_kacs_copy_up_source_dentry(context, dentry);
	return allowed;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static void pkm_kacs_kunit_init_copy_up_dentry(
	struct dentry *dentry, struct inode *inode, struct dentry *parent,
	const char *name)
{
	struct qstr *qstr;

	memset(dentry, 0, sizeof(*dentry));
	dentry->d_inode = inode;
	dentry->d_parent = parent ? parent : dentry;
	qstr = (struct qstr *)&dentry->d_name;
	qstr->name = (const u8 *)name;
	qstr->len = strlen(name);
	if (inode && S_ISDIR(inode->i_mode))
		dentry->d_flags = DCACHE_DIRECTORY_TYPE;
	else if (inode && S_ISLNK(inode->i_mode))
		dentry->d_flags = DCACHE_SYMLINK_TYPE;
	else if (inode)
		dentry->d_flags = DCACHE_REGULAR_TYPE;
}

static void pkm_kacs_kunit_init_copy_up_context(
	struct pkm_kacs_stratafs_copy_up *context, struct path *provider)
{
	memset(context, 0, sizeof(*context));
	refcount_set(&context->refs, 1);
	atomic_set(&context->attached, 1);
	mutex_init(&context->lock);
	INIT_LIST_HEAD(&context->created_objects);
	context->provider = *provider;
	context->provider_inode = d_inode(provider->dentry);
	context->capability_user_ns = current_user_ns();
}

static void pkm_kunit_copy_up_scope_is_exact(struct kunit *test)
{
	static const u8 provider_capability[] = { 0x01, 0x02, 0x03 };
	static const u8 wrong_capability[] = { 0x01, 0x02, 0x04 };
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct pkm_kacs_stratafs_copy_up context;
	struct super_block sb = { .s_magic = TMPFS_MAGIC };
	struct inode provider_inode = { .i_mode = S_IFREG, .i_sb = &sb };
	struct inode parent_inode = { .i_mode = S_IFDIR, .i_sb = &sb };
	struct inode stage_inode = { .i_mode = S_IFREG, .i_sb = &sb };
	struct inode wrong_inode = { .i_mode = S_IFREG, .i_sb = &sb };
	struct dentry provider;
	struct dentry parent;
	struct dentry stage;
	struct dentry wrong;
	struct dentry materialized;
	struct dentry target;
	struct dentry other_target;
	struct vfsmount mnt = { .mnt_sb = &sb };
	struct vfsmount alias_mnt = { .mnt_sb = &sb };
	struct path provider_path;
	struct path alias_provider_path;
	struct path parent_path;
	struct path stage_path;
	struct path materialized_path;
	struct pkm_kacs_copy_up_created created = {};

	KUNIT_ASSERT_NULL(test, task_sec->copy_up_context);
	pkm_kacs_kunit_init_copy_up_dentry(&provider, &provider_inode, NULL,
					   "provider");
	pkm_kacs_kunit_init_copy_up_dentry(&parent, &parent_inode, NULL,
					   "parent");
	pkm_kacs_kunit_init_copy_up_dentry(&stage, &stage_inode, &parent,
					   "stage");
	pkm_kacs_kunit_init_copy_up_dentry(&wrong, &wrong_inode, NULL,
					   "wrong");
	pkm_kacs_kunit_init_copy_up_dentry(&materialized, &wrong_inode,
					   &parent, "materialized");
	pkm_kacs_kunit_init_copy_up_dentry(&target, NULL, &parent, "target");
	pkm_kacs_kunit_init_copy_up_dentry(&other_target, NULL, &parent,
					   "other");
	mnt.mnt_root = &parent;
	mnt.mnt_idmap = &nop_mnt_idmap;
	alias_mnt.mnt_root = &parent;
	alias_mnt.mnt_idmap = &nop_mnt_idmap;
	provider_path = (struct path){ .mnt = &mnt, .dentry = &provider };
	alias_provider_path = (struct path){
		.mnt = &alias_mnt,
		.dentry = &provider,
	};
	parent_path = (struct path){ .mnt = &mnt, .dentry = &parent };
	stage_path = (struct path){ .mnt = &mnt, .dentry = &stage };
	materialized_path = (struct path){
		.mnt = &mnt,
		.dentry = &materialized,
	};
	pkm_kacs_kunit_init_copy_up_context(&context, &provider_path);
	task_sec->copy_up_context = &context;

	context.phase = PKM_KACS_COPY_UP_PHASE_SOURCE_READ;
	KUNIT_EXPECT_TRUE(test,
		pkm_kacs_copy_up_allows_inode_permission(&provider_inode,
							 MAY_READ));
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_allows_inode_permission(&provider_inode,
							 MAY_WRITE));
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_allows_inode_permission(&wrong_inode,
							 MAY_READ));
	KUNIT_EXPECT_TRUE(test, pkm_kacs_copy_up_allows_getattr(&provider));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_getattr(&wrong));
	KUNIT_EXPECT_TRUE(test,
		pkm_kacs_copy_up_allows_path_getattr(&provider_path));
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_allows_path_getattr(&alias_provider_path));
	provider.d_inode = &wrong_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_getattr(&provider));
	provider.d_inode = &provider_inode;
	KUNIT_EXPECT_TRUE(test, pkm_kacs_copy_up_allows_getxattr(
		&provider, "user.copy"));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_getxattr(
		&provider, "security.peios.sd"));

	context.phase = PKM_KACS_COPY_UP_PHASE_POPULATE;
	context.staging = stage_path;
	context.staging_parent = parent_path;
	context.staging_inode = &stage_inode;
	context.staging_parent_inode = &parent_inode;
	context.staging_bound = true;
	context.provider_capability = (u8 *)provider_capability;
	context.provider_capability_len = sizeof(provider_capability);
	context.provider_capability_present = true;
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_copy_up_validate_capability_clone(
			&context, provider_capability,
			sizeof(provider_capability)), 0);
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_copy_up_validate_capability_clone(
			&context, wrong_capability, sizeof(wrong_capability)),
		-ESTALE);
	context.provider_capability_present = false;
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_copy_up_validate_capability_clone(
			&context, provider_capability,
			sizeof(provider_capability)), -ESTALE);
	context.provider_capability_present = true;
	KUNIT_EXPECT_TRUE(test, pkm_kacs_copy_up_allows_setattr(&stage));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_setattr(&provider));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_setxattr(
		&stage, "security.capability"));
	KUNIT_EXPECT_EQ(test, pkm_kacs_inode_setxattr(
		&nop_mnt_idmap, &stage, "security.capability", "x", 1, 0),
		-EPERM);
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_setxattr(
		&stage, "security.peios.sd"));
	KUNIT_EXPECT_TRUE(test, pkm_kacs_copy_up_allows_setxattr(
		&stage, STRATAFS_STAGING_XATTR));
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_allows_setxattr(&wrong, "user.copy"));
	context.capability_clone_active = true;
	KUNIT_EXPECT_TRUE(test,
		pkm_kacs_copy_up_allows_capability_use(current_user_ns()));
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_allows_capability_use(NULL));
	KUNIT_EXPECT_TRUE(test,
		pkm_kacs_copy_up_allows_capability_setxattr(&stage));
	context.capability_clone_active = false;
	context.capability_clone_hook_seen = false;
	stage.d_inode = &wrong_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_setattr(&stage));
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_allows_capability_use(current_user_ns()));
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_copy_up_validate_capability_clone(
			&context, provider_capability,
			sizeof(provider_capability)), -EPERM);
	stage.d_inode = &stage_inode;
	stage.d_parent = &wrong;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_setattr(&stage));
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_allows_capability_use(current_user_ns()));
	stage.d_parent = &parent;
	parent.d_inode = &wrong_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_setattr(&stage));
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_allows_capability_use(current_user_ns()));
	parent.d_inode = &parent_inode;

	context.phase = PKM_KACS_COPY_UP_PHASE_CREATE;
	context.phase_parent = parent_path;
	context.phase_parent_inode = &parent_inode;
	context.phase_parent_pinned = true;
	context.phase_dentry = &target;
	context.phase_mode = S_IFREG | 0600;
	{
		struct file stage_file = {
			.f_inode = &stage_inode,
			.f_path = {
				.mnt = &mnt,
				.dentry = &target,
			},
		};

		target.d_inode = &stage_inode;
		target.d_flags = DCACHE_REGULAR_TYPE;
		KUNIT_EXPECT_FALSE(test,
			pkm_kacs_copy_up_file_path_allowed(&context, &stage_file));
		context.phase_create_seen = true;
		context.phase_init_security_seen = true;
		context.pending_created_inode = &wrong_inode;
		KUNIT_EXPECT_FALSE(test,
			pkm_kacs_copy_up_file_path_allowed(&context, &stage_file));
		context.pending_created_inode = &stage_inode;
		KUNIT_EXPECT_TRUE(test,
			pkm_kacs_copy_up_file_path_allowed(&context, &stage_file));
		target.d_inode = NULL;
		target.d_flags = 0;
		context.pending_created_inode = NULL;
	}

	context.phase = PKM_KACS_COPY_UP_PHASE_PUBLISH_LINK;
	context.phase_parent = parent_path;
	context.phase_parent_inode = &parent_inode;
	context.phase_parent_pinned = true;
	context.phase_dentry = &target;
	context.staging_parent = parent_path;
	context.staging_parent_inode = &parent_inode;
	created.path = materialized_path;
	created.inode = &wrong_inode;
	created.parent = parent_path;
	created.parent_inode = &parent_inode;
	list_add_tail(&created.node, &context.created_objects);
	KUNIT_EXPECT_TRUE(test, pkm_kacs_copy_up_allows_link(
		&stage, &parent_inode, &target));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_link(
		&stage, &parent_inode, &other_target));
	target.d_parent = &wrong;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_link(
		&stage, &parent_inode, &target));
	target.d_parent = &parent;
	target.d_inode = &wrong_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_link(
		&stage, &parent_inode, &target));
	target.d_inode = NULL;

	context.phase = PKM_KACS_COPY_UP_PHASE_PUBLISH_RENAME;
	KUNIT_EXPECT_TRUE(test, pkm_kacs_copy_up_allows_rename(
		&parent_inode, &stage, &parent_inode, &target));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_rename(
		&parent_inode, &wrong, &parent_inode, &target));
	stage.d_parent = &wrong;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_rename(
		&parent_inode, &stage, &parent_inode, &target));
	stage.d_parent = &parent;

	context.phase = PKM_KACS_COPY_UP_PHASE_CLEANUP;
	context.phase_dentry = &stage;
	context.phase_inode = &stage_inode;
	context.phase_directory = false;
	KUNIT_EXPECT_TRUE(test,
		pkm_kacs_copy_up_cleanup_target_tracked_locked(
			&context, &parent_path, &parent_inode, &stage,
			&stage_inode));
	KUNIT_EXPECT_TRUE(test,
		pkm_kacs_copy_up_cleanup_target_tracked_locked(
			&context, &parent_path, &parent_inode, &materialized,
			&wrong_inode));
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_cleanup_target_tracked_locked(
			&context, &parent_path, &parent_inode, &provider,
			&provider_inode));
	KUNIT_EXPECT_TRUE(test, pkm_kacs_copy_up_allows_unlink(
		&parent_inode, &stage, false));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_unlink(
		&parent_inode, &stage, true));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_unlink(
		&parent_inode, &wrong, false));
	stage.d_inode = &wrong_inode;
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_unlink(
		&parent_inode, &stage, false));
	stage.d_inode = &stage_inode;

	context.phase = PKM_KACS_COPY_UP_PHASE_ORPHAN_MARKER;
	KUNIT_EXPECT_TRUE(test, pkm_kacs_copy_up_allows_setxattr(
		&provider, STRATAFS_STAGING_XATTR));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_setxattr(
		&provider, "user.copy"));
	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_setxattr(
		&stage, STRATAFS_STAGING_XATTR));
	context.phase = PKM_KACS_COPY_UP_PHASE_NONE;
	KUNIT_EXPECT_EQ(test, pkm_kacs_inode_setxattr(
		&nop_mnt_idmap, &provider, STRATAFS_STAGING_XATTR,
		"x", 1, 0), -EPERM);

	task_sec->copy_up_context = NULL;
	list_del(&created.node);
	mutex_destroy(&context.lock);
}

static void pkm_kunit_copy_up_exact_sd_is_installed_and_cached(
	struct kunit *test)
{
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct pkm_kacs_stratafs_copy_up context;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_security *inode_sec;
	struct super_block sb = { .s_magic = TMPFS_MAGIC };
	struct inode provider_inode = { .i_mode = S_IFREG, .i_sb = &sb };
	struct inode parent_inode = { .i_mode = S_IFDIR, .i_sb = &sb };
	struct inode created_inode = { .i_mode = S_IFREG, .i_sb = &sb };
	struct dentry provider;
	struct dentry parent;
	struct dentry target;
	struct vfsmount mnt = { .mnt_sb = &sb };
	struct path provider_path;
	struct path parent_path;
	struct xattr xattrs[2] = {};
	void *inode_blob;
	const u8 *retry_sd = NULL;
	size_t retry_len = 0;
	int xattr_count = 0;
	int ret;

	KUNIT_ASSERT_NULL(test, task_sec->copy_up_context);
	inode_blob = kunit_kzalloc(
		test, pkm_blob_sizes.lbs_inode +
			      sizeof(struct pkm_kacs_inode_security), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, inode_blob);
	created_inode.i_security = inode_blob;
	atomic_set(&created_inode.i_count, 1);
	KUNIT_ASSERT_EQ(test,
		pkm_kacs_inode_alloc_security(&created_inode), 0);

	pkm_kacs_kunit_init_copy_up_dentry(&provider, &provider_inode, NULL,
					   "provider");
	pkm_kacs_kunit_init_copy_up_dentry(&parent, &parent_inode, NULL,
					   "parent");
	pkm_kacs_kunit_init_copy_up_dentry(&target, NULL, &parent, "target");
	mnt.mnt_root = &parent;
	mnt.mnt_idmap = &nop_mnt_idmap;
	provider_path = (struct path){ .mnt = &mnt, .dentry = &provider };
	parent_path = (struct path){ .mnt = &mnt, .dentry = &parent };
	pkm_kacs_kunit_init_copy_up_context(&context, &provider_path);
	context.provider_sd = (u8 *)pkm_kunit_system_read_sd;
	context.provider_sd_len = sizeof(pkm_kunit_system_read_sd);
	context.phase = PKM_KACS_COPY_UP_PHASE_CREATE;
	context.phase_provider = provider_path;
	context.phase_provider_inode = &provider_inode;
	context.phase_provider_pinned = true;
	context.phase_parent = parent_path;
	context.phase_parent_inode = &parent_inode;
	context.phase_parent_pinned = true;
	context.phase_dentry = &target;
	context.phase_mode = S_IFREG | 0600;
	context.phase_sd = (u8 *)pkm_kunit_system_read_sd;
	context.phase_sd_len = sizeof(pkm_kunit_system_read_sd);
	task_sec->copy_up_context = &context;

	KUNIT_EXPECT_FALSE(test, pkm_kacs_copy_up_allows_create(
		&parent_inode, &target, S_IFDIR));
	ret = pkm_kacs_copy_up_allows_create(
		&parent_inode, &target, S_IFREG);
	KUNIT_EXPECT_TRUE(test, ret);
	if (!ret)
		goto out;
	/* The synthetic KUnit path has no real mount references to pin. */
	context.phase_anonymous = true;
	ret = pkm_kacs_inode_init_security(
		&created_inode, &parent_inode, &target.d_name,
		xattrs, &xattr_count);
	KUNIT_EXPECT_EQ(test, ret, 0);
	if (ret)
		goto out;
	KUNIT_EXPECT_EQ(test, xattr_count, 1);
	if (xattr_count != 1)
		goto out;
	KUNIT_EXPECT_STREQ(test, xattrs[0].name, "peios.sd");
	KUNIT_EXPECT_EQ(test, xattrs[0].value_len,
			(size_t)sizeof(pkm_kunit_system_read_sd));
	if (xattrs[0].value_len == sizeof(pkm_kunit_system_read_sd))
		KUNIT_EXPECT_MEMEQ(test, xattrs[0].value,
				   pkm_kunit_system_read_sd,
				   sizeof(pkm_kunit_system_read_sd));

	inode_sec = pkm_kacs_inode(&created_inode);
	cache = pkm_kacs_inode_sd_cache_get_current(&created_inode, inode_sec);
	KUNIT_EXPECT_NOT_NULL(test, cache);
	if (cache) {
		KUNIT_EXPECT_EQ(test, cache->state,
				(u8)PKM_KACS_INODE_SD_VALID);
		KUNIT_EXPECT_EQ(test, cache->len,
				(size_t)sizeof(pkm_kunit_system_read_sd));
		if (cache->len == sizeof(pkm_kunit_system_read_sd))
			KUNIT_EXPECT_MEMEQ(test, cache->bytes,
					   pkm_kunit_system_read_sd,
					   sizeof(pkm_kunit_system_read_sd));
		pkm_kacs_inode_sd_cache_free(cache);
	}

	KUNIT_EXPECT_EQ(test, pkm_kacs_copy_up_init_security(
		&created_inode, &parent_inode, &target.d_name,
		&retry_sd, &retry_len), -EACCES);
	KUNIT_EXPECT_NULL(test, retry_sd);
	KUNIT_EXPECT_EQ(test, retry_len, (size_t)0);

out:
	if (context.pending_created_inode) {
		iput(context.pending_created_inode);
		context.pending_created_inode = NULL;
	}
	kfree(xattrs[0].value);
	task_sec->copy_up_context = NULL;
	pkm_kacs_inode_free_security_rcu(created_inode.i_security);
	created_inode.i_security = NULL;
	mutex_destroy(&context.lock);
}

static void pkm_kunit_copy_up_stacked_tmpfile_binds_outer_inode(
	struct kunit *test)
{
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct pkm_kacs_stratafs_copy_up context;
	struct super_block outer_sb = { .s_magic = 0x794c7630 };
	struct super_block real_sb = { .s_magic = TMPFS_MAGIC };
	struct inode provider_inode = { .i_mode = S_IFREG, .i_sb = &real_sb };
	struct inode outer_parent_inode = {
		.i_mode = S_IFDIR,
		.i_sb = &outer_sb,
	};
	struct inode outer_inode = { .i_mode = S_IFREG, .i_sb = &outer_sb };
	struct inode real_parent_inode = {
		.i_mode = S_IFDIR,
		.i_sb = &real_sb,
	};
	struct inode real_inode = { .i_mode = S_IFREG, .i_sb = &real_sb };
	struct dentry provider;
	struct dentry outer_parent;
	struct dentry outer_tmpfile;
	struct vfsmount provider_mnt = { .mnt_sb = &real_sb };
	struct vfsmount outer_mnt = { .mnt_sb = &outer_sb };
	struct path provider_path;
	struct path outer_parent_path;
	struct xattr xattrs[2] = {};
	void *real_inode_blob;
	int xattr_count = 0;
	int ret;

	KUNIT_ASSERT_NULL(test, task_sec->copy_up_context);
	real_inode_blob = kunit_kzalloc(
		test, pkm_blob_sizes.lbs_inode +
			      sizeof(struct pkm_kacs_inode_security), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, real_inode_blob);
	real_inode.i_security = real_inode_blob;
	atomic_set(&real_inode.i_count, 1);
	atomic_set(&outer_inode.i_count, 1);
	KUNIT_ASSERT_EQ(test, pkm_kacs_inode_alloc_security(&real_inode), 0);

	pkm_kacs_kunit_init_copy_up_dentry(&provider, &provider_inode, NULL,
					   "provider");
	pkm_kacs_kunit_init_copy_up_dentry(
		&outer_parent, &outer_parent_inode, NULL, "outer-parent");
	pkm_kacs_kunit_init_copy_up_dentry(
		&outer_tmpfile, NULL, &outer_parent, "/");
	provider_mnt.mnt_root = &provider;
	provider_mnt.mnt_idmap = &nop_mnt_idmap;
	outer_mnt.mnt_root = &outer_parent;
	outer_mnt.mnt_idmap = &nop_mnt_idmap;
	provider_path = (struct path){
		.mnt = &provider_mnt,
		.dentry = &provider,
	};
	outer_parent_path = (struct path){
		.mnt = &outer_mnt,
		.dentry = &outer_parent,
	};
	pkm_kacs_kunit_init_copy_up_context(&context, &provider_path);
	context.phase = PKM_KACS_COPY_UP_PHASE_CREATE;
	context.phase_parent = outer_parent_path;
	context.phase_parent_inode = &outer_parent_inode;
	context.phase_parent_pinned = true;
	context.phase_mode = S_IFREG | 0600;
	context.phase_anonymous = true;
	context.phase_sd = (u8 *)pkm_kunit_system_read_sd;
	context.phase_sd_len = sizeof(pkm_kunit_system_read_sd);
	task_sec->copy_up_context = &context;

	ret = pkm_kacs_copy_up_dentry_create_files_as(
		&outer_tmpfile, S_IFREG | 0600, &outer_tmpfile.d_name,
		NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, context.phase_stacked_create_seen);
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_copy_up_dentry_create_files_as(
			&outer_tmpfile, S_IFREG | 0600,
			&outer_tmpfile.d_name, NULL, NULL),
		-EACCES);

	ret = pkm_kacs_inode_init_security(
		&real_inode, &real_parent_inode, &outer_tmpfile.d_name,
		xattrs, &xattr_count);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, xattr_count, 1);
	KUNIT_EXPECT_TRUE(test, context.phase_stacked_sd_initialized);
	KUNIT_EXPECT_NULL(test, context.pending_created_inode);
	KUNIT_EXPECT_EQ(test, xattrs[0].value_len,
			(size_t)sizeof(pkm_kunit_system_read_sd));
	if (xattrs[0].value_len == sizeof(pkm_kunit_system_read_sd))
		KUNIT_EXPECT_MEMEQ(test, xattrs[0].value,
				   pkm_kunit_system_read_sd,
				   sizeof(pkm_kunit_system_read_sd));

	/* The real filesystem's post hook must not become the outer anchor. */
	pkm_kacs_copy_up_post_create_tmpfile(&nop_mnt_idmap, &real_inode);
	KUNIT_EXPECT_NULL(test, context.pending_created_inode);
	outer_tmpfile.d_inode = &outer_inode;
	outer_tmpfile.d_flags = DCACHE_REGULAR_TYPE;
	pkm_kacs_copy_up_post_create_tmpfile(&nop_mnt_idmap, &outer_inode);
	KUNIT_EXPECT_PTR_EQ(test, context.pending_created_inode, &outer_inode);

	if (context.pending_created_inode) {
		iput(context.pending_created_inode);
		context.pending_created_inode = NULL;
	}
	kfree(xattrs[0].value);
	task_sec->copy_up_context = NULL;
	pkm_kacs_inode_free_security_rcu(real_inode.i_security);
	real_inode.i_security = NULL;
	mutex_destroy(&context.lock);
}

static void pkm_kunit_copy_up_internal_file_fails_closed(struct kunit *test)
{
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct pkm_kacs_stratafs_copy_up context;
	struct super_block sb = { .s_magic = TMPFS_MAGIC };
	struct inode provider_inode = { .i_mode = S_IFREG, .i_sb = &sb };
	struct dentry provider;
	struct vfsmount mnt = { .mnt_sb = &sb };
	struct path provider_path;
	struct file file = {};
	void *file_blob;

	KUNIT_ASSERT_NULL(test, task_sec->copy_up_context);
	file_blob = kunit_kzalloc(
		test, pkm_blob_sizes.lbs_file +
			      sizeof(struct pkm_kacs_file_security), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, file_blob);
	pkm_kacs_kunit_init_copy_up_dentry(&provider, &provider_inode, NULL,
					   "provider");
	mnt.mnt_root = &provider;
	mnt.mnt_idmap = &nop_mnt_idmap;
	provider_path = (struct path){ .mnt = &mnt, .dentry = &provider };
	pkm_kacs_kunit_init_copy_up_context(&context, &provider_path);
	context.phase = PKM_KACS_COPY_UP_PHASE_SOURCE_READ;
	task_sec->copy_up_context = &context;
	file.f_inode = &provider_inode;
	file.f_security = file_blob;
	*(struct path *)&file.f_path = provider_path;
	file.f_mode = FMODE_READ;
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_alloc_security(&file), 0);

	KUNIT_EXPECT_EQ(test, pkm_kacs_copy_up_file_open(&file),
			PKM_KACS_COPY_UP_FILE_ALLOW);
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_permission(&file, MAY_READ), 0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_permission(&file, MAY_WRITE),
			-EACCES);
	KUNIT_EXPECT_TRUE(test, pkm_kacs_file(&file)->managed);
	KUNIT_EXPECT_EQ(test, pkm_kacs_file(&file)->granted_access, 0U);
	KUNIT_EXPECT_TRUE(test, pkm_kacs_copy_up_file_is_internal(&file));
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_fcntl(&file, F_GETFL, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_receive(&file), -EACCES);
	context.phase = PKM_KACS_COPY_UP_PHASE_POPULATE;
	context.staging = provider_path;
	context.staging_parent = provider_path;
	context.staging_inode = &provider_inode;
	context.staging_parent_inode = &provider_inode;
	context.staging_bound = true;
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_sd_xattr_set(
		&file, "security.capability"), -EPERM);
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_sd_xattr_remove(
		&file, "security.capability"), 0);

	context.phase = PKM_KACS_COPY_UP_PHASE_NONE;
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_permission(&file, MAY_READ),
			-EACCES);
	context.phase_generation++;
	context.phase = PKM_KACS_COPY_UP_PHASE_SOURCE_READ;
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_permission(&file, MAY_READ),
			-EACCES);
	context.phase = PKM_KACS_COPY_UP_PHASE_NONE;
	task_sec->copy_up_context = NULL;
	KUNIT_EXPECT_EQ(test, pkm_kacs_file_permission(&file, MAY_READ),
			-EACCES);
	pkm_kacs_copy_up_file_release(&file);
	KUNIT_EXPECT_NULL(test, pkm_kacs_file(&file)->copy_up_context);
	mutex_destroy(&context.lock);
}

static void pkm_kunit_copy_up_source_directory_resume_is_exact(
	struct kunit *test)
{
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct pkm_kacs_stratafs_copy_up context;
	struct super_block sb = { .s_magic = TMPFS_MAGIC };
	struct inode provider_inode = { .i_mode = S_IFDIR, .i_sb = &sb };
	struct dentry provider;
	struct dentry wrong;
	struct vfsmount mnt = { .mnt_sb = &sb };
	struct path provider_path;
	struct file directory = {};
	void *file_blob;

	KUNIT_ASSERT_NULL(test, task_sec->copy_up_context);
	file_blob = kunit_kzalloc(
		test, pkm_blob_sizes.lbs_file +
			      sizeof(struct pkm_kacs_file_security), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, file_blob);
	pkm_kacs_kunit_init_copy_up_dentry(&provider, &provider_inode, NULL,
					   "provider");
	pkm_kacs_kunit_init_copy_up_dentry(&wrong, &provider_inode, NULL,
					   "wrong");
	mnt.mnt_root = &provider;
	mnt.mnt_idmap = &nop_mnt_idmap;
	provider_path = (struct path){ .mnt = &mnt, .dentry = &provider };
	pkm_kacs_kunit_init_copy_up_context(&context, &provider_path);
	context.phase = PKM_KACS_COPY_UP_PHASE_SOURCE_READ;
	context.phase_generation = 1;
	task_sec->copy_up_context = &context;
	directory.f_inode = &provider_inode;
	directory.f_security = file_blob;
	*(struct path *)&directory.f_path = provider_path;
	directory.f_mode = FMODE_READ;
	KUNIT_ASSERT_EQ(test, pkm_kacs_file_alloc_security(&directory), 0);
	KUNIT_ASSERT_EQ(test, pkm_kacs_copy_up_file_open(&directory),
			PKM_KACS_COPY_UP_FILE_ALLOW);

	context.phase = PKM_KACS_COPY_UP_PHASE_NONE;
	context.phase_generation++;
	context.phase = PKM_KACS_COPY_UP_PHASE_SOURCE_READ;
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_file_permission(&directory, MAY_READ), -EACCES);

	directory.f_mode |= FMODE_WRITE;
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_stratafs_copy_up_resume_source_directory(
			&context, &directory), -EACCES);
	directory.f_mode = FMODE_READ;
	*(struct dentry **)&directory.f_path.dentry = &wrong;
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_stratafs_copy_up_resume_source_directory(
			&context, &directory), -EACCES);
	*(struct dentry **)&directory.f_path.dentry = &provider;
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_stratafs_copy_up_resume_source_directory(
			&context, &directory), 0);
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_file_permission(&directory, MAY_READ), 0);

	context.phase = PKM_KACS_COPY_UP_PHASE_POPULATE;
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_stratafs_copy_up_resume_source_directory(
			&context, &directory), -EACCES);
	context.phase = PKM_KACS_COPY_UP_PHASE_SOURCE_READ;
	task_sec->copy_up_context = NULL;
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_stratafs_copy_up_resume_source_directory(
			&context, &directory), -EPERM);

	context.phase = PKM_KACS_COPY_UP_PHASE_NONE;
	pkm_kacs_copy_up_file_release(&directory);
	KUNIT_EXPECT_NULL(test,
		pkm_kacs_file(&directory)->copy_up_context);
	mutex_destroy(&context.lock);
}

static void pkm_kunit_copy_up_context_is_non_nesting(struct kunit *test)
{
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct pkm_kacs_stratafs_copy_up context = {};

	KUNIT_ASSERT_NULL(test, task_sec->copy_up_context);
	refcount_set(&context.refs, 1);
	atomic_set(&context.attached, 0);
	mutex_init(&context.lock);
	KUNIT_ASSERT_EQ(test, pkm_kacs_stratafs_copy_up_enter(&context), 0);
	KUNIT_EXPECT_PTR_EQ(test, task_sec->copy_up_context, &context);
	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_copy_up_begin_source_read(&context), 0);
	KUNIT_EXPECT_EQ(test, context.phase_generation, (u64)1);
	pkm_kacs_stratafs_copy_up_end_phase(&context);
	KUNIT_ASSERT_EQ(test,
		pkm_kacs_stratafs_copy_up_begin_source_read(&context), 0);
	KUNIT_EXPECT_EQ(test, context.phase_generation, (u64)2);
	pkm_kacs_stratafs_copy_up_end_phase(&context);
	KUNIT_EXPECT_EQ(test, pkm_kacs_stratafs_copy_up_enter(&context),
			-EBUSY);
	pkm_kacs_stratafs_copy_up_leave(&context);
	KUNIT_EXPECT_NULL(test, task_sec->copy_up_context);
	KUNIT_EXPECT_EQ(test, atomic_read(&context.attached), 0);
	KUNIT_EXPECT_EQ(test, refcount_read(&context.refs), 1U);
	KUNIT_ASSERT_EQ(test, pkm_kacs_stratafs_copy_up_enter(&context), 0);
	pkm_kacs_copy_up_task_exit(current);
	KUNIT_EXPECT_NULL(test, task_sec->copy_up_context);
	KUNIT_EXPECT_EQ(test, atomic_read(&context.attached), 0);
	KUNIT_EXPECT_EQ(test, refcount_read(&context.refs), 1U);
	mutex_destroy(&context.lock);
}

static void pkm_kunit_copy_up_adopts_outer_descriptor_snapshot(
	struct kunit *test)
{
	struct pkm_kacs_stratafs_copy_up context = {};
	struct pkm_kacs_file_security outer = {
		.granted_access = KACS_FILE_READ_DATA | KACS_FILE_WRITE_DATA,
		.continuous_audit_mask = KACS_FILE_WRITE_DATA,
		.managed = 1,
	};
	struct pkm_kacs_file_security backing = {
		.copy_up_context = &context,
		.copy_up_phase_generation = 7,
	};
	struct pkm_kacs_backing_file_security backing_auth = {};

	refcount_set(&context.refs, 2);
	context.phase_generation = 7;
	KUNIT_ASSERT_EQ(test,
		pkm_kacs_copy_up_adopt_file_security(
			&context, &outer, &backing, &backing_auth), 0);
	KUNIT_EXPECT_EQ(test, backing.granted_access, outer.granted_access);
	KUNIT_EXPECT_EQ(test, backing.continuous_audit_mask,
			outer.continuous_audit_mask);
	KUNIT_EXPECT_TRUE(test, backing.managed);
	KUNIT_EXPECT_NULL(test, backing.copy_up_context);
	KUNIT_EXPECT_EQ(test, backing.copy_up_phase_generation, 0ULL);
	KUNIT_EXPECT_EQ(test, backing_auth.granted_access,
			outer.granted_access);
	KUNIT_EXPECT_EQ(test, backing_auth.continuous_audit_mask,
			outer.continuous_audit_mask);
	KUNIT_EXPECT_TRUE(test, backing_auth.managed);
	KUNIT_EXPECT_TRUE(test, backing_auth.inherited);
	KUNIT_EXPECT_EQ(test, refcount_read(&context.refs), 1U);

	outer.managed = 0;
	backing.copy_up_context = &context;
	backing.copy_up_phase_generation = 7;
	KUNIT_EXPECT_EQ(test,
		pkm_kacs_copy_up_adopt_file_security(
			&context, &outer, &backing, &backing_auth), -EACCES);
		KUNIT_EXPECT_PTR_EQ(test, backing.copy_up_context, &context);
}

static void pkm_kunit_copy_up_publish_identity_matches_vfs_semantics(
	struct kunit *test)
{
	struct pkm_kacs_stratafs_copy_up context = {};
	struct inode inode = { .i_mode = S_IFREG };
	struct dentry stage;
	struct dentry target;
	struct dentry other;
	struct vfsmount mnt = {};
	struct path published = { .mnt = &mnt };
	struct qstr *stage_name;

	pkm_kacs_kunit_init_copy_up_dentry(&stage, &inode, NULL, "stage");
	pkm_kacs_kunit_init_copy_up_dentry(&target, &inode, NULL, "target");
	pkm_kacs_kunit_init_copy_up_dentry(&other, &inode, NULL, "target");
	context.staging.dentry = &stage;
	context.phase_dentry = &target;
	context.phase_name = "target";
	context.phase_name_len = sizeof("target") - 1;

	context.phase = PKM_KACS_COPY_UP_PHASE_PUBLISH_LINK;
	published.dentry = &target;
	KUNIT_EXPECT_TRUE(test,
		pkm_kacs_copy_up_published_object_matches(&context, &published));
	published.dentry = &stage;
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_published_object_matches(&context, &published));

	/* vfs_rename() moves the source dentry and changes its name. */
	stage_name = (struct qstr *)&stage.d_name;
	stage_name->name = (const u8 *)"target";
	stage_name->len = sizeof("target") - 1;
	context.phase = PKM_KACS_COPY_UP_PHASE_PUBLISH_RENAME;
	published.dentry = &stage;
	KUNIT_EXPECT_TRUE(test,
		pkm_kacs_copy_up_published_object_matches(&context, &published));
	published.dentry = &target;
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_published_object_matches(&context, &published));
	published.dentry = &other;
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_published_object_matches(&context, &published));

	stage_name->name = (const u8 *)"wrong";
	stage_name->len = sizeof("wrong") - 1;
	published.dentry = &stage;
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_published_object_matches(&context, &published));
	context.phase = PKM_KACS_COPY_UP_PHASE_NONE;
	KUNIT_EXPECT_FALSE(test,
		pkm_kacs_copy_up_published_object_matches(&context, &published));
}

/*
 * The overlayfs path: a descriptor left on the cred by
 * pkm_kacs_inode_copy_up() is what the created inode gets, in both the xattr
 * and the SD cache -- not one inherited from the parent directory.
 *
 * No StrataFS context is armed here, so this exercises the branch that fires
 * for a plain overlayfs copy-up.
 */
static void pkm_kunit_overlay_copy_up_sd_is_installed_and_cached(
	struct kunit *test)
{
	struct pkm_kacs_task_security *task_sec = pkm_kacs_task(current);
	struct pkm_kacs_cred_security *cred_sec;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_security *inode_sec;
	struct super_block sb = { .s_magic = TMPFS_MAGIC };
	struct inode parent_inode = { .i_mode = S_IFDIR, .i_sb = &sb };
	struct inode created_inode = { .i_mode = S_IFREG, .i_sb = &sb };
	struct dentry parent;
	struct dentry target;
	struct xattr xattrs[2] = {};
	u8 *saved_sd;
	size_t saved_len;
	void *inode_blob;
	int xattr_count = 0;
	int ret;

	KUNIT_ASSERT_NULL(test, task_sec->copy_up_context);
	KUNIT_ASSERT_NOT_NULL(test, current_cred());
	KUNIT_ASSERT_NOT_NULL(test, current_cred()->security);
	cred_sec = pkm_kacs_cred(current_cred());

	inode_blob = kunit_kzalloc(
		test, pkm_blob_sizes.lbs_inode +
			      sizeof(struct pkm_kacs_inode_security), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, inode_blob);
	created_inode.i_security = inode_blob;
	atomic_set(&created_inode.i_count, 1);
	KUNIT_ASSERT_EQ(test,
		pkm_kacs_inode_alloc_security(&created_inode), 0);

	pkm_kacs_kunit_init_copy_up_dentry(&parent, &parent_inode, NULL,
					   "parent");
	pkm_kacs_kunit_init_copy_up_dentry(&target, NULL, &parent, "target");

	saved_sd = cred_sec->pending_create_sd;
	saved_len = cred_sec->pending_create_sd_len;
	cred_sec->pending_create_sd = (u8 *)pkm_kunit_system_read_sd;
	cred_sec->pending_create_sd_len = sizeof(pkm_kunit_system_read_sd);

	ret = pkm_kacs_inode_init_security(
		&created_inode, &parent_inode, &target.d_name,
		xattrs, &xattr_count);

	/*
	 * Restored before any assertion can abort the test: the borrowed bytes
	 * are static and must not reach pkm_kacs_cred_free().
	 */
	cred_sec->pending_create_sd = saved_sd;
	cred_sec->pending_create_sd_len = saved_len;

	KUNIT_EXPECT_EQ(test, ret, 0);
	if (ret)
		goto out;
	KUNIT_EXPECT_EQ(test, xattr_count, 1);
	if (xattr_count != 1)
		goto out;
	KUNIT_EXPECT_STREQ(test, xattrs[0].name, "peios.sd");
	KUNIT_EXPECT_EQ(test, xattrs[0].value_len,
			(size_t)sizeof(pkm_kunit_system_read_sd));
	if (xattrs[0].value_len == sizeof(pkm_kunit_system_read_sd))
		KUNIT_EXPECT_MEMEQ(test, xattrs[0].value,
				   pkm_kunit_system_read_sd,
				   sizeof(pkm_kunit_system_read_sd));

	inode_sec = pkm_kacs_inode(&created_inode);
	cache = pkm_kacs_inode_sd_cache_get_current(&created_inode, inode_sec);
	KUNIT_EXPECT_NOT_NULL(test, cache);
	if (cache) {
		KUNIT_EXPECT_EQ(test, cache->state,
				(u8)PKM_KACS_INODE_SD_VALID);
		KUNIT_EXPECT_EQ(test, cache->len,
				(size_t)sizeof(pkm_kunit_system_read_sd));
		if (cache->len == sizeof(pkm_kunit_system_read_sd))
			KUNIT_EXPECT_MEMEQ(test, cache->bytes,
					   pkm_kunit_system_read_sd,
					   sizeof(pkm_kunit_system_read_sd));
		pkm_kacs_inode_sd_cache_free(cache);
	}
out:
	kfree(xattrs[0].value);
	pkm_kacs_inode_free_security_rcu(created_inode.i_security);
	created_inode.i_security = NULL;
}

/*
 * The guard that keeps the above from leaking. A cred derived from one
 * carrying a pending copy-up descriptor must not inherit it -- otherwise the
 * next unrelated create in that task would be stamped with a descriptor lifted
 * off the file being copied up.
 */
static void pkm_kunit_overlay_copy_up_sd_is_not_inherited(struct kunit *test)
{
	struct pkm_kacs_cred_security *old_sec;
	struct pkm_kacs_cred_security *new_sec;
	struct cred new_cred = {};
	void *cred_blob;
	u8 *saved_sd;
	size_t saved_len;
	int ret;

	KUNIT_ASSERT_NOT_NULL(test, current_cred());
	KUNIT_ASSERT_NOT_NULL(test, current_cred()->security);
	old_sec = pkm_kacs_cred(current_cred());

	cred_blob = kunit_kzalloc(
		test, pkm_blob_sizes.lbs_cred +
			      sizeof(struct pkm_kacs_cred_security), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cred_blob);
	new_cred.security = cred_blob;

	saved_sd = old_sec->pending_create_sd;
	saved_len = old_sec->pending_create_sd_len;
	old_sec->pending_create_sd = (u8 *)pkm_kunit_system_read_sd;
	old_sec->pending_create_sd_len = sizeof(pkm_kunit_system_read_sd);

	/*
	 * Poison the destination first. The blob arrives zeroed, so without
	 * this the assertions below would hold even if cred_prepare touched
	 * the field not at all -- the test would pass while proving nothing.
	 * Only an active clear survives a non-NULL start.
	 */
	new_sec = pkm_kacs_cred(&new_cred);
	new_sec->pending_create_sd = (u8 *)pkm_kunit_system_read_sd;
	new_sec->pending_create_sd_len = sizeof(pkm_kunit_system_read_sd);

	ret = pkm_kacs_cred_prepare(&new_cred, current_cred(), GFP_KERNEL);

	old_sec->pending_create_sd = saved_sd;
	old_sec->pending_create_sd_len = saved_len;

	KUNIT_EXPECT_EQ(test, ret, 0);
	if (ret)
		return;

	KUNIT_EXPECT_NULL(test, new_sec->pending_create_sd);
	KUNIT_EXPECT_EQ(test, new_sec->pending_create_sd_len, (size_t)0);

	/*
	 * Drop the poison rather than let cred_free see it. If the guard above
	 * has regressed the field still points at static bytes, and kfree()
	 * on those would crash the run -- burying the assertion that just told
	 * us exactly what broke.
	 */
	new_sec->pending_create_sd = NULL;
	new_sec->pending_create_sd_len = 0;

	/* cred_prepare cloned the token; release what it took. */
	pkm_kacs_cred_free(&new_cred);
}

/*
 * An ordinary create through an overlay: the descriptor must come out of the
 * *overlay* parent, computed for the *calling* principal -- not for the
 * mounter whose credentials overlayfs has already installed by the time the
 * real create runs.
 *
 * The parent descriptor here grants FILE_ALL to a token the KUnit task does
 * not hold, so the hook only succeeds if it took its subject from the cred it
 * was handed. Reading current instead would fail the FILE_ADD_FILE check.
 *
 * The bytes are then compared against what the inheritance builder yields for
 * that same subject and parent, which is what inode_init_security would have
 * produced had overlayfs not stood between the caller and the create.
 */
static void pkm_kunit_overlay_create_takes_caller_and_overlay_parent(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *pending_sd = NULL;
	const u8 *expected_sd = NULL;
	size_t parent_sd_len = 0;
	size_t pending_sd_len = 0;
	size_t expected_sd_len = 0;
	int ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_PTR_NE(test, subject_token,
			    pkm_kacs_current_effective_token_ptr());

	parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     PKM_KUNIT_FILE_ADD_FILE |
						     PKM_KUNIT_FILE_ADD_SUBDIRECTORY,
						     &parent_sd_len);
	if (!parent_sd) {
		kacs_rust_token_drop(subject_token);
		KUNIT_FAIL(test, "parent SD allocation failed");
		return;
	}
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	ret = pkm_kacs_kunit_overlay_create_files_as(
		subject_token, parent_sd, parent_sd_len, false, &pending_sd,
		&pending_sd_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, pending_sd);
	if (ret || !pending_sd)
		goto out;

	ret = (int)pkm_kacs_kunit_build_created_sd_for_parent(
		subject_token, parent_sd, parent_sd_len, false, &expected_sd,
		&expected_sd_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, expected_sd);
	if (ret || !expected_sd)
		goto out;

	KUNIT_EXPECT_EQ(test, pending_sd_len, expected_sd_len);
	if (pending_sd_len == expected_sd_len)
		KUNIT_EXPECT_MEMEQ(test, pending_sd, expected_sd,
				   expected_sd_len);
out:
	kfree((void *)pending_sd);
	if (expected_sd)
		pkm_kacs_free((void *)expected_sd);
	pkm_kacs_free((void *)parent_sd);
	kacs_rust_token_drop(subject_token);
}

/*
 * A caller with no token leaves the cred untouched, so inode_init_security
 * still reaches its own NO_TOKEN denial. Two places must not decide the same
 * thing differently.
 */
static void pkm_kunit_overlay_create_without_a_token_defers(struct kunit *test)
{
	const void *subject_token;
	const u8 *parent_sd = NULL;
	const u8 *pending_sd = NULL;
	size_t parent_sd_len = 0;
	size_t pending_sd_len = 0;
	int ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	parent_sd = pkm_kunit_create_precise_file_sd(subject_token,
						     PKM_KUNIT_FILE_ADD_FILE |
						     PKM_KUNIT_FILE_ADD_SUBDIRECTORY,
						     &parent_sd_len);
	kacs_rust_token_drop(subject_token);
	if (!parent_sd) {
		KUNIT_FAIL(test, "parent SD allocation failed");
		return;
	}
	pkm_kunit_make_first_file_ace_inheritable((u8 *)parent_sd, 0x03);

	ret = pkm_kacs_kunit_overlay_create_files_as(
		NULL, parent_sd, parent_sd_len, false, &pending_sd,
		&pending_sd_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NULL(test, pending_sd);
	KUNIT_EXPECT_EQ(test, pending_sd_len, (size_t)0);

	kfree((void *)pending_sd);
	pkm_kacs_free((void *)parent_sd);
}

/*
 * A descriptor written through a stacking filesystem reaches two inodes.
 * kacs_set_sd refreshes the cache on the one it was handed; the write then
 * re-enters on the real inode below, whose cache nothing else touches. The
 * post-setxattr hook is what keeps that second inode from serving a
 * descriptor its own xattr has already contradicted (PEI-564).
 */
static void pkm_kunit_post_setxattr_drops_a_superseded_cache(struct kunit *test)
{
	bool survived = true;
	int ret;

	ret = pkm_kacs_kunit_post_setxattr_drops_cache(
		pkm_kunit_system_read_sd, sizeof(pkm_kunit_system_read_sd),
		"security.peios.sd", &survived);
	KUNIT_EXPECT_EQ(test, ret, 0);
	if (ret)
		return;
	KUNIT_EXPECT_FALSE(test, survived);
}

/* ...and leaves every other xattr's cache alone. */
static void pkm_kunit_post_setxattr_keeps_an_unrelated_cache(struct kunit *test)
{
	bool survived = false;
	int ret;

	ret = pkm_kacs_kunit_post_setxattr_drops_cache(
		pkm_kunit_system_read_sd, sizeof(pkm_kunit_system_read_sd),
		"user.something.else", &survived);
	KUNIT_EXPECT_EQ(test, ret, 0);
	if (ret)
		return;
	KUNIT_EXPECT_TRUE(test, survived);
}

static struct kunit_case pkm_kunit_copy_up_cases[] = {
	KUNIT_CASE(pkm_kunit_copy_up_scope_is_exact),
	KUNIT_CASE(pkm_kunit_copy_up_exact_sd_is_installed_and_cached),
	KUNIT_CASE(pkm_kunit_copy_up_stacked_tmpfile_binds_outer_inode),
	KUNIT_CASE(pkm_kunit_copy_up_internal_file_fails_closed),
	KUNIT_CASE(pkm_kunit_copy_up_source_directory_resume_is_exact),
	KUNIT_CASE(pkm_kunit_copy_up_context_is_non_nesting),
	KUNIT_CASE(pkm_kunit_copy_up_adopts_outer_descriptor_snapshot),
	KUNIT_CASE(pkm_kunit_copy_up_publish_identity_matches_vfs_semantics),
	KUNIT_CASE(pkm_kunit_overlay_copy_up_sd_is_installed_and_cached),
	KUNIT_CASE(pkm_kunit_overlay_copy_up_sd_is_not_inherited),
	KUNIT_CASE(pkm_kunit_overlay_create_takes_caller_and_overlay_parent),
	KUNIT_CASE(pkm_kunit_overlay_create_without_a_token_defers),
	KUNIT_CASE(pkm_kunit_post_setxattr_drops_a_superseded_cache),
	KUNIT_CASE(pkm_kunit_post_setxattr_keeps_an_unrelated_cache),
	{}
};

static struct kunit_suite pkm_kunit_copy_up_suite = {
	.name = "pkm_kunit_copy_up",
	.test_cases = pkm_kunit_copy_up_cases,
};

kunit_test_suite(pkm_kunit_copy_up_suite);
#endif
