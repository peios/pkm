// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/backing-file.h>
#include <linux/kacs_stratafs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/random.h>
#include <linux/xattr.h>

#include "../internal.h"
#include "stratafs.h"

#define STRATAFS_COPY_BUFFER_SIZE (64U * 1024U)
#define STRATAFS_STAGE_PREFIX ".stratafs-stage-"
#define STRATAFS_RECOVERY_BATCH 128U

struct stratafs_recovery_name {
	struct list_head list;
	char *name;
};

struct stratafs_recovery_capture {
	struct dir_context ctx;
	struct list_head names;
	unsigned int count;
	int error;
};

static void stratafs_copy_phase_leave(
	struct pkm_kacs_stratafs_copy_up *context);
static void stratafs_copy_context_finish(
	struct pkm_kacs_stratafs_copy_up *context);

static bool stratafs_recovery_actor(struct dir_context *ctx, const char *name,
				    int len, loff_t offset, u64 ino,
				    unsigned int type)
{
	struct stratafs_recovery_capture *capture = container_of(
		ctx, struct stratafs_recovery_capture, ctx);
	struct stratafs_recovery_name *candidate;

	if (len <= strlen(STRATAFS_STAGE_PREFIX) ||
	    memcmp(name, STRATAFS_STAGE_PREFIX, strlen(STRATAFS_STAGE_PREFIX)))
		return true;
	if (capture->count == STRATAFS_RECOVERY_BATCH)
		return false;
	candidate = kzalloc_obj(*candidate, GFP_KERNEL);
	if (!candidate) {
		capture->error = -ENOMEM;
		return false;
	}
	candidate->name = kmemdup_nul(name, len, GFP_KERNEL);
	if (!candidate->name) {
		kfree(candidate);
		capture->error = -ENOMEM;
		return false;
	}
	list_add_tail(&candidate->list, &capture->names);
	capture->count++;
	return true;
}

static void stratafs_recover_one(struct super_block *sb,
				 const struct path *parent, const char *name)
{
	struct pkm_kacs_stratafs_copy_up *context;
	struct stratafs_stage_marker marker;
	struct path victim_path = { .mnt = parent->mnt };
	struct qstr q = QSTR_INIT(name, strlen(name));
	struct dentry *victim;
	struct dentry *locked;
	bool directory;
	int ret;

	q.hash = full_name_hash(parent->dentry, q.name, q.len);
	victim = lookup_noperm_unlocked(&q, parent->dentry);
	if (IS_ERR(victim) || !d_really_is_positive(victim)) {
		if (!IS_ERR(victim))
			dput(victim);
		return;
	}
	victim_path.dentry = victim;
	ret = pkm_kacs_stratafs_probe_staging_marker(
		&victim_path, &marker, sizeof(marker));
	if (ret != sizeof(marker) ||
	    le32_to_cpu(marker.magic) != STRATAFS_STAGE_MARKER_MAGIC ||
	    le16_to_cpu(marker.version) != STRATAFS_STAGE_MARKER_VERSION ||
	    le16_to_cpu(marker.size) != sizeof(marker) ||
	    stratafs_stage_owner_live(le64_to_cpu(marker.boot_cookie),
				      le64_to_cpu(marker.mount_cookie)))
		goto out_victim;
	ret = mnt_want_write(parent->mnt);
	if (ret)
		goto out_victim;
	context = pkm_kacs_stratafs_copy_up_begin(&victim_path);
	if (IS_ERR(context))
		goto out_write;

	directory = d_is_dir(victim);
	ret = pkm_kacs_stratafs_copy_up_begin_orphan_cleanup(
		context, parent, victim, directory);
	if (ret)
		goto out_context;
	locked = start_removing_dentry(parent->dentry, victim);
	if (IS_ERR(locked)) {
		ret = PTR_ERR(locked);
	} else {
		if (directory)
			ret = vfs_rmdir(mnt_idmap(parent->mnt),
					d_inode(parent->dentry), locked, NULL);
		else
			ret = vfs_unlink(mnt_idmap(parent->mnt),
					 d_inode(parent->dentry), locked, NULL);
		end_removing(locked);
	}
	stratafs_copy_phase_leave(context);
	if (ret)
		pr_warn_ratelimited(
			"stratafs: stale staging cleanup failed: %d\n", ret);
out_context:
	stratafs_copy_context_finish(context);
out_write:
	mnt_drop_write(parent->mnt);
out_victim:
	dput(victim);
}

void stratafs_recover_published_marker(struct super_block *sb,
				       const struct path *path)
{
	struct stratafs_stage_marker marker;
	struct pkm_kacs_stratafs_copy_up *context;
	int ret;

	ret = pkm_kacs_stratafs_probe_staging_marker(
		path, &marker, sizeof(marker));
	if (ret != sizeof(marker) ||
	    le32_to_cpu(marker.magic) != STRATAFS_STAGE_MARKER_MAGIC ||
	    le16_to_cpu(marker.version) != STRATAFS_STAGE_MARKER_VERSION ||
	    le16_to_cpu(marker.size) != sizeof(marker))
		return;
	/*
	 * This helper is called only for a published, non-staging name.  A valid
	 * marker there is publication residue and is safe to remove even while
	 * its mount is live; requiring the owner to disappear would make a
	 * transient removexattr failure persist until unmount.
	 */

	context = pkm_kacs_stratafs_copy_up_begin(path);
	if (IS_ERR(context))
		return;
	ret = mnt_want_write(path->mnt);
	if (ret) {
		stratafs_copy_context_finish(context);
		return;
	}
	ret = pkm_kacs_stratafs_copy_up_begin_orphan_marker_cleanup(context);
	if (!ret)
		ret = vfs_removexattr(mnt_idmap(path->mnt), path->dentry,
				      STRATAFS_XATTR_STAGING);
	if (!ret)
		stratafs_copy_phase_leave(context);
	else
		pkm_kacs_stratafs_copy_up_end_phase(context);
	mnt_drop_write(path->mnt);
	stratafs_copy_context_finish(context);
	if (ret)
		pr_warn_ratelimited(
			"stratafs: published recovery marker cleanup failed: %d\n",
			ret);
}

void stratafs_recover_staging_parent(struct super_block *sb,
				     const struct path *parent)
{
	struct stratafs_recovery_capture capture = {
		.ctx.actor = stratafs_recovery_actor,
	};
	struct stratafs_recovery_name *candidate;
	struct stratafs_recovery_name *next;
	struct pkm_kacs_stratafs_copy_up *context;
	struct file *directory = NULL;
	bool attached = false;
	bool phase_active = false;
	int ret;

	if (!parent || !parent->dentry || !d_is_dir(parent->dentry))
		return;
	INIT_LIST_HEAD(&capture.names);
	context = pkm_kacs_stratafs_copy_up_begin(parent);
	if (IS_ERR(context))
		return;
	attached = true;
	ret = pkm_kacs_stratafs_copy_up_begin_source_read(context);
	if (ret)
		goto out;
	phase_active = true;
	directory = dentry_open(parent, O_RDONLY | O_DIRECTORY | O_LARGEFILE,
				  STRATAFS_SB(sb)->resolution_cred);
	if (IS_ERR(directory)) {
		ret = PTR_ERR(directory);
		directory = NULL;
		goto out;
	}

	for (;;) {
		capture.count = 0;
		capture.error = 0;
		ret = iterate_dir(directory, &capture.ctx);
		pkm_kacs_stratafs_copy_up_end_phase(context);
		phase_active = false;
		pkm_kacs_stratafs_copy_up_leave(context);
		attached = false;
		list_for_each_entry_safe(candidate, next, &capture.names, list) {
			stratafs_recover_one(sb, parent, candidate->name);
			list_del(&candidate->list);
			kfree(candidate->name);
			kfree(candidate);
		}
		if (!ret)
			ret = capture.error;
		if (ret || capture.count < STRATAFS_RECOVERY_BATCH)
			break;

		ret = pkm_kacs_stratafs_copy_up_enter(context);
		if (ret)
			break;
		attached = true;
		ret = pkm_kacs_stratafs_copy_up_begin_source_read(context);
		if (ret)
			break;
		phase_active = true;
		ret = pkm_kacs_stratafs_copy_up_resume_source_directory(
			context, directory);
		if (ret)
			break;
	}

out:
	if (phase_active)
		pkm_kacs_stratafs_copy_up_end_phase(context);
	if (attached)
		pkm_kacs_stratafs_copy_up_leave(context);
	if (directory)
		fput(directory);
	pkm_kacs_stratafs_copy_up_put(context);
	if (ret)
		pr_warn_ratelimited(
			"stratafs: staging recovery scan failed: %d\n", ret);
}

bool stratafs_is_staging(const struct super_block *sb, unsigned int index,
			 const char *relative)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	struct stratafs_staging *staging;
	bool found = false;

	if ((int)index != sbi->create_index)
		return false;
	mutex_lock(&sbi->staging_lock);
	list_for_each_entry(staging, &sbi->staging, list) {
		if (!strcmp(staging->relative, relative)) {
			found = true;
			break;
		}
	}
	mutex_unlock(&sbi->staging_lock);
	return found;
}

struct stratafs_staging *stratafs_add_staging(struct super_block *sb,
					       const char *relative)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	struct stratafs_staging *staging;

	staging = kzalloc_obj(*staging, GFP_KERNEL);
	if (!staging)
		return ERR_PTR(-ENOMEM);
	staging->relative = kstrdup(relative, GFP_KERNEL);
	if (!staging->relative) {
		kfree(staging);
		return ERR_PTR(-ENOMEM);
	}
	mutex_lock(&sbi->staging_lock);
	list_add(&staging->list, &sbi->staging);
	mutex_unlock(&sbi->staging_lock);
	return staging;
}

void stratafs_remove_staging(struct super_block *sb,
			     struct stratafs_staging *staging)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);

	if (!staging)
		return;
	mutex_lock(&sbi->staging_lock);
	list_del(&staging->list);
	mutex_unlock(&sbi->staging_lock);
	kfree(staging->relative);
	kfree(staging);
}

static int stratafs_copy_phase_enter(
	struct pkm_kacs_stratafs_copy_up *context)
{
	/* copy_up_begin() returns a context already attached to current. */
	return context ? 0 : -EINVAL;
}

static void stratafs_copy_phase_leave(
	struct pkm_kacs_stratafs_copy_up *context)
{
	pkm_kacs_stratafs_copy_up_end_phase(context);
}

static void stratafs_copy_context_finish(
	struct pkm_kacs_stratafs_copy_up *context)
{
	pkm_kacs_stratafs_copy_up_leave(context);
	pkm_kacs_stratafs_copy_up_put(context);
}

static int stratafs_stage_marker(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *stage,
	const struct stratafs_sb_info *sbi, bool remove)
{
	struct stratafs_stage_marker marker = {
		.magic = cpu_to_le32(STRATAFS_STAGE_MARKER_MAGIC),
		.version = cpu_to_le16(STRATAFS_STAGE_MARKER_VERSION),
		.size = cpu_to_le16(sizeof(marker)),
		.boot_cookie = cpu_to_le64(sbi->boot_cookie),
		.mount_cookie = cpu_to_le64(sbi->mount_cookie),
	};
	int ret;

	ret = pkm_kacs_stratafs_copy_up_begin_populate(context);
	if (ret)
		return ret;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		return ret;
	}
	if (remove)
		ret = vfs_removexattr(mnt_idmap(stage->mnt), stage->dentry,
				      STRATAFS_XATTR_STAGING);
	else
		ret = vfs_setxattr(mnt_idmap(stage->mnt), stage->dentry,
				   STRATAFS_XATTR_STAGING, &marker,
				   sizeof(marker), XATTR_CREATE);
	stratafs_copy_phase_leave(context);
	return ret;
}

static int stratafs_verify_provider(struct dentry *dentry,
				    const char *relative,
				    const struct path *expected)
{
	struct stratafs_paths paths;
	int provider;
	int ret;

	ret = stratafs_resolve_all(dentry->d_sb, relative, false, &paths);
	if (ret)
		return ret;
	provider = stratafs_provider_index(&paths,
					   STRATAFS_SB(dentry->d_sb)->count);
	if (provider < 0 || !path_equal(&paths.path[provider], expected) ||
	    d_inode(paths.path[provider].dentry) != d_inode(expected->dentry))
		ret = -ESTALE;
	else
		ret = 0;
	stratafs_put_paths(&paths, STRATAFS_SB(dentry->d_sb)->count);
	return ret;
}

static char *stratafs_parent_relative(const char *relative)
{
	char *parent = kstrdup(relative, GFP_KERNEL);
	char *slash;

	if (!parent)
		return ERR_PTR(-ENOMEM);
	slash = strrchr(parent, '/');
	if (slash)
		*slash = '\0';
	else
		parent[0] = '\0';
	return parent;
}

int stratafs_provider_directory(struct super_block *sb, const char *relative,
				struct path *provider)
{
	struct stratafs_paths paths;
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	int provider_index;
	int ret;

	ret = stratafs_resolve_all(sb, relative, true, &paths);
	if (ret)
		return ret;
	provider_index = stratafs_provider_index(&paths, sbi->count);
	if (provider_index < 0)
		ret = -ENOENT;
	else if (!d_is_dir(paths.path[provider_index].dentry))
		ret = -ENOTDIR;
	else {
		*provider = paths.path[provider_index];
		path_get(provider);
		ret = 0;
	}
	stratafs_put_paths(&paths, sbi->count);
	return ret;
}

int stratafs_kacs_creation_parent(const struct path *outer_parent,
				   struct path *security_parent)
{
	struct stratafs_sb_info *sbi;
	struct path create_root;
	char *relative;
	int ret;

	if (!outer_parent || !outer_parent->dentry || !security_parent ||
	    outer_parent->dentry->d_sb->s_magic != STRATAFS_MAGIC ||
	    !d_is_dir(outer_parent->dentry))
		return -EINVAL;
	sbi = STRATAFS_SB(outer_parent->dentry->d_sb);
	if (!sbi || !STRATAFS_I(d_inode(outer_parent->dentry)) ||
	    sbi->create_index < 0)
		return -EROFS;
	relative = stratafs_inode_relative(d_inode(outer_parent->dentry));
	if (IS_ERR(relative))
		return PTR_ERR(relative);

	/* An absent create stratum is never materialised by StrataFS itself. */
	ret = stratafs_resolve_one(outer_parent->dentry->d_sb, sbi->create_index,
				   "", true, &create_root);
	if (ret) {
		if (ret == -ENOENT)
			ret = -EROFS;
		goto out_relative;
	}
	if (!d_is_dir(create_root.dentry)) {
		path_put(&create_root);
		ret = -ENOTDIR;
		goto out_relative;
	}
	path_put(&create_root);

	ret = stratafs_resolve_one(outer_parent->dentry->d_sb,
				   sbi->create_index, relative, true,
				   security_parent);
	if (ret == -ENOENT)
		ret = stratafs_provider_directory(outer_parent->dentry->d_sb,
						 relative, security_parent);
	if (ret)
		goto out_relative;
	if (!d_is_dir(security_parent->dentry)) {
		path_put(security_parent);
		ret = -ENOTDIR;
	}
out_relative:
	kfree(relative);
	return ret;
}

int stratafs_kacs_removal_parent(const struct path *outer_target,
				  struct path *security_parent)
{
	struct path provider;
	char *relative;
	char *parent_relative;
	unsigned int provider_index;
	int ret;

	if (!outer_target || !outer_target->dentry || !security_parent ||
	    outer_target->dentry->d_sb->s_magic != STRATAFS_MAGIC ||
	    !d_really_is_positive(outer_target->dentry))
		return -EINVAL;
	relative = stratafs_inode_relative(d_inode(outer_target->dentry));
	if (IS_ERR(relative))
		return PTR_ERR(relative);
	parent_relative = stratafs_parent_relative(relative);
	if (IS_ERR(parent_relative)) {
		ret = PTR_ERR(parent_relative);
		goto out_relative;
	}
	ret = stratafs_get_provider(outer_target->dentry, &provider,
				    &provider_index);
	if (ret)
		goto out_relative;
	ret = stratafs_verify_provider(outer_target->dentry, relative, &provider);
	path_put(&provider);
	if (ret)
		goto out_relative;
	ret = stratafs_resolve_one(outer_target->dentry->d_sb, provider_index,
				   parent_relative, true,
				   security_parent);
	if (ret)
		goto out_relative;
	if (!d_is_dir(security_parent->dentry)) {
		path_put(security_parent);
		ret = -ENOTDIR;
	}
out_relative:
	if (!IS_ERR_OR_NULL(parent_relative))
		kfree(parent_relative);
	kfree(relative);
	return ret;
}

int stratafs_kacs_removal_target(const struct path *outer_target,
				  struct path *security_target)
{
	char *relative;
	int ret;

	if (!outer_target || !outer_target->dentry || !security_target ||
	    outer_target->dentry->d_sb->s_magic != STRATAFS_MAGIC ||
	    !d_really_is_positive(outer_target->dentry))
		return -EINVAL;
	relative = stratafs_inode_relative(d_inode(outer_target->dentry));
	if (IS_ERR(relative))
		return PTR_ERR(relative);
	ret = stratafs_get_provider(outer_target->dentry, security_target, NULL);
	if (ret)
		goto out;
	ret = stratafs_verify_provider(outer_target->dentry, relative,
					security_target);
	if (ret)
		path_put(security_target);
out:
	kfree(relative);
	return ret;
}

int stratafs_validate_supersede_dentry(const struct dentry *outer_target)
{
	struct stratafs_sb_info *sbi;
	struct stratafs_paths paths;
	struct path provider;
	struct path create_root;
	char *relative;
	unsigned int provider_index;
	unsigned int i;
	int ret;

	if (!outer_target || outer_target->d_sb->s_magic != STRATAFS_MAGIC ||
	    !d_really_is_positive((struct dentry *)outer_target))
		return -EINVAL;
	sbi = STRATAFS_SB(outer_target->d_sb);
	if (!sbi || !STRATAFS_I(d_inode(outer_target)) || sbi->create_index < 0)
		return -EROFS;
	relative = stratafs_inode_relative(d_inode(outer_target));
	if (IS_ERR(relative))
		return PTR_ERR(relative);
	ret = stratafs_resolve_one(outer_target->d_sb,
				   sbi->create_index, "", true, &create_root);
	if (ret) {
		if (ret == -ENOENT)
			ret = -EROFS;
		goto out_relative;
	}
	ret = d_is_dir(create_root.dentry) ? 0 : -ENOTDIR;
	path_put(&create_root);
	if (ret)
		goto out_relative;
	ret = stratafs_get_provider((struct dentry *)outer_target, &provider,
				    &provider_index);
	if (ret)
		goto out_relative;
	if (!stratafs_stratum_accepts(outer_target->d_sb,
				      provider_index, &provider)) {
		path_put(&provider);
		ret = -EROFS;
		goto out_relative;
	}
	ret = stratafs_verify_provider((struct dentry *)outer_target, relative,
					&provider);
	path_put(&provider);
	if (ret)
		goto out_relative;

	ret = stratafs_resolve_all(outer_target->d_sb, relative,
				   false, &paths);
	if (ret)
		goto out_relative;
	ret = -ESTALE;
	if (!(paths.present & BIT_ULL(provider_index)) ||
	    stratafs_provider_index(&paths, sbi->count) != provider_index)
		goto out;
	/*
	 * Removing the provider must expose the create stratum's new object.
	 * A second holder above it would shadow the replacement, while an
	 * already-existing entry in the create stratum would itself need a
	 * separate, unauthorized removal.
	 */
	for (i = 0; i < (unsigned int)sbi->create_index; i++) {
		if (i != provider_index && (paths.present & BIT_ULL(i))) {
			ret = -EROFS;
			goto out;
		}
	}
	if (provider_index != (unsigned int)sbi->create_index &&
	    (paths.present & BIT_ULL(sbi->create_index))) {
		ret = -EROFS;
		goto out;
	}
	ret = 0;
out:
	stratafs_put_paths(&paths, sbi->count);
out_relative:
	kfree(relative);
	return ret;
}

int stratafs_kacs_validate_supersede(const struct path *outer_target)
{
	if (!outer_target || !outer_target->mnt || !outer_target->dentry)
		return -EINVAL;
	return stratafs_validate_supersede_dentry(outer_target->dentry);
}

static int stratafs_materialize_directory(
	struct super_block *sb, struct pkm_kacs_stratafs_copy_up *context,
	const struct path *provider, const struct path *parent, const char *name,
	struct path *created)
{
	struct qstr q = QSTR_INIT(name, strlen(name));
	struct dentry *child;
	struct dentry *mkdir_result;
	struct mnt_idmap *idmap = mnt_idmap(parent->mnt);
	umode_t mode = d_inode(provider->dentry)->i_mode;
	int ret;

	ret = mnt_want_write(parent->mnt);
	if (ret)
		return ret;
	q.hash = full_name_hash(parent->dentry, q.name, q.len);
	child = start_creating_noperm(parent->dentry, &q);
	if (IS_ERR(child)) {
		ret = PTR_ERR(child);
		goto out_write;
	}
	if (d_really_is_positive(child)) {
		ret = d_is_dir(child) ? 0 : -ENOTDIR;
		if (!ret) {
			created->mnt = parent->mnt;
			created->dentry = child;
			path_get(created);
		}
		end_creating(child);
		goto out_write;
	}

	ret = pkm_kacs_stratafs_copy_up_begin_create(
		context, provider, parent, child, mode);
	if (ret)
		goto out;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		goto out;
	}
	mkdir_result = vfs_mkdir(idmap, d_inode(parent->dentry), child, mode,
				 NULL);
	stratafs_copy_phase_leave(context);
	if (IS_ERR(mkdir_result)) {
		ret = PTR_ERR(mkdir_result);
		/* vfs_mkdir() already ended and consumed child on error. */
		child = NULL;
		goto out;
	}
	created->mnt = parent->mnt;
	created->dentry = mkdir_result;
	path_get(created);
	end_creating(mkdir_result);
	ret = 0;
	goto out_write;
out:
	if (child)
		end_creating(child);
out_write:
	mnt_drop_write(parent->mnt);
	return ret;
}

static int stratafs_ensure_create_parent_context(
	struct dentry *parent_dentry,
	const char *parent_relative,
	struct pkm_kacs_stratafs_copy_up *context, struct path *result)
{
	struct super_block *sb = parent_dentry->d_sb;
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	struct path create_cursor;
	char *walk = NULL;
	char *cursor;
	char *component;
	char *prefix = NULL;
	size_t prefix_len = 0;
	int ret;

	if (sbi->create_index < 0)
		return -EROFS;
	ret = stratafs_resolve_one(sb, sbi->create_index, "", true,
				   &create_cursor);
	if (ret)
		return ret == -ENOENT ? -EROFS : ret;
	if (!d_is_dir(create_cursor.dentry)) {
		path_put(&create_cursor);
		return -ENOTDIR;
	}
	if (!parent_relative[0]) {
		*result = create_cursor;
		return 0;
	}

	walk = kstrdup(parent_relative, GFP_KERNEL);
	prefix = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!walk || !prefix) {
		ret = -ENOMEM;
		goto fail;
	}
	cursor = walk;
	while ((component = strsep(&cursor, "/")) != NULL) {
		struct path existing;
		struct path provider;
		struct path created;
		size_t len = strlen(component);

		if (!len || prefix_len + !!prefix_len + len + 1 > PATH_MAX) {
			ret = -EINVAL;
			goto fail;
		}
		if (prefix_len)
			prefix[prefix_len++] = '/';
		memcpy(prefix + prefix_len, component, len + 1);
		prefix_len += len;

		ret = stratafs_resolve_one(sb, sbi->create_index, prefix, true,
					   &existing);
		if (!ret) {
			if (!d_is_dir(existing.dentry)) {
				path_put(&existing);
				ret = -ENOTDIR;
				goto fail;
			}
			path_put(&create_cursor);
			create_cursor = existing;
			continue;
		}
		if (ret != -ENOENT) {
			if (ret == -ENOTDIR)
				ret = -ENOTDIR;
			goto fail;
		}
		ret = stratafs_provider_directory(sb, prefix, &provider);
		if (ret)
			goto fail;
		ret = stratafs_materialize_directory(sb, context, &provider,
						     &create_cursor, component, &created);
		path_put(&provider);
		if (ret)
			goto fail;
		path_put(&create_cursor);
		create_cursor = created;
	}
	kfree(walk);
	kfree(prefix);
	*result = create_cursor;
	return 0;
fail:
	kfree(walk);
	kfree(prefix);
	path_put(&create_cursor);
	return ret;
}

int stratafs_ensure_create_parent(struct dentry *parent,
				  struct path *create_parent)
{
	struct path provider;
	struct pkm_kacs_stratafs_copy_up *context;
	char *relative;
	int ret;

	relative = stratafs_inode_relative(d_inode(parent));
	if (IS_ERR(relative))
		return PTR_ERR(relative);
	ret = stratafs_provider_directory(parent->d_sb, relative, &provider);
	if (ret)
		goto out_relative;
	context = pkm_kacs_stratafs_copy_up_begin(&provider);
	path_put(&provider);
	if (IS_ERR(context)) {
		ret = PTR_ERR(context);
		goto out_relative;
	}
	ret = stratafs_ensure_create_parent_context(parent, relative, context,
						     create_parent);
	stratafs_copy_context_finish(context);
out_relative:
	kfree(relative);
	return ret;
}

static int stratafs_copy_regular_contents(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *source,
	const struct path *stage, struct file *source_file)
{
	char *buffer;
	loff_t position = 0;
	int ret = 0;

	buffer = kvmalloc(STRATAFS_COPY_BUFFER_SIZE, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	for (;;) {
		struct file *file;
		ssize_t read;
		loff_t read_pos = position;
		loff_t write_pos = position;
		ssize_t written = 0;

		ret = pkm_kacs_stratafs_copy_up_begin_source_read(context);
		if (ret)
			break;
		ret = stratafs_copy_phase_enter(context);
		if (ret) {
			pkm_kacs_stratafs_copy_up_end_phase(context);
			break;
		}
		file = source_file ?: kernel_file_open(
			source, O_RDONLY | O_LARGEFILE, current_cred());
		if (IS_ERR(file))
			read = PTR_ERR(file);
		else {
			read = kernel_read(file, buffer, STRATAFS_COPY_BUFFER_SIZE,
					   &read_pos);
			if (!source_file)
				fput(file);
		}
		stratafs_copy_phase_leave(context);
		if (read < 0) {
			ret = read;
			break;
		}
		if (!read)
			break;

		ret = pkm_kacs_stratafs_copy_up_begin_populate(context);
		if (ret)
			break;
		ret = stratafs_copy_phase_enter(context);
		if (ret) {
			pkm_kacs_stratafs_copy_up_end_phase(context);
			break;
		}
		file = kernel_file_open(stage, O_WRONLY | O_LARGEFILE,
					current_cred());
		if (IS_ERR(file))
			ret = PTR_ERR(file);
		else {
			while (written < read) {
				ssize_t amount = kernel_write(file, buffer + written,
							read - written, &write_pos);

				if (amount <= 0) {
					ret = amount < 0 ? amount : -EIO;
					break;
				}
				written += amount;
			}
			fput(file);
		}
		stratafs_copy_phase_leave(context);
		if (ret)
			break;
		position += read;
	}
	kvfree(buffer);
	return ret;
}

static int stratafs_copy_one_xattr(
	struct super_block *sb, struct pkm_kacs_stratafs_copy_up *context,
	const struct path *source, const struct path *stage, const char *name)
{
	void *value = NULL;
	ssize_t size;
	int ret;

	if (!strncmp(name, STRATAFS_XATTR_PREFIX,
			strlen(STRATAFS_XATTR_PREFIX)) ||
	    !strcmp(name, STRATAFS_XATTR_STAGING) ||
	    pkm_kacs_stratafs_is_descriptor_xattr(d_inode(source->dentry), name))
		return 0;

	ret = pkm_kacs_stratafs_copy_up_begin_source_read(context);
	if (ret)
		return ret;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		return ret;
	}
	size = vfs_getxattr(mnt_idmap(source->mnt), source->dentry, name, NULL, 0);
	if (size > 0) {
		value = kvmalloc(size, GFP_KERNEL);
		if (!value)
			ret = -ENOMEM;
		else {
			ret = vfs_getxattr(mnt_idmap(source->mnt), source->dentry,
					   name, value, size);
			if (ret == size)
				ret = 0;
			else if (ret >= 0)
				ret = -EIO;
		}
	} else if (size == 0) {
		ret = 0;
	} else {
		ret = size;
	}
	stratafs_copy_phase_leave(context);
	if (ret)
		goto out;

	ret = pkm_kacs_stratafs_copy_up_begin_populate(context);
	if (ret)
		goto out;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		goto out;
	}
	if (!strcmp(name, XATTR_NAME_CAPS)) {
		ret = pkm_kacs_stratafs_copy_up_set_capability(context, value, size);
		/*
		 * Unconditional, not just on error.  The clone helper has
		 * *already* installed the attribute via vfs_setxattr() with
		 * XATTR_CREATE, having satisfied CAP_SETFCAP synchronously
		 * inside the call, and it clears capability_clone_active before
		 * returning.  Falling through to the generic path below re-
		 * entered the LSM with that window closed, so the second write
		 * was denied -EPERM and stratafs_copy_xattrs() turned it into
		 * -EIO -- failing every copy-up of a capability-bearing file
		 * (ping, newuidmap, newgidmap) after the privileged work had
		 * correctly succeeded.
		 */
		goto leave;
	}
	ret = vfs_setxattr(mnt_idmap(stage->mnt), stage->dentry, name, value,
			   size, XATTR_CREATE);
leave:
	stratafs_copy_phase_leave(context);
out:
	kvfree(value);
	return ret;
}

static int stratafs_copy_xattrs(
	struct super_block *sb, struct pkm_kacs_stratafs_copy_up *context,
	const struct path *source, const struct path *stage)
{
	char *list = NULL;
	ssize_t length;
	char *name;
	size_t left;
	int ret;

	ret = pkm_kacs_stratafs_copy_up_begin_source_read(context);
	if (ret)
		return ret;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		return ret;
	}
	length = vfs_listxattr(source->dentry, NULL, 0);
	if (length > 0) {
		if (length > XATTR_LIST_MAX) {
			ret = -EIO;
			goto leave;
		}
		list = kvmalloc(length, GFP_KERNEL);
		if (!list)
			ret = -EIO;
		else {
			ret = vfs_listxattr(source->dentry, list, length);
			if (ret == length)
				ret = 0;
			else
				ret = -EIO;
		}
	} else if (length == 0) {
		ret = 0;
	} else {
		ret = -EIO;
	}
leave:
	stratafs_copy_phase_leave(context);
	if (ret)
		goto out;

	for (name = list, left = length; left;) {
		size_t size = strnlen(name, left) + 1;

		if (size > left) {
			ret = -EIO;
			break;
		}
		ret = stratafs_copy_one_xattr(sb, context, source, stage, name);
		if (ret) {
			ret = -EIO;
			break;
		}
		name += size;
		left -= size;
	}
out:
	kvfree(list);
	return ret;
}

static int stratafs_copy_metadata(
	struct super_block *sb, struct pkm_kacs_stratafs_copy_up *context,
	const struct path *source, const struct path *stage)
{
	struct inode *inode = d_inode(source->dentry);
	struct iattr attr = {
		.ia_valid = ATTR_MTIME | ATTR_MTIME_SET,
		.ia_mtime = inode_get_mtime(inode),
	};
	int ret;

	/*
	 * A symlink's mode is fixed by the VFS and not the caller's to set, so
	 * only the timestamp is carried across for one.
	 */
	if (!S_ISLNK(inode->i_mode)) {
		attr.ia_valid |= ATTR_MODE;
		attr.ia_mode = inode->i_mode;
	}

	ret = pkm_kacs_stratafs_copy_up_begin_populate(context);
	if (ret)
		return ret;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		return ret;
	}
	ret = stratafs_notify_change(stage, &attr);
	if (ret) {
		stratafs_copy_phase_leave(context);
		return ret;
	}

	/*
	 * POSIX ownership, so quota follows the object rather than the caller.
	 *
	 * PCSA §5.8: the copy is accounted to the owner of the object copied
	 * *from*, not to the caller whose operation caused it. The KACS
	 * descriptor already carried its owner SID across (§6.3), but disk
	 * quota keys on uid/gid, and the stage is created with current_cred()
	 * -- so the space landed against whoever provoked the copy.
	 *
	 * That mattered because §6.2 deliberately permits a caller entitled to
	 * write a file in a read-only stratum to cause an entry to appear in
	 * the create stratum without holding rights over that directory, on
	 * the reasoning that they gain no access and the space is accounted to
	 * the preserved owner. Half of that was not true.
	 *
	 * Chowning to another uid needs authority the caller does not have, so
	 * it runs under the mount's own credential -- the same one stratafs
	 * already uses to reach providers the caller cannot. It is a separate
	 * notify_change because the mode and timestamp above are the caller's
	 * to set and should stay that way.
	 */
	if (!uid_eq(inode->i_uid, current_fsuid()) ||
	    !gid_eq(inode->i_gid, current_fsgid())) {
		struct iattr owner = {
			.ia_valid = ATTR_UID | ATTR_GID,
			.ia_uid = inode->i_uid,
			.ia_gid = inode->i_gid,
		};
		const struct cred *old_cred;

		old_cred = override_creds(STRATAFS_SB(sb)->resolution_cred);
		ret = stratafs_notify_change(stage, &owner);
		revert_creds(old_cred);
	}

	stratafs_copy_phase_leave(context);
	return ret;
}

static int stratafs_read_symlink(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *source,
	char **target)
{
	struct delayed_call done = {};
	const char *link;
	int ret;

	ret = pkm_kacs_stratafs_copy_up_begin_source_read(context);
	if (ret)
		return ret;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		return ret;
	}
	link = vfs_get_link(source->dentry, &done);
	if (IS_ERR(link))
		ret = PTR_ERR(link);
	else {
		*target = kstrdup(link, GFP_KERNEL);
		ret = *target ? 0 : -ENOMEM;
	}
	do_delayed_call(&done);
	stratafs_copy_phase_leave(context);
	return ret;
}

static int stratafs_cleanup_named(
	struct pkm_kacs_stratafs_copy_up *context, const struct path *parent,
	const struct path *stage, bool directory)
{
	struct dentry *victim;
	int ret;

	if (!d_really_is_positive(stage->dentry))
		return 0;
	ret = pkm_kacs_stratafs_copy_up_begin_cleanup(
		context, parent, stage->dentry, directory);
	if (ret)
		return ret;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		return ret;
	}
	victim = start_removing_dentry(parent->dentry, stage->dentry);
	if (IS_ERR(victim))
		ret = PTR_ERR(victim);
	else {
		if (directory)
			ret = vfs_rmdir(mnt_idmap(parent->mnt),
					d_inode(parent->dentry), victim, NULL);
		else
			ret = vfs_unlink(mnt_idmap(parent->mnt),
					 d_inode(parent->dentry), victim, NULL);
		end_removing(victim);
	}
	stratafs_copy_phase_leave(context);
	return ret;
}

static int stratafs_create_named_stage(
	struct dentry *dentry, struct pkm_kacs_stratafs_copy_up *context,
	const char *parent_relative, const struct path *source,
	const struct path *parent, const char *link,
	struct path *stage, struct stratafs_staging **tracking)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(dentry->d_sb);
	char name[64];
	struct qstr q;
	struct dentry *child;
	struct dentry *mkdir_result = NULL;
	char *relative;
	umode_t mode = d_inode(source->dentry)->i_mode;
	unsigned int attempt;
	int ret = -EEXIST;

	ret = mnt_want_write(parent->mnt);
	if (ret)
		return ret;
	for (attempt = 0; attempt < 8; attempt++) {
		u64 id = get_random_u64() ^ atomic64_inc_return(&sbi->next_stage);

		snprintf(name, sizeof(name), ".stratafs-stage-%016llx-%016llx",
			 sbi->mount_cookie, id);
		q = (struct qstr)QSTR_INIT(name, strlen(name));
		q.hash = full_name_hash(parent->dentry, q.name, q.len);
		relative = stratafs_child_relative(parent_relative, &q);
		if (IS_ERR(relative)) {
			ret = PTR_ERR(relative);
			goto out_write;
		}
		*tracking = stratafs_add_staging(dentry->d_sb, relative);
		kfree(relative);
		if (IS_ERR(*tracking)) {
			ret = PTR_ERR(*tracking);
			goto out_write;
		}
		child = start_creating_noperm(parent->dentry, &q);
		if (IS_ERR(child)) {
			ret = PTR_ERR(child);
			stratafs_remove_staging(dentry->d_sb, *tracking);
			*tracking = NULL;
			goto out_write;
		}
		if (d_really_is_positive(child)) {
			end_creating(child);
			stratafs_remove_staging(dentry->d_sb, *tracking);
			*tracking = NULL;
			continue;
		}

		ret = pkm_kacs_stratafs_copy_up_begin_create(
			context, source, parent, child, mode);
		if (ret)
			goto out_child;
		ret = stratafs_copy_phase_enter(context);
		if (ret) {
			pkm_kacs_stratafs_copy_up_end_phase(context);
			goto out_child;
		}
		if (S_ISDIR(mode)) {
			mkdir_result = vfs_mkdir(mnt_idmap(parent->mnt),
					d_inode(parent->dentry), child, mode, NULL);
			if (IS_ERR(mkdir_result)) {
				/* vfs_mkdir() consumed child on failure. */
				ret = PTR_ERR(mkdir_result);
				mkdir_result = NULL;
				child = NULL;
			} else {
				ret = 0;
			}
		} else {
			ret = vfs_symlink(mnt_idmap(parent->mnt),
					d_inode(parent->dentry), child, link, NULL);
		}
		if (!ret) {
			struct path created = {
				.mnt = parent->mnt,
				.dentry = mkdir_result ?: child,
			};

			ret = pkm_kacs_stratafs_copy_up_confirm_named_create(
				context, &created);
		}
		stratafs_copy_phase_leave(context);
		if (ret)
			goto out_child;
		stage->mnt = parent->mnt;
		stage->dentry = mkdir_result ?: child;
		path_get(stage);
		end_creating(mkdir_result ?: child);
		ret = 0;
		goto out_write;
out_child:
		if (child)
			end_creating(child);
		stratafs_remove_staging(dentry->d_sb, *tracking);
		*tracking = NULL;
		goto out_write;
	}

out_write:
	mnt_drop_write(parent->mnt);
	return ret;
}

static int stratafs_publish_named(
	struct dentry *dentry, struct pkm_kacs_stratafs_copy_up *context,
	const struct path *source, const struct path *stage,
	const struct path *parent, const char *relative, const char *name,
	struct path *published)
{
	struct qstr q = QSTR_INIT(name, strlen(name));
	struct dentry *target;
	struct renamedata rd = {
		.mnt_idmap = mnt_idmap(parent->mnt),
		.old_parent = parent->dentry,
		.old_dentry = stage->dentry,
		.new_parent = parent->dentry,
		.flags = RENAME_NOREPLACE,
	};
	int ret;

	q.hash = full_name_hash(parent->dentry, q.name, q.len);
	target = lookup_noperm_unlocked(&q, parent->dentry);
	if (IS_ERR(target))
		return PTR_ERR(target);
	rd.new_dentry = target;
	ret = start_renaming_two_dentries(&rd, stage->dentry, target);
	if (ret)
		goto out_target;
	if (d_really_is_positive(target)) {
		ret = -ESTALE;
		goto out_rename;
	}
	ret = stratafs_verify_provider(dentry, relative, source);
	if (ret)
		goto out_rename;
	ret = pkm_kacs_stratafs_copy_up_begin_publish_rename(
		context, parent, target);
	if (ret)
		goto out_rename;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		goto out_rename;
	}
	ret = vfs_rename(&rd);
	if (!ret) {
		published->mnt = parent->mnt;
		/* vfs_rename() moves the source dentry to the target name. */
		published->dentry = stage->dentry;
		path_get(published);
		ret = pkm_kacs_stratafs_copy_up_finish_publish(context, published);
		if (ret) {
			path_put(published);
			memset(published, 0, sizeof(*published));
		}
	} else {
		stratafs_copy_phase_leave(context);
	}
	if (ret == -EEXIST)
		ret = -ESTALE;
out_rename:
	end_renaming(&rd);
out_target:
	dput(target);
	return ret;
}

static int stratafs_copy_up_named(struct dentry *dentry, const char *relative,
				  struct path *published)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(dentry->d_sb);
	struct path source;
	struct path parent;
	struct path stage = {};
	struct stratafs_staging *tracking = NULL;
	struct pkm_kacs_stratafs_copy_up *context;
	char *parent_relative;
	const char *name;
	char *link = NULL;
	unsigned int source_index;
	bool directory;
	bool published_ok = false;
	bool write_held = false;
	int ret;

	parent_relative = stratafs_parent_relative(relative);
	if (IS_ERR(parent_relative))
		return PTR_ERR(parent_relative);
	name = strrchr(relative, '/');
	name = name ? name + 1 : relative;
	if (!*name) {
		ret = -ESTALE;
		goto out_relative;
	}
	ret = stratafs_get_provider(dentry, &source, &source_index);
	if (ret)
		goto out_relative;
	directory = d_is_dir(source.dentry);
	ret = stratafs_verify_provider(dentry, relative, &source);
	if (ret)
		goto out_source;
	ret = stratafs_resolve_one(dentry->d_sb, sbi->create_index,
		parent_relative, true, &parent);
	if (!ret) {
		if (d_is_dir(parent.dentry))
			stratafs_recover_staging_parent(dentry->d_sb, &parent);
		path_put(&parent);
	} else if (ret != -ENOENT) {
		goto out_source;
	}
	ret = stratafs_test_hook(STRATAFS_HOOK_COPY_UP_BEGIN);
	if (ret)
		goto out_source;
	context = pkm_kacs_stratafs_copy_up_begin(&source);
	if (IS_ERR(context)) {
		ret = PTR_ERR(context);
		goto out_source;
	}
	ret = stratafs_ensure_create_parent_context(dentry->d_parent,
						     parent_relative, context, &parent);
	if (ret)
		goto out_context;
	ret = mnt_want_write(parent.mnt);
	if (ret)
		goto out_parent;
	write_held = true;
	if (d_is_symlink(source.dentry)) {
		ret = stratafs_read_symlink(context, &source, &link);
		if (ret)
			goto out_parent;
	}
	ret = stratafs_create_named_stage(dentry, context, parent_relative,
					  &source, &parent, link, &stage, &tracking);
	if (ret)
		goto out_parent;
	ret = pkm_kacs_stratafs_copy_up_bind_staging(context, &stage);
	if (ret)
		goto out_stage;
	ret = stratafs_stage_marker(context, &stage, sbi, false);
	if (ret)
		goto out_stage;
	ret = stratafs_copy_xattrs(dentry->d_sb, context, &source, &stage);
	if (ret)
		goto out_stage;
	/*
	 * Symlinks too: PCSA asks that modification timestamps be preserved,
	 * and a copied-up symlink used to arrive with the current time because
	 * only the directory case reached here. Regular files are handled on
	 * their own path below.
	 */
	if (directory || d_is_symlink(source.dentry)) {
		ret = stratafs_copy_metadata(dentry->d_sb, context, &source,
					     &stage);
		if (ret)
			goto out_stage;
	}
	ret = stratafs_test_hook(STRATAFS_HOOK_COPY_UP_PUBLISH);
	if (ret)
		goto out_stage;
	ret = stratafs_publish_named(dentry, context, &source, &stage, &parent,
				     relative, name, published);
	if (!ret) {
		published_ok = true;
		ret = stratafs_stage_marker(context, published, sbi, true);
		if (ret)
			pr_warn_ratelimited(
				"stratafs: published copy retains recovery marker: %d\n",
				ret);
		/* Publication succeeded; marker recovery is best-effort here. */
		ret = 0;
	}
out_stage:
	if (!published_ok) {
		int cleanup_ret = stratafs_cleanup_named(context, &parent, &stage,
							 directory);

		if (!ret)
			ret = cleanup_ret;
	}
	stratafs_remove_staging(dentry->d_sb, tracking);
	path_put(&stage);
out_parent:
	kfree(link);
	if (write_held)
		mnt_drop_write(parent.mnt);
	path_put(&parent);
out_context:
	stratafs_copy_context_finish(context);
out_source:
	path_put(&source);
out_relative:
	kfree(parent_relative);
	return ret;
}

static int stratafs_publish_anonymous(
	struct dentry *dentry, struct pkm_kacs_stratafs_copy_up *context,
	const struct path *source, const struct path *stage,
	const struct path *parent, const char *relative, const char *name,
	struct path *published)
{
	struct qstr q = QSTR_INIT(name, strlen(name));
	struct dentry *target;
	int ret;

	q.hash = full_name_hash(parent->dentry, q.name, q.len);
	target = start_creating_noperm(parent->dentry, &q);
	if (IS_ERR(target))
		return PTR_ERR(target);
	if (d_really_is_positive(target)) {
		ret = -ESTALE;
		goto out;
	}
	ret = stratafs_verify_provider(dentry, relative, source);
	if (ret)
		goto out;
	ret = pkm_kacs_stratafs_copy_up_begin_publish_link(
		context, parent, target);
	if (ret)
		goto out;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		goto out;
	}
	ret = vfs_link(stage->dentry, mnt_idmap(parent->mnt),
		       d_inode(parent->dentry), target, NULL);
	if (!ret) {
		int finish_ret;

		published->mnt = parent->mnt;
		published->dentry = target;
		path_get(published);
		finish_ret = pkm_kacs_stratafs_copy_up_finish_publish(
			context, published);
		if (finish_ret) {
			int cleanup_ret = -ESTALE;

			path_put(published);
			memset(published, 0, sizeof(*published));
			if (d_inode(target) == d_inode(stage->dentry)) {
				cleanup_ret =
					pkm_kacs_stratafs_begin_created_cleanup(
						d_inode(parent->dentry), target);
				if (!cleanup_ret) {
					cleanup_ret = vfs_unlink(
						mnt_idmap(parent->mnt),
						d_inode(parent->dentry), target,
						NULL);
					pkm_kacs_stratafs_end_created_cleanup();
				}
			}
			if (cleanup_ret) {
				stratafs_audit_refusal(
					dentry, "copy-up-publication-rollback",
					STRATAFS_SB(dentry->d_sb)->create_index,
					cleanup_ret, true);
				pr_err_ratelimited(
					"stratafs: failed to roll back linked copy after publication handoff failure: %d\n",
					cleanup_ret);
			}
			ret = finish_ret;
		}
	} else {
		stratafs_copy_phase_leave(context);
	}
	if (ret == -EEXIST)
		ret = -ESTALE;
out:
	end_creating(target);
	return ret;
}

static int stratafs_copy_up_regular(
	struct dentry *dentry, const char *relative, struct file *outer,
	struct path *published,
	struct file **backing_out,
	struct pkm_kacs_stratafs_copy_up **context_out)
{
	struct path source;
	struct path parent;
	struct path stage;
	struct file *tmpfile = NULL;
	struct file *backing = NULL;
	struct file *source_file = NULL;
	struct pkm_kacs_stratafs_copy_up *context;
	char *parent_relative;
	const char *name;
	unsigned int source_index;
	umode_t mode;
	bool write_held = false;
	int ret;

	if (!!outer != !!backing_out || !!outer != !!context_out)
		return -EINVAL;

	parent_relative = stratafs_parent_relative(relative);
	if (IS_ERR(parent_relative))
		return PTR_ERR(parent_relative);
	name = strrchr(relative, '/');
	name = name ? name + 1 : relative;
	if (!*name) {
		ret = -ESTALE;
		goto out_relative;
	}
	ret = stratafs_get_provider(dentry, &source, &source_index);
	if (ret)
		goto out_relative;
	ret = stratafs_verify_provider(dentry, relative, &source);
	if (ret)
		goto out_source;
	if (outer) {
		struct stratafs_file_info *info = outer->private_data;

		source_file = get_file(info->real);
		if (file_inode(source_file) != d_inode(source.dentry)) {
			ret = -ESTALE;
			goto out_source;
		}
	}
	ret = stratafs_test_hook(STRATAFS_HOOK_COPY_UP_BEGIN);
	if (ret)
		goto out_source;
	context = pkm_kacs_stratafs_copy_up_begin(&source);
	if (IS_ERR(context)) {
		ret = PTR_ERR(context);
		goto out_source;
	}
	ret = stratafs_ensure_create_parent_context(dentry->d_parent,
						     parent_relative, context, &parent);
	if (ret)
		goto out_context;
	ret = mnt_want_write(parent.mnt);
	if (ret)
		goto out_parent;
	write_held = true;
	mode = d_inode(source.dentry)->i_mode;
	ret = pkm_kacs_stratafs_copy_up_begin_anonymous_create(
		context, &source, &parent, mode);
	if (ret)
		goto out_parent;
	ret = stratafs_copy_phase_enter(context);
	if (ret) {
		pkm_kacs_stratafs_copy_up_end_phase(context);
		goto out_parent;
	}
	tmpfile = kernel_tmpfile_open(mnt_idmap(parent.mnt), &parent, mode,
				   O_RDWR | O_LARGEFILE, current_cred());
	stratafs_copy_phase_leave(context);
	if (IS_ERR(tmpfile)) {
		ret = PTR_ERR(tmpfile);
		tmpfile = NULL;
		goto out_parent;
	}
	stage = tmpfile->f_path;
	path_get(&stage);
	ret = pkm_kacs_stratafs_copy_up_bind_staging(context, &stage);
	if (ret)
		goto out_stage;
	ret = stratafs_copy_regular_contents(context, &source, &stage,
					      source_file);
	if (ret)
		goto out_stage;
	ret = stratafs_copy_xattrs(dentry->d_sb, context, &source, &stage);
	if (ret)
		goto out_stage;
	ret = stratafs_copy_metadata(dentry->d_sb, context, &source, &stage);
	if (ret)
		goto out_stage;
	if (outer) {
		ret = pkm_kacs_stratafs_copy_up_begin_populate(context);
		if (ret)
			goto out_stage;
		backing = backing_file_open(outer, outer->f_flags, &stage,
					    current_cred());
		pkm_kacs_stratafs_copy_up_end_phase(context);
		if (IS_ERR(backing)) {
			ret = PTR_ERR(backing);
			backing = NULL;
			goto out_stage;
		}
		ret = pkm_kacs_stratafs_copy_up_adopt_backing_file(
			context, outer, backing);
		if (ret)
			goto out_stage;
	}
	ret = stratafs_test_hook(STRATAFS_HOOK_COPY_UP_PUBLISH);
	if (ret)
		goto out_stage;
	ret = stratafs_publish_anonymous(dentry, context, &source, &stage,
					  &parent, relative, name, published);
	if (!ret && context_out) {
		*context_out = context;
		context = NULL;
		if (backing_out) {
			*backing_out = backing;
			backing = NULL;
		}
	}
out_stage:
	if (backing)
		fput(backing);
	path_put(&stage);
	fput(tmpfile);
out_parent:
	if (write_held)
		mnt_drop_write(parent.mnt);
	path_put(&parent);
out_context:
	if (context)
		stratafs_copy_context_finish(context);
out_source:
	if (source_file)
		fput(source_file);
	path_put(&source);
out_relative:
	kfree(parent_relative);
	return ret;
}

int stratafs_copy_up_path(struct dentry *dentry, struct path *result,
			  unsigned int *index)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(dentry->d_sb);
	struct stratafs_inode_info *info = STRATAFS_I(d_inode(dentry));
	struct path original;
	char *relative;
	unsigned int provider_index;
	int ret;

	if (sbi->create_index < 0)
		return -EROFS;
	/* Rename can replace and free the inode's relative name concurrently. */
	mutex_lock(&info->rebind_lock);
	relative = kstrdup(info->relative, GFP_KERNEL);
	mutex_unlock(&info->rebind_lock);
	if (!relative)
		return -ENOMEM;
	ret = stratafs_get_provider(dentry, &original, &provider_index);
	if (ret)
		goto out_relative;
	path_put(&original);
	if (S_ISREG(d_inode(dentry)->i_mode))
		ret = stratafs_copy_up_regular(dentry, relative, NULL, result,
					       NULL, NULL);
	else if (S_ISDIR(d_inode(dentry)->i_mode) ||
		 S_ISLNK(d_inode(dentry)->i_mode))
		ret = stratafs_copy_up_named(dentry, relative, result);
	else
		ret = -EROFS;
	if (!ret) {
		/* A path resolution must never be rebound to a new provider (§4.4). */
		d_drop(dentry);
		if (index)
			*index = sbi->create_index;
	}
	pkm_kacs_stratafs_audit_copy_up(
		relative, provider_index, sbi->strata[provider_index].path,
		sbi->create_index, sbi->strata[sbi->create_index].path, ret);
out_relative:
	kfree(relative);
	return ret;
}

int stratafs_copy_up_file(struct file *file)
{
	struct stratafs_file_info *info = file->private_data;
	struct stratafs_sb_info *sbi = STRATAFS_SB(file_inode(file)->i_sb);
	struct stratafs_inode_info *inode_info = STRATAFS_I(file_inode(file));
	struct pkm_kacs_stratafs_copy_up *context = NULL;
	struct path published;
	struct path published_parent;
	struct file *real = NULL;
	char *relative;
	unsigned int provider_index = info->provider_index;
	int ret;

	/* Superseding rename can replace this descriptor-private name. */
	mutex_lock(&inode_info->rebind_lock);
	relative = kstrdup(inode_info->relative, GFP_KERNEL);
	mutex_unlock(&inode_info->rebind_lock);
	if (!relative)
		return -ENOMEM;
	ret = stratafs_copy_up_regular(file->f_path.dentry, relative, file,
				       &published, &real, &context);
	if (ret)
		goto out_audit;
	ret = stratafs_rebind_open_file(file, &published, sbi->create_index);
	if (ret) {
		published_parent.mnt = mntget(published.mnt);
		published_parent.dentry = dget_parent(published.dentry);
		if (stratafs_cleanup_named(context, &published_parent, &published,
					   false))
			pr_err_ratelimited(
				"stratafs: failed to roll back published copy after descriptor handoff failure\n");
		path_put(&published_parent);
		fput(real);
		goto out_context;
	}
	stratafs_copy_context_finish(context);
	context = NULL;
	if (WARN_ON_ONCE(info->retired_real))
		fput(info->retired_real);
	info->retired_real = info->real;
	path_put(&info->provider);
	info->real = real;
	info->provider = published;
	info->provider_index = sbi->create_index;
	ret = 0;
	goto out_audit;

out_context:
	stratafs_copy_context_finish(context);
	path_put(&published);
out_audit:
	pkm_kacs_stratafs_audit_copy_up(
		relative, provider_index,
		sbi->strata[provider_index].path, sbi->create_index,
		sbi->strata[sbi->create_index].path, ret);
	kfree(relative);
	return ret;
}
