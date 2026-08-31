// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/fs_struct.h>
#include <linux/kacs_stratafs.h>
#include <linux/namei.h>
#include <pkm/file.h>
#include <trace/events/stratafs.h>

#include "../internal.h"
#include "stratafs.h"

struct stratafs_resolution_guard {
	struct list_head list;
	const struct task_struct *task;
	const struct super_block *sb;
};

static LIST_HEAD(stratafs_resolution_guards);
static DEFINE_SPINLOCK(stratafs_resolution_guard_lock);

static bool stratafs_resolution_enter(struct stratafs_resolution_guard *guard,
				      const struct super_block *sb)
{
	struct stratafs_resolution_guard *active;
	bool entered = false;

	spin_lock(&stratafs_resolution_guard_lock);
	list_for_each_entry(active, &stratafs_resolution_guards, list) {
		if (active->task == current && active->sb == sb)
			goto out;
	}
	guard->task = current;
	guard->sb = sb;
	list_add(&guard->list, &stratafs_resolution_guards);
	entered = true;
out:
	spin_unlock(&stratafs_resolution_guard_lock);
	return entered;
}

static void stratafs_resolution_leave(struct stratafs_resolution_guard *guard)
{
	spin_lock(&stratafs_resolution_guard_lock);
	list_del(&guard->list);
	spin_unlock(&stratafs_resolution_guard_lock);
}

static char *stratafs_join_path(const char *base, const char *relative)
{
	size_t base_len = strlen(base);
	size_t rel_len = strlen(relative);
	bool slash = base_len > 0 && base[base_len - 1] != '/' && rel_len > 0;
	char *joined;

	if (base_len + slash + rel_len + 1 > PATH_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	joined = kmalloc(base_len + slash + rel_len + 1, GFP_KERNEL);
	if (!joined)
		return ERR_PTR(-ENOMEM);
	memcpy(joined, base, base_len);
	if (slash)
		joined[base_len++] = '/';
	memcpy(joined + base_len, relative, rel_len + 1);
	return joined;
}

int stratafs_resolve_one(const struct super_block *sb, unsigned int index,
			 const char *relative, bool follow_final,
			 struct path *result)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	struct stratafs_resolution_guard guard;
	const struct cred *old_cred;
	struct filename *name;
	char *joined;
	int ret;

	if (!sbi || index >= sbi->count || !relative || !result)
		return -EINVAL;
	if (!stratafs_resolution_enter(&guard, sb))
		return -ELOOP;
	joined = stratafs_join_path(sbi->strata[index].path, relative);
	if (IS_ERR(joined)) {
		ret = PTR_ERR(joined);
		goto out_guard;
	}
	name = getname_kernel(joined);
	kfree(joined);
	if (IS_ERR(name)) {
		ret = PTR_ERR(name);
		goto out_guard;
	}

	old_cred = override_creds(sbi->resolution_cred);
	ret = filename_lookup(AT_FDCWD, name, follow_final ? LOOKUP_FOLLOW : 0,
			      result, &sbi->resolution_root);
	revert_creds(old_cred);
	putname(name);
out_guard:
	stratafs_resolution_leave(&guard);
	return ret;
}

static int stratafs_resolve_all_raw(const struct super_block *sb,
				    const char *relative, bool follow_final,
				    struct stratafs_paths *paths)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	unsigned int i;
	int ret;

	memset(paths, 0, sizeof(*paths));
	for (i = 0; i < sbi->count; i++) {
		ret = stratafs_resolve_one(sb, i, relative, follow_final,
					   &paths->path[i]);
		if (ret == -ENOENT || ret == -ENOTDIR)
			continue;
		if (ret)
			goto fail;
		if (stratafs_is_staging(sb, i, relative)) {
			path_put(&paths->path[i]);
			memset(&paths->path[i], 0, sizeof(paths->path[i]));
			continue;
		}
		paths->present |= BIT_ULL(i);
	}
	return 0;
fail:
	stratafs_put_paths(paths, sbi->count);
	return ret;
}

int stratafs_resolve_all(const struct super_block *sb, const char *relative,
			 bool follow_final, struct stratafs_paths *paths)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	struct stratafs_paths ancestors;
	char *prefix;
	char *slash;
	int provider;
	int ret;

	if (!relative || !strchr(relative, '/'))
		return stratafs_resolve_all_raw(sb, relative, follow_final, paths);

	/*
	 * A full lower lookup reports ENOTDIR when that stratum has a
	 * non-directory at an ancestor, but another stratum can still resolve
	 * the complete string.  Whether that second answer is reachable depends
	 * on the merged provider of each ancestor: a higher non-directory masks
	 * the entire lower subtree.  Validate each proper prefix independently
	 * before collecting the final participants.
	 */
	prefix = kstrdup(relative, GFP_KERNEL);
	if (!prefix)
		return -ENOMEM;
	for (slash = strchr(prefix, '/'); slash;
	     slash = strchr(slash + 1, '/')) {
		*slash = '\0';
		ret = stratafs_resolve_all_raw(sb, prefix, true, &ancestors);
		if (ret)
			goto out;
		provider = stratafs_provider_index(&ancestors, sbi->count);
		if (provider < 0)
			ret = -ENOENT;
		else if (!d_is_dir(ancestors.path[provider].dentry))
			ret = -ENOTDIR;
		else
			ret = 0;
		stratafs_put_paths(&ancestors, sbi->count);
		*slash = '/';
		if (ret)
			goto out;
	}
	ret = stratafs_resolve_all_raw(sb, relative, follow_final, paths);
out:
	kfree(prefix);
	return ret;
}

void stratafs_put_paths(struct stratafs_paths *paths, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (paths->present & BIT_ULL(i))
			path_put(&paths->path[i]);
	}
	memset(paths, 0, sizeof(*paths));
}

int stratafs_provider_index(const struct stratafs_paths *paths,
			    unsigned int count)
{
	return stratafs_rust_provider(paths->present, count);
}

char *stratafs_child_relative(const char *parent, const struct qstr *name)
{
	size_t parent_len = strlen(parent);
	bool slash = parent_len > 0;
	char *relative;

	if (parent_len + slash + name->len + 1 > PATH_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	relative = kmalloc(parent_len + slash + name->len + 1, GFP_KERNEL);
	if (!relative)
		return ERR_PTR(-ENOMEM);
	memcpy(relative, parent, parent_len);
	if (slash)
		relative[parent_len++] = '/';
	memcpy(relative + parent_len, name->name, name->len);
	relative[parent_len + name->len] = '\0';
	return relative;
}

struct dentry *stratafs_lookup(struct inode *dir, struct dentry *dentry,
			       unsigned int flags)
{
	struct stratafs_dentry_info *info;
	struct stratafs_paths paths;
	struct inode *inode = NULL;
	char *parent_relative;
	char *relative;
	int provider;
	int ret;

	parent_relative = stratafs_inode_relative(dir);
	if (IS_ERR(parent_relative))
		return ERR_CAST(parent_relative);

	/*
	 * A directory descriptor performs live relative resolution.  If the
	 * name by which that directory was opened is now masked by a
	 * non-directory, its old lower directories must not become a path
	 * through the mask merely because the caller retained the descriptor.
	 * The mount root is special: absent or non-directory stratum roots do
	 * not change the synthetic root's directory type.
	 */
	if (parent_relative[0]) {
		struct stratafs_paths parent_paths;
		int parent_provider;

		ret = stratafs_resolve_all(dir->i_sb, parent_relative,
					   false, &parent_paths);
		if (ret)
			goto fail_parent_relative;
		parent_provider = stratafs_provider_index(
			&parent_paths, STRATAFS_SB(dir->i_sb)->count);
		if (parent_provider < 0)
			ret = -ENOENT;
		else if (!d_is_dir(parent_paths.path[parent_provider].dentry))
			ret = -ENOTDIR;
		else
			ret = 0;
		stratafs_put_paths(&parent_paths,
				   STRATAFS_SB(dir->i_sb)->count);
		if (ret)
			goto fail_parent_relative;
	}

	relative = stratafs_child_relative(parent_relative,
					   &dentry->d_name);
	if (IS_ERR(relative)) {
		ret = PTR_ERR(relative);
		goto fail_parent_relative;
	}
	if (STRATAFS_SB(dir->i_sb)->create_index >= 0 &&
	    dentry->d_name.len > strlen(".stratafs-stage-") &&
	    !memcmp(dentry->d_name.name, ".stratafs-stage-",
		    strlen(".stratafs-stage-"))) {
		struct path create_parent;

		ret = stratafs_resolve_one(
			dir->i_sb, STRATAFS_SB(dir->i_sb)->create_index,
			parent_relative, true, &create_parent);
		if (!ret) {
			stratafs_recover_staging_parent(dir->i_sb, &create_parent);
			path_put(&create_parent);
		}
	}
	ret = stratafs_resolve_all(dir->i_sb, relative, false, &paths);
	if (ret)
		goto fail_relative;
	provider = stratafs_provider_index(&paths, STRATAFS_SB(dir->i_sb)->count);
	if (provider >= 0) {
		if (provider == STRATAFS_SB(dir->i_sb)->create_index)
			stratafs_recover_published_marker(
				dir->i_sb, &paths.path[provider]);
		inode = stratafs_new_inode(dir->i_sb, &paths.path[provider],
					   provider, relative);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			inode = NULL;
			goto fail_paths;
		}
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -ENOMEM;
		goto fail_inode;
	}
	info->relative = relative;
	if (provider >= 0) {
		info->provider = paths.path[provider];
		path_get(&info->provider);
		info->provider_index = provider;
		info->has_provider = true;
	}
	dentry->d_fsdata = info;
	dentry->d_op = &stratafs_dentry_operations;
	d_add(dentry, inode);
	stratafs_put_paths(&paths, STRATAFS_SB(dir->i_sb)->count);
	kfree(parent_relative);
	return NULL;

fail_inode:
	if (inode)
		iput(inode);
fail_paths:
	stratafs_put_paths(&paths, STRATAFS_SB(dir->i_sb)->count);
fail_relative:
	kfree(relative);
fail_parent_relative:
	kfree(parent_relative);
	return ERR_PTR(ret);
}

static int stratafs_d_revalidate(struct inode *dir, const struct qstr *name,
				 struct dentry *dentry, unsigned int flags)
{
	struct inode *inode;
	int ret;

	if (dentry == dentry->d_sb->s_root)
		return 1;
	ret = (flags & LOOKUP_RCU) ? -ECHILD : 0;
	inode = d_inode_rcu(dentry);
	trace_stratafs_d_revalidate(STRATAFS_SB(dentry->d_sb)->mount_cookie,
				    inode ? (u64)inode->i_ino : 0,
				    flags & LOOKUP_RCU, ret);
	return ret;
}

static void stratafs_d_release(struct dentry *dentry)
{
	struct stratafs_dentry_info *info = dentry->d_fsdata;

	if (!info)
		return;
	if (info->has_provider)
		path_put(&info->provider);
	if (info->settled_paths) {
		stratafs_put_paths(info->settled_paths,
				   STRATAFS_SB(dentry->d_sb)->count);
		kfree(info->settled_paths);
	}
	kfree(info->relative);
	kfree(info);
}

const struct dentry_operations stratafs_dentry_operations = {
	.d_revalidate = stratafs_d_revalidate,
	.d_release = stratafs_d_release,
};

int stratafs_get_provider(struct dentry *dentry, struct path *path,
			  unsigned int *index)
{
	struct stratafs_dentry_info *info;

	if (dentry == dentry->d_sb->s_root) {
		struct stratafs_paths roots;
		int provider = -1;
		unsigned int i;
		int ret = stratafs_resolve_all(dentry->d_sb, "", true, &roots);

		if (ret)
			return ret;
		for (i = 0; i < STRATAFS_SB(dentry->d_sb)->count; i++) {
			if ((roots.present & BIT_ULL(i)) &&
			    d_is_dir(roots.path[i].dentry)) {
				provider = i;
				break;
			}
		}
		if (provider < 0) {
			stratafs_put_paths(&roots,
					   STRATAFS_SB(dentry->d_sb)->count);
			return -ENOENT;
		}
		*path = roots.path[provider];
		path_get(path);
		if (index)
			*index = provider;
		/*
		 * Follow the root's inode number to whatever now provides it.
		 *
		 * The root inode is created once in stratafs_fill_super and
		 * ->d_revalidate keeps s_root, so nothing else ever rewrites
		 * its i_ino. When a higher-precedence stratum root appears, or
		 * the mount-time one goes, stat() on the mount point kept
		 * reporting the number allocated for the mount-time provider.
		 *
		 * The identity map is already keyed by provider inode, so the
		 * number the root should report is the number any other merged
		 * path to that same provider reports. Without this they
		 * disagree -- two paths naming one object with unequal inode
		 * numbers, which is the false-inequality direction and is what
		 * breaks hard-link detection in backup tools.
		 *
		 * The dentry stays pinned; only the number follows.
		 */
		if (d_inode(dentry)) {
			struct inode *provider_inode = d_inode(path->dentry);
			unsigned long number = stratafs_provider_ino(
				dentry->d_sb, provider_inode);

			if (number)
				d_inode(dentry)->i_ino = number;
		}
		stratafs_put_paths(&roots, STRATAFS_SB(dentry->d_sb)->count);
		return 0;
	}

	spin_lock(&dentry->d_lock);
	info = dentry->d_fsdata;
	if (info && info->has_provider) {
		*path = info->provider;
		path_get(path);
		if (index)
			*index = info->provider_index;
		spin_unlock(&dentry->d_lock);
		return 0;
	}
	spin_unlock(&dentry->d_lock);
	return -ESTALE;
}

int stratafs_check_paths_access(const struct stratafs_paths *paths,
				unsigned int count, u32 access)
{
	unsigned int i;
	int ret;

	for (i = 0; i < count; i++) {
		if (!(paths->present & BIT_ULL(i)))
			continue;
		if (!d_is_dir(paths->path[i].dentry))
			continue;
		ret = pkm_kacs_stratafs_authorize_path(&paths->path[i], access);
		if (ret)
			return ret;
	}
	return 0;
}

int stratafs_check_directory_access(struct mnt_idmap *idmap,
				    struct inode *inode, int mask)
{
	struct stratafs_paths paths;
	char *relative;
	u32 access = 0;
	int ret;

	if (!S_ISDIR(inode->i_mode))
		return 0;
	if (mask & MAY_NOT_BLOCK) {
		trace_stratafs_rcu_walk_refused(
			STRATAFS_SB(inode->i_sb)->mount_cookie, inode->i_ino);
		return -ECHILD;
	}
	if (mask & MAY_EXEC)
		access |= KACS_FILE_TRAVERSE;
	if (mask & MAY_READ)
		access |= KACS_FILE_LIST_DIRECTORY;
	if (!access)
		return 0;

	relative = stratafs_inode_relative(inode);
	if (IS_ERR(relative))
		return PTR_ERR(relative);
	/* Masked, per §3.3; see the note in stratafs_merged_empty. */
	ret = stratafs_resolve_all(inode->i_sb, relative, false, &paths);
	if (ret)
		goto out_relative;
	if (relative[0]) {
		int provider = stratafs_provider_index(
			&paths, STRATAFS_SB(inode->i_sb)->count);

		if (provider < 0)
			ret = -ENOENT;
		else if (!d_is_dir(paths.path[provider].dentry))
			ret = -ENOTDIR;
		if (ret)
			goto out;
	}
	ret = stratafs_check_paths_access(&paths, STRATAFS_SB(inode->i_sb)->count,
					  access);
out:
	stratafs_put_paths(&paths, STRATAFS_SB(inode->i_sb)->count);
out_relative:
	kfree(relative);
	return ret;
}
