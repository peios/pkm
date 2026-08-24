// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>

#include "stratafs.h"

unsigned long stratafs_provider_ino(struct super_block *sb,
				    struct inode *provider)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	struct stratafs_identity *identity;
	unsigned long key = (unsigned long)provider >> 3;
	unsigned long number = 0;
	int ret;

	mutex_lock(&sbi->identity_lock);
	identity = xa_load(&sbi->identities, key);
	if (identity) {
		if (WARN_ON(identity->inode != provider))
			goto out;
		number = identity->number;
		goto out;
	}

	identity = kzalloc(sizeof(*identity), GFP_KERNEL);
	if (!identity)
		goto out;
	identity->inode = igrab(provider);
	if (!identity->inode) {
		kfree(identity);
		goto out;
	}
	identity->number = atomic64_inc_return(&sbi->next_ino);
	ret = xa_err(xa_store(&sbi->identities, key, identity, GFP_KERNEL));
	if (ret) {
		iput(identity->inode);
		kfree(identity);
		goto out;
	}
	number = identity->number;
out:
	mutex_unlock(&sbi->identity_lock);
	return number;
}

void stratafs_refresh_inode(struct inode *inode, const struct path *provider)
{
	struct inode *real = provider ? d_inode(provider->dentry) : NULL;

	if (!real) {
		inode->i_mode = S_IFDIR;
		set_nlink(inode, 1);
		return;
	}
	inode->i_mode = real->i_mode;
	i_uid_write(inode, i_uid_read(real));
	i_gid_write(inode, i_gid_read(real));
	inode->i_rdev = real->i_rdev;
	inode->i_flags = real->i_flags;
	inode_set_atime_to_ts(inode, inode_get_atime(real));
	inode_set_mtime_to_ts(inode, inode_get_mtime(real));
	inode_set_ctime_to_ts(inode, inode_get_ctime(real));
	i_size_write(inode, i_size_read(real));
	inode->i_blocks = real->i_blocks;
	set_nlink(inode, S_ISDIR(real->i_mode) ? 1 : real->i_nlink);
}

char *stratafs_inode_relative(struct inode *inode)
{
	struct stratafs_inode_info *info = STRATAFS_I(inode);
	char *relative;

	if (!info)
		return ERR_PTR(-ESTALE);
	mutex_lock(&info->rebind_lock);
	relative = kstrdup(info->relative, GFP_KERNEL);
	mutex_unlock(&info->rebind_lock);
	return relative ?: ERR_PTR(-ENOMEM);
}

struct inode *stratafs_new_inode(struct super_block *sb,
				 const struct path *provider,
				 unsigned int provider_index,
				 const char *relative)
{
	struct stratafs_inode_info *info;
	struct inode *inode;
	unsigned long number;

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	info = kzalloc_obj(*info, GFP_KERNEL);
	if (!info)
		goto fail;
	mutex_init(&info->rebind_lock);
	info->relative = kstrdup(relative, GFP_KERNEL);
	if (!info->relative)
		goto fail_info;
	if (provider) {
		info->provider = igrab(d_inode(provider->dentry));
		if (!info->provider)
			goto fail_relative;
		info->provider_index = provider_index;
		number = stratafs_provider_ino(sb, info->provider);
		if (!number)
			goto fail_provider;
		inode->i_ino = number;
	} else {
		inode->i_ino = atomic64_inc_return(&STRATAFS_SB(sb)->next_ino);
	}
	inode->i_private = info;
	stratafs_refresh_inode(inode, provider);

	if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &stratafs_dir_inode_operations;
		inode->i_fop = &stratafs_dir_operations;
	} else if (S_ISREG(inode->i_mode)) {
		inode->i_op = &stratafs_file_inode_operations;
		inode->i_fop = &stratafs_file_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &stratafs_symlink_inode_operations;
	} else {
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		/*
		 * The provider's special-file open still runs on the backing file.
		 * Keep StrataFS operations on the outer inode so FIFOs and devices
		 * are forwarded to that provider instead of creating an unrelated
		 * outer pipe or opening the device directly from the synthetic inode.
		 */
		inode->i_op = &stratafs_special_inode_operations;
		inode->i_fop = &stratafs_file_operations;
	}
	return inode;

fail_provider:
	iput(info->provider);
fail_relative:
	kfree(info->relative);
fail_info:
	kfree(info);
fail:
	iput(inode);
	return ERR_PTR(-ENOMEM);
}

static struct stratafs_dentry_info *
stratafs_file_dentry_info(const char *relative, const struct path *provider,
			 unsigned int provider_index)
{
	struct stratafs_dentry_info *info;

	info = kzalloc_obj(*info, GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);
	info->relative = kstrdup(relative, GFP_KERNEL);
	if (!info->relative) {
		kfree(info);
		return ERR_PTR(-ENOMEM);
	}
	info->provider = *provider;
	path_get(&info->provider);
	info->provider_index = provider_index;
	info->has_provider = true;
	info->descriptor_view = true;
	return info;
}

static int stratafs_get_detached_file_access(const struct file *file,
					     struct inode *inode)
{
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ) {
		i_readcount_inc(inode);
		return 0;
	}
	if (file->f_mode & FMODE_WRITER)
		return get_write_access(inode);
	return 0;
}

static void stratafs_put_detached_file_access(const struct file *file,
					      struct inode *inode)
{
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_dec(inode);
	else if (file->f_mode & FMODE_WRITER)
		put_write_access(inode);
}

int stratafs_detach_open_file(struct file *file, const struct path *provider,
			      unsigned int provider_index)
{
	struct inode *old_inode = file_inode(file);
	struct stratafs_dentry_info *dinfo;
	struct dentry *old_dentry = file->f_path.dentry;
	struct dentry *private_dentry;
	struct inode *private_inode;
	char *relative;
	int ret;

	relative = stratafs_inode_relative(old_inode);
	if (IS_ERR(relative))
		return PTR_ERR(relative);
	dinfo = stratafs_file_dentry_info(relative, provider,
					 provider_index);
	if (IS_ERR(dinfo)) {
		ret = PTR_ERR(dinfo);
		goto out_relative;
	}
	private_inode = stratafs_new_inode(old_inode->i_sb, provider,
					 provider_index, relative);
	if (IS_ERR(private_inode)) {
		ret = PTR_ERR(private_inode);
		path_put(&dinfo->provider);
		kfree(dinfo->relative);
		kfree(dinfo);
		goto out_relative;
	}
	/* A descriptor keeps the inode number against which it was opened. */
	private_inode->i_ino = old_inode->i_ino;
	private_dentry = d_alloc(old_dentry->d_parent, &old_dentry->d_name);
	if (!private_dentry) {
		ret = -ENOMEM;
		iput(private_inode);
		path_put(&dinfo->provider);
		kfree(dinfo->relative);
		kfree(dinfo);
		goto out_relative;
	}
	private_dentry->d_fsdata = dinfo;
	d_instantiate(private_dentry, private_inode);
	ret = stratafs_get_detached_file_access(file, private_inode);
	if (ret) {
		dput(private_dentry);
		goto out_relative;
	}

	/*
	 * ->open has not returned, so the file is not observable yet.  VFS open
	 * accounting, however, already belongs to old_inode.  Move the read or
	 * writer reference with f_inode; otherwise __fput() accounts the private
	 * inode and underflows it on close.
	 */
	file->__f_path.dentry = private_dentry;
	file->f_inode = private_inode;
	file->f_mapping = private_inode->i_mapping;
	stratafs_put_detached_file_access(file, old_inode);
	dput(old_dentry);
	ret = 0;
out_relative:
	kfree(relative);
	return ret;
}

int stratafs_settle_open_directory(struct file *file,
				   const struct stratafs_paths *participants)
{
	struct stratafs_dentry_info *dinfo;
	struct stratafs_paths *settled;
	struct super_block *sb = file_inode(file)->i_sb;
	unsigned int i;
	int provider;
	int ret;

	provider = stratafs_provider_index(participants, STRATAFS_SB(sb)->count);
	if (provider < 0)
		return 0;
	settled = kzalloc_obj(*settled, GFP_KERNEL);
	if (!settled)
		return -ENOMEM;
	settled->present = participants->present;
	for (i = 0; i < STRATAFS_SB(sb)->count; i++) {
		if (!(settled->present & BIT_ULL(i)))
			continue;
		settled->path[i] = participants->path[i];
		path_get(&settled->path[i]);
	}
	ret = stratafs_detach_open_file(
		file, &participants->path[provider], provider);
	if (ret) {
		stratafs_put_paths(settled, STRATAFS_SB(sb)->count);
		kfree(settled);
		return ret;
	}
	dinfo = file->f_path.dentry->d_fsdata;
	dinfo->settled_paths = settled;
	return 0;
}

int stratafs_rebind_dentry(struct dentry *dentry,
			   const struct path *provider,
			   unsigned int provider_index)
{
	struct inode *inode;
	struct stratafs_inode_info *iinfo;
	struct stratafs_dentry_info *dinfo;
	struct path old_path = {};
	struct inode *old_provider;
	struct inode *new_provider;
	bool had_old_path;

	if (!dentry || !provider || !provider->mnt ||
	    !d_really_is_positive(provider->dentry))
		return -ESTALE;
	inode = d_inode(dentry);
	iinfo = STRATAFS_I(inode);
	if (!iinfo)
		return -ESTALE;
	new_provider = d_inode(provider->dentry);
	ihold(new_provider);
	path_get(provider);
	mutex_lock(&iinfo->rebind_lock);

	spin_lock(&dentry->d_lock);
	dinfo = dentry->d_fsdata;
	if (!dinfo) {
		spin_unlock(&dentry->d_lock);
		mutex_unlock(&iinfo->rebind_lock);
		path_put(provider);
		iput(new_provider);
		return -ESTALE;
	}
	had_old_path = dinfo->has_provider;
	if (had_old_path)
		old_path = dinfo->provider;
	dinfo->provider = *provider;
	dinfo->provider_index = provider_index;
	dinfo->has_provider = true;
	spin_unlock(&dentry->d_lock);

	spin_lock(&inode->i_lock);
	old_provider = iinfo->provider;
	iinfo->provider = new_provider;
	iinfo->provider_index = provider_index;
	spin_unlock(&inode->i_lock);
	iput(old_provider);
	if (had_old_path)
		path_put(&old_path);
	stratafs_refresh_inode(inode, provider);
	mutex_unlock(&iinfo->rebind_lock);
	return 0;
}

int stratafs_rebind_open_file(struct file *file, const struct path *provider,
			      unsigned int provider_index)
{
	return stratafs_rebind_dentry(file->f_path.dentry, provider,
				       provider_index);
}

int stratafs_getattr(struct mnt_idmap *idmap, const struct path *path,
			     struct kstat *stat, u32 request_mask,
			     unsigned int flags)
{
	struct path provider;
	const struct cred *old_cred;
	int ret;

	ret = stratafs_get_provider(path->dentry, &provider, NULL);
	if (ret == -ENOENT && path->dentry == path->dentry->d_sb->s_root) {
		generic_fillattr(idmap, request_mask, d_inode(path->dentry), stat);
		stat->dev = path->dentry->d_sb->s_dev;
		stat->ino = d_inode(path->dentry)->i_ino;
		stat->nlink = 1;
		return 0;
	}
	if (ret)
		return ret;
	old_cred = override_creds(STRATAFS_SB(path->dentry->d_sb)->resolution_cred);
	ret = vfs_getattr_nosec(&provider, stat, request_mask, flags);
	revert_creds(old_cred);
	path_put(&provider);
	if (ret)
		return ret;
	stat->dev = path->dentry->d_sb->s_dev;
	stat->ino = d_inode(path->dentry)->i_ino;
	if (S_ISDIR(stat->mode))
		stat->nlink = 1;
	return 0;
}

int stratafs_notify_change(const struct path *provider,
			   const struct iattr *attr)
{
	struct inode *provider_inode;
	struct iattr provider_attr;
	bool write_access = false;
	int ret;

	if (!provider || !provider->mnt || !provider->dentry || !attr)
		return -ESTALE;
	provider_inode = d_inode(provider->dentry);
	if (!provider_inode)
		return -ESTALE;

	provider_attr = *attr;
	/*
	 * ia_file belongs to the StrataFS layer, not to the provider.  Passing
	 * it through would let a lower filesystem mistake an outer file for
	 * one of its own.  O_TRUNC has likewise not necessarily reached the
	 * provider open, so force the provider to perform the size change.
	 */
	provider_attr.ia_valid &= ~(ATTR_FILE | ATTR_OPEN);

	if (provider_attr.ia_valid & ATTR_SIZE) {
		ret = get_write_access(provider_inode);
		if (ret)
			return ret;
		write_access = true;
	}

	/* notify_change() requires the affected inode's i_rwsem exclusively. */
	inode_lock(provider_inode);
	ret = notify_change(mnt_idmap(provider->mnt), provider->dentry,
			    &provider_attr, NULL);
	inode_unlock(provider_inode);

	if (write_access)
		put_write_access(provider_inode);
	return ret;
}

int stratafs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			     struct iattr *attr)
{
	struct path provider;
	struct file *metadata_file = NULL;
	struct inode *inode = d_inode(dentry);
	unsigned int index;
	bool copied_up = false;
	int route;
	int ret;

	ret = setattr_prepare(&nop_mnt_idmap, dentry, attr);
	if (ret)
		return ret;

	ret = stratafs_get_provider(dentry, &provider, &index);
	if (ret)
		return ret;
	route = stratafs_route_existing(dentry->d_sb, index, &provider,
					 S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
					 S_ISLNK(inode->i_mode));
	path_put(&provider);
	if (route == STRATAFS_ROUTE_READ_ONLY) {
		stratafs_audit_refusal(dentry, "setattr", index, -EROFS, false);
		return -EROFS;
	}
	if (route == STRATAFS_ROUTE_COPY_UP) {
		metadata_file = pkm_kacs_stratafs_metadata_file(inode);

		if (metadata_file)
			ret = stratafs_copy_up_metadata_file(
				metadata_file, dentry, &provider, &index);
		else
			ret = stratafs_copy_up_path(dentry, &provider, &index);
		if (ret)
			return ret;
		copied_up = true;
	} else {
		ret = stratafs_get_provider(dentry, &provider, &index);
		if (ret)
			return ret;
	}

	ret = mnt_want_write(provider.mnt);
	if (ret)
		goto out_provider;
	ret = pkm_kacs_stratafs_rebind_metadata_decision(
		inode, d_inode(provider.dentry));
	if (!ret)
		ret = stratafs_notify_change(&provider, attr);
	pkm_kacs_stratafs_end_metadata_decision(d_inode(provider.dentry));
	mnt_drop_write(provider.mnt);
	if (!ret && (!copied_up || metadata_file))
		stratafs_refresh_inode(inode, &provider);
out_provider:
	path_put(&provider);
	return ret;
}

static const char *stratafs_get_link(struct dentry *dentry, struct inode *inode,
				     struct delayed_call *done)
{
	const char *(*get_link)(struct dentry *, struct inode *,
			       struct delayed_call *);
	struct inode *provider_inode;
	struct path provider;
	const char *link;
	int ret;

	if (!dentry)
		return ERR_PTR(-ECHILD);
	ret = stratafs_get_provider(dentry, &provider, NULL);
	if (ret)
		return ERR_PTR(ret);
	provider_inode = d_inode(provider.dentry);
	if (!provider_inode || !d_is_symlink(provider.dentry) ||
	    !provider_inode->i_op || !provider_inode->i_op->get_link) {
		link = ERR_PTR(-EINVAL);
		goto out;
	}

	/*
	 * Forward the VFS operation which reached this ->get_link method.  Do
	 * not call vfs_get_link(): that helper is the readlink(2) entry point
	 * and unconditionally runs security_inode_readlink() on the provider.
	 * A pathname follow reaches ->get_link after security_inode_follow_link,
	 * and turning it into a provider readlink adds FILE_READ_DATA authority
	 * which ordinary symlink traversal does not require.  In particular, a
	 * link that may be followed directly through an overlay provider could
	 * then be refused only through StrataFS.
	 *
	 * Explicit readlink(2) remains protected: the VFS has already called
	 * security_inode_readlink() on the StrataFS inode before arriving here,
	 * and KACS obtains that inode's effective descriptor from this exact
	 * provider.  A stacking provider such as overlayfs may in turn call
	 * vfs_get_link() for its own lower layer, just as it does on a direct
	 * pathname follow.
	 */
	get_link = provider_inode->i_op->get_link;
	link = get_link(provider.dentry, provider_inode, done);
out:
	path_put(&provider);
	return link;
}

const struct inode_operations stratafs_file_inode_operations = {
	.setattr = stratafs_setattr,
	.getattr = stratafs_getattr,
	.listxattr = stratafs_listxattr,
};

const struct inode_operations stratafs_symlink_inode_operations = {
	.get_link = stratafs_get_link,
	.setattr = stratafs_setattr,
	.getattr = stratafs_getattr,
	.listxattr = stratafs_listxattr,
};

const struct inode_operations stratafs_special_inode_operations = {
	.setattr = stratafs_setattr,
	.getattr = stratafs_getattr,
	.listxattr = stratafs_listxattr,
};

static void stratafs_evict_inode(struct inode *inode)
{
	struct stratafs_inode_info *info = STRATAFS_I(inode);

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (info) {
		iput(info->provider);
		kfree(info->relative);
		kfree(info);
		inode->i_private = NULL;
	}
}

static void stratafs_put_super(struct super_block *sb)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);

	sb->s_fs_info = NULL;
	stratafs_free_sbi(sbi);
}

/*
 * §7.3 requires the mount table to report the stack "in exactly the strata=
 * form of §7.1, including flags and escaping", and "sufficient to reconstruct
 * the stack: the same paths, in the same order, with the same flags."
 *
 * seq_show_option() cannot do that here. It applies seq_escape() with
 * ESCAPE_OCTAL over ",\t\n\\", which is a second and incompatible escaping
 * layer on a value that already carries §7.1's. The stored value's backslashes
 * get re-escaped, so a path containing ':' reports as a dangling escape and is
 * rejected on read-back, and one containing ',' reads back as a different path:
 *
 *	supplied /a\:b  ->  reported strata=/a\134:b     (rejected)
 *	supplied /a\,b  ->  reported strata=/a\134\054b  (reads as /a\,b)
 *
 * Paths free of ':', '+', ',', '\' and whitespace — the spec's own example
 * among them — round-trip byte-identical, which is why this survived.
 *
 * display_options holds the caller's raw option value (super.c), and §7.1's
 * escaping already makes it safe inside a comma-separated options string. So
 * it goes out verbatim: the key through seq_puts, then the value.
 */
void stratafs_show_strata(struct seq_file *m, const struct stratafs_sb_info *sbi)
{
	if (!sbi->display_options)
		return;
	seq_puts(m, ",strata=");
	seq_puts(m, sbi->display_options);
}

static int stratafs_show_options(struct seq_file *m, struct dentry *root)
{
	stratafs_show_strata(m, STRATAFS_SB(root->d_sb));
	return 0;
}

static int stratafs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(dentry->d_sb);
	struct stratafs_paths roots;
	unsigned int i;
	int selected = -1;
	int ret;

	ret = stratafs_resolve_all(dentry->d_sb, "", true, &roots);
	if (ret)
		return ret;
	if (sbi->create_index >= 0 &&
	    (roots.present & BIT_ULL(sbi->create_index)) &&
	    d_is_dir(roots.path[sbi->create_index].dentry))
		selected = sbi->create_index;
	else {
		/*
		 * Highest-precedence *present* stratum, per PCSA -- presence
		 * alone, with no directory requirement. Requiring one skipped a
		 * present-but-non-directory root and reported a lower stratum's
		 * filesystem instead. Reachable only if a stratum root's type
		 * changes after mount, since mount-time validation excludes it.
		 */
		for (i = 0; i < sbi->count; i++) {
			if (roots.present & BIT_ULL(i)) {
				selected = i;
				break;
			}
		}
	}
	if (selected >= 0)
		ret = vfs_statfs(&roots.path[selected], buf);
	else {
		memset(buf, 0, sizeof(*buf));
		ret = 0;
	}
	stratafs_put_paths(&roots, sbi->count);
	if (!ret)
		buf->f_type = STRATAFS_MAGIC;
	return ret;
}

static int stratafs_validate_mountpoint_recursive(
	struct super_block *sb, const struct path *mountpoint,
	struct super_block **visited, unsigned int depth)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	unsigned int i;
	int ret;

	if (!sbi || depth > FILESYSTEM_MAX_STACK_DEPTH)
		return -ELOOP;
	for (i = 0; i < depth; i++)
		if (visited[i] == sb)
			return -ELOOP;
	visited[depth] = sb;

	for (i = 0; i < sbi->count; i++) {
		struct path stratum;
		struct super_block *lower_sb;

		ret = stratafs_resolve_one(sb, i, "", true, &stratum);
		if (ret == -ENOENT &&
		    (sbi->strata[i].flags & STRATAFS_F_AM))
			continue;
		if (ret)
			return ret;
		if (path_is_under(&stratum, mountpoint)) {
			path_put(&stratum);
			return -ELOOP;
		}

		lower_sb = stratum.dentry->d_sb;
		if (lower_sb->s_magic == STRATAFS_MAGIC)
			ret = stratafs_validate_mountpoint_recursive(
				lower_sb, mountpoint, visited, depth + 1);
		else
			ret = 0;
		path_put(&stratum);
		if (ret)
			return ret;
	}
	return 0;
}

static int stratafs_validate_mountpoint(struct super_block *sb,
					const struct path *mountpoint)
{
	struct super_block *visited[FILESYSTEM_MAX_STACK_DEPTH + 1] = {};

	if (!mountpoint || !mountpoint->mnt || !mountpoint->dentry)
		return -EINVAL;
	return stratafs_validate_mountpoint_recursive(
		sb, mountpoint, visited, 0);
}

static int stratafs_freeze_fs(struct super_block *sb)
{
	/*
	 * The synthetic superblock owns no storage.  Reporting a successful
	 * freeze would be misleading because writes through the lower mounts
	 * can continue, while forwarding the request would unexpectedly freeze
	 * whole filesystems shared with callers outside this StrataFS mount.
	 */
	return -EOPNOTSUPP;
}

const struct super_operations stratafs_super_operations = {
	.evict_inode = stratafs_evict_inode,
	.put_super = stratafs_put_super,
	.statfs = stratafs_statfs,
	.show_options = stratafs_show_options,
	.validate_mountpoint = stratafs_validate_mountpoint,
	.freeze_fs = stratafs_freeze_fs,
};
