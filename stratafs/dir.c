// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/backing-file.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/kacs_stratafs.h>
#include <linux/list.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <pkm/file.h>

#include "stratafs.h"

struct stratafs_dir_entry {
	struct list_head list;
	char *name;
	unsigned int len;
	unsigned int type;
	unsigned int participant_index;
	unsigned long ino;
};

struct stratafs_dir_file {
	struct stratafs_paths participants;
	struct list_head entries;
	char *relative;
	unsigned int count;
};

struct stratafs_capture_context {
	struct dir_context ctx;
	struct stratafs_dir_file *dir;
	struct file *outer;
	struct path participant;
	unsigned int participant_index;
	int error;
};

static int stratafs_create_common(struct inode *dir, struct dentry *dentry,
				  umode_t mode, dev_t dev, const char *link);

/*
 * VFS ->open() accepts only zero or a negated errno.  An out-of-contract
 * value is especially dangerous here: do_filp_open() encodes a negative
 * result as an ERR_PTR, but IS_ERR() recognises only the -MAX_ERRNO range.
 * Without this boundary check an invalid result can reach fd_install() as a
 * purported struct file pointer.
 */
static int stratafs_dir_open_result(const char *stage, int ret)
{
	if (likely(!ret || (ret < 0 && ret >= -MAX_ERRNO)))
		return ret;
	pr_err_ratelimited(
		"stratafs: directory open stage %s returned invalid result %d\n",
		stage, ret);
	return -EIO;
}

static bool stratafs_arrangement_error(int ret)
{
	switch (ret) {
	case -EROFS:
	case -EXDEV:
	case -ENOTDIR:
	case -EISDIR:
	case -ENOTEMPTY:
	case -EEXIST:
	case -EINVAL:
		return true;
	default:
		return false;
	}
}

static void stratafs_replace_relative(struct dentry *dentry,
				      char **new_drelative,
				      char **new_irelative)
{
	struct stratafs_dentry_info *dinfo = dentry->d_fsdata;
	struct stratafs_inode_info *iinfo = STRATAFS_I(d_inode(dentry));
	char *old_drelative;
	char *old_irelative;

	mutex_lock(&iinfo->rebind_lock);
	spin_lock(&dentry->d_lock);
	old_drelative = dinfo->relative;
	dinfo->relative = *new_drelative;
	*new_drelative = NULL;
	spin_unlock(&dentry->d_lock);
	old_irelative = iinfo->relative;
	iinfo->relative = *new_irelative;
	*new_irelative = NULL;
	mutex_unlock(&iinfo->rebind_lock);
	kfree(old_drelative);
	kfree(old_irelative);
}

static struct stratafs_dir_entry *
stratafs_find_entry(struct stratafs_dir_file *dir, const char *name, int len)
{
	struct stratafs_dir_entry *entry;

	list_for_each_entry(entry, &dir->entries, list)
		if (entry->len == len && !memcmp(entry->name, name, len))
			return entry;
	return NULL;
}

static bool stratafs_entry_is_staging(struct super_block *sb,
				      unsigned int participant_index,
				      const char *parent_relative,
				      const char *name, int len, int *error)
{
	struct qstr q = QSTR_INIT(name, len);
	char *relative;
	bool staging;

	if (participant_index != STRATAFS_SB(sb)->create_index)
		return false;

	relative = stratafs_child_relative(parent_relative, &q);
	if (IS_ERR(relative)) {
		*error = PTR_ERR(relative);
		return false;
	}
	staging = stratafs_is_staging(sb, participant_index, relative);
	kfree(relative);
	return staging;
}

static bool stratafs_capture_actor(struct dir_context *ctx, const char *name,
				   int len, loff_t offset, u64 ino,
				   unsigned int type)
{
	struct stratafs_capture_context *capture =
		container_of(ctx, struct stratafs_capture_context, ctx);
	struct stratafs_dir_entry *entry;

	if ((len == 1 && name[0] == '.') ||
	    (len == 2 && name[0] == '.' && name[1] == '.'))
		return true;
	if (stratafs_find_entry(capture->dir, name, len))
		return true;
	if (stratafs_entry_is_staging(file_inode(capture->outer)->i_sb,
				      capture->participant_index,
				      capture->dir->relative, name, len,
				      &capture->error))
		return true;
	if (capture->error)
		return false;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		capture->error = -ENOMEM;
		return false;
	}
	entry->name = kmemdup_nul(name, len, GFP_KERNEL);
	if (!entry->name) {
		kfree(entry);
		capture->error = -ENOMEM;
		return false;
	}
	entry->len = len;
	entry->type = type;
	entry->participant_index = capture->participant_index;
	list_add_tail(&entry->list, &capture->dir->entries);
	capture->dir->count++;
	return true;
}

static int
stratafs_resolve_captured_entries(struct stratafs_capture_context *capture)
{
	struct stratafs_dir_entry *entry, *next;

	list_for_each_entry_safe(entry, next, &capture->dir->entries, list) {
		struct path child;
		int ret;

		if (entry->participant_index != capture->participant_index ||
		    entry->ino)
			continue;
		ret = vfs_path_lookup(capture->participant.dentry,
				      capture->participant.mnt, entry->name, 0,
				      &child);
		if (ret) {
			if (ret != -ENOENT && ret != -ENOTDIR)
				return ret;
			/* A concurrent removal is ordinary provider behaviour. */
			list_del(&entry->list);
			kfree(entry->name);
			kfree(entry);
			capture->dir->count--;
			continue;
		}
		entry->ino = stratafs_provider_ino(
			file_inode(capture->outer)->i_sb, d_inode(child.dentry));
		path_put(&child);
		if (!entry->ino)
			return -ENOMEM;
	}
	return 0;
}

static void stratafs_free_entries(struct stratafs_dir_file *dir)
{
	struct stratafs_dir_entry *entry, *next;

	list_for_each_entry_safe(entry, next, &dir->entries, list) {
		list_del(&entry->list);
		kfree(entry->name);
		kfree(entry);
	}
	dir->count = 0;
}

static int stratafs_capture_entries(struct file *file,
				    struct stratafs_dir_file *dir)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(file_inode(file)->i_sb);
	unsigned int i;
	int ret = 0;

	for (i = 0; i < sbi->count; i++) {
		struct stratafs_capture_context capture = {
			.ctx.actor = stratafs_capture_actor,
			.dir = dir,
			.outer = file,
			.error = 0,
		};
		struct file *real;

		if (!(dir->participants.present & BIT_ULL(i)) ||
		    !d_is_dir(dir->participants.path[i].dentry))
			continue;
		capture.participant = dir->participants.path[i];
		capture.participant_index = i;
		/*
		 * The merged intersection was checked above.  Carry the outer
		 * handle's immutable grant into each internal participant open so
		 * capture neither reauthorizes as the acting task nor duplicates
		 * provider-open audit records.
		 */
		real = backing_file_open(file,
					 O_RDONLY | O_DIRECTORY | O_LARGEFILE,
					 &capture.participant, file->f_cred);
		if (IS_ERR(real)) {
			ret = PTR_ERR(real);
			break;
		}
		ret = stratafs_dir_open_result("iterate",
					       iterate_dir(real, &capture.ctx));
		fput(real);
		if (!ret)
			ret = stratafs_dir_open_result("capture", capture.error);
		/*
		 * Never look names up from the filldir actor.  iterate_dir() holds
		 * the provider inode's i_rwsem while invoking it, and stacked
		 * filesystems such as overlayfs may need that same lock for lookup.
		 * Resolve the captured names only after iterate_dir() has released
		 * the provider lock.
		 */
		if (!ret)
			ret = stratafs_dir_open_result(
				"entry-resolution",
				stratafs_resolve_captured_entries(&capture));
		if (ret)
			break;
	}
	if (ret) {
		stratafs_free_entries(dir);
		return ret;
	}
	return 0;
}

static int stratafs_dir_open(struct inode *inode, struct file *file)
{
	struct stratafs_dir_file *dir;
	bool origin_read_allowed = false;
	int ret;

	dir = kzalloc_obj(*dir, GFP_KERNEL);
	if (!dir)
		return -ENOMEM;
	INIT_LIST_HEAD(&dir->entries);
	dir->relative = stratafs_inode_relative(inode);
	if (IS_ERR(dir->relative)) {
		ret = PTR_ERR(dir->relative);
		dir->relative = NULL;
		goto fail;
	}
	ret = stratafs_dir_open_result(
		"participant-resolution",
		stratafs_resolve_all(inode->i_sb, dir->relative, true,
				     &dir->participants));
	if (ret)
		goto fail;
	if (STRATAFS_SB(inode->i_sb)->create_index >= 0 &&
	    (dir->participants.present &
	     BIT_ULL(STRATAFS_SB(inode->i_sb)->create_index)) &&
	    d_is_dir(dir->participants
			     .path[STRATAFS_SB(inode->i_sb)->create_index]
			     .dentry))
		stratafs_recover_staging_parent(
			inode->i_sb,
			&dir->participants
				 .path[STRATAFS_SB(inode->i_sb)->create_index]);
	ret = stratafs_dir_open_result(
		"list-authorization",
		stratafs_check_paths_access(&dir->participants,
			STRATAFS_SB(inode->i_sb)->count,
			KACS_FILE_TRAVERSE | KACS_FILE_LIST_DIRECTORY));
	if (ret)
		goto fail_paths;
	/*
	 * Capture while the opener's KACS token is still authoritative.  Apart
	 * from settling the directory objects, this prevents a transferred file
	 * descriptor from authorizing its first enumeration as the receiver.
	 */
	ret = stratafs_dir_open_result("enumeration-capture",
				       stratafs_capture_entries(file, dir));
	if (ret)
		goto fail_paths;
	/*
	 * READ_EA is a legacy-open compatibility right.  Settle its merged
	 * intersection now so a later fgetxattr() remains descriptor-local
	 * after SCM_RIGHTS transfer, just like the captured directory listing.
	 */
	ret = stratafs_check_paths_access(&dir->participants,
					  STRATAFS_SB(inode->i_sb)->count,
					  KACS_FILE_READ_EA);
	if (!ret)
		origin_read_allowed = true;
	ret = stratafs_dir_open_result(
		"settle", stratafs_settle_open_directory(file,
						    &dir->participants));
	if (ret)
		goto fail_entries;
	if (file->f_path.dentry->d_fsdata)
		((struct stratafs_dentry_info *)file->f_path.dentry->d_fsdata)
			->settled_origin_read_allowed = origin_read_allowed;
	file->private_data = dir;
	return 0;

fail_entries:
	stratafs_free_entries(dir);
fail_paths:
	stratafs_put_paths(&dir->participants, STRATAFS_SB(inode->i_sb)->count);
fail:
	kfree(dir->relative);
	kfree(dir);
	return stratafs_dir_open_result("return", ret);
}

static int stratafs_dir_release(struct inode *inode, struct file *file)
{
	struct stratafs_dir_file *dir = file->private_data;

	if (!dir)
		return 0;
	stratafs_free_entries(dir);
	stratafs_put_paths(&dir->participants, STRATAFS_SB(inode->i_sb)->count);
	kfree(dir->relative);
	kfree(dir);
	return 0;
}

static int stratafs_iterate(struct file *file, struct dir_context *ctx)
{
	struct stratafs_dir_file *dir = file->private_data;
	struct stratafs_dir_entry *entry;
	loff_t position = 2;

	if (!dir_emit_dots(file, ctx))
		return 0;
	list_for_each_entry(entry, &dir->entries, list) {
		if (position++ < ctx->pos)
			continue;
		if (!dir_emit(ctx, entry->name, entry->len, entry->ino,
			      entry->type))
			break;
		ctx->pos = position;
	}
	return 0;
}

static int stratafs_dir_fsync(struct file *file, loff_t start, loff_t end,
			      int datasync)
{
	struct stratafs_paths paths;
	struct stratafs_sb_info *sbi = STRATAFS_SB(file_inode(file)->i_sb);
	char *relative;
	unsigned int i;
	int first_error = 0;
	int ret;

	relative = stratafs_inode_relative(file_inode(file));
	if (IS_ERR(relative))
		return PTR_ERR(relative);
	ret = stratafs_resolve_all(file_inode(file)->i_sb, relative, true,
				   &paths);
	kfree(relative);
	if (ret)
		return ret;
	for (i = 0; i < sbi->count; i++) {
		struct file *real;

		if (!(paths.present & BIT_ULL(i)) ||
		    !d_is_dir(paths.path[i].dentry))
			continue;
		real = backing_file_open(file, O_RDONLY | O_DIRECTORY,
					 &paths.path[i], file->f_cred);
		if (IS_ERR(real)) {
			if (!first_error)
				first_error = PTR_ERR(real);
			continue;
		}
		ret = vfs_fsync(real, datasync);
		fput(real);
		if (ret && !first_error)
			first_error = ret;
	}
	stratafs_put_paths(&paths, sbi->count);
	return first_error;
}

static int stratafs_check_create_access(struct dentry *parent, bool directory)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(parent->d_sb);
	struct path target;
	char *relative;
	u32 access = directory ? KACS_FILE_ADD_SUBDIRECTORY : KACS_FILE_ADD_FILE;
	int ret;

	if (sbi->create_index < 0)
		return -EROFS;
	relative = stratafs_inode_relative(d_inode(parent));
	if (IS_ERR(relative))
		return PTR_ERR(relative);
	ret = stratafs_resolve_one(parent->d_sb, sbi->create_index,
				   relative, true, &target);
	if (ret == -ENOENT)
		ret = stratafs_provider_directory(parent->d_sb, relative,
						 &target);
	kfree(relative);
	if (ret)
		return ret == -ENOENT ? -EROFS : ret;
	if (!d_is_dir(target.dentry)) {
		path_put(&target);
		return -ENOTDIR;
	}
	ret = pkm_kacs_stratafs_begin_create_decision(&target, access);
	path_put(&target);
	return ret;
}

static int stratafs_install_created(struct dentry *dentry,
				    const struct path *created,
				    unsigned int index)
{
	struct stratafs_dentry_info *dinfo = dentry->d_fsdata;
	struct stratafs_inode_info *parent_info =
		STRATAFS_I(d_inode(dentry->d_parent));
	struct inode *inode;
	char *relative;

	if (dinfo)
		relative = kstrdup(dinfo->relative, GFP_KERNEL);
	else
		relative = stratafs_child_relative(parent_info->relative,
						   &dentry->d_name);
	if (IS_ERR_OR_NULL(relative))
		return relative ? PTR_ERR(relative) : -ENOMEM;
	inode = stratafs_new_inode(dentry->d_sb, created, index, relative);
	kfree(relative);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (!dinfo) {
		dinfo = kzalloc_obj(*dinfo, GFP_KERNEL);
		if (!dinfo) {
			iput(inode);
			return -ENOMEM;
		}
		dinfo->relative = stratafs_child_relative(parent_info->relative,
							 &dentry->d_name);
		if (IS_ERR(dinfo->relative)) {
			int ret = PTR_ERR(dinfo->relative);

			kfree(dinfo);
			iput(inode);
			return ret;
		}
		dentry->d_fsdata = dinfo;
		dentry->d_op = &stratafs_dentry_operations;
	}
	dinfo->provider = *created;
	path_get(&dinfo->provider);
	dinfo->provider_index = index;
	dinfo->has_provider = true;
	d_instantiate(dentry, inode);
	return 0;
}

static int stratafs_rollback_created(const struct path *parent,
				     struct dentry *created, bool directory)
{
	int ret;

	ret = pkm_kacs_stratafs_begin_created_cleanup(
		d_inode(parent->dentry), created);
	if (ret)
		return ret;
	if (directory)
		ret = vfs_rmdir(mnt_idmap(parent->mnt), d_inode(parent->dentry),
				created, NULL);
	else
		ret = vfs_unlink(mnt_idmap(parent->mnt), d_inode(parent->dentry),
				 created, NULL);
	pkm_kacs_stratafs_end_created_cleanup();
	return ret;
}

static int stratafs_create_common(struct inode *dir, struct dentry *dentry,
				  umode_t mode, dev_t dev, const char *link)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(dir->i_sb);
	struct path parent;
	struct path created;
	struct qstr q = dentry->d_name;
	struct dentry *target;
	struct dentry *mkdir_result = NULL;
	struct mnt_idmap *idmap;
	bool directory = S_ISDIR(mode);
	bool write_held = false;
	int ret;

	if (sb_rdonly(dir->i_sb)) {
		stratafs_audit_refusal(dentry, "create", -1, -EROFS, false);
		return -EROFS;
	}
	ret = stratafs_check_create_access(dentry->d_parent, directory);
	if (ret) {
		if (stratafs_arrangement_error(ret))
			stratafs_audit_refusal(dentry, "create", -1, ret,
						 false);
		return ret;
	}
	ret = stratafs_ensure_create_parent(dentry->d_parent, &parent);
	if (ret)
		goto out_decision;
	ret = mnt_want_write(parent.mnt);
	if (ret)
		goto out_parent;
	write_held = true;
	idmap = mnt_idmap(parent.mnt);
	q.hash = full_name_hash(parent.dentry, q.name, q.len);
	target = start_creating(idmap, parent.dentry, &q);
	if (IS_ERR(target)) {
		ret = PTR_ERR(target);
		goto out_parent;
	}
	if (d_really_is_positive(target)) {
		ret = -EEXIST;
		goto out_target;
	}
	ret = pkm_kacs_stratafs_bind_create_decision(
		d_inode(parent.dentry), target);
	if (ret)
		goto out_target;
	ret = pkm_kacs_stratafs_rebind_native_create_request(
		dir, d_inode(parent.dentry));
	if (ret)
		goto out_target;

	if (S_ISREG(mode))
		ret = vfs_create(idmap, target, mode, NULL);
	else if (S_ISDIR(mode)) {
		mkdir_result = vfs_mkdir(idmap, d_inode(parent.dentry), target,
					 mode, NULL);
		if (IS_ERR(mkdir_result)) {
			/* vfs_mkdir() already ended and consumed target on error. */
			ret = PTR_ERR(mkdir_result);
			mkdir_result = NULL;
			target = NULL;
		} else {
			ret = 0;
		}
	} else if (S_ISLNK(mode))
		ret = vfs_symlink(idmap, d_inode(parent.dentry), target, link,
				  NULL);
	else
		ret = vfs_mknod(idmap, d_inode(parent.dentry), target, mode, dev,
				NULL);
	pkm_kacs_stratafs_end_native_create_request(dir,
						   d_inode(parent.dentry));
	pkm_kacs_stratafs_end_create_decision();
	if (ret)
		goto out_target;
	created.mnt = parent.mnt;
	created.dentry = mkdir_result ?: target;
	path_get(&created);
	ret = stratafs_install_created(dentry, &created, sbi->create_index);
	path_put(&created);
	if (ret) {
		int cleanup_ret = stratafs_rollback_created(
			&parent, mkdir_result ?: target, directory);

		if (cleanup_ret)
			stratafs_audit_refusal(dentry, "create-rollback",
						 sbi->create_index, cleanup_ret, true);
		if (cleanup_ret)
			pr_warn_ratelimited(
				"stratafs: could not roll back failed create: %d\n",
				cleanup_ret);
	}
out_target:
	if (mkdir_result || target)
		end_creating(mkdir_result ?: target);
out_parent:
	if (write_held)
		mnt_drop_write(parent.mnt);
	path_put(&parent);
out_decision:
	pkm_kacs_stratafs_end_create_decision();
	if (stratafs_arrangement_error(ret))
		stratafs_audit_refusal(dentry, "create", -1, ret, false);
	return ret;
}

static int stratafs_create(struct mnt_idmap *idmap, struct inode *dir,
			   struct dentry *dentry, umode_t mode, bool excl)
{
	return stratafs_create_common(dir, dentry, S_IFREG | mode, 0, NULL);
}

static struct dentry *stratafs_mkdir(struct mnt_idmap *idmap,
				     struct inode *dir,
				     struct dentry *dentry, umode_t mode)
{
	int ret = stratafs_create_common(dir, dentry, S_IFDIR | mode, 0, NULL);

	return ret ? ERR_PTR(ret) : dget(dentry);
}

static int stratafs_mknod(struct mnt_idmap *idmap, struct inode *dir,
			  struct dentry *dentry, umode_t mode, dev_t dev)
{
	return stratafs_create_common(dir, dentry, mode, dev, NULL);
}

static int stratafs_symlink(struct mnt_idmap *idmap, struct inode *dir,
			    struct dentry *dentry, const char *link)
{
	return stratafs_create_common(dir, dentry, S_IFLNK | 0777, 0, link);
}

static int stratafs_tmpfile_dummy_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int stratafs_tmpfile(struct mnt_idmap *idmap, struct inode *dir,
			    struct file *file, umode_t mode)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(dir->i_sb);
	struct dentry *dentry = file->f_path.dentry;
	struct stratafs_dentry_info *dinfo = NULL;
	struct stratafs_file_info *finfo = NULL;
	struct path parent;
	struct file *real = NULL;
	struct inode *inode = NULL;
	int ret;

	if (sb_rdonly(dir->i_sb)) {
		stratafs_audit_refusal(dentry, "tmpfile", -1, -EROFS, false);
		return -EROFS;
	}
	ret = stratafs_check_create_access(dentry->d_parent, false);
	if (ret) {
		if (stratafs_arrangement_error(ret))
			stratafs_audit_refusal(dentry, "tmpfile", -1, ret,
						 false);
		return ret;
	}
	ret = stratafs_ensure_create_parent(dentry->d_parent, &parent);
	if (ret)
		goto out_decision;
	ret = mnt_want_write(parent.mnt);
	if (ret) {
		path_put(&parent);
		goto out_decision;
	}
	ret = pkm_kacs_stratafs_bind_create_decision(
		d_inode(parent.dentry), NULL);
	if (ret) {
		mnt_drop_write(parent.mnt);
		path_put(&parent);
		goto out_decision;
	}
	real = backing_tmpfile_open(file, file->f_flags, &parent, mode,
				    current_cred());
	pkm_kacs_stratafs_end_create_decision();
	mnt_drop_write(parent.mnt);
	path_put(&parent);
	if (IS_ERR(real)) {
		ret = PTR_ERR(real);
		if (stratafs_arrangement_error(ret))
			stratafs_audit_refusal(dentry, "tmpfile", -1, ret,
						 false);
		return ret;
	}

	inode = stratafs_new_inode(dir->i_sb, &real->f_path,
				   sbi->create_index, STRATAFS_I(dir)->relative);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		inode = NULL;
		goto fail;
	}
	dinfo = kzalloc(sizeof(*dinfo), GFP_KERNEL);
	finfo = kzalloc_obj(*finfo, GFP_KERNEL);
	if (!dinfo || !finfo) {
		ret = -ENOMEM;
		goto fail;
	}
	dinfo->relative = kstrdup(STRATAFS_I(dir)->relative, GFP_KERNEL);
	if (!dinfo->relative) {
		ret = -ENOMEM;
		goto fail;
	}
	dinfo->provider = real->f_path;
	path_get(&dinfo->provider);
	dinfo->provider_index = sbi->create_index;
	dinfo->has_provider = true;
	dinfo->unnamed = true;
	finfo->real = real;
	finfo->provider = real->f_path;
	path_get(&finfo->provider);
	finfo->provider_index = sbi->create_index;
	mutex_init(&finfo->mutation_lock);
	dentry->d_fsdata = dinfo;
	dentry->d_op = &stratafs_dentry_operations;
	d_instantiate(dentry, inode);
	inode = NULL;
	file->private_data = finfo;
	ret = finish_open(file, dentry, stratafs_tmpfile_dummy_open);
	if (ret)
		goto fail_instantiated;
	return 0;

fail_instantiated:
	file->private_data = NULL;
	/* dentry teardown owns dinfo and the instantiated inode from here. */
	fput(finfo->real);
	path_put(&finfo->provider);
	kfree(finfo);
	return ret;
fail:
	iput(inode);
	if (dinfo) {
		kfree(dinfo->relative);
		kfree(dinfo);
	}
	kfree(finfo);
	fput(real);
	return ret;
out_decision:
	pkm_kacs_stratafs_end_create_decision();
	if (stratafs_arrangement_error(ret))
		stratafs_audit_refusal(dentry, "tmpfile", -1, ret, false);
	return ret;
}

/*
 * Whether a create-stratum entry is an in-flight copy-up staging object.
 *
 * Enumeration has always hidden these, but the emptiness and foreign-entry
 * scans did not, so an in-flight copy-up made rmdir of the directory fail
 * with ENOTEMPTY -- and a rename refuse EXDEV -- over an entry the caller
 * cannot see in the merged view.
 *
 * Extracted so the three scans cannot drift apart again.
 */
struct stratafs_empty_context {
	struct dir_context ctx;
	struct super_block *sb;
	const char *relative;
	unsigned int participant_index;
	bool empty;
	int error;
};

static bool stratafs_empty_actor(struct dir_context *ctx, const char *name,
				 int len, loff_t offset, u64 ino,
				 unsigned int type)
{
	struct stratafs_empty_context *empty =
		container_of(ctx, struct stratafs_empty_context, ctx);

	if ((len == 1 && name[0] == '.') ||
	    (len == 2 && name[0] == '.' && name[1] == '.'))
		return true;
	if (stratafs_entry_is_staging(empty->sb, empty->participant_index,
				      empty->relative, name, len,
				      &empty->error))
		return true;
	if (empty->error)
		return false;
	empty->empty = false;
	return false;
}

static int stratafs_merged_empty(struct dentry *dentry)
{
	struct stratafs_inode_info *info = STRATAFS_I(d_inode(dentry));
	struct stratafs_sb_info *sbi = STRATAFS_SB(dentry->d_sb);
	struct stratafs_paths paths;
	unsigned int i;
	int ret;

	ret = stratafs_resolve_all(dentry->d_sb, info->relative, true, &paths);
	if (ret)
		return ret;
	ret = stratafs_check_paths_access(&paths, sbi->count,
					  KACS_FILE_TRAVERSE |
					  KACS_FILE_LIST_DIRECTORY);
	if (ret)
		goto out;
	for (i = 0; i < sbi->count; i++) {
		struct stratafs_empty_context empty = {
			.ctx.actor = stratafs_empty_actor,
			.sb = dentry->d_sb,
			.relative = info->relative,
			.participant_index = i,
			.empty = true,
		};
		struct file *real;

		if (!(paths.present & BIT_ULL(i)) ||
		    !d_is_dir(paths.path[i].dentry))
			continue;
		real = dentry_open(&paths.path[i], O_RDONLY | O_DIRECTORY,
				   sbi->resolution_cred);
		if (IS_ERR(real)) {
			ret = PTR_ERR(real);
			goto out;
		}
		ret = iterate_dir(real, &empty.ctx);
		fput(real);
		if (!ret)
			ret = empty.error;
		if (ret)
			goto out;
		if (!empty.empty) {
			ret = -ENOTEMPTY;
			goto out;
		}
	}
out:
	stratafs_put_paths(&paths, sbi->count);
	return ret;
}

static int stratafs_remove(struct inode *dir, struct dentry *dentry,
			   bool directory)
{
	struct stratafs_inode_info *parent_info = STRATAFS_I(dir);
	struct stratafs_dentry_info *dinfo = dentry->d_fsdata;
	struct path provider;
	struct path provider_parent;
	const char *basename;
	struct qstr q;
	struct dentry *target;
	unsigned int index;
	bool deferred;
	bool created_cleanup;
	bool write_held = false;
	int ret;

	deferred = !directory &&
		   pkm_kacs_stratafs_delete_on_close_active(dentry);
	created_cleanup = pkm_kacs_stratafs_created_cleanup_active(dentry);
	if (sb_rdonly(dir->i_sb)) {
		stratafs_audit_refusal(dentry,
					 directory ? "rmdir" : "unlink", -1,
					 -EROFS, deferred || created_cleanup);
		return -EROFS;
	}
	if (!dinfo || !dinfo->relative) {
		if (deferred || created_cleanup)
			stratafs_audit_refusal(dentry,
						 directory ? "rmdir" : "unlink", -1,
						 -ESTALE,
						 true);
		return -ESTALE;
	}
	basename = strrchr(dinfo->relative, '/');
	basename = basename ? basename + 1 : dinfo->relative;
	if (!*basename) {
		if (deferred || created_cleanup)
			stratafs_audit_refusal(dentry,
						 directory ? "rmdir" : "unlink", -1,
						 -ESTALE,
						 true);
		return -ESTALE;
	}
	q = (struct qstr)QSTR_INIT(basename, strlen(basename));
	ret = stratafs_get_provider(dentry, &provider, &index);
	if (ret) {
		if (deferred || created_cleanup)
			stratafs_audit_refusal(
				dentry, directory ? "rmdir" : "unlink", -1, ret,
				true);
		return ret;
	}
	if (!stratafs_stratum_accepts(dir->i_sb, index, &provider)) {
		ret = -EROFS;
		goto out_provider;
	}
	if (directory) {
		ret = stratafs_merged_empty(dentry);
		if (ret)
			goto out_provider;
	}
	ret = stratafs_resolve_one(dir->i_sb, index, parent_info->relative, true,
				   &provider_parent);
	if (ret) {
		if (deferred && (ret == -ENOENT || ret == -ENOTDIR))
			ret = 0;
		goto out_provider;
	}
	ret = mnt_want_write(provider_parent.mnt);
	if (ret)
		goto out_parent;
	write_held = true;
	q.hash = full_name_hash(provider_parent.dentry, q.name, q.len);
	target = start_removing(mnt_idmap(provider_parent.mnt),
				provider_parent.dentry, &q);
	if (IS_ERR(target)) {
		ret = PTR_ERR(target);
		if (deferred && ret == -ENOENT)
			ret = 0;
		goto out_parent;
	}
	if (d_inode(target) != d_inode(provider.dentry)) {
		ret = deferred ? 0 : -ESTALE;
		goto out_target;
	}
	if (deferred) {
		ret = pkm_kacs_stratafs_delete_on_close_bind_provider(
			dentry, &provider_parent, target);
		if (ret)
			goto out_target;
	}
	if (created_cleanup) {
		ret = pkm_kacs_stratafs_begin_created_cleanup(
			d_inode(provider_parent.dentry), target);
		if (ret)
			goto out_target;
	}
	if (directory)
		ret = vfs_rmdir(mnt_idmap(provider_parent.mnt),
				d_inode(provider_parent.dentry), target, NULL);
	else
		ret = vfs_unlink(mnt_idmap(provider_parent.mnt),
				 d_inode(provider_parent.dentry), target, NULL);
	if (deferred)
		pkm_kacs_stratafs_delete_on_close_unbind_provider();
	if (created_cleanup)
		pkm_kacs_stratafs_end_created_cleanup();
	if (deferred && ret == -ENOENT)
		ret = 0;
	if (!ret)
		d_drop(dentry);
out_target:
	end_removing(target);
out_parent:
	if (write_held)
		mnt_drop_write(provider_parent.mnt);
	path_put(&provider_parent);
out_provider:
	path_put(&provider);
	if (((deferred || created_cleanup) && ret) ||
	    stratafs_arrangement_error(ret))
		stratafs_audit_refusal(dentry,
					 directory ? "rmdir" : "unlink", index,
					 ret, deferred || created_cleanup);
	return ret;
}

static int stratafs_unlink(struct inode *dir, struct dentry *dentry)
{
	return stratafs_remove(dir, dentry, false);
}

static int stratafs_rmdir(struct inode *dir, struct dentry *dentry)
{
	return stratafs_remove(dir, dentry, true);
}

struct stratafs_foreign_context {
	struct dir_context ctx;
	struct path provider;
	const struct cred *cred;
	struct super_block *sb;
	const char *relative;
	unsigned int participant_index;
	bool foreign;
	int error;
};

static bool stratafs_foreign_actor(struct dir_context *ctx, const char *name,
				   int len, loff_t offset, u64 ino,
				   unsigned int type)
{
	struct stratafs_foreign_context *foreign =
		container_of(ctx, struct stratafs_foreign_context, ctx);
	struct path provider_child;
	const struct cred *old_cred;
	char *terminated;
	int ret;

	if ((len == 1 && name[0] == '.') ||
	    (len == 2 && name[0] == '.' && name[1] == '.'))
		return true;
	if (stratafs_entry_is_staging(foreign->sb, foreign->participant_index,
				      foreign->relative, name, len,
				      &foreign->error))
		return true;
	if (foreign->error)
		return false;
	terminated = kmemdup_nul(name, len, GFP_KERNEL);
	if (!terminated) {
		foreign->error = -ENOMEM;
		return false;
	}
	old_cred = override_creds(foreign->cred);
	ret = vfs_path_lookup(foreign->provider.dentry, foreign->provider.mnt,
			      terminated, 0, &provider_child);
	revert_creds(old_cred);
	kfree(terminated);
	if (!ret) {
		path_put(&provider_child);
		return true;
	}
	if (ret == -ENOENT || ret == -ENOTDIR) {
		foreign->foreign = true;
		return false;
	}
	foreign->error = ret;
	return false;
}

static int stratafs_directory_provider_only(struct dentry *dentry,
					    unsigned int provider_index)
{
	struct stratafs_inode_info *info = STRATAFS_I(d_inode(dentry));
	struct stratafs_sb_info *sbi = STRATAFS_SB(dentry->d_sb);
	struct stratafs_paths paths;
	unsigned int i;
	int ret;

	ret = stratafs_resolve_all(dentry->d_sb, info->relative, true, &paths);
	if (ret)
		return ret;
	ret = stratafs_check_paths_access(&paths, sbi->count,
					  KACS_FILE_TRAVERSE |
					  KACS_FILE_LIST_DIRECTORY);
	if (ret)
		goto out;
	if (!(paths.present & BIT_ULL(provider_index)) ||
	    !d_is_dir(paths.path[provider_index].dentry)) {
		ret = -ESTALE;
		goto out;
	}
	for (i = 0; i < sbi->count; i++) {
		struct stratafs_foreign_context foreign = {
			.ctx.actor = stratafs_foreign_actor,
			.provider = paths.path[provider_index],
			.cred = sbi->resolution_cred,
			.sb = dentry->d_sb,
			.relative = info->relative,
			.participant_index = i,
		};
		struct file *real;

		if (i == provider_index || !(paths.present & BIT_ULL(i)) ||
		    !d_is_dir(paths.path[i].dentry))
			continue;
		real = dentry_open(&paths.path[i], O_RDONLY | O_DIRECTORY,
				   sbi->resolution_cred);
		if (IS_ERR(real)) {
			ret = PTR_ERR(real);
			goto out;
		}
		ret = iterate_dir(real, &foreign.ctx);
		fput(real);
		if (!ret)
			ret = foreign.error;
		if (ret)
			goto out;
		if (foreign.foreign) {
			ret = -EXDEV;
			goto out;
		}
	}
out:
	stratafs_put_paths(&paths, sbi->count);
	return ret;
}

static int stratafs_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	struct stratafs_dentry_info *old_info = old_dentry->d_fsdata;
	struct stratafs_inode_info *dest_info = STRATAFS_I(dir);
	struct path source;
	struct path destination_parent;
	struct path created;
	struct qstr q = new_dentry->d_name;
	struct dentry *target;
	unsigned int provider_index;
	bool create_decision = false;
	bool write_held = false;
	int ret;

	if (sb_rdonly(dir->i_sb)) {
		stratafs_audit_refusal(new_dentry, "link", -1, -EROFS,
					 false);
		return -EROFS;
	}
	if (old_dentry->d_sb != dir->i_sb) {
		stratafs_audit_refusal(new_dentry, "link", -1, -EXDEV,
					 false);
		return -EXDEV;
	}
	ret = stratafs_get_provider(old_dentry, &source, &provider_index);
	if (ret)
		return ret;
	if (old_info && old_info->unnamed) {
		struct stratafs_dentry_info *new_info = new_dentry->d_fsdata;
		struct stratafs_paths existing;

		if ((int)provider_index != STRATAFS_SB(dir->i_sb)->create_index) {
			ret = -EXDEV;
			goto out_source;
		}
		if (!new_info || !new_info->relative) {
			ret = -ESTALE;
			goto out_source;
		}
		ret = stratafs_resolve_all(dir->i_sb, new_info->relative, false,
					   &existing);
		if (ret)
			goto out_source;
		if (existing.present)
			ret = -EEXIST;
		stratafs_put_paths(&existing, STRATAFS_SB(dir->i_sb)->count);
		if (ret)
			goto out_source;
		ret = stratafs_check_create_access(new_dentry->d_parent, false);
		if (ret)
			goto out_source;
		create_decision = true;
		ret = stratafs_ensure_create_parent(new_dentry->d_parent,
						    &destination_parent);
		if (ret)
			goto out_source;
		if (source.mnt != destination_parent.mnt) {
			ret = -EXDEV;
			goto out_parent;
		}
		goto create_link;
	}
	if (!stratafs_stratum_accepts(dir->i_sb, provider_index, &source)) {
		ret = -EXDEV;
		goto out_source;
	}
	ret = stratafs_resolve_one(dir->i_sb, provider_index,
				   dest_info->relative, true, &destination_parent);
	if (ret || !d_is_dir(destination_parent.dentry)) {
		if (!ret)
			path_put(&destination_parent);
		ret = -EXDEV;
		goto out_source;
	}
	if (source.mnt != destination_parent.mnt) {
		ret = -EXDEV;
		goto out_parent;
	}
create_link:
	ret = mnt_want_write(destination_parent.mnt);
	if (ret)
		goto out_parent;
	write_held = true;
	q.hash = full_name_hash(destination_parent.dentry, q.name, q.len);
	target = start_creating(mnt_idmap(destination_parent.mnt),
				destination_parent.dentry, &q);
	if (IS_ERR(target)) {
		ret = PTR_ERR(target);
		goto out_parent;
	}
	if (d_really_is_positive(target)) {
		ret = -EEXIST;
		goto out_target;
	}
	if (create_decision) {
		ret = pkm_kacs_stratafs_bind_create_decision(
			d_inode(destination_parent.dentry), target);
		if (ret)
			goto out_target;
		ret = pkm_kacs_stratafs_mark_unnamed_link(source.dentry);
		if (ret)
			goto out_target;
	}
	ret = vfs_link(source.dentry, mnt_idmap(destination_parent.mnt),
		       d_inode(destination_parent.dentry), target, NULL);
	if (create_decision)
		pkm_kacs_stratafs_end_create_decision();
	if (ret)
		goto out_target;
	created.mnt = destination_parent.mnt;
	created.dentry = target;
	path_get(&created);
	ret = stratafs_install_created(new_dentry, &created, provider_index);
	path_put(&created);
	if (ret) {
		int cleanup_ret = stratafs_rollback_created(
			&destination_parent, target, false);

		if (cleanup_ret)
			stratafs_audit_refusal(new_dentry, "link-rollback",
						 provider_index, cleanup_ret, true);
		if (cleanup_ret)
			pr_warn_ratelimited(
				"stratafs: could not roll back failed link: %d\n",
				cleanup_ret);
	}
out_target:
	end_creating(target);
out_parent:
	if (write_held)
		mnt_drop_write(destination_parent.mnt);
	path_put(&destination_parent);
out_source:
	if (create_decision)
		pkm_kacs_stratafs_end_create_decision();
	path_put(&source);
	if (stratafs_arrangement_error(ret))
		stratafs_audit_refusal(new_dentry, "link", provider_index, ret,
					 false);
	return ret;
}

static int stratafs_supersede_rename(struct dentry *old_dentry,
				     struct dentry *new_dentry,
				     const struct path *source,
				     unsigned int source_index)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(old_dentry->d_sb);
	struct stratafs_inode_info *old_parent_info =
		STRATAFS_I(d_inode(old_dentry->d_parent));
	struct stratafs_inode_info *new_parent_info =
		STRATAFS_I(d_inode(new_dentry->d_parent));
	struct stratafs_dentry_info *old_info = old_dentry->d_fsdata;
	struct stratafs_dentry_info *new_info = new_dentry->d_fsdata;
	const struct file *supersede_file;
	struct stratafs_dentry_info *file_dinfo = NULL;
	struct stratafs_inode_info *file_iinfo = NULL;
	struct path target;
	struct path target_parent = {};
	struct path create_parent;
	struct renamedata rd = {};
	struct qstr old_q = old_dentry->d_name;
	struct qstr new_q = new_dentry->d_name;
	struct dentry *remove_target;
	unsigned int target_index;
	bool removed = false;
	bool target_write_held = false;
	bool create_write_held = false;
	char *new_drelative = NULL;
	char *new_irelative = NULL;
	char *outer_drelative = NULL;
	char *outer_irelative = NULL;
	int ret;

	if (!sbi || !old_parent_info || !new_parent_info || !new_info ||
	    !new_info->relative ||
	    source_index != (unsigned int)sbi->create_index ||
	    !stratafs_stratum_accepts(old_dentry->d_sb, source_index, source)) {
		stratafs_audit_refusal(new_dentry, "supersede", source_index,
					 -EROFS, false);
		return -EROFS;
	}
	if (old_dentry->d_parent != new_dentry->d_parent) {
		stratafs_audit_refusal(new_dentry, "supersede", source_index,
					 -EXDEV, false);
		return -EXDEV;
	}
	if (!old_info || !old_info->relative ||
	    !STRATAFS_I(d_inode(old_dentry)))
		return -ESTALE;
	supersede_file = pkm_kacs_stratafs_supersede_file(old_dentry,
							 new_dentry);
	if (!supersede_file)
		return -EACCES;
	file_dinfo = file_dentry((struct file *)supersede_file)->d_fsdata;
	file_iinfo = STRATAFS_I(file_inode((struct file *)supersede_file));
	if (!file_dinfo || !file_dinfo->descriptor_view || !file_iinfo ||
	    file_inode((struct file *)supersede_file)->i_sb != old_dentry->d_sb)
		return -ESTALE;
	/* Allocate every descriptor retarget resource before either mutation. */
	new_drelative = kstrdup(new_info->relative, GFP_KERNEL);
	new_irelative = kstrdup(new_info->relative, GFP_KERNEL);
	outer_drelative = kstrdup(new_info->relative, GFP_KERNEL);
	outer_irelative = kstrdup(new_info->relative, GFP_KERNEL);
	if (!new_drelative || !new_irelative || !outer_drelative ||
	    !outer_irelative) {
		ret = -ENOMEM;
		goto out_relative;
	}
	ret = stratafs_validate_supersede_dentry(new_dentry);
	if (ret)
		goto out_relative;
	ret = stratafs_get_provider(new_dentry, &target, &target_index);
	if (ret)
		goto out_relative;
	if (!stratafs_stratum_accepts(new_dentry->d_sb, target_index,
				      &target)) {
		ret = -EROFS;
		goto out_target;
	}

	/* A target outside the create stratum is the removal half. */
	if (target_index != source_index) {
		ret = stratafs_resolve_one(new_dentry->d_sb, target_index,
					   new_parent_info->relative, true,
					   &target_parent);
		if (ret)
			goto out_target;
		ret = mnt_want_write(target_parent.mnt);
		if (ret)
			goto out_target_parent;
		target_write_held = true;
		new_q.hash = full_name_hash(target_parent.dentry, new_q.name,
					    new_q.len);
		remove_target = start_removing(mnt_idmap(target_parent.mnt),
					       target_parent.dentry, &new_q);
		if (IS_ERR(remove_target)) {
			ret = PTR_ERR(remove_target);
			goto out_target_parent;
		}
		if (d_inode(remove_target) != d_inode(target.dentry)) {
			ret = -ESTALE;
			goto out_remove;
		}
		ret = pkm_kacs_stratafs_begin_supersede_unlink(
			d_inode(target_parent.dentry), remove_target);
		if (!ret)
			ret = vfs_unlink(mnt_idmap(target_parent.mnt),
					 d_inode(target_parent.dentry),
					 remove_target, NULL);
		pkm_kacs_stratafs_end_supersede_phase();
		if (!ret)
			removed = true;
out_remove:
		end_removing(remove_target);
		if (ret)
			goto out_target_parent;
		mnt_drop_write(target_parent.mnt);
		target_write_held = false;
		path_put(&target_parent);
		memset(&target_parent, 0, sizeof(target_parent));
	}

	ret = stratafs_resolve_one(old_dentry->d_sb, source_index,
				   old_parent_info->relative, true,
				   &create_parent);
	if (ret)
		goto out_after_remove;
	if (!d_is_dir(create_parent.dentry) ||
	    create_parent.mnt != source->mnt) {
		ret = -EXDEV;
		goto out_create_parent;
	}
	ret = mnt_want_write(create_parent.mnt);
	if (ret)
		goto out_create_parent;
	create_write_held = true;
	old_q.hash = full_name_hash(create_parent.dentry, old_q.name,
				    old_q.len);
	new_q.hash = full_name_hash(create_parent.dentry, new_q.name,
				    new_q.len);
	rd.mnt_idmap = mnt_idmap(create_parent.mnt);
	rd.old_parent = create_parent.dentry;
	rd.new_parent = create_parent.dentry;
	ret = start_renaming(&rd, 0, &old_q, &new_q);
	if (ret)
		goto out_create_parent;
	if (d_inode(rd.old_dentry) != d_inode(source->dentry) ||
	    (target_index == source_index &&
	     d_inode(rd.new_dentry) != d_inode(target.dentry)) ||
	    (target_index != source_index && d_really_is_positive(rd.new_dentry))) {
		ret = -ESTALE;
		goto out_rename;
	}
	ret = pkm_kacs_stratafs_begin_supersede_rename(
		d_inode(rd.old_parent), rd.old_dentry,
		d_inode(rd.new_parent), rd.new_dentry);
	if (!ret)
		ret = vfs_rename(&rd);
	pkm_kacs_stratafs_end_supersede_phase();
	if (!ret) {
		char *old_drelative;
		char *old_irelative;

		mutex_lock(&file_iinfo->rebind_lock);
		spin_lock(&file_dentry((struct file *)supersede_file)->d_lock);
		old_drelative = file_dinfo->relative;
		file_dinfo->relative = new_drelative;
		file_dinfo->unnamed = false;
		new_drelative = NULL;
		spin_unlock(&file_dentry((struct file *)supersede_file)->d_lock);
		old_irelative = file_iinfo->relative;
		file_iinfo->relative = new_irelative;
		new_irelative = NULL;
		mutex_unlock(&file_iinfo->rebind_lock);
		kfree(old_drelative);
		kfree(old_irelative);
		stratafs_replace_relative(old_dentry, &outer_drelative,
					  &outer_irelative);
		d_move(old_dentry, new_dentry);
	}
out_rename:
	end_renaming(&rd);
out_create_parent:
	if (create_write_held)
		mnt_drop_write(create_parent.mnt);
	path_put(&create_parent);
out_after_remove:
	/* A lower-filesystem publication failure after removal is reported. */
	if (ret && removed) {
		stratafs_audit_refusal(new_dentry, "supersede-publication",
					 target_index, ret, false);
		pr_warn_ratelimited(
			"stratafs: supersede removed provider but could not publish replacement: %d\n",
			ret);
	}
out_target_parent:
	if (target_write_held)
		mnt_drop_write(target_parent.mnt);
	if (target_parent.dentry)
		path_put(&target_parent);
out_target:
	path_put(&target);
out_relative:
	kfree(new_drelative);
	kfree(new_irelative);
	kfree(outer_drelative);
	kfree(outer_irelative);
	if (stratafs_arrangement_error(ret) && !removed)
		stratafs_audit_refusal(new_dentry, "supersede",
					 source_index, ret, false);
	return ret;
}

static int stratafs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
			   struct dentry *old_dentry, struct inode *new_dir,
			   struct dentry *new_dentry, unsigned int flags)
{
	struct stratafs_inode_info *old_parent_info = STRATAFS_I(old_dir);
	struct stratafs_inode_info *new_parent_info = STRATAFS_I(new_dir);
	struct stratafs_dentry_info *old_info = old_dentry->d_fsdata;
	struct stratafs_dentry_info *new_info = new_dentry->d_fsdata;
	struct path source;
	struct path destination = {};
	struct path old_parent;
	struct path new_parent;
	struct renamedata rd = {};
	struct qstr old_q = old_dentry->d_name;
	struct qstr new_q = new_dentry->d_name;
	char *old_new_drelative = NULL;
	char *old_new_irelative = NULL;
	char *new_new_drelative = NULL;
	char *new_new_irelative = NULL;
	unsigned int provider_index;
	unsigned int destination_index = 0;
	bool destination_present;
	bool write_held = false;
	int ret;

	if (flags & RENAME_WHITEOUT) {
		stratafs_audit_refusal(new_dentry, "rename", -1, -EINVAL,
					 false);
		return -EINVAL;
	}
	if (sb_rdonly(old_dir->i_sb)) {
		stratafs_audit_refusal(old_dentry, "rename", -1, -EROFS,
					 false);
		return -EROFS;
	}
	ret = stratafs_get_provider(old_dentry, &source, &provider_index);
	if (ret)
		return ret;
	if (pkm_kacs_stratafs_supersede_active(old_dentry, new_dentry)) {
		ret = stratafs_supersede_rename(old_dentry, new_dentry, &source,
						 provider_index);
		goto out_source;
	}
	if (!stratafs_stratum_accepts(old_dir->i_sb, provider_index, &source)) {
		ret = -EROFS;
		goto out_source;
	}
	destination_present = d_really_is_positive(new_dentry);
	if (destination_present) {
		ret = stratafs_get_provider(new_dentry, &destination,
					    &destination_index);
		if (ret)
			goto out_source;
	}
	if ((flags & RENAME_EXCHANGE) &&
	    (!destination_present || destination_index != provider_index)) {
		ret = -EROFS;
		goto out_destination;
	}
	if ((flags & RENAME_EXCHANGE) &&
	    !stratafs_stratum_accepts(old_dir->i_sb, provider_index,
				       &destination)) {
		ret = -EROFS;
		goto out_destination;
	}
	if (!(flags & (RENAME_NOREPLACE | RENAME_EXCHANGE)) &&
	    destination_present && destination_index < provider_index) {
		ret = -EROFS;
		goto out_destination;
	}
	ret = stratafs_resolve_one(old_dir->i_sb, provider_index,
				   old_parent_info->relative, true, &old_parent);
	if (ret)
		goto out_destination;
	ret = stratafs_resolve_one(new_dir->i_sb, provider_index,
				   new_parent_info->relative, true, &new_parent);
	if (ret || !d_is_dir(new_parent.dentry)) {
		if (!ret)
			path_put(&new_parent);
		ret = -EXDEV;
		goto out_old_parent;
	}
	if (source.mnt != old_parent.mnt || old_parent.mnt != new_parent.mnt) {
		ret = -EXDEV;
		goto out_new_parent;
	}
	ret = mnt_want_write(old_parent.mnt);
	if (ret)
		goto out_new_parent;
	write_held = true;
	if (d_is_dir(old_dentry)) {
		ret = stratafs_directory_provider_only(old_dentry, provider_index);
		if (ret)
			goto out_new_parent;
	}
	if ((flags & RENAME_EXCHANGE) && d_is_dir(new_dentry)) {
		ret = stratafs_directory_provider_only(new_dentry, provider_index);
		if (ret)
			goto out_new_parent;
	}
	/*
	 * PSD-011 gives conditions 1, 3 and 4 precedence over the
	 * RENAME_NOREPLACE existence test.  The checks above deliberately
	 * run first so an arrangement error is not disclosed as EEXIST.
	 */
	if ((flags & RENAME_NOREPLACE) && destination_present) {
		ret = -EEXIST;
		goto out_new_parent;
	}
	if (!(flags & RENAME_EXCHANGE) && destination_present) {
		if (d_is_dir(old_dentry) != d_is_dir(new_dentry)) {
			ret = d_is_dir(old_dentry) ? -ENOTDIR : -EISDIR;
			goto out_new_parent;
		}
		if (d_is_dir(new_dentry)) {
			ret = stratafs_merged_empty(new_dentry);
			if (ret)
				goto out_new_parent;
		}
	}
	if (!old_info || !old_info->relative || !new_info ||
	    !new_info->relative || !STRATAFS_I(d_inode(old_dentry)) ||
	    ((flags & RENAME_EXCHANGE) && !STRATAFS_I(d_inode(new_dentry)))) {
		ret = -ESTALE;
		goto out_new_parent;
	}
	old_new_drelative = kstrdup(new_info->relative, GFP_KERNEL);
	old_new_irelative = kstrdup(new_info->relative, GFP_KERNEL);
	if (!old_new_drelative || !old_new_irelative) {
		ret = -ENOMEM;
		goto out_new_parent;
	}
	if (flags & RENAME_EXCHANGE) {
		new_new_drelative = kstrdup(old_info->relative, GFP_KERNEL);
		new_new_irelative = kstrdup(old_info->relative, GFP_KERNEL);
		if (!new_new_drelative || !new_new_irelative) {
			ret = -ENOMEM;
			goto out_new_parent;
		}
	}

	old_q.hash = full_name_hash(old_parent.dentry, old_q.name, old_q.len);
	new_q.hash = full_name_hash(new_parent.dentry, new_q.name, new_q.len);
	rd.mnt_idmap = mnt_idmap(old_parent.mnt);
	rd.old_parent = old_parent.dentry;
	rd.new_parent = new_parent.dentry;
	rd.flags = flags;
	ret = start_renaming(&rd, 0, &old_q, &new_q);
	if (ret)
		goto out_new_parent;
	if (d_inode(rd.old_dentry) != d_inode(source.dentry)) {
		ret = -ESTALE;
		goto out_rename;
	}
	/* rename(2) of two hard links to one object is a namespace no-op. */
	if (d_inode(rd.new_dentry) == d_inode(rd.old_dentry)) {
		ret = 0;
		goto out_rename;
	}
	ret = vfs_rename(&rd);
	if (!ret) {
		stratafs_replace_relative(old_dentry, &old_new_drelative,
					  &old_new_irelative);
		if (flags & RENAME_EXCHANGE) {
			stratafs_replace_relative(new_dentry, &new_new_drelative,
						  &new_new_irelative);
			d_exchange(old_dentry, new_dentry);
		} else {
			d_move(old_dentry, new_dentry);
		}
	}
out_rename:
	end_renaming(&rd);
out_new_parent:
	if (write_held)
		mnt_drop_write(old_parent.mnt);
	path_put(&new_parent);
out_old_parent:
	path_put(&old_parent);
out_destination:
	if (destination.dentry)
		path_put(&destination);
out_source:
	path_put(&source);
	kfree(old_new_drelative);
	kfree(old_new_irelative);
	kfree(new_new_drelative);
	kfree(new_new_irelative);
	if (stratafs_arrangement_error(ret) &&
	    !pkm_kacs_stratafs_supersede_active(old_dentry, new_dentry))
		stratafs_audit_refusal(new_dentry, "rename", provider_index, ret,
					 false);
	return ret;
}

const struct file_operations stratafs_dir_operations = {
	.open = stratafs_dir_open,
	.release = stratafs_dir_release,
	.iterate_shared = stratafs_iterate,
	.llseek = generic_file_llseek,
	.fsync = stratafs_dir_fsync,
};

const struct inode_operations stratafs_dir_inode_operations = {
	.lookup = stratafs_lookup,
	.permission = stratafs_check_directory_access,
	.create = stratafs_create,
	.mkdir = stratafs_mkdir,
	.mknod = stratafs_mknod,
	.symlink = stratafs_symlink,
	.tmpfile = stratafs_tmpfile,
	.unlink = stratafs_unlink,
	.rmdir = stratafs_rmdir,
	.link = stratafs_link,
	.rename = stratafs_rename,
	.setattr = stratafs_setattr,
	.getattr = stratafs_getattr,
	.listxattr = stratafs_listxattr,
};
