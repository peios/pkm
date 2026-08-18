// SPDX-License-Identifier: GPL-2.0-only

#include <linux/backing-file.h>
#include <linux/filelock.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/poll.h>
#include <linux/splice.h>

#include "stratafs.h"

bool stratafs_stratum_accepts(const struct super_block *sb,
			      unsigned int index,
			      const struct path *provider)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);

	if (index >= sbi->count || !provider || !provider->dentry)
		return false;
	if (sbi->strata[index].flags & STRATAFS_F_RO)
		return false;
	if (__mnt_is_readonly(provider->mnt))
		return false;
	if (IS_IMMUTABLE(d_inode(provider->dentry)))
		return false;
	return true;
}

void stratafs_audit_refusal(const struct dentry *dentry,
			    const char *operation, int provider_index,
			    int result, bool deferred)
{
	const struct stratafs_dentry_info *dinfo;
	struct stratafs_inode_info *iinfo;
	const struct stratafs_sb_info *sbi;
	struct inode *inode;
	char *relative_copy = NULL;
	const char *relative = "";
	const char *provider = "";

	if (!dentry || !dentry->d_sb || result >= 0)
		return;
	sbi = STRATAFS_SB(dentry->d_sb);
	if (!sbi)
		return;
	/*
	 * Rename swaps dentry and inode relative names and then frees the old
	 * strings.  Audit is commonly reached from error paths which do not hold
	 * namespace locks, so take a private snapshot before formatting the
	 * record.  The dentry copy uses GFP_ATOMIC because d_lock protects the
	 * pointer through the copy; the inode fallback is protected by the
	 * sleeping rebind lock.
	 */
	spin_lock(&((struct dentry *)dentry)->d_lock);
	dinfo = dentry->d_fsdata;
	if (dinfo && dinfo->relative)
		relative_copy = kstrdup(dinfo->relative, GFP_ATOMIC);
	spin_unlock(&((struct dentry *)dentry)->d_lock);
	if (!relative_copy) {
		inode = d_inode((struct dentry *)dentry);
		iinfo = inode ? STRATAFS_I(inode) : NULL;
		if (iinfo) {
			mutex_lock(&iinfo->rebind_lock);
			relative_copy = kstrdup(iinfo->relative, GFP_KERNEL);
			mutex_unlock(&iinfo->rebind_lock);
		}
	}
	if (relative_copy)
		relative = relative_copy;
	if (provider_index >= 0 &&
	    (unsigned int)provider_index < sbi->count)
		provider = sbi->strata[provider_index].path;
	else
		provider_index = -1;
	pkm_kacs_stratafs_audit_mutation_refused(
		relative, operation, provider_index, provider, result, deferred);
	kfree(relative_copy);
}

int stratafs_route_existing(const struct super_block *sb,
			    unsigned int provider_index,
			    const struct path *provider, bool copyable)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	struct path create_root;
	bool create_present = false;

	if (sbi->create_index >= 0) {
		if (!stratafs_resolve_one(sb, sbi->create_index, "", true,
					  &create_root)) {
			create_present = d_is_dir(create_root.dentry);
			path_put(&create_root);
		}
	}
	return stratafs_rust_route_existing(
		provider_index,
		stratafs_stratum_accepts(sb, provider_index, provider),
		sbi->create_index, create_present, copyable,
		sb_rdonly((struct super_block *)sb));
}

static struct backing_file_ctx stratafs_backing_ctx(struct file *file)
{
	return (struct backing_file_ctx) {
		.cred = file->f_cred,
	};
}

static int stratafs_open(struct inode *inode, struct file *file)
{
	struct stratafs_file_info *info;
	struct path provider;
	struct file *real;
	unsigned int index;
	int open_flags;
	int route;
	int ret;

	ret = stratafs_get_provider(file->f_path.dentry, &provider, &index);
	if (ret)
		return ret;
	route = stratafs_route_existing(inode->i_sb, index, &provider,
					 S_ISREG(inode->i_mode));
	open_flags = file->f_flags;
	if (S_ISREG(inode->i_mode) &&
	    route != STRATAFS_ROUTE_IN_PLACE &&
	    (file->f_mode & FMODE_WRITE)) {
		open_flags &= ~(O_ACCMODE | O_APPEND);
		open_flags |= O_RDONLY;
	}
	if (route != STRATAFS_ROUTE_IN_PLACE)
		open_flags &= ~O_TRUNC;
	ret = stratafs_detach_open_file(file, &provider, index);
	if (ret) {
		path_put(&provider);
		return ret;
	}
	inode = file_inode(file);
	real = backing_file_open(file, open_flags, &provider, file->f_cred);
	if (IS_ERR(real)) {
		path_put(&provider);
		return PTR_ERR(real);
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		fput(real);
		path_put(&provider);
		return -ENOMEM;
	}
	info->real = real;
	info->provider = provider;
	info->provider_index = index;
	mutex_init(&info->mutation_lock);
	file->private_data = info;
	if ((file->f_flags & O_TRUNC) && S_ISREG(inode->i_mode)) {
		if (route == STRATAFS_ROUTE_READ_ONLY) {
			ret = -EROFS;
			stratafs_audit_refusal(file->f_path.dentry, "truncate",
						 info->provider_index, ret, false);
			goto fail_info;
		}
		if (route == STRATAFS_ROUTE_COPY_UP) {
			ret = stratafs_copy_up_file(file);
			if (ret)
				goto fail_info;
		}
	}
	return 0;

fail_info:
	file->private_data = NULL;
	fput(info->real);
	path_put(&info->provider);
	kfree(info);
	return ret;
}

static int stratafs_release(struct inode *inode, struct file *file)
{
	struct stratafs_file_info *info = file->private_data;

	if (info) {
		void *owner = file;

		/* Leases use the outer open description as their identity. */
		kernel_setlease(info->real, F_UNLCK, NULL, &owner);
		if (info->retired_real) {
			owner = file;
			kernel_setlease(info->retired_real, F_UNLCK, NULL,
					&owner);
		}
		fput(info->real);
		if (info->retired_real)
			fput(info->retired_real);
		path_put(&info->provider);
		kfree(info);
	}
	return 0;
}

static loff_t stratafs_llseek(struct file *file, loff_t offset, int whence)
{
	struct stratafs_file_info *info = file->private_data;
	loff_t ret;

	mutex_lock(&info->mutation_lock);
	ret = vfs_llseek(info->real, offset, whence);
	if (ret >= 0)
		file->f_pos = ret;
	mutex_unlock(&info->mutation_lock);
	return ret;
}

static ssize_t stratafs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct stratafs_file_info *info = file->private_data;
	struct backing_file_ctx ctx = stratafs_backing_ctx(file);

	ssize_t ret;

	mutex_lock(&info->mutation_lock);
	ret = backing_file_read_iter(info->real, iter, iocb, iocb->ki_flags,
				     &ctx);
	mutex_unlock(&info->mutation_lock);
	return ret;
}

static ssize_t stratafs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct stratafs_file_info *info = file->private_data;
	struct backing_file_ctx ctx = stratafs_backing_ctx(file);
	ssize_t ret;

	mutex_lock(&info->mutation_lock);
	if (S_ISREG(file_inode(file)->i_mode)) {
		ret = stratafs_route_existing(file_inode(file)->i_sb,
					       info->provider_index,
					       &info->provider, true);
		if (ret == STRATAFS_ROUTE_READ_ONLY)
			goto read_only;
		if (ret == STRATAFS_ROUTE_COPY_UP) {
			ret = stratafs_copy_up_file(file);
			if (ret)
				goto out;
			info = file->private_data;
		}
	}

	ret = backing_file_write_iter(info->real, iter, iocb, iocb->ki_flags,
				       &ctx);
	if (ret >= 0)
		stratafs_refresh_inode(file_inode(file), &info->provider);
out:
	mutex_unlock(&info->mutation_lock);
	return ret;
read_only:
	ret = -EROFS;
	stratafs_audit_refusal(file->f_path.dentry, "write",
				 info->provider_index, ret, false);
	goto out;
}

static int stratafs_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	struct stratafs_file_info *info = file->private_data;
	int ret;

	mutex_lock(&info->mutation_lock);
	ret = vfs_fsync_range(info->real, start, end, datasync);
	mutex_unlock(&info->mutation_lock);
	return ret;
}

static int stratafs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct stratafs_file_info *info = file->private_data;
	struct backing_file_ctx ctx = stratafs_backing_ctx(file);
	int route;
	int ret;

	mutex_lock(&info->mutation_lock);
	if (S_ISREG(file_inode(file)->i_mode) &&
	    (vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE)) {
		route = stratafs_route_existing(file_inode(file)->i_sb,
						 info->provider_index,
						 &info->provider, true);
		if (route == STRATAFS_ROUTE_READ_ONLY)
			goto read_only;
		if (route == STRATAFS_ROUTE_COPY_UP) {
			ret = stratafs_copy_up_file(file);
			if (ret)
				goto out;
			info = file->private_data;
		}
	}
	ret = backing_file_mmap(info->real, vma, &ctx);
out:
	mutex_unlock(&info->mutation_lock);
	return ret;
read_only:
	ret = -EROFS;
	stratafs_audit_refusal(file->f_path.dentry, "mmap",
				 info->provider_index, ret, false);
	goto out;
}

static long stratafs_fallocate(struct file *file, int mode, loff_t offset,
			       loff_t len)
{
	struct stratafs_file_info *info = file->private_data;
	int route;
	int ret;

	mutex_lock(&info->mutation_lock);
	route = stratafs_route_existing(file_inode(file)->i_sb,
					 info->provider_index, &info->provider, true);
	if (route == STRATAFS_ROUTE_READ_ONLY)
		goto read_only;
	if (route == STRATAFS_ROUTE_COPY_UP) {
		ret = stratafs_copy_up_file(file);
		if (ret)
			goto out;
		info = file->private_data;
	}
	ret = vfs_fallocate(info->real, mode, offset, len);
	if (!ret)
		stratafs_refresh_inode(file_inode(file), &info->provider);
out:
	mutex_unlock(&info->mutation_lock);
	return ret;
read_only:
	ret = -EROFS;
	stratafs_audit_refusal(file->f_path.dentry, "fallocate",
				 info->provider_index, ret, false);
	goto out;
}

static int stratafs_flush(struct file *file, fl_owner_t id)
{
	struct stratafs_file_info *info = file->private_data;
	struct file *retired;
	int current_ret = 0;
	int ret = 0;

	mutex_lock(&info->mutation_lock);
	retired = info->retired_real;
	if (retired) {
		if (retired->f_op->flush)
			ret = retired->f_op->flush(retired, id);
		/*
		 * filp_close() removes POSIX locks from the outer inode after
		 * ->flush.  The locks were installed on the provider inode, so
		 * mirror that close-time cleanup while both provider files are
		 * stable under mutation_lock.
		 */
		locks_remove_posix(retired, id);
	}
	if (info->real->f_op->flush)
		current_ret = info->real->f_op->flush(info->real, id);
	locks_remove_posix(info->real, id);
	if (!ret)
		ret = current_ret;
	mutex_unlock(&info->mutation_lock);
	return ret;
}

static ssize_t stratafs_splice_read(struct file *in, loff_t *ppos,
				    struct pipe_inode_info *pipe,
				    size_t len, unsigned int flags)
{
	struct stratafs_file_info *info = in->private_data;
	struct backing_file_ctx ctx = stratafs_backing_ctx(in);
	struct kiocb iocb;
	ssize_t ret;

	mutex_lock(&info->mutation_lock);
	init_sync_kiocb(&iocb, in);
	iocb.ki_pos = *ppos;
	ret = backing_file_splice_read(info->real, &iocb, pipe, len, flags,
				       &ctx);
	if (ret > 0)
		*ppos = iocb.ki_pos;
	mutex_unlock(&info->mutation_lock);
	return ret;
}

static ssize_t stratafs_splice_write(struct pipe_inode_info *pipe,
				     struct file *out, loff_t *ppos,
				     size_t len, unsigned int flags)
{
	struct stratafs_file_info *info = out->private_data;
	struct backing_file_ctx ctx = stratafs_backing_ctx(out);
	struct kiocb iocb;
	ssize_t ret;

	mutex_lock(&info->mutation_lock);
	if (S_ISREG(file_inode(out)->i_mode)) {
		ret = stratafs_route_existing(file_inode(out)->i_sb,
					       info->provider_index,
					       &info->provider, true);
		if (ret == STRATAFS_ROUTE_READ_ONLY)
			goto read_only;
		if (ret == STRATAFS_ROUTE_COPY_UP) {
			ret = stratafs_copy_up_file(out);
			if (ret)
				goto out;
			info = out->private_data;
		}
	}

	init_sync_kiocb(&iocb, out);
	iocb.ki_pos = *ppos;
	ret = backing_file_splice_write(pipe, info->real, &iocb, len, flags,
					&ctx);
	if (ret > 0) {
		*ppos = iocb.ki_pos;
		stratafs_refresh_inode(file_inode(out), &info->provider);
	}
out:
	mutex_unlock(&info->mutation_lock);
	return ret;
read_only:
	ret = -EROFS;
	stratafs_audit_refusal(out->f_path.dentry, "splice-write",
				 info->provider_index, ret, false);
	goto out;
}

static int stratafs_fadvise(struct file *file, loff_t offset, loff_t len,
			    int advice)
{
	struct stratafs_file_info *info = file->private_data;
	int ret;

	mutex_lock(&info->mutation_lock);
	ret = vfs_fadvise(info->real, offset, len, advice);
	mutex_unlock(&info->mutation_lock);
	return ret;
}

int stratafs_copy_up_metadata_file(struct file *file, struct dentry *dentry,
				    struct path *provider,
				    unsigned int *provider_index)
{
	struct stratafs_file_info *info;
	int route;
	int ret;

	if (!file || file->f_op != &stratafs_file_operations ||
	    file->f_path.dentry != dentry || !file->private_data)
		return -ESTALE;
	info = file->private_data;
	mutex_lock(&info->mutation_lock);
	/* The descriptor may have been rebound after the caller routed by path. */
	route = stratafs_route_existing(file_inode(file)->i_sb,
					info->provider_index, &info->provider, true);
	if (route == STRATAFS_ROUTE_READ_ONLY)
		ret = -EROFS;
	else if (route == STRATAFS_ROUTE_COPY_UP)
		ret = stratafs_copy_up_file(file);
	else
		ret = 0;
	if (!ret) {
		info = file->private_data;
		*provider = info->provider;
		path_get(provider);
		if (provider_index)
			*provider_index = info->provider_index;
	}
	mutex_unlock(&info->mutation_lock);
	return ret;
}

static ssize_t stratafs_copy_file_range(struct file *file_in, loff_t pos_in,
					struct file *file_out, loff_t pos_out,
					size_t len, unsigned int flags)
{
	struct stratafs_file_info *in_info = file_in->private_data;
	struct stratafs_file_info *out_info = file_out->private_data;
	struct file *real_in;
	ssize_t ret;

	mutex_lock(&in_info->mutation_lock);
	real_in = get_file(in_info->real);
	mutex_unlock(&in_info->mutation_lock);
	mutex_lock(&out_info->mutation_lock);
	ret = stratafs_route_existing(file_inode(file_out)->i_sb,
				       out_info->provider_index,
				       &out_info->provider, true);
	if (ret == STRATAFS_ROUTE_READ_ONLY)
		goto read_only;
	if (ret == STRATAFS_ROUTE_COPY_UP) {
		ret = stratafs_copy_up_file(file_out);
		if (ret)
			goto out;
		out_info = file_out->private_data;
	}
	/* A concurrent copy-up may have happened before out_info was locked. */
	if (file_in == file_out) {
		fput(real_in);
		real_in = get_file(out_info->real);
	}

	ret = vfs_copy_file_range(real_in, pos_in, out_info->real,
				  pos_out, len, flags);
	if (ret >= 0)
		stratafs_refresh_inode(file_inode(file_out), &out_info->provider);
out:
	mutex_unlock(&out_info->mutation_lock);
	fput(real_in);
	return ret;
read_only:
	ret = -EROFS;
	stratafs_audit_refusal(file_out->f_path.dentry, "copy-file-range",
				 out_info->provider_index, ret, false);
	goto out;
}

static loff_t stratafs_remap_file_range(struct file *file_in, loff_t pos_in,
					struct file *file_out, loff_t pos_out,
					loff_t len, unsigned int remap_flags)
{
	struct stratafs_file_info *in_info = file_in->private_data;
	struct stratafs_file_info *out_info = file_out->private_data;
	struct file *real_in;
	loff_t ret;

	if (remap_flags & ~(REMAP_FILE_DEDUP | REMAP_FILE_ADVISORY))
		return -EINVAL;
	mutex_lock(&in_info->mutation_lock);
	real_in = get_file(in_info->real);
	mutex_unlock(&in_info->mutation_lock);
	mutex_lock(&out_info->mutation_lock);
	ret = stratafs_route_existing(file_inode(file_out)->i_sb,
				       out_info->provider_index,
				       &out_info->provider, true);
	if (ret == STRATAFS_ROUTE_READ_ONLY)
		goto read_only;
	if (ret == STRATAFS_ROUTE_COPY_UP) {
		ret = stratafs_copy_up_file(file_out);
		if (ret)
			goto out;
		out_info = file_out->private_data;
	}
	/* A concurrent copy-up may have happened before out_info was locked. */
	if (file_in == file_out) {
		fput(real_in);
		real_in = get_file(out_info->real);
	}

	if (remap_flags & REMAP_FILE_DEDUP)
		ret = vfs_dedupe_file_range_one(real_in, pos_in,
						out_info->real, pos_out, len,
						remap_flags);
	else
		ret = vfs_clone_file_range(real_in, pos_in,
					   out_info->real, pos_out, len,
					   remap_flags);
	if (ret >= 0)
		stratafs_refresh_inode(file_inode(file_out), &out_info->provider);
out:
	mutex_unlock(&out_info->mutation_lock);
	fput(real_in);
	return ret;
read_only:
	ret = -EROFS;
	stratafs_audit_refusal(file_out->f_path.dentry, "remap-file-range",
				 out_info->provider_index, ret, false);
	goto out;
}

static int stratafs_lock(struct file *file, int cmd, struct file_lock *lock)
{
	struct stratafs_file_info *info = file->private_data;
	struct file_lock retired_lock;
	struct file *real;
	struct file *retired = NULL;
	struct file *outer = lock->c.flc_file;
	fl_owner_t outer_owner = lock->c.flc_owner;
	int current_ret;
	int ret;

	mutex_lock(&info->mutation_lock);
	real = get_file(info->real);
	if (lock->c.flc_type == F_UNLCK && info->retired_real)
		retired = get_file(info->retired_real);
	mutex_unlock(&info->mutation_lock);
	ret = 0;
	if (retired) {
		locks_init_lock(&retired_lock);
		locks_copy_lock(&retired_lock, lock);
		retired_lock.c.flc_file = retired;
		if (retired_lock.c.flc_flags & FL_OFDLCK)
			retired_lock.c.flc_owner = retired;
		ret = vfs_lock_file(retired, cmd, &retired_lock, NULL);
		/* locks_copy_lock() took the original lock-manager owner ref. */
		retired_lock.c.flc_owner = outer_owner;
		locks_release_private(&retired_lock);
	}
	lock->c.flc_file = real;
	if (lock->c.flc_flags & FL_OFDLCK)
		lock->c.flc_owner = real;
	current_ret = vfs_lock_file(real, cmd, lock, NULL);
	if (!ret)
		ret = current_ret;
	lock->c.flc_file = outer;
	lock->c.flc_owner = outer_owner;
	if (retired)
		fput(retired);
	fput(real);
	return ret;
}

static int stratafs_flock(struct file *file, int cmd, struct file_lock *lock)
{
	struct stratafs_file_info *info = file->private_data;
	struct file_lock retired_lock;
	struct file *real;
	struct file *retired = NULL;
	struct file *outer = lock->c.flc_file;
	fl_owner_t outer_owner = lock->c.flc_owner;
	int current_ret;
	int ret;

	mutex_lock(&info->mutation_lock);
	real = get_file(info->real);
	if (lock->c.flc_type == F_UNLCK && info->retired_real)
		retired = get_file(info->retired_real);
	mutex_unlock(&info->mutation_lock);
	ret = 0;
	if (retired) {
		locks_init_lock(&retired_lock);
		locks_copy_lock(&retired_lock, lock);
		retired_lock.c.flc_file = retired;
		retired_lock.c.flc_owner = retired;
		if (retired->f_op->flock)
			ret = retired->f_op->flock(retired, cmd,
						   &retired_lock);
		else
			ret = locks_lock_file_wait(retired, &retired_lock);
		retired_lock.c.flc_owner = outer_owner;
		locks_release_private(&retired_lock);
	}
	lock->c.flc_file = real;
	lock->c.flc_owner = real;
	if (real->f_op->flock)
		current_ret = real->f_op->flock(real, cmd, lock);
	else
		current_ret = locks_lock_file_wait(real, lock);
	if (!ret)
		ret = current_ret;
	lock->c.flc_file = outer;
	lock->c.flc_owner = outer_owner;
	if (retired)
		fput(retired);
	fput(real);
	return ret;
}

static int stratafs_setlease(struct file *file, int arg,
			     struct file_lease **lease, void **priv)
{
	struct stratafs_file_info *info = file->private_data;
	struct file *real;
	struct file *retired = NULL;
	struct file *target;
	unsigned int flavor;
	int lease_type;
	int current_ret;
	int ret;

	/* vfs_setlease() already performed the caller-facing security check. */
	mutex_lock(&info->mutation_lock);
	real = get_file(info->real);
	if (info->retired_real)
		retired = get_file(info->retired_real);
	mutex_unlock(&info->mutation_lock);
	if (arg == F_UNLCK && retired) {
		ret = kernel_setlease(retired, arg, lease, priv);
		current_ret = kernel_setlease(real, arg, lease, priv);
		if (current_ret == 0 || ret != 0)
			ret = current_ret;
	} else {
		target = real;
		if (retired && lease && *lease) {
			flavor = (*lease)->c.flc_flags;
			lease_type = kernel_getlease(retired,
						      (*lease)->c.flc_file,
						      flavor);
			if (lease_type < 0) {
				ret = lease_type;
				goto out;
			}
			if (lease_type != F_UNLCK)
				target = retired;
		}
		ret = kernel_setlease(target, arg, lease, priv);
	}
out:
	if (retired)
		fput(retired);
	fput(real);
	return ret;
}

static int stratafs_getlease(struct file *file, struct file *lease_file,
			     unsigned int flavor)
{
	struct stratafs_file_info *info = file->private_data;
	struct file *real;
	struct file *retired = NULL;
	int current_type;
	int retired_type = F_UNLCK;

	mutex_lock(&info->mutation_lock);
	real = get_file(info->real);
	if (info->retired_real)
		retired = get_file(info->retired_real);
	mutex_unlock(&info->mutation_lock);
	if (retired)
		retired_type = kernel_getlease(retired, lease_file, flavor);
	current_type = kernel_getlease(real, lease_file, flavor);
	if (retired)
		fput(retired);
	fput(real);
	if (retired_type < 0)
		return retired_type;
	if (current_type < 0)
		return current_type;
	if (retired_type == F_WRLCK || current_type == F_WRLCK)
		return F_WRLCK;
	if (retired_type == F_RDLCK || current_type == F_RDLCK)
		return F_RDLCK;
	return F_UNLCK;
}

static __poll_t stratafs_poll(struct file *file, poll_table *wait)
{
	struct stratafs_file_info *info = file->private_data;
	struct file *real;
	__poll_t ret;

	mutex_lock(&info->mutation_lock);
	real = get_file(info->real);
	mutex_unlock(&info->mutation_lock);
	ret = vfs_poll(real, wait);
	fput(real);
	return ret;
}

static long stratafs_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct stratafs_file_info *info = file->private_data;
	struct file *real;
	long ret = -ENOTTY;

	/* Stored-file ioctls can mutate data and need command-specific routing. */
	if (S_ISREG(file_inode(file)->i_mode))
		return -ENOTTY;
	mutex_lock(&info->mutation_lock);
	real = get_file(info->real);
	mutex_unlock(&info->mutation_lock);
	if (real->f_op->unlocked_ioctl)
		ret = real->f_op->unlocked_ioctl(real, cmd, arg);
	fput(real);
	return ret == -ENOIOCTLCMD ? -ENOTTY : ret;
}

#ifdef CONFIG_COMPAT
static long stratafs_compat_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	struct stratafs_file_info *info = file->private_data;
	struct file *real;
	long ret = -ENOIOCTLCMD;

	if (S_ISREG(file_inode(file)->i_mode))
		return -ENOIOCTLCMD;
	mutex_lock(&info->mutation_lock);
	real = get_file(info->real);
	mutex_unlock(&info->mutation_lock);
	if (real->f_op->compat_ioctl)
		ret = real->f_op->compat_ioctl(real, cmd, arg);
	fput(real);
	return ret;
}
#endif

static int stratafs_fasync(int fd, struct file *file, int on)
{
	struct stratafs_file_info *info = file->private_data;
	struct file *real;
	int ret = -EINVAL;

	mutex_lock(&info->mutation_lock);
	real = get_file(info->real);
	mutex_unlock(&info->mutation_lock);
	if (real->f_op->fasync)
		ret = real->f_op->fasync(fd, real, on);
	fput(real);
	return ret;
}

const struct file_operations stratafs_file_operations = {
	.open = stratafs_open,
	.release = stratafs_release,
	.llseek = stratafs_llseek,
	.read_iter = stratafs_read_iter,
	.write_iter = stratafs_write_iter,
	.fsync = stratafs_fsync,
	.mmap = stratafs_mmap,
	.fallocate = stratafs_fallocate,
	.flush = stratafs_flush,
	.splice_read = stratafs_splice_read,
	.splice_write = stratafs_splice_write,
	.fadvise = stratafs_fadvise,
	.copy_file_range = stratafs_copy_file_range,
	.remap_file_range = stratafs_remap_file_range,
	.lock = stratafs_lock,
	.flock = stratafs_flock,
	.setlease = stratafs_setlease,
	.getlease = stratafs_getlease,
	.poll = stratafs_poll,
	.unlocked_ioctl = stratafs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = stratafs_compat_ioctl,
#endif
	.fasync = stratafs_fasync,
};
