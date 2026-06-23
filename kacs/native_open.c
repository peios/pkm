// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include <pkm/sd.h>

#include "access_check.h"
#include "file_access.h"
#include "file_sd_cache.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "native_open.h"
#include "token_runtime.h"

static atomic64_t pkm_kacs_native_supersede_tmp_counter = ATOMIC64_INIT(0);

u64 pkm_kacs_next_native_supersede_tmp_id(void)
{
	return (u64)atomic64_inc_return(&pkm_kacs_native_supersede_tmp_counter);
}

static long pkm_kacs_copy_open_how_from_user(
	struct kacs_open_how *out,
	const struct kacs_open_how __user *uhow, size_t howsize)
{
	int ret;

	if (!out || !uhow)
		return -EINVAL;
	if (howsize < KACS_OPEN_HOW_MIN_SIZE)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	ret = copy_struct_from_user(out, sizeof(*out), uhow, howsize);
	if (ret == -E2BIG)
		return -EINVAL;
	return ret;
}

static long pkm_kacs_map_file_generic_access_mask(u32 desired, u32 *mapped_out)
{
	u32 mapped;
	u32 valid_mask;

	if (!mapped_out || desired == 0)
		return -EINVAL;

	valid_mask = KACS_FILE_READ_DATA | KACS_FILE_WRITE_DATA |
		     KACS_FILE_APPEND_DATA | KACS_FILE_READ_EA |
		     KACS_FILE_WRITE_EA | KACS_FILE_EXECUTE |
		     KACS_FILE_DELETE_CHILD |
		     KACS_FILE_READ_ATTRIBUTES |
		     KACS_FILE_WRITE_ATTRIBUTES | KACS_ACCESS_DELETE |
		     KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC |
		     KACS_ACCESS_WRITE_OWNER | KACS_ACCESS_SYNCHRONIZE |
		     KACS_ACCESS_ACCESS_SYSTEM_SECURITY |
		     KACS_ACCESS_MAXIMUM_ALLOWED |
		     KACS_ACCESS_GENERIC_ALL |
		     KACS_ACCESS_GENERIC_EXECUTE |
		     KACS_ACCESS_GENERIC_WRITE |
		     KACS_ACCESS_GENERIC_READ;
	if ((desired & ~valid_mask) != 0)
		return -EINVAL;

	mapped = desired;
	if ((mapped & KACS_ACCESS_GENERIC_READ) != 0) {
		mapped &= ~KACS_ACCESS_GENERIC_READ;
		mapped |= KACS_FILE_READ_DATA |
			  KACS_FILE_READ_ATTRIBUTES |
			  KACS_FILE_READ_EA |
			  KACS_ACCESS_READ_CONTROL |
			  KACS_ACCESS_SYNCHRONIZE;
	}
	if ((mapped & KACS_ACCESS_GENERIC_WRITE) != 0) {
		mapped &= ~KACS_ACCESS_GENERIC_WRITE;
		mapped |= KACS_FILE_WRITE_DATA |
			  KACS_FILE_APPEND_DATA |
			  KACS_FILE_WRITE_ATTRIBUTES |
			  KACS_FILE_WRITE_EA |
			  KACS_ACCESS_READ_CONTROL |
			  KACS_ACCESS_SYNCHRONIZE;
	}
	if ((mapped & KACS_ACCESS_GENERIC_EXECUTE) != 0) {
		mapped &= ~KACS_ACCESS_GENERIC_EXECUTE;
		mapped |= KACS_FILE_EXECUTE |
			  KACS_FILE_READ_ATTRIBUTES |
			  KACS_ACCESS_READ_CONTROL |
			  KACS_ACCESS_SYNCHRONIZE;
	}
	if ((mapped & KACS_ACCESS_GENERIC_ALL) != 0) {
		mapped &= ~KACS_ACCESS_GENERIC_ALL;
		mapped |= KACS_FILE_READ_DATA |
			  KACS_FILE_WRITE_DATA |
			  KACS_FILE_APPEND_DATA |
			  KACS_FILE_READ_EA |
			  KACS_FILE_WRITE_EA |
			  KACS_FILE_EXECUTE |
			  KACS_FILE_DELETE_CHILD |
			  KACS_FILE_READ_ATTRIBUTES |
			  KACS_FILE_WRITE_ATTRIBUTES |
			  KACS_ACCESS_DELETE |
			  KACS_ACCESS_READ_CONTROL |
			  KACS_ACCESS_WRITE_DAC |
			  KACS_ACCESS_WRITE_OWNER |
			  KACS_ACCESS_SYNCHRONIZE;
	}

	*mapped_out = mapped;
	return 0;
}

long pkm_kacs_prepare_native_open(
	const struct kacs_open_how *how,
	struct pkm_kacs_native_open_prepared *prepared)
{
	u32 desired_access;
	u32 data_mask;
	bool has_read;
	bool has_write;
	bool has_execute;
	int open_flags = 0;
	long ret;

	if (!how || !prepared)
		return -EINVAL;
	if ((how->flags & ~PKM_KACS_OPEN_ALLOWED_AT_FLAGS) != 0)
		return -EINVAL;
	if ((how->create_options &
	     ~(KACS_CREATE_OPT_DIRECTORY |
	       KACS_CREATE_OPT_DELETE_ON_CLOSE)) != 0)
		return -EINVAL;
	if (how->__pad != 0)
		return -EINVAL;
	if ((how->sd_ptr == 0) != (how->sd_len == 0))
		return -EINVAL;
	if (how->sd_len > PKM_KACS_MAX_SD_BYTES)
		return -EINVAL;
	if (how->create_disposition > KACS_DISPOSITION_OVERWRITE_IF)
		return -EINVAL;
	if (how->create_disposition == KACS_DISPOSITION_OPEN &&
	    (how->sd_ptr != 0 || how->sd_len != 0))
		return -EOPNOTSUPP;
	if (how->create_disposition == KACS_DISPOSITION_OVERWRITE &&
	    (how->sd_ptr != 0 || how->sd_len != 0))
		return -EINVAL;

	ret = pkm_kacs_map_file_generic_access_mask(how->desired_access,
						    &desired_access);
	if (ret)
		return ret;
	if ((desired_access & KACS_FILE_DELETE_CHILD) != 0)
		return -EOPNOTSUPP;

	data_mask = KACS_FILE_READ_DATA |
		    KACS_FILE_WRITE_DATA |
		    KACS_FILE_APPEND_DATA;
	has_read = (desired_access & KACS_FILE_READ_DATA) != 0;
	has_write = (desired_access &
		     (KACS_FILE_WRITE_DATA |
		      KACS_FILE_APPEND_DATA)) != 0;
	has_execute = (desired_access & KACS_FILE_EXECUTE) != 0;
	if ((desired_access & data_mask) == 0 && !has_execute)
		return -EINVAL;
	if (how->create_disposition == KACS_DISPOSITION_OVERWRITE &&
	    (desired_access & KACS_FILE_WRITE_DATA) == 0)
		return -EINVAL;
	if ((how->create_disposition == KACS_DISPOSITION_SUPERSEDE ||
	     how->create_disposition == KACS_DISPOSITION_OVERWRITE ||
	     how->create_disposition == KACS_DISPOSITION_OVERWRITE_IF) &&
	    (how->create_options & KACS_CREATE_OPT_DIRECTORY) != 0)
		return -EOPNOTSUPP;
	if ((how->create_options &
	     (KACS_CREATE_OPT_DIRECTORY |
	      KACS_CREATE_OPT_DELETE_ON_CLOSE)) ==
	    (KACS_CREATE_OPT_DIRECTORY |
	     KACS_CREATE_OPT_DELETE_ON_CLOSE))
		return -EOPNOTSUPP;

	if (has_write && has_read)
		open_flags = O_RDWR;
	else if (has_write)
		open_flags = O_WRONLY;
	else
		open_flags = O_RDONLY;
	if ((desired_access & KACS_FILE_APPEND_DATA) != 0 &&
	    (desired_access & KACS_FILE_WRITE_DATA) == 0)
		open_flags |= O_APPEND;
	if (has_execute)
		open_flags |= __FMODE_EXEC;
	if ((how->create_options & KACS_CREATE_OPT_DIRECTORY) != 0)
		open_flags |= O_DIRECTORY;

	prepared->desired_access = desired_access;
	prepared->create_disposition = how->create_disposition;
	switch (how->create_disposition) {
	case KACS_DISPOSITION_OVERWRITE:
	case KACS_DISPOSITION_OVERWRITE_IF:
		prepared->status = KACS_STATUS_OVERWRITTEN;
		break;
	case KACS_DISPOSITION_SUPERSEDE:
		prepared->status = KACS_STATUS_SUPERSEDED;
		break;
	default:
		prepared->status = KACS_STATUS_OPENED;
		break;
	}
	prepared->create_options = how->create_options;
	prepared->open_flags = open_flags;
	prepared->directory_required =
		(how->create_options & KACS_CREATE_OPT_DIRECTORY) != 0;
	return 0;
}

static long pkm_kacs_copy_creator_sd_from_user(
	const struct kacs_open_how *how,
	u8 **creator_sd_bytes_out,
	size_t *creator_sd_len_out)
{
	u8 *creator_sd_bytes;

	if (!how || !creator_sd_bytes_out || !creator_sd_len_out)
		return -EINVAL;

	*creator_sd_bytes_out = NULL;
	*creator_sd_len_out = 0;
	if (how->sd_ptr == 0 || how->sd_len == 0)
		return 0;

	creator_sd_bytes = memdup_user(u64_to_user_ptr(how->sd_ptr), how->sd_len);
	if (IS_ERR(creator_sd_bytes))
		return PTR_ERR(creator_sd_bytes);

	*creator_sd_bytes_out = creator_sd_bytes;
	*creator_sd_len_out = how->sd_len;
	return 0;
}

void pkm_kacs_set_current_native_open_request(
	const struct path *path, u32 desired_access, u32 create_options)
{
	struct pkm_kacs_task_security *sec;

	if (!current->security)
		return;

	sec = pkm_kacs_task(current);
	sec->native_open.expected_dentry = path ? path->dentry : NULL;
	sec->native_open.expected_mnt = path ? path->mnt : NULL;
	sec->native_open.desired_access = desired_access;
	sec->native_open.create_options = create_options;
	sec->native_open.active = path != NULL;
}

void pkm_kacs_clear_current_native_open_request(void)
{
	pkm_kacs_set_current_native_open_request(NULL, 0, 0);
}

bool pkm_kacs_native_open_request_matches(struct file *file,
					  u32 *desired_access_out,
					  u32 *create_options_out)
{
	struct pkm_kacs_task_security *sec;

	if (!file || !current->security)
		return false;

	sec = pkm_kacs_task(current);
	if (!sec->native_open.active)
		return false;
	if (file->f_path.dentry != sec->native_open.expected_dentry ||
	    file->f_path.mnt != sec->native_open.expected_mnt)
		return false;

	if (desired_access_out)
		*desired_access_out = sec->native_open.desired_access;
	if (create_options_out)
		*create_options_out = sec->native_open.create_options;
	return true;
}

bool pkm_kacs_file_delete_on_close_pending(const struct file *file)
{
	struct inode *inode;

	if (!file)
		return false;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return false;

	return atomic_read(&pkm_kacs_inode(inode)->delete_on_close_lineages) > 0;
}

static long pkm_kacs_authorize_delete_on_close_for_subject(
	const void *subject_token, struct file *file)
{
	struct path parent_path = {};
	struct file parent_file = {};
	struct inode *inode;
	long ret;

	if (!subject_token || !file || !file_dentry(file))
		return -EACCES;

	ret = pkm_kacs_authorize_live_file_access_core(subject_token, file,
						       KACS_ACCESS_DELETE);
	if (ret != -EACCES)
		return ret;

	inode = file_inode(file);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (inode && pkm_kacs_inode(inode)->kunit_fake_xattr_enabled) {
		parent_path.mnt = file->f_path.mnt;
		parent_path.dentry = file_dentry(file)->d_parent;
		if (!parent_path.mnt || !parent_path.dentry)
			return -EACCES;

		pkm_kacs_init_path_anchor_file(&parent_file, &parent_path);
		return pkm_kacs_authorize_live_file_access_core(
			subject_token, &parent_file, KACS_FILE_DELETE_CHILD);
	}
#endif

	parent_path.mnt = mntget(file->f_path.mnt);
	parent_path.dentry = dget_parent(file_dentry(file));
	if (!parent_path.mnt || !parent_path.dentry) {
		if (parent_path.mnt)
			mntput(parent_path.mnt);
		return -EACCES;
	}

	pkm_kacs_init_path_anchor_file(&parent_file, &parent_path);
	ret = pkm_kacs_authorize_live_file_access_core(
		subject_token, &parent_file, KACS_FILE_DELETE_CHILD);
	path_put(&parent_path);
	return ret;
}

long pkm_kacs_unlink_delete_on_close_file(struct file *file)
{
	struct inode *inode;
	struct inode *parent_inode;
	struct path parent_path = {};
	struct dentry *dentry;
	long ret;

	if (!file)
		return -EACCES;

	dentry = file_dentry(file);
	inode = file_inode(file);
	if (!dentry || !inode || !inode->i_security)
		return -EACCES;

#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (pkm_kacs_inode(inode)->kunit_fake_xattr_enabled) {
		pkm_kacs_inode(inode)->kunit_unlink_calls++;
		return 0;
	}
#endif

	parent_path.mnt = mntget(file->f_path.mnt);
	parent_path.dentry = dget_parent(dentry);
	if (!parent_path.mnt || !parent_path.dentry) {
		if (parent_path.mnt)
			mntput(parent_path.mnt);
		return -EACCES;
	}

	parent_inode = d_inode(parent_path.dentry);
	if (!parent_inode) {
		path_put(&parent_path);
		return -EACCES;
	}

	ret = mnt_want_write(parent_path.mnt);
	if (ret) {
		path_put(&parent_path);
		return ret;
	}

	inode_lock(parent_inode);
	ret = vfs_unlink(mnt_idmap(parent_path.mnt), parent_inode, dentry, NULL);
	inode_unlock(parent_inode);
	mnt_drop_write(parent_path.mnt);
	path_put(&parent_path);
	return ret;
}

long pkm_kacs_maybe_arm_delete_on_close_for_subject(
	const void *subject_token, struct file *file, u32 create_options)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct inode *inode;
	long ret;

	if ((create_options & KACS_CREATE_OPT_DELETE_ON_CLOSE) == 0)
		return 0;
	if (!subject_token || !file || !file->f_security ||
	    (file->f_mode & FMODE_PATH) != 0)
		return -EOPNOTSUPP;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    KACS_MOUNT_POLICY_UNMANAGED)
		return -EOPNOTSUPP;

	file_sec = pkm_kacs_file(file);
	if (file_sec->delete_on_close)
		return 0;

	ret = pkm_kacs_authorize_delete_on_close_for_subject(subject_token, file);
	if (ret)
		return ret;

	inode_sec = pkm_kacs_inode(inode);
	mutex_lock(&inode_sec->lock);
	if (atomic_read(&inode_sec->delete_on_close_lineages) != 0) {
		ret = -EACCES;
	} else {
		atomic_inc(&inode_sec->delete_on_close_lineages);
		file_sec->delete_on_close = 1;
		ret = 0;
	}
	mutex_unlock(&inode_sec->lock);
	return ret;
}

void pkm_kacs_set_current_native_create_request(
	const struct inode *parent_inode, bool directory, const u8 *sd_bytes,
	size_t sd_len)
{
	struct pkm_kacs_task_security *sec;

	if (!current->security)
		return;

	sec = pkm_kacs_task(current);
	sec->native_create.expected_parent_inode = parent_inode;
	sec->native_create.sd_bytes = sd_bytes;
	sec->native_create.sd_len = sd_len;
	sec->native_create.directory = directory;
	sec->native_create.active = parent_inode && sd_bytes && sd_len != 0;
}

void pkm_kacs_clear_current_native_create_request(void)
{
	pkm_kacs_set_current_native_create_request(NULL, false, NULL, 0);
}

bool pkm_kacs_current_native_create_request_matches(
	const struct inode *parent_inode, bool directory,
	const u8 **sd_bytes_out, size_t *sd_len_out)
{
	struct pkm_kacs_task_security *sec;

	if (!current->security)
		return false;

	sec = pkm_kacs_task(current);
	if (!sec->native_create.active)
		return false;
	if (sec->native_create.expected_parent_inode != parent_inode ||
	    sec->native_create.directory != directory)
		return false;

	if (sd_bytes_out)
		*sd_bytes_out = sec->native_create.sd_bytes;
	if (sd_len_out)
		*sd_len_out = sec->native_create.sd_len;
	return true;
}

umode_t pkm_kacs_native_create_mode(bool directory)
{
	return directory ? (S_IFDIR | 0700) : (S_IFREG | 0600);
}

bool pkm_kacs_special_node_mode_supported(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		return true;
	default:
		return false;
	}
}

bool pkm_kacs_existing_file_object_mode_supported(umode_t mode)
{
	return S_ISREG(mode) || pkm_kacs_special_node_mode_supported(mode);
}

static long pkm_kacs_open_path_lookup_flags(u32 flags,
					    unsigned int *lookup_flags_out)
{
	unsigned int lookup_flags = 0;

	if (!lookup_flags_out)
		return -EINVAL;
	if ((flags & ~PKM_KACS_OPEN_ALLOWED_AT_FLAGS) != 0)
		return -EINVAL;

	if ((flags & AT_SYMLINK_NOFOLLOW) == 0)
		lookup_flags |= LOOKUP_FOLLOW;

	*lookup_flags_out = lookup_flags;
	return 0;
}

long pkm_kacs_build_created_file_sd_for_subject(
	const void *subject_token, struct file *parent_file,
	const u8 *creator_sd_ptr, size_t creator_sd_len, bool directory,
	u32 desired_access, const u8 **out_sd_ptr, size_t *out_sd_len,
	u32 *granted_access_out)
{
	struct inode *parent_inode;
	struct pkm_kacs_inode_security *parent_sec;
	struct pkm_kacs_inode_sd_cache *parent_cache = NULL;
	u32 parent_right;
	u32 granted_access = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long ret;

	if (!subject_token || !parent_file || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;
	if (granted_access_out)
		*granted_access_out = 0;
	if (creator_sd_len != 0 && !creator_sd_ptr)
		return -EINVAL;

	parent_inode = file_inode(parent_file);
	if (!parent_inode || !parent_inode->i_security)
		return -EACCES;
	if (!pkm_kacs_mount_policy_is_managed(
		    pkm_kacs_superblock_mount_policy(parent_inode->i_sb)))
		return -EOPNOTSUPP;
	if (pkm_kacs_inode_is_ntfs(parent_inode))
		return -EOPNOTSUPP;

	parent_sec = pkm_kacs_inode(parent_inode);
	parent_right = directory ? KACS_FILE_ADD_SUBDIRECTORY :
				   KACS_FILE_ADD_FILE;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	mutex_lock(&parent_sec->lock);
	ret = pkm_kacs_inode_resolve_effective_cache_locked(parent_file, parent_sec,
							    &parent_cache, 0);
	if (ret)
		goto out_unlock;
	if (parent_cache->state != PKM_KACS_INODE_SD_VALID ||
	    !parent_cache->bytes || parent_cache->len == 0) {
		ret = -EACCES;
		goto out_unlock;
	}

	ret = kacs_rust_check_cached_file_sd_with_intent(
		subject_token, parent_cache->bytes, parent_cache->len,
		&parent_cache->layout, parent_right, 0, pip_type, pip_trust,
		&granted_access);
	if (ret)
		goto out_unlock;

	ret = kacs_rust_build_created_file_sd(subject_token, parent_cache->bytes,
					      parent_cache->len, creator_sd_ptr,
					      creator_sd_len, directory,
					      out_sd_ptr, out_sd_len);
out_unlock:
	mutex_unlock(&parent_sec->lock);
	if (ret)
		return ret;

	if (desired_access != 0) {
		ret = kacs_rust_check_file_sd_with_intent(
			subject_token, *out_sd_ptr, *out_sd_len,
			desired_access, 0, pip_type, pip_trust,
			&granted_access);
		if (ret) {
			pkm_kacs_free((void *)*out_sd_ptr);
			*out_sd_ptr = NULL;
			*out_sd_len = 0;
			return ret;
		}
	}

	if (granted_access_out)
		*granted_access_out = granted_access;
	return 0;
}

static long pkm_kacs_open_native_existing_path(
	const struct path *resolved_path,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out)
{
	struct file *file;

	if (!resolved_path || !prepared || !file_out)
		return -EINVAL;

	*file_out = NULL;
	pkm_kacs_set_current_native_open_request(resolved_path,
						 prepared->desired_access,
						 prepared->create_options);
	file = dentry_open(resolved_path, prepared->open_flags, current_cred());
	pkm_kacs_clear_current_native_open_request();
	if (IS_ERR(file))
		return PTR_ERR(file);

	*file_out = file;
	return 0;
}

static long pkm_kacs_apply_native_overwrite_truncate(struct file *file)
{
	struct inode *inode;
	int ret;

	if (!file || !file_dentry(file))
		return -EACCES;

	inode = file_inode(file);
	if (!inode || !S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	ret = get_write_access(inode);
	if (ret)
		return ret;

	ret = security_file_truncate(file);
	if (!ret) {
		ret = do_truncate(file_mnt_idmap(file), file_dentry(file), 0,
				  ATTR_MTIME | ATTR_CTIME | ATTR_OPEN, file);
	}
	put_write_access(inode);
	return ret;
}

long pkm_kacs_do_native_overwrite_open(
	const struct path *resolved_path,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out)
{
	struct file *file = NULL;
	struct inode *inode;
	long ret;

	if (!resolved_path || !prepared || !file_out || !status_out)
		return -EINVAL;

	if ((prepared->desired_access & KACS_FILE_WRITE_DATA) == 0)
		return -EINVAL;

	inode = d_inode(resolved_path->dentry);
	if (!inode)
		return -EACCES;
	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	ret = pkm_kacs_open_native_existing_path(resolved_path, prepared, &file);
	if (ret)
		return ret;

	ret = pkm_kacs_apply_native_overwrite_truncate(file);
	if (ret) {
		fput(file);
		return ret;
	}

	*file_out = file;
	*status_out = KACS_STATUS_OVERWRITTEN;
	return 0;
}

long pkm_kacs_do_native_supersede_open(
	const void *subject_token, const struct path *resolved_path,
	const struct kacs_open_how *how,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out)
{
	struct path parent_path = {};
	struct file parent_file = {};
	struct path tmp_path = {};
	u8 *creator_sd_bytes = NULL;
	struct renamedata rd = {};
	struct inode *parent_inode;
	struct file *opened_file = NULL;
	struct dentry *dentry;
	struct dentry *tmp_dentry = NULL;
	const u8 *created_sd = NULL;
	size_t creator_sd_len = 0;
	size_t created_sd_len = 0;
	u32 granted_access = 0;
	unsigned int tmp_name_len;
	umode_t mode;
	char tmp_name[48];
	struct qstr tmp_qstr;
	int attempt;
	long ret;

	if (!subject_token || !resolved_path || !resolved_path->dentry || !how ||
	    !prepared || !file_out || !status_out)
		return -EINVAL;

	dentry = resolved_path->dentry;
	if (!d_inode(dentry))
		return -EACCES;
	if (!S_ISREG(d_inode(dentry)->i_mode))
		return -EOPNOTSUPP;

	parent_path.mnt = mntget(resolved_path->mnt);
	parent_path.dentry = dget_parent(dentry);
	if (!parent_path.mnt || !parent_path.dentry) {
		if (parent_path.mnt)
			mntput(parent_path.mnt);
		return -EACCES;
	}
	pkm_kacs_init_path_anchor_file(&parent_file, &parent_path);

	ret = pkm_kacs_copy_creator_sd_from_user(
		how, &creator_sd_bytes, &creator_sd_len);
	if (ret)
		goto out_parent;

	ret = pkm_kacs_build_created_file_sd_for_subject(
		subject_token, &parent_file, creator_sd_bytes, creator_sd_len,
		false, prepared->desired_access, &created_sd, &created_sd_len,
		&granted_access);
	if (ret)
		goto out_creator;

	ret = pkm_kacs_authorize_path_file_access_core(
		subject_token, resolved_path, KACS_ACCESS_DELETE);
	if (ret == -EACCES) {
		ret = pkm_kacs_authorize_live_file_access_core(
			subject_token, &parent_file,
			KACS_FILE_DELETE_CHILD);
	}
	if (ret)
		goto out_created_sd;

	parent_inode = d_inode(parent_path.dentry);
	if (!parent_inode) {
		ret = -EACCES;
		goto out_created_sd;
	}

	ret = mnt_want_write(parent_path.mnt);
	if (ret)
		goto out_created_sd;

	inode_lock(parent_inode);
	for (attempt = 0; attempt < 4; attempt++) {
		tmp_name_len = scnprintf(
			tmp_name, sizeof(tmp_name), ".kacs-super.%llu",
			(unsigned long long)pkm_kacs_next_native_supersede_tmp_id());
		tmp_qstr = (struct qstr)QSTR_INIT(tmp_name, tmp_name_len);
		tmp_dentry = lookup_one_qstr_excl(
			&tmp_qstr, parent_path.dentry,
			LOOKUP_CREATE | LOOKUP_EXCL);
		if (!IS_ERR(tmp_dentry) || PTR_ERR(tmp_dentry) != -EEXIST)
			break;
	}
	if (IS_ERR(tmp_dentry)) {
		ret = PTR_ERR(tmp_dentry);
		tmp_dentry = NULL;
		goto out_unlock_write;
	}

	mode = pkm_kacs_native_create_mode(false);
	pkm_kacs_set_current_native_create_request(parent_inode, false,
						   created_sd, created_sd_len);
	ret = security_path_mknod(&parent_path, tmp_dentry, mode, 0);
	if (ret)
		goto out_unlock_write;
	ret = vfs_create(mnt_idmap(parent_path.mnt), tmp_dentry, mode, NULL);
	pkm_kacs_clear_current_native_create_request();
	if (ret)
		goto out_unlock_write;
	inode_unlock(parent_inode);

	tmp_path.mnt = mntget(parent_path.mnt);
	tmp_path.dentry = dget(tmp_dentry);
	ret = pkm_kacs_open_native_existing_path(&tmp_path, prepared, &opened_file);
	path_put(&tmp_path);
	if (ret)
		goto out_tmp_cleanup;

	rd.mnt_idmap = mnt_idmap(parent_path.mnt);
	rd.new_parent = parent_path.dentry;
	rd.flags = 0;
	ret = start_renaming_two_dentries(&rd, tmp_dentry, dentry);
	if (ret)
		goto out_tmp_file;
	ret = security_path_rename(&parent_path, rd.old_dentry, &parent_path,
				   rd.new_dentry, 0);
	if (!ret)
		ret = vfs_rename(&rd);
	end_renaming(&rd);
	if (ret)
		goto out_tmp_file;

	*file_out = opened_file;
	*status_out = KACS_STATUS_SUPERSEDED;
	ret = 0;
	goto out_tmp_dentry;

out_tmp_file:
	fput(opened_file);
	opened_file = NULL;
out_tmp_cleanup:
	inode_lock(parent_inode);
	(void)vfs_unlink(mnt_idmap(parent_path.mnt), parent_inode, tmp_dentry,
			 NULL);
	inode_unlock(parent_inode);
	goto out_tmp_dentry;
out_unlock_write:
	pkm_kacs_clear_current_native_create_request();
	inode_unlock(parent_inode);
out_tmp_dentry:
	if (tmp_dentry)
		dput(tmp_dentry);
	mnt_drop_write(parent_path.mnt);
out_created_sd:
	if (created_sd)
		pkm_kacs_free((void *)created_sd);
out_creator:
	kfree(creator_sd_bytes);
out_parent:
	path_put(&parent_path);
	return ret;
}

static long pkm_kacs_do_native_create_open(
	int dirfd, const char __user *path, const struct kacs_open_how *how,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out)
{
	struct path parent_path = {};
	struct path child_path = {};
	struct file parent_file = {};
	struct file *opened_file = NULL;
	struct dentry *dentry;
	struct inode *parent_inode;
	const void *subject_token;
	const u8 *created_sd = NULL;
	u8 *creator_sd_bytes = NULL;
	size_t created_sd_len = 0;
	size_t creator_sd_len = 0;
	u32 granted_access = 0;
	unsigned int lookup_flags = 0;
	umode_t mode;
	bool directory;
	long ret;

	if (!path || !how || !prepared || !file_out || !status_out)
		return -EINVAL;

	*file_out = NULL;
	*status_out = 0;
	directory = prepared->directory_required;
	if (directory &&
	    (prepared->desired_access & PKM_KACS_DIRECTORY_MUTATION_RIGHTS) != 0)
		return -EOPNOTSUPP;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	ret = pkm_kacs_open_path_lookup_flags(how->flags, &lookup_flags);
	if (ret)
		return ret;
	if (directory)
		lookup_flags |= LOOKUP_DIRECTORY;

	ret = pkm_kacs_copy_creator_sd_from_user(
		how, &creator_sd_bytes, &creator_sd_len);
	if (ret)
		return ret;

	dentry = start_creating_user_path(dirfd, path, &parent_path, lookup_flags);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto out_creator_sd;
	}

	parent_inode = d_inode(parent_path.dentry);
	if (!parent_inode) {
		ret = -EACCES;
		goto out_end_create;
	}

	parent_file.f_inode = parent_inode;
	*(struct path *)&parent_file.f_path = parent_path;
	ret = pkm_kacs_build_created_file_sd_for_subject(
		subject_token, &parent_file, creator_sd_bytes, creator_sd_len,
		directory, prepared->desired_access, &created_sd, &created_sd_len,
		&granted_access);
	if (ret)
		goto out_end_create;

	mode = pkm_kacs_native_create_mode(directory);
	pkm_kacs_set_current_native_create_request(parent_inode, directory,
						   created_sd, created_sd_len);
	if (directory)
		ret = security_path_mkdir(&parent_path, dentry, mode);
	else
		ret = security_path_mknod(&parent_path, dentry, mode, 0);
	if (!ret) {
		if (directory) {
			struct dentry *created = vfs_mkdir(mnt_idmap(parent_path.mnt),
							   parent_inode, dentry,
							   mode, NULL);
			if (IS_ERR(created))
				ret = PTR_ERR(created);
			else
				dentry = created;
		} else {
			ret = vfs_create(mnt_idmap(parent_path.mnt), dentry, mode,
					 NULL);
		}
	}
	pkm_kacs_clear_current_native_create_request();
	if (ret)
		goto out_end_create;

	child_path.mnt = mntget(parent_path.mnt);
	child_path.dentry = dget(dentry);
	pkm_kacs_set_current_native_open_request(&child_path,
						 prepared->desired_access,
						 prepared->create_options);
	opened_file = dentry_open(&child_path, prepared->open_flags, current_cred());
	pkm_kacs_clear_current_native_open_request();
	path_put(&child_path);
	if (IS_ERR(opened_file)) {
		ret = PTR_ERR(opened_file);
		opened_file = NULL;
		if (directory)
			vfs_rmdir(mnt_idmap(parent_path.mnt), parent_inode, dentry,
				  NULL);
		else
			vfs_unlink(mnt_idmap(parent_path.mnt), parent_inode, dentry,
				   NULL);
		goto out_end_create;
	}

	*file_out = opened_file;
	*status_out = KACS_STATUS_CREATED;
	ret = 0;

out_end_create:
	pkm_kacs_clear_current_native_create_request();
	end_creating_path(&parent_path, dentry);
	if (created_sd)
		pkm_kacs_free((void *)created_sd);
out_creator_sd:
	kfree(creator_sd_bytes);
	return ret;
}

static long pkm_kacs_resolve_native_open_path(
	int dirfd, const char __user *path,
	const struct pkm_kacs_native_open_prepared *prepared,
	u32 flags, struct path *resolved_path)
{
	unsigned int lookup_flags = 0;
	struct inode *inode;
	long ret;

	if (!path || !prepared || !resolved_path)
		return -EINVAL;

	ret = pkm_kacs_open_path_lookup_flags(flags, &lookup_flags);
	if (ret)
		return ret;

	ret = user_path_at(dirfd, path, lookup_flags, resolved_path);
	if (ret)
		return ret;
	if (!resolved_path->dentry || !d_inode(resolved_path->dentry)) {
		path_put(resolved_path);
		return -EACCES;
	}

	inode = d_inode(resolved_path->dentry);
	if ((flags & AT_SYMLINK_NOFOLLOW) != 0 && S_ISLNK(inode->i_mode)) {
		path_put(resolved_path);
		return -ELOOP;
	}
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    KACS_MOUNT_POLICY_UNMANAGED) {
		path_put(resolved_path);
		return -EOPNOTSUPP;
	}

	if (S_ISDIR(inode->i_mode)) {
		if ((prepared->desired_access &
		     PKM_KACS_DIRECTORY_MUTATION_RIGHTS) != 0) {
			path_put(resolved_path);
			return -EOPNOTSUPP;
		}
	} else if (prepared->directory_required) {
		path_put(resolved_path);
		return -ENOTDIR;
	} else if (!pkm_kacs_existing_file_object_mode_supported(
			   inode->i_mode)) {
		path_put(resolved_path);
		return -EACCES;
	} else if (!S_ISREG(inode->i_mode) &&
		   (prepared->desired_access & KACS_FILE_EXECUTE) != 0) {
		path_put(resolved_path);
		return -EACCES;
	}

	return 0;
}

SYSCALL_DEFINE5(kacs_open, int, dirfd, const char __user *, path,
		struct kacs_open_how __user *, uhow, size_t, howsize,
		u32 __user *, status_out)
{
	struct pkm_kacs_native_open_prepared prepared = {};
	struct path resolved_path = {};
	struct file *file;
	const void *subject_token;
	struct kacs_open_how how;
	u32 status = KACS_STATUS_OPENED;
	int fd;
	long ret;

	if (!current->security)
		return -EACCES;
	if (!path || !uhow)
		return -EINVAL;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	ret = pkm_kacs_copy_open_how_from_user(&how, uhow, howsize);
	if (ret)
		return ret;

	ret = pkm_kacs_prepare_native_open(&how, &prepared);
	if (ret)
		return ret;
	status = prepared.status;

	if (prepared.create_disposition == KACS_DISPOSITION_CREATE)
		goto do_create;

	ret = pkm_kacs_resolve_native_open_path(dirfd, path, &prepared,
						 how.flags, &resolved_path);
	if (!ret) {
		if ((prepared.create_disposition == KACS_DISPOSITION_OPEN_IF ||
		     prepared.create_disposition == KACS_DISPOSITION_OVERWRITE_IF) &&
		    (how.sd_ptr != 0 || how.sd_len != 0)) {
			path_put(&resolved_path);
			return -EINVAL;
		}
		switch (prepared.create_disposition) {
		case KACS_DISPOSITION_OVERWRITE:
		case KACS_DISPOSITION_OVERWRITE_IF:
			ret = pkm_kacs_do_native_overwrite_open(
				&resolved_path, &prepared, &file, &status);
			break;
		case KACS_DISPOSITION_SUPERSEDE:
			ret = pkm_kacs_do_native_supersede_open(
				subject_token, &resolved_path, &how, &prepared,
				&file, &status);
			break;
		default:
			ret = pkm_kacs_open_native_existing_path(
				&resolved_path, &prepared, &file);
			break;
		}
		path_put(&resolved_path);
		if (ret)
			return ret;
		goto install_fd;
	}
	if (ret != -ENOENT ||
	    (prepared.create_disposition != KACS_DISPOSITION_OPEN_IF &&
	     prepared.create_disposition != KACS_DISPOSITION_OVERWRITE_IF &&
	     prepared.create_disposition != KACS_DISPOSITION_SUPERSEDE))
		return ret;

do_create:
	ret = pkm_kacs_do_native_create_open(dirfd, path, &how, &prepared, &file,
					     &status);
	if (ret)
		return ret;

install_fd:
	fd = get_unused_fd_flags(0);
	if (fd < 0) {
		fput(file);
		return fd;
	}

	if (status_out &&
	    put_user(status, status_out)) {
		put_unused_fd(fd);
		fput(file);
		return -EFAULT;
	}

	fd_install(fd, file);
	return fd;
}
