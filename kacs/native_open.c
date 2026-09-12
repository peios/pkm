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
#include <linux/kacs_stratafs.h>
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
#include "file_metadata.h"
#include "file_sd_cache.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "native_open.h"
#include "token_runtime.h"
#include <trace/events/kacs.h>

static atomic64_t pkm_kacs_native_supersede_tmp_counter = ATOMIC64_INIT(0);

static int pkm_kacs_native_creation_parent(const struct path *parent,
					    struct path *security_parent)
{
	if (!parent || !parent->dentry || !security_parent)
		return -EINVAL;
#if IS_ENABLED(CONFIG_STRATAFS_FS)
	if (parent->dentry->d_sb->s_magic == STRATAFS_SUPER_MAGIC)
		return stratafs_kacs_creation_parent(parent, security_parent);
#endif
	*security_parent = *parent;
	path_get(security_parent);
	return 0;
}

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
	u8 nox_reason = KACS_NOX_PREPARE_OK;
	long ret;

	if (!how || !prepared)
		return -EINVAL;
	if ((how->flags & ~PKM_KACS_OPEN_ALLOWED_AT_FLAGS) != 0) {
		ret = -EINVAL;
		nox_reason = KACS_NOX_PREPARE_BAD_FLAGS;
		goto reject;
	}
	if ((how->create_options &
	     ~(KACS_CREATE_OPT_DIRECTORY |
	       KACS_CREATE_OPT_DELETE_ON_CLOSE)) != 0) {
		ret = -EINVAL;
		nox_reason = KACS_NOX_PREPARE_BAD_FLAGS;
		goto reject;
	}
	if (how->__pad != 0) {
		ret = -EINVAL;
		nox_reason = KACS_NOX_PREPARE_BAD_FLAGS;
		goto reject;
	}
	if ((how->sd_ptr == 0) != (how->sd_len == 0)) {
		ret = -EINVAL;
		nox_reason = KACS_NOX_PREPARE_BAD_SD_ARGS;
		goto reject;
	}
	if (how->sd_len > PKM_KACS_MAX_SD_BYTES) {
		ret = -EINVAL;
		nox_reason = KACS_NOX_PREPARE_BAD_SD_ARGS;
		goto reject;
	}
	if (how->create_disposition > KACS_DISPOSITION_OVERWRITE_IF) {
		ret = -EINVAL;
		nox_reason = KACS_NOX_PREPARE_BAD_DISPOSITION;
		goto reject;
	}
	if (how->create_disposition == KACS_DISPOSITION_OPEN &&
	    (how->sd_ptr != 0 || how->sd_len != 0)) {
		ret = -EOPNOTSUPP;
		nox_reason = KACS_NOX_PREPARE_BAD_SD_ARGS;
		goto reject;
	}
	if (how->create_disposition == KACS_DISPOSITION_OVERWRITE &&
	    (how->sd_ptr != 0 || how->sd_len != 0)) {
		ret = -EINVAL;
		nox_reason = KACS_NOX_PREPARE_BAD_SD_ARGS;
		goto reject;
	}

	ret = pkm_kacs_map_file_generic_access_mask(how->desired_access,
						    &desired_access);
	if (ret) {
		nox_reason = KACS_NOX_PREPARE_BAD_ACCESS;
		goto reject;
	}
	if ((desired_access & KACS_FILE_DELETE_CHILD) != 0) {
		ret = -EOPNOTSUPP;
		nox_reason = KACS_NOX_PREPARE_UNSUPPORTED;
		goto reject;
	}

	data_mask = KACS_FILE_READ_DATA |
		    KACS_FILE_WRITE_DATA |
		    KACS_FILE_APPEND_DATA;
	has_read = (desired_access & KACS_FILE_READ_DATA) != 0;
	has_write = (desired_access &
		     (KACS_FILE_WRITE_DATA |
		      KACS_FILE_APPEND_DATA)) != 0;
	has_execute = (desired_access & KACS_FILE_EXECUTE) != 0;
	if ((desired_access & data_mask) == 0 && !has_execute) {
		ret = -EINVAL;
		nox_reason = KACS_NOX_PREPARE_BAD_ACCESS;
		goto reject;
	}
	if (how->create_disposition == KACS_DISPOSITION_OVERWRITE &&
	    (desired_access & KACS_FILE_WRITE_DATA) == 0) {
		ret = -EINVAL;
		nox_reason = KACS_NOX_PREPARE_BAD_ACCESS;
		goto reject;
	}
	if ((how->create_disposition == KACS_DISPOSITION_SUPERSEDE ||
	     how->create_disposition == KACS_DISPOSITION_OVERWRITE ||
	     how->create_disposition == KACS_DISPOSITION_OVERWRITE_IF) &&
	    (how->create_options & KACS_CREATE_OPT_DIRECTORY) != 0) {
		ret = -EOPNOTSUPP;
		nox_reason = KACS_NOX_PREPARE_UNSUPPORTED;
		goto reject;
	}
	if ((how->create_options &
	     (KACS_CREATE_OPT_DIRECTORY |
	      KACS_CREATE_OPT_DELETE_ON_CLOSE)) ==
	    (KACS_CREATE_OPT_DIRECTORY |
	     KACS_CREATE_OPT_DELETE_ON_CLOSE)) {
		ret = -EOPNOTSUPP;
		nox_reason = KACS_NOX_PREPARE_UNSUPPORTED;
		goto reject;
	}

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
	trace_kacs_native_open_ext(how->create_disposition, desired_access,
				   KACS_NOX_PREPARE_OK, 0);
	return 0;

reject:
	trace_kacs_native_open_ext(how->create_disposition, how->desired_access,
				   nox_reason, ret);
	return ret;
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
	struct pkm_kacs_task_security *task_sec;
	struct inode *inode;
	struct inode *parent_inode;
	struct path parent_path = {};
	struct dentry *dentry;
	long ret;

	if (!file)
		return -EACCES;
	if (!current || !current->security)
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->delete_on_close_file)
		return -EBUSY;

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
	/*
	 * The pathname may already be gone.  An unlink by someone else while
	 * the lineage lived leaves this dentry unhashed (and negative once
	 * the last reference goes), and a name re-created since names another
	 * inode.  Either way the deletion this handle promised has happened
	 * or been overtaken, so the final close is a no-op rather than a
	 * second unlink of the same entry -- which on tmpfs drops the pin
	 * shmem_link took a second time and frees the dentry under us
	 * (PEI-694).
	 *
	 * StrataFS is the exception to the unhashed test: it drops a merged
	 * entry on copy-up by design (section 4.4), so its dentries are
	 * routinely unhashed while very much alive, and its own unlink
	 * looks the provider entry up afresh and tolerates ENOENT for a
	 * deferred deletion.
	 */
	if (!d_is_positive(dentry) || d_inode(dentry) != inode ||
	    (d_unhashed(dentry) &&
	     inode->i_sb->s_magic != STRATAFS_SUPER_MAGIC)) {
		ret = 0;
		goto out_unlock;
	}
	task_sec->delete_on_close_file = file;
	ret = vfs_unlink(mnt_idmap(parent_path.mnt), parent_inode, dentry, NULL);
	task_sec->delete_on_close_inode = NULL;
	task_sec->delete_on_close_dentry = NULL;
	task_sec->delete_on_close_parent_inode = NULL;
	task_sec->delete_on_close_file = NULL;
out_unlock:
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
	if (ret) {
		trace_kacs_native_open_ext(0, KACS_ACCESS_DELETE,
					   KACS_NOX_DELETE_ON_CLOSE_ARM, ret);
		return ret;
	}

	inode_sec = pkm_kacs_inode(inode);
	mutex_lock(&inode_sec->lock);
	if (atomic_read(&inode_sec->delete_on_close_lineages) != 0) {
		ret = -EACCES;
	} else {
		atomic_inc(&inode_sec->delete_on_close_lineages);
		file_sec->delete_on_close = 1;
		file_sec->delete_on_close_token =
			kacs_rust_token_clone(subject_token);
		ret = 0;
	}
	mutex_unlock(&inode_sec->lock);
	trace_kacs_native_open_ext(0, KACS_ACCESS_DELETE,
				   KACS_NOX_DELETE_ON_CLOSE_ARM, ret);
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

int pkm_kacs_stratafs_rebind_native_create_request(
	const struct inode *outer_parent, const struct inode *provider_parent)
{
	struct pkm_kacs_task_security *sec;

	if (!outer_parent || !provider_parent || !current || !current->security)
		return -EACCES;
	sec = pkm_kacs_task(current);
	if (!sec->native_create.active)
		return 0;
	if (sec->native_create.expected_parent_inode != outer_parent)
		return -EACCES;
	sec->native_create.expected_parent_inode = provider_parent;
	return 0;
}

void pkm_kacs_stratafs_end_native_create_request(
	const struct inode *outer_parent, const struct inode *provider_parent)
{
	struct pkm_kacs_task_security *sec;

	if (!outer_parent || !provider_parent || !current || !current->security)
		return;
	sec = pkm_kacs_task(current);
	if (sec->native_create.active &&
	    sec->native_create.expected_parent_inode == provider_parent)
		sec->native_create.expected_parent_inode = outer_parent;
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
	if (!parent_inode || !parent_inode->i_security) {
		trace_kacs_native_open_ext(0, desired_access,
					   KACS_NOX_BUILD_CREATED_SD, -EACCES);
		return -EACCES;
	}
	if (!pkm_kacs_mount_policy_is_managed(
		    pkm_kacs_superblock_mount_policy(parent_inode->i_sb))) {
		trace_kacs_native_open_ext(0, desired_access,
					   KACS_NOX_BUILD_CREATED_SD,
					   -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}
	if (pkm_kacs_inode_is_ntfs(parent_inode)) {
		trace_kacs_native_open_ext(0, desired_access,
					   KACS_NOX_BUILD_CREATED_SD,
					   -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}

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
	if (ret) {
		trace_kacs_native_open_ext(0, desired_access,
					   KACS_NOX_BUILD_CREATED_SD, ret);
		return ret;
	}

	if (desired_access != 0) {
		ret = kacs_rust_check_file_sd_with_intent(
			subject_token, *out_sd_ptr, *out_sd_len,
			desired_access, 0, pip_type, pip_trust,
			&granted_access);
		if (ret) {
			pkm_kacs_free((void *)*out_sd_ptr);
			*out_sd_ptr = NULL;
			*out_sd_len = 0;
			trace_kacs_native_open_ext(0, desired_access,
						   KACS_NOX_BUILD_CREATED_SD,
						   ret);
			return ret;
		}
	}

	if (granted_access_out)
		*granted_access_out = granted_access;
	trace_kacs_native_open_ext(0, desired_access,
				   KACS_NOX_BUILD_CREATED_SD, 0);
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
	pkm_kacs_file_end_metadata(file);
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
	struct path security_parent = {};
	struct path removal_parent = {};
	struct path removal_target = {};
	struct file parent_file = {};
	struct file creation_parent_file = {};
	struct file removal_parent_file = {};
	struct file removal_target_file = {};
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
	bool stratafs_supersede = false;
	bool supersede_context = false;
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
	stratafs_supersede =
		parent_path.dentry->d_sb->s_magic == STRATAFS_SUPER_MAGIC;
	if (stratafs_supersede) {
#if IS_ENABLED(CONFIG_STRATAFS_FS)
		ret = stratafs_kacs_validate_supersede(resolved_path);
		if (ret)
			goto out_parent;
		ret = stratafs_kacs_removal_parent(resolved_path,
						     &removal_parent);
		if (ret)
			goto out_parent;
		ret = stratafs_kacs_removal_target(resolved_path,
						     &removal_target);
		if (ret)
			goto out_parent;
		pkm_kacs_init_path_anchor_file(&removal_parent_file,
						&removal_parent);
		pkm_kacs_init_path_anchor_file(&removal_target_file,
						&removal_target);
#else
		ret = -EOPNOTSUPP;
		goto out_parent;
#endif
	} else {
		pkm_kacs_init_path_anchor_file(&parent_file, &parent_path);
	}
	ret = pkm_kacs_native_creation_parent(&parent_path, &security_parent);
	if (ret)
		goto out_parent;
	pkm_kacs_init_path_anchor_file(&creation_parent_file, &security_parent);

	ret = pkm_kacs_copy_creator_sd_from_user(
		how, &creator_sd_bytes, &creator_sd_len);
	if (ret)
		goto out_security_parent;

	ret = pkm_kacs_build_created_file_sd_for_subject(
		subject_token, &creation_parent_file, creator_sd_bytes, creator_sd_len,
		false, prepared->desired_access, &created_sd, &created_sd_len,
		&granted_access);
	if (ret)
		goto out_creator;
	if (stratafs_supersede) {
		ret = pkm_kacs_stratafs_set_native_create_decision(
			&security_parent, KACS_FILE_ADD_FILE);
		if (ret)
			goto out_created_sd;
	}

	ret = pkm_kacs_authorize_path_file_access_core(
		subject_token,
		stratafs_supersede ? &removal_target : resolved_path,
		KACS_ACCESS_DELETE);
	if (ret == -EACCES) {
		ret = pkm_kacs_authorize_live_file_access_core(
			subject_token,
			stratafs_supersede ? &removal_parent_file : &parent_file,
			KACS_FILE_DELETE_CHILD);
	}
	if (ret)
		goto out_created_sd;

	parent_inode = d_inode(parent_path.dentry);
	if (!parent_inode) {
		ret = -EACCES;
		goto out_created_sd;
	}
	if (stratafs_supersede) {
		ret = pkm_kacs_stratafs_begin_supersede(dentry);
		if (ret)
			goto out_created_sd;
		supersede_context = true;
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
	if (stratafs_supersede) {
		ret = pkm_kacs_stratafs_bind_supersede_source(dentry,
							       tmp_dentry);
		if (ret) {
			inode_unlock(parent_inode);
			goto out_tmp_cleanup;
		}
	}
	inode_unlock(parent_inode);

	tmp_path.mnt = mntget(parent_path.mnt);
	tmp_path.dentry = dget(tmp_dentry);
	ret = pkm_kacs_open_native_existing_path(&tmp_path, prepared, &opened_file);
	path_put(&tmp_path);
	if (ret)
		goto out_tmp_cleanup;
	if (stratafs_supersede) {
		ret = pkm_kacs_stratafs_bind_supersede_file(
			tmp_dentry, dentry, opened_file);
		if (ret)
			goto out_tmp_file;
	}

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
	if (stratafs_supersede)
		(void)pkm_kacs_stratafs_arm_created_cleanup(tmp_dentry);
	(void)vfs_unlink(mnt_idmap(parent_path.mnt), parent_inode, tmp_dentry,
			 NULL);
	if (stratafs_supersede)
		pkm_kacs_stratafs_end_created_cleanup();
	inode_unlock(parent_inode);
	goto out_tmp_dentry;
out_unlock_write:
	pkm_kacs_clear_current_native_create_request();
	inode_unlock(parent_inode);
out_tmp_dentry:
	if (supersede_context) {
		pkm_kacs_stratafs_end_supersede();
		supersede_context = false;
	}
	if (tmp_dentry)
		dput(tmp_dentry);
	mnt_drop_write(parent_path.mnt);
out_created_sd:
	pkm_kacs_stratafs_end_create_decision();
	if (supersede_context)
		pkm_kacs_stratafs_end_supersede();
	if (created_sd)
		pkm_kacs_free((void *)created_sd);
out_creator:
	kfree(creator_sd_bytes);
out_security_parent:
	path_put(&security_parent);
out_parent:
	if (removal_target.dentry)
		path_put(&removal_target);
	if (removal_parent.dentry)
		path_put(&removal_parent);
	path_put(&parent_path);
	return ret;
}

static long pkm_kacs_do_native_create_open(
	int dirfd, const char __user *path, const struct kacs_open_how *how,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out)
{
	struct path parent_path = {};
	struct path security_parent = {};
	struct path child_path = {};
	struct file parent_file = {};
	struct file *opened_file = NULL;
	struct dentry *dentry;
	struct dentry *open_dentry;
	struct dentry *looked_up = NULL;
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
	bool stratafs_creation;
	long ret;

	if (!path || !how || !prepared || !file_out || !status_out)
		return -EINVAL;

	*file_out = NULL;
	*status_out = 0;
	directory = prepared->directory_required;
	stratafs_creation = false;
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

	ret = pkm_kacs_native_creation_parent(&parent_path, &security_parent);
	if (ret)
		goto out_end_create;
	stratafs_creation =
		parent_path.dentry->d_sb->s_magic == STRATAFS_SUPER_MAGIC;
	pkm_kacs_init_path_anchor_file(&parent_file, &security_parent);
	ret = pkm_kacs_build_created_file_sd_for_subject(
		subject_token, &parent_file, creator_sd_bytes, creator_sd_len,
		directory, prepared->desired_access, &created_sd, &created_sd_len,
		&granted_access);
	if (ret)
		goto out_end_create;
	if (stratafs_creation) {
		ret = pkm_kacs_stratafs_set_native_create_decision(
			&security_parent,
			directory ? KACS_FILE_ADD_SUBDIRECTORY :
				    KACS_FILE_ADD_FILE);
		if (ret)
			goto out_end_create;
	}

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

	/*
	 * Filesystems that instantiate inodes lazily on lookup (kernfs /
	 * cgroupfs and friends) leave `dentry` NEGATIVE after a successful
	 * vfs_mkdir: their ->mkdir returns NULL without splicing an inode onto
	 * the dentry, which is only filled in on the next lookup. A plain
	 * mkdir(2) never notices, but we open the result immediately, and
	 * dentry_open() on a negative dentry dereferences a NULL inode and
	 * oopses. Re-look-up the name under the parent lock we still hold
	 * (lookup_one() requires it) to obtain a positive dentry; ordinary
	 * filesystems already returned a positive dentry from vfs_mkdir and skip
	 * this. The original (possibly negative) create dentry is still cleaned
	 * up by end_creating_path() below.
	 */
	open_dentry = dentry;
	if (d_really_is_negative(dentry)) {
		struct qstr name =
			QSTR_INIT(dentry->d_name.name, dentry->d_name.len);

		trace_kacs_native_open(parent_inode, prepared->desired_access,
				       0, KACS_TR_LAZY_DENTRY_RELOOKUP);
		looked_up = lookup_one(mnt_idmap(parent_path.mnt), &name,
				       parent_path.dentry);
		if (IS_ERR(looked_up)) {
			ret = PTR_ERR(looked_up);
			looked_up = NULL;
			goto out_end_create;
		}
		if (d_really_is_negative(looked_up)) {
			/*
			 * Defensive: a positive dentry must exist immediately
			 * after a successful create. If it does not, refuse to
			 * open rather than oops.
			 */
			trace_kacs_native_open(parent_inode,
					       prepared->desired_access, -ENOENT,
					       KACS_TR_NEGATIVE_AFTER_CREATE);
			ret = -ENOENT;
			goto out_end_create;
		}
		open_dentry = looked_up;
	}

	child_path.mnt = mntget(parent_path.mnt);
	child_path.dentry = dget(open_dentry);
	pkm_kacs_set_current_native_open_request(&child_path,
						 prepared->desired_access,
						 prepared->create_options);
	opened_file = dentry_open(&child_path, prepared->open_flags, current_cred());
	pkm_kacs_clear_current_native_open_request();
	path_put(&child_path);
	if (IS_ERR(opened_file)) {
		ret = PTR_ERR(opened_file);
		opened_file = NULL;
		if (stratafs_creation)
			(void)pkm_kacs_stratafs_arm_created_cleanup(open_dentry);
		if (directory)
			vfs_rmdir(mnt_idmap(parent_path.mnt), parent_inode,
				  open_dentry, NULL);
		else
			vfs_unlink(mnt_idmap(parent_path.mnt), parent_inode,
				   open_dentry, NULL);
		if (stratafs_creation)
			pkm_kacs_stratafs_end_created_cleanup();
		goto out_end_create;
	}

	*file_out = opened_file;
	*status_out = KACS_STATUS_CREATED;
	ret = 0;

out_end_create:
	pkm_kacs_stratafs_end_create_decision();
	pkm_kacs_clear_current_native_create_request();
	end_creating_path(&parent_path, dentry);
	if (looked_up)
		dput(looked_up);
	if (created_sd)
		pkm_kacs_free((void *)created_sd);
	if (security_parent.dentry)
		path_put(&security_parent);
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
	/*
	 * Unmanaged filesystems (proc, sysfs, nullfs) carry no SD, so the
	 * native-open access protocol does not apply. A plain OPEN / OPEN_IF of
	 * an existing file there must still SUCCEED, exactly as the legacy open
	 * path does — otherwise no libpeios consumer could open a /proc or /sys
	 * file (e.g. peinit reading /proc/self/mountinfo at Phase-1 boot). The
	 * downstream file_open hook grants an unmanaged fd and gates only sysfs
	 * writes. The creating dispositions (CREATE / OVERWRITE / SUPERSEDE) DO
	 * stay rejected: materialising or replacing a file by SD makes no sense
	 * on a synthetic fs that cannot store one.
	 */
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
		    KACS_MOUNT_POLICY_UNMANAGED &&
	    prepared->create_disposition != KACS_DISPOSITION_OPEN &&
	    prepared->create_disposition != KACS_DISPOSITION_OPEN_IF) {
		path_put(resolved_path);
		trace_kacs_native_open_ext(prepared->create_disposition,
					   prepared->desired_access,
					   KACS_NOX_RESOLVE, -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}

	if (S_ISDIR(inode->i_mode)) {
		if ((prepared->desired_access &
		     PKM_KACS_DIRECTORY_MUTATION_RIGHTS) != 0) {
			path_put(resolved_path);
			trace_kacs_native_open_ext(prepared->create_disposition,
						   prepared->desired_access,
						   KACS_NOX_RESOLVE, -EOPNOTSUPP);
			return -EOPNOTSUPP;
		}
	} else if (prepared->directory_required) {
		path_put(resolved_path);
		trace_kacs_native_open_ext(prepared->create_disposition,
					   prepared->desired_access,
					   KACS_NOX_RESOLVE, -ENOTDIR);
		return -ENOTDIR;
	} else if (!pkm_kacs_existing_file_object_mode_supported(
			   inode->i_mode)) {
		path_put(resolved_path);
		trace_kacs_native_open_ext(prepared->create_disposition,
					   prepared->desired_access,
					   KACS_NOX_RESOLVE, -EACCES);
		return -EACCES;
	} else if (!S_ISREG(inode->i_mode) &&
		   (prepared->desired_access & KACS_FILE_EXECUTE) != 0) {
		path_put(resolved_path);
		trace_kacs_native_open_ext(prepared->create_disposition,
					   prepared->desired_access,
					   KACS_NOX_RESOLVE, -EACCES);
		return -EACCES;
	}

	trace_kacs_native_open_ext(prepared->create_disposition,
				   prepared->desired_access, KACS_NOX_RESOLVE, 0);
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
