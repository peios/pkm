// SPDX-License-Identifier: GPL-2.0-only

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/falloc.h>
#include <linux/fcntl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/kacs_stratafs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/path.h>
#include <linux/pidfd.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/xattr.h>

#include <asm/ioctls.h>

#include <pkm/file.h>
#include <pkm/sd.h>

#include "../kmes/kmes.h"
#include "access_check.h"
#include "caap_cache.h"
#include "copy_up.h"
#include "file_access.h"
#include "file_metadata.h"
#include <trace/events/kacs.h>
#include "file_sd_cache.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "native_open.h"
#include "object_lifecycle.h"
#include "token_runtime.h"

#define PKM_KACS_FILE_DATA_RIGHTS                                             \
	(KACS_FILE_READ_DATA | KACS_FILE_WRITE_DATA | KACS_FILE_APPEND_DATA)

static size_t pkm_kacs_msgpack_string_size(size_t len)
{
	if (len <= 31)
		return 1 + len;
	if (len <= U8_MAX)
		return 2 + len;
	return 3 + len;
}

static u8 *pkm_kacs_msgpack_string_header(u8 *out, size_t len)
{
	if (len <= 31) {
		*out++ = 0xa0 | len;
	} else if (len <= U8_MAX) {
		*out++ = 0xd9;
		*out++ = len;
	} else {
		*out++ = 0xda;
		*out++ = len >> 8;
		*out++ = len;
	}
	return out;
}

static u8 *pkm_kacs_msgpack_string(u8 *out, const char *value, size_t len)
{
	out = pkm_kacs_msgpack_string_header(out, len);
	memcpy(out, value, len);
	return out + len;
}

static u8 *pkm_kacs_msgpack_u32(u8 *out, u32 value)
{
	*out++ = 0xce;
	*out++ = value >> 24;
	*out++ = value >> 16;
	*out++ = value >> 8;
	*out++ = value;
	return out;
}

static u8 *pkm_kacs_msgpack_s32(u8 *out, s32 value)
{
	*out++ = 0xd2;
	*out++ = (u32)value >> 24;
	*out++ = (u32)value >> 16;
	*out++ = (u32)value >> 8;
	*out++ = (u32)value;
	return out;
}

void pkm_kacs_stratafs_audit_copy_up(const char *relative_path,
				     u32 provider_index,
				     const char *provider_stratum,
				     u32 create_index,
				     const char *create_stratum,
				     int result)
{
	static const char event_type[] = "STRATAFS_COPY_UP";
	static const char path_key[] = "path";
	static const char provider_index_key[] = "provider_index";
	static const char provider_key[] = "provider_stratum";
	static const char create_index_key[] = "create_index";
	static const char create_key[] = "create_stratum";
	static const char result_key[] = "result_errno";
	const char *relative = relative_path ? relative_path : "";
	size_t relative_len = strnlen(relative, PATH_MAX);
	bool add_slash;
	size_t path_len;
	size_t provider_len;
	size_t create_len;
	size_t size;
	u8 *payload;
	u8 *out;

	if (!provider_stratum || !create_stratum || relative_len == PATH_MAX)
		return;
	add_slash = !relative_len || relative[0] != '/';
	path_len = relative_len + add_slash;
	provider_len = strnlen(provider_stratum, PATH_MAX);
	create_len = strnlen(create_stratum, PATH_MAX);
	if (provider_len == PATH_MAX || create_len == PATH_MAX)
		return;

	size = 1 +
		pkm_kacs_msgpack_string_size(sizeof(path_key) - 1) +
		pkm_kacs_msgpack_string_size(path_len) +
		pkm_kacs_msgpack_string_size(sizeof(provider_index_key) - 1) + 5 +
		pkm_kacs_msgpack_string_size(sizeof(provider_key) - 1) +
		pkm_kacs_msgpack_string_size(provider_len) +
		pkm_kacs_msgpack_string_size(sizeof(create_index_key) - 1) + 5 +
		pkm_kacs_msgpack_string_size(sizeof(create_key) - 1) +
		pkm_kacs_msgpack_string_size(create_len) +
		pkm_kacs_msgpack_string_size(sizeof(result_key) - 1) + 5;
	payload = kmalloc(size, GFP_KERNEL);
	if (!payload)
		return;

	out = payload;
	*out++ = 0x86; /* map(6) */
	out = pkm_kacs_msgpack_string(out, path_key, sizeof(path_key) - 1);
	out = pkm_kacs_msgpack_string_header(out, path_len);
	if (add_slash)
		*out++ = '/';
	memcpy(out, relative, relative_len);
	out += relative_len;
	out = pkm_kacs_msgpack_string(out, provider_index_key,
				      sizeof(provider_index_key) - 1);
	out = pkm_kacs_msgpack_u32(out, provider_index);
	out = pkm_kacs_msgpack_string(out, provider_key,
				      sizeof(provider_key) - 1);
	out = pkm_kacs_msgpack_string(out, provider_stratum, provider_len);
	out = pkm_kacs_msgpack_string(out, create_index_key,
				      sizeof(create_index_key) - 1);
	out = pkm_kacs_msgpack_u32(out, create_index);
	out = pkm_kacs_msgpack_string(out, create_key, sizeof(create_key) - 1);
	out = pkm_kacs_msgpack_string(out, create_stratum, create_len);
	out = pkm_kacs_msgpack_string(out, result_key, sizeof(result_key) - 1);
	out = pkm_kacs_msgpack_s32(out, result);

	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, event_type,
			     sizeof(event_type) - 1, payload, out - payload);
	kfree(payload);
}

void pkm_kacs_stratafs_audit_mutation_refused(
	const char *relative_path, const char *operation, s32 provider_index,
	const char *provider_stratum, int result, bool deferred)
{
	static const char event_type[] = "STRATAFS_MUTATION_REFUSED";
	static const char path_key[] = "path";
	static const char operation_key[] = "operation";
	static const char provider_index_key[] = "provider_index";
	static const char provider_key[] = "provider_stratum";
	static const char result_key[] = "result_errno";
	static const char deferred_key[] = "deferred";
	const char *relative = relative_path ? relative_path : "";
	const char *provider = provider_stratum ? provider_stratum : "";
	size_t relative_len = strnlen(relative, PATH_MAX);
	size_t operation_len;
	size_t provider_len;
	bool add_slash;
	size_t path_len;
	size_t size;
	u8 *payload;
	u8 *out;

	if (!operation || result >= 0 || relative_len == PATH_MAX)
		return;
	operation_len = strnlen(operation, 64);
	provider_len = strnlen(provider, PATH_MAX);
	if (!operation_len || operation_len == 64 || provider_len == PATH_MAX)
		return;
	add_slash = !relative_len || relative[0] != '/';
	path_len = relative_len + add_slash;
	size = 1 +
		pkm_kacs_msgpack_string_size(sizeof(path_key) - 1) +
		pkm_kacs_msgpack_string_size(path_len) +
		pkm_kacs_msgpack_string_size(sizeof(operation_key) - 1) +
		pkm_kacs_msgpack_string_size(operation_len) +
		pkm_kacs_msgpack_string_size(sizeof(provider_index_key) - 1) + 5 +
		pkm_kacs_msgpack_string_size(sizeof(provider_key) - 1) +
		pkm_kacs_msgpack_string_size(provider_len) +
		pkm_kacs_msgpack_string_size(sizeof(result_key) - 1) + 5 +
		pkm_kacs_msgpack_string_size(sizeof(deferred_key) - 1) + 1;
	payload = kmalloc(size, GFP_KERNEL);
	if (!payload)
		return;

	out = payload;
	*out++ = 0x86; /* map(6) */
	out = pkm_kacs_msgpack_string(out, path_key, sizeof(path_key) - 1);
	out = pkm_kacs_msgpack_string_header(out, path_len);
	if (add_slash)
		*out++ = '/';
	memcpy(out, relative, relative_len);
	out += relative_len;
	out = pkm_kacs_msgpack_string(out, operation_key,
				      sizeof(operation_key) - 1);
	out = pkm_kacs_msgpack_string(out, operation, operation_len);
	out = pkm_kacs_msgpack_string(out, provider_index_key,
				      sizeof(provider_index_key) - 1);
	out = pkm_kacs_msgpack_s32(out, provider_index);
	out = pkm_kacs_msgpack_string(out, provider_key,
				      sizeof(provider_key) - 1);
	out = pkm_kacs_msgpack_string(out, provider, provider_len);
	out = pkm_kacs_msgpack_string(out, result_key, sizeof(result_key) - 1);
	out = pkm_kacs_msgpack_s32(out, result);
	out = pkm_kacs_msgpack_string(out, deferred_key,
				      sizeof(deferred_key) - 1);
	*out++ = deferred ? 0xc3 : 0xc2;

	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, event_type,
			     sizeof(event_type) - 1, payload, out - payload);
	kfree(payload);
}

ssize_t pkm_kacs_stratafs_probe_staging_marker(const struct path *path,
					       void *buffer, size_t size)
{
	struct inode *inode;

	if (!path || !path->dentry || !buffer || !size)
		return -EINVAL;
	inode = d_inode(path->dentry);
	if (!inode)
		return -ESTALE;
	return __vfs_getxattr(path->dentry, inode, STRATAFS_STAGING_XATTR,
			      buffer, size);
}

bool pkm_kacs_stratafs_delete_on_close_active(const struct dentry *outer)
{
	struct pkm_kacs_task_security *task_sec;
	const struct file *file;

	if (!outer || !current || !current->security)
		return false;
	task_sec = pkm_kacs_task(current);
	file = task_sec->delete_on_close_file;
	return file && file_dentry((struct file *)file) == outer &&
	       file_inode((struct file *)file) == d_inode(outer);
}

int pkm_kacs_stratafs_delete_on_close_bind_provider(
	const struct dentry *outer, const struct path *parent,
	struct dentry *target)
{
	struct pkm_kacs_task_security *task_sec;
	struct inode *parent_inode;
	struct inode *target_inode;

	if (!pkm_kacs_stratafs_delete_on_close_active(outer) || !parent ||
	    !parent->mnt || !parent->dentry || !target ||
	    target->d_parent != parent->dentry)
		return -EPERM;
	parent_inode = d_inode(parent->dentry);
	target_inode = d_inode(target);
	if (!parent_inode || !target_inode || !S_ISDIR(parent_inode->i_mode) ||
	    !d_is_positive(target))
		return -ESTALE;
	task_sec = pkm_kacs_task(current);
	if (task_sec->delete_on_close_parent_inode ||
	    task_sec->delete_on_close_dentry || task_sec->delete_on_close_inode)
		return -EBUSY;
	task_sec->delete_on_close_parent_inode = parent_inode;
	task_sec->delete_on_close_dentry = target;
	task_sec->delete_on_close_inode = target_inode;
	return 0;
}

void pkm_kacs_stratafs_delete_on_close_unbind_provider(void)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return;
	task_sec = pkm_kacs_task(current);
	task_sec->delete_on_close_inode = NULL;
	task_sec->delete_on_close_dentry = NULL;
	task_sec->delete_on_close_parent_inode = NULL;
}

int pkm_kacs_stratafs_authorize_path(const struct path *path,
				     u32 desired_access)
{
	const void *subject_token;
	const void *caap_cache = NULL;
	const char *name;
	struct inode *inode;
	u8 *bytes = NULL;
	ssize_t len;
	u32 granted = 0;
	u32 continuous_audit = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	int ret;

	if (!path || !path->dentry || !desired_access)
		return -EINVAL;
	inode = d_inode(path->dentry);
	if (!inode)
		return -EACCES;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;
	name = pkm_kacs_inode_sd_xattr_name(inode);

	/*
	 * Read the provider's descriptor directly.  In particular, do not ask
	 * its superblock to synthesize a missing value: StrataFS is permanently
	 * DENY_MISSING even when the provider mount is not.
	 */
	if (current && current->security)
		pkm_kacs_task(current)->internal_sd_read_depth++;
	len = __vfs_getxattr(path->dentry, inode, name, NULL, 0);
	if (current && current->security)
		pkm_kacs_task(current)->internal_sd_read_depth--;
	if (len == -ENODATA || len == -EOPNOTSUPP)
		return -EACCES;
	if (len <= 0 || len > PKM_KACS_MAX_SD_BYTES)
		return len < 0 ? (int)len : -EACCES;
	bytes = kvmalloc(len, GFP_KERNEL);
	if (!bytes)
		return -ENOMEM;
	if (current && current->security)
		pkm_kacs_task(current)->internal_sd_read_depth++;
	ret = __vfs_getxattr(path->dentry, inode, name, bytes, len);
	if (current && current->security)
		pkm_kacs_task(current)->internal_sd_read_depth--;
	if (ret != len || kacs_rust_validate_stored_sd_bytes(bytes, len)) {
		ret = ret < 0 ? ret : -EACCES;
		goto out;
	}
	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		goto out;
	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret)
		goto out;
	ret = kacs_rust_check_file_sd_with_intent_audit_caap(
		subject_token, bytes, len, desired_access, 0, pip_type, pip_trust,
		caap_cache, &granted, &continuous_audit);
	pkm_kacs_caap_cache_unlock();
out:
	kvfree(bytes);
	return ret;
}

void pkm_kacs_stratafs_end_create_decision(void)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return;
	task_sec = pkm_kacs_task(current);
	task_sec->stratafs_create_subject = NULL;
	task_sec->stratafs_create_authority = NULL;
	task_sec->stratafs_create_parent = NULL;
	task_sec->stratafs_create_dentry = NULL;
	task_sec->stratafs_create_link_source = NULL;
	task_sec->stratafs_create_link_inode = NULL;
	task_sec->stratafs_create_access = 0;
	task_sec->stratafs_create_state = 0;
}

int pkm_kacs_stratafs_begin_create_decision(const struct path *authority,
					     u32 desired_access)
{
	struct pkm_kacs_task_security *task_sec;
	const void *subject_token;
	int ret;

	if (!current || !current->security || !authority ||
	    !authority->dentry || !desired_access)
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;
	if (task_sec->stratafs_create_state) {
		if (task_sec->stratafs_create_state == 1 &&
		    task_sec->stratafs_create_subject == subject_token &&
		    task_sec->stratafs_create_authority ==
			    d_inode(authority->dentry) &&
		    task_sec->stratafs_create_access == desired_access)
			return 0;
		return -EBUSY;
	}
	ret = pkm_kacs_stratafs_authorize_path(authority, desired_access);
	if (ret)
		return ret;
	task_sec->stratafs_create_subject = subject_token;
	task_sec->stratafs_create_authority = d_inode(authority->dentry);
	task_sec->stratafs_create_access = desired_access;
	task_sec->stratafs_create_state = 1;
	return 0;
}

int pkm_kacs_stratafs_set_native_create_decision(
	const struct path *authority, u32 desired_access)
{
	struct pkm_kacs_task_security *task_sec;
	const void *subject_token;

	if (!current || !current->security || !authority ||
	    !authority->dentry || !d_is_dir(authority->dentry) ||
	    !desired_access)
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_create_state)
		return -EBUSY;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;
	/* The native-create SD builder just authorized this exact directory. */
	task_sec->stratafs_create_subject = subject_token;
	task_sec->stratafs_create_authority = d_inode(authority->dentry);
	task_sec->stratafs_create_access = desired_access;
	task_sec->stratafs_create_state = 1;
	return 0;
}

int pkm_kacs_stratafs_bind_create_decision(const struct inode *provider_parent,
					    const struct dentry *target)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !provider_parent ||
	    (target && (d_inode((struct dentry *)target) ||
			target->d_parent == NULL ||
			d_inode(target->d_parent) != provider_parent)))
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_create_state != 1 ||
	    task_sec->stratafs_create_subject !=
		pkm_kacs_current_effective_token_ptr())
		return -EACCES;
	task_sec->stratafs_create_parent = provider_parent;
	task_sec->stratafs_create_dentry = target;
	task_sec->stratafs_create_state = 2;
	return 0;
}

int pkm_kacs_stratafs_mark_unnamed_link(const struct dentry *source)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !source ||
	    !d_really_is_positive((struct dentry *)source))
		return -EACCES;
	task_sec = pkm_kacs_task(current);
	if (task_sec->stratafs_create_state != 2 ||
	    task_sec->stratafs_create_link_source)
		return -EACCES;
	task_sec->stratafs_create_link_source = source;
	task_sec->stratafs_create_link_inode = d_inode(source);
	return 0;
}

bool pkm_kacs_stratafs_is_descriptor_xattr(const struct inode *inode,
					   const char *name)
{
	return pkm_kacs_is_canonical_sd_xattr(inode, name);
}

static const u8 pkm_kacs_sysfs_write_gate_sd[] = {
	/* Self-relative SD: owner SYSTEM, group SYSTEM, DACL below. */
	0x01, 0x00, 0x0f, 0x80, 0x14, 0x00, 0x00, 0x00,
	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x2c, 0x00, 0x00, 0x00,
	/* S-1-5-18 */
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x12, 0x00, 0x00, 0x00,
	/* S-1-5-18 */
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x12, 0x00, 0x00, 0x00,
	/* DACL: Administrators and SYSTEM may write. */
	0x02, 0x00, 0x34, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x18, 0x00, 0x02, 0x00, 0x00, 0x00,
	/* S-1-5-32-544 */
	0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00,
	/* S-1-5-18 */
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x12, 0x00, 0x00, 0x00,
};

static const char pkm_kacs_audit_op_file_access[] = "file.access";
static const char pkm_kacs_audit_op_file_mmap[] = "file.mmap";
static const char pkm_kacs_audit_op_file_mprotect[] = "file.mprotect";
static const char pkm_kacs_audit_op_file_permission[] = "file.permission";
static const char pkm_kacs_audit_op_file_write[] = "file.write";
static const char pkm_kacs_audit_op_file_ioctl[] = "file.ioctl";
static const char pkm_kacs_audit_op_file_lock[] = "file.lock";
static const char pkm_kacs_audit_op_file_fcntl[] = "file.fcntl";
static const char pkm_kacs_audit_op_file_truncate[] = "file.truncate";
static const char pkm_kacs_audit_op_file_fallocate[] = "file.fallocate";

void pkm_kacs_init_path_anchor_file(struct file *file, const struct path *path)
{
	if (!file || !path)
		return;

	memset(file, 0, sizeof(*file));
	file->f_inode = d_inode(path->dentry);
	file->f_mode = FMODE_PATH;
	*(struct path *)&file->f_path = *path;
}

int pkm_kacs_file_permission(struct file *file, int mask)
{
	enum pkm_kacs_copy_up_file_access copy_up;

	copy_up = pkm_kacs_copy_up_file_permission(file, mask);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
		return -EACCES;
	/* The user-visible file was checked immediately before this call. */
	if (pkm_kacs_backing_file_inherited(file))
		return 0;
	return pkm_kacs_check_file_permission_snapshot(file, mask);
}

int pkm_kacs_file_ioctl(struct file *file, unsigned int cmd,
			unsigned long arg)
{
	if (pkm_kacs_copy_up_file_is_internal(file))
		return -EACCES;
	return pkm_kacs_check_file_ioctl_snapshot(file, cmd, arg, false);
}

int pkm_kacs_file_ioctl_compat(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	if (pkm_kacs_copy_up_file_is_internal(file))
		return -EACCES;
	return pkm_kacs_check_file_ioctl_snapshot(file, cmd, arg, true);
}

int pkm_kacs_file_lock(struct file *file, unsigned int cmd)
{
	if (pkm_kacs_copy_up_file_is_internal(file))
		return -EACCES;
	return pkm_kacs_check_file_lock_snapshot(file, cmd);
}

int pkm_kacs_file_fcntl(struct file *file, unsigned int cmd,
			unsigned long arg)
{
	if (pkm_kacs_copy_up_file_is_internal(file))
		return -EACCES;
	return pkm_kacs_check_file_fcntl_snapshot(file, cmd, arg);
}

int pkm_kacs_file_truncate(struct file *file)
{
	int ret;

	if (pkm_kacs_copy_up_file_is_internal(file))
		return -EACCES;
	ret = pkm_kacs_check_file_truncate_snapshot(file);
	if (ret)
		return ret;
	return pkm_kacs_file_truncate_metadata(file);
}

int pkm_kacs_file_fsync(struct file *file)
{
	if (pkm_kacs_copy_up_file_is_internal(file))
		return -EACCES;
	return pkm_kacs_check_file_snapshot_grant(
		file, KACS_ACCESS_SYNCHRONIZE);
}

int pkm_kacs_file_begin_write_intent(struct file *file, u32 rwf_flags,
				     bool positioned)
{
	struct pkm_kacs_task_security *task_sec;

	if (!file || !current || !current->security)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	if (task_sec->write_intent.active)
		return -EACCES;

	task_sec->write_intent.file = file;
	task_sec->write_intent.rwf_flags = rwf_flags;
	task_sec->write_intent.positioned = positioned ? 1 : 0;
	task_sec->write_intent.active = 1;
	return 0;
}

void pkm_kacs_file_end_write_intent(struct file *file)
{
	struct pkm_kacs_task_security *task_sec;

	(void)file;

	if (!current || !current->security)
		return;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->write_intent.active)
		return;

	task_sec->write_intent.active = 0;
	task_sec->write_intent.file = NULL;
	task_sec->write_intent.rwf_flags = 0;
	task_sec->write_intent.positioned = 0;
}

int pkm_kacs_file_fallocate(struct file *file, int mode)
{
	int ret;

	if (!file)
		return -EACCES;
	if (pkm_kacs_copy_up_file_is_internal(file))
		return -EACCES;

	ret = security_file_permission(file, MAY_WRITE);
	if (ret)
		return ret;

	return pkm_kacs_check_file_fallocate_snapshot(file, mode);
}

static void pkm_kacs_trace_file_snapshot(struct file *file, u8 op,
					 u32 required_access, u8 reason,
					 long ret)
{
	struct pkm_kacs_file_security *file_sec;
	u8 managed = 0;
	u32 granted_access = 0;

	if (file && file->f_security) {
		file_sec = pkm_kacs_file(file);
		managed = file_sec->managed ? 1 : 0;
		granted_access = file_sec->granted_access;
	}

	trace_kacs_file_snapshot(file ? file_inode(file) : NULL, op, managed,
				 granted_access, required_access, reason, ret);
}

static int pkm_kacs_check_sysfs_write_gate_for_subject(
	const void *subject_token)
{
	u32 granted = 0;
	int ret;

	if (!subject_token)
		return -EACCES;

	ret = kacs_rust_check_file_sd_with_intent(
		subject_token, pkm_kacs_sysfs_write_gate_sd,
		sizeof(pkm_kacs_sysfs_write_gate_sd), KACS_FILE_WRITE_DATA,
		0, 0, 0, &granted);
	if (ret)
		return ret;
	if ((granted & KACS_FILE_WRITE_DATA) != KACS_FILE_WRITE_DATA)
		return -EACCES;

	return 0;
}

int pkm_kacs_check_sysfs_file_write_for_subject(const void *subject_token,
						const struct file *file,
						bool write_attempt)
{
	int ret;

	if (!write_attempt)
		return 0;
	if (!file)
		return -EACCES;
	if (!pkm_kacs_inode_on_sysfs_mount(file_inode(file)))
		return 0;

	ret = pkm_kacs_check_sysfs_write_gate_for_subject(subject_token);
	pkm_kacs_trace_file_snapshot((struct file *)file,
				     KACS_FSOP_SYSFS_WRITE_GATE,
				     KACS_FILE_WRITE_DATA,
				     KACS_FSR_UNMANAGED_SYSFS, ret);
	return ret;
}

long pkm_kacs_authorize_live_file_access_core(
	const void *subject_token, struct file *file, u32 desired_access)
{
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct inode *inode;
	u32 granted_access = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	u8 cache_state = 0xff;
	long ret;

	if (!subject_token || !file || desired_access == 0) {
		trace_kacs_file_access(file ? file_inode(file) : NULL,
				       desired_access, -EINVAL, KACS_TR_BAD_ARGS);
		return -EINVAL;
	}

	inode = file_inode(file);
	if (!inode || !inode->i_security) {
		/*
		 * An inode with no security blob yet — e.g. accessed mid-mount
		 * before inode_alloc_security has populated it. This path used
		 * to return silently; the trace makes that visible.
		 */
		trace_kacs_file_access(inode, desired_access, -EACCES,
				       KACS_TR_NO_ISEC);
		return -EACCES;
	}
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    KACS_MOUNT_POLICY_UNMANAGED) {
		trace_kacs_file_access(inode, desired_access, -EOPNOTSUPP,
				       KACS_TR_UNMANAGED);
		return -EOPNOTSUPP;
	}

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret) {
		trace_kacs_file_access(inode, desired_access, ret,
				       KACS_TR_PIP_CONTEXT);
		return ret;
	}

	sec = pkm_kacs_inode(inode);
	ret = pkm_kacs_inode_ensure_effective_cache(file, sec);
	if (!ret) {
		cache = pkm_kacs_inode_sd_cache_get_current(inode, sec);
		if (!cache) {
			ret = -EACCES;
			goto log;
		}
		cache_state = cache->state;
		if (cache->state != PKM_KACS_INODE_SD_VALID || !cache->bytes ||
		    cache->len == 0) {
			ret = -EACCES;
		} else {
			ret = kacs_rust_check_cached_file_sd_with_intent(
				subject_token, cache->bytes, cache->len,
				&cache->layout, desired_access, 0, pip_type,
				pip_trust, &granted_access);
		}
		pkm_kacs_inode_sd_cache_free(cache);
	}
log:
	/*
	 * Debug instrumentation for the DENY_MISSING boot bring-up. Kept behind
	 * pr_debug (compiled out / off unless dynamic debug enables it) and the
	 * accessed filename dropped, so it cannot disclose pathnames to dmesg in
	 * a production build.
	 */
	if (ret && ret != -EOPNOTSUPP) {
		pr_debug(
			"kacs: deny live_file_access ino=%lu sb_magic=0x%lx policy=%u cache_state=0x%x desired=0x%x comm=%s pid=%d ret=%ld\n",
			inode->i_ino,
			(unsigned long)inode->i_sb->s_magic,
			pkm_kacs_superblock_mount_policy(inode->i_sb),
			(unsigned)cache_state,
			desired_access, current->comm,
			current->pid, ret);
	}
	/*
	 * Final decision (allow or deny, including the cache-path denials
	 * above). Unlike the pr_debug, this also records the allow case, so a
	 * `trace_event=kacs:*` boot shows the full sequence of what passed, not
	 * only what failed.
	 */
	trace_kacs_file_access(inode, desired_access, ret, KACS_TR_DECISION);
	return ret;
}

long pkm_kacs_authorize_path_file_access_core(
	const void *subject_token, const struct path *path, u32 desired_access)
{
	struct file file = {};

	if (!path)
		return -EINVAL;

	pkm_kacs_init_path_anchor_file(&file, path);
	return pkm_kacs_authorize_live_file_access_core(subject_token, &file,
							desired_access);
}


static long pkm_kacs_build_legacy_open_access_masks(const struct file *file,
						    u32 *core_access_out,
						    u32 *requested_access_out)
{
	struct inode *inode;
	u32 core_access = 0;
	u32 compat_access = KACS_FILE_READ_EA |
			    KACS_ACCESS_READ_CONTROL |
			    KACS_FILE_WRITE_ATTRIBUTES |
			    KACS_FILE_WRITE_EA |
			    KACS_ACCESS_WRITE_DAC |
			    KACS_ACCESS_WRITE_OWNER |
			    KACS_ACCESS_SYNCHRONIZE;
	u32 mode;

	if (!file || !core_access_out || !requested_access_out)
		return -EINVAL;

	inode = file_inode(file);
	if (!inode)
		return -EACCES;

	mode = file->f_mode & (FMODE_READ | FMODE_WRITE);
	if (S_ISDIR(inode->i_mode)) {
		if ((mode & FMODE_WRITE) != 0 || (mode & FMODE_READ) == 0)
			return -EACCES;

		core_access = KACS_FILE_READ_ATTRIBUTES |
			      KACS_FILE_TRAVERSE;
		compat_access |= KACS_FILE_LIST_DIRECTORY;
	} else {
		if (!(S_ISREG(inode->i_mode) || S_ISCHR(inode->i_mode) ||
		      S_ISBLK(inode->i_mode) || S_ISFIFO(inode->i_mode) ||
		      S_ISSOCK(inode->i_mode)))
			return -EACCES;

		switch (mode) {
		case FMODE_READ:
			core_access = KACS_FILE_READ_DATA |
				      KACS_FILE_READ_ATTRIBUTES;
			break;
		case FMODE_WRITE:
			core_access = KACS_FILE_WRITE_DATA |
				      KACS_FILE_READ_ATTRIBUTES;
			break;
		case FMODE_READ | FMODE_WRITE:
			core_access = KACS_FILE_READ_DATA |
				      KACS_FILE_WRITE_DATA |
				      KACS_FILE_READ_ATTRIBUTES;
			break;
		default:
			return -EACCES;
		}

		if (S_ISREG(inode->i_mode))
			compat_access |= KACS_FILE_EXECUTE;
		if ((file->f_flags & O_APPEND) != 0) {
			if ((core_access & KACS_FILE_WRITE_DATA) != 0) {
				core_access &= ~KACS_FILE_WRITE_DATA;
				core_access |= KACS_FILE_APPEND_DATA;
			}
			compat_access |= KACS_FILE_WRITE_DATA;
		}
		if ((file->f_flags & O_TRUNC) != 0)
			core_access |= KACS_FILE_WRITE_DATA;
	}

	*core_access_out = core_access;
	*requested_access_out = core_access | compat_access;
	return 0;
}

long pkm_kacs_stamp_native_file_granted_access_for_subject(
	const void *subject_token, struct file *file, u32 desired_access)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct inode *inode;
	const void *caap_cache = NULL;
	u32 granted_access = 0;
	u32 continuous_audit_mask = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long ret;

	if (!subject_token || !file || !file->f_security || desired_access == 0)
		return -EACCES;
	if (pkm_kacs_file_delete_on_close_pending(file))
		return -EACCES;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	file_sec->granted_access = 0;
	file_sec->continuous_audit_mask = 0;
	file_sec->managed = 0;

	/*
	 * Unmanaged filesystems (proc, sysfs, nullfs) carry no SD, so the
	 * native-open access protocol does not apply — but the open must still
	 * SUCCEED, leaving the fd unmanaged (managed=0 above). Mirror the legacy
	 * open path (pkm_kacs_stamp_file_granted_access_for_subject): allow the
	 * open, gating only sysfs *writes*. Without this the native open returned
	 * -EOPNOTSUPP and no libpeios consumer could open a /proc or /sys file —
	 * e.g. peinit reading /proc/self/mountinfo at Phase-1 boot. SD-bearing
	 * operations on the returned fd (fd_get_sd, etc.) still EOPNOTSUPP, which
	 * is correct: there is no SD to read.
	 */
	if (!pkm_kacs_mount_policy_is_managed(
		    pkm_kacs_superblock_mount_policy(inode->i_sb)))
		return pkm_kacs_check_sysfs_file_write_for_subject(
			subject_token, file, (file->f_mode & FMODE_WRITE) != 0);

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;
	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret)
		return ret;

	inode_sec = pkm_kacs_inode(inode);
	ret = pkm_kacs_inode_ensure_effective_cache(file, inode_sec);
	if (!ret) {
		cache = pkm_kacs_inode_sd_cache_get_current(inode, inode_sec);
		if (!cache) {
			ret = -EACCES;
			goto out_unlock_caap;
		}
		if (cache->state != PKM_KACS_INODE_SD_VALID || !cache->bytes ||
		    cache->len == 0) {
			ret = -EACCES;
		} else {
			ret = kacs_rust_check_cached_file_sd_with_intent_audit_caap(
				subject_token, cache->bytes, cache->len,
				&cache->layout, desired_access, 0, pip_type,
				pip_trust, caap_cache, &granted_access,
				&continuous_audit_mask);
			if (!ret) {
				file_sec->granted_access = granted_access;
				file_sec->continuous_audit_mask =
					continuous_audit_mask;
				file_sec->managed = 1;
				if ((desired_access &
				     KACS_FILE_EXECUTE) != 0)
					file->f_mode |= FMODE_EXEC;
				if (!S_ISDIR(inode->i_mode)) {
					if ((desired_access &
					     KACS_FILE_READ_DATA) == 0)
						file->f_mode &= ~FMODE_READ;
					if ((desired_access &
					     (KACS_FILE_WRITE_DATA |
					      KACS_FILE_APPEND_DATA)) == 0)
						file->f_mode &= ~FMODE_WRITE;
				}
			}
		}
		pkm_kacs_inode_sd_cache_free(cache);
	}
out_unlock_caap:
	pkm_kacs_caap_cache_unlock();
	return ret;
}

long pkm_kacs_stamp_file_granted_access_for_subject(
	const void *subject_token, struct file *file)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct inode *inode;
	const void *caap_cache = NULL;
	u32 mount_policy;
	u32 core_access = 0;
	u32 requested_access = 0;
	u32 granted_access = 0;
	u32 continuous_audit_mask = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long ret;

	if (!subject_token || !file || !file->f_security)
		return -EACCES;
	if (pkm_kacs_file_delete_on_close_pending(file))
		return -EACCES;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	file_sec->granted_access = 0;
	file_sec->continuous_audit_mask = 0;
	file_sec->managed = 0;

	mount_policy = pkm_kacs_superblock_mount_policy(inode->i_sb);
	if (!pkm_kacs_mount_policy_is_managed(mount_policy)) {
		return pkm_kacs_check_sysfs_file_write_for_subject(
			subject_token, file, (file->f_mode & FMODE_WRITE) != 0);
	}

	ret = pkm_kacs_build_legacy_open_access_masks(file, &core_access,
						      &requested_access);
	if (ret)
		return ret;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;
	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret)
		return ret;

	inode_sec = pkm_kacs_inode(inode);
	ret = pkm_kacs_inode_ensure_effective_cache(file, inode_sec);
	if (!ret) {
		cache = pkm_kacs_inode_sd_cache_get_current(inode, inode_sec);
		if (!cache) {
			ret = -EACCES;
			goto out_unlock_caap;
		}
		if (cache->state != PKM_KACS_INODE_SD_VALID || !cache->bytes ||
		    cache->len == 0) {
			ret = -EACCES;
		} else {
			ret = kacs_rust_granted_cached_file_sd_with_intent_audit_caap(
				subject_token, cache->bytes, cache->len,
				&cache->layout, requested_access, 0, pip_type,
				pip_trust, caap_cache, &granted_access,
				&continuous_audit_mask);
			if (!ret &&
			    (granted_access & core_access) != core_access)
				ret = -EACCES;
			if (!ret) {
				file_sec->granted_access = granted_access;
				file_sec->continuous_audit_mask =
					continuous_audit_mask;
				file_sec->managed = 1;
			}
		}
		pkm_kacs_inode_sd_cache_free(cache);
	}
out_unlock_caap:
	pkm_kacs_caap_cache_unlock();
	return ret;
}

int pkm_kacs_file_open(struct file *file)
{
	enum pkm_kacs_copy_up_file_access copy_up;
	const void *subject_token;
	u32 desired_access = 0;
	u32 create_options = 0;
	long ret;

	if (!file)
		return -EACCES;
	if (pkm_kacs_file_delete_on_close_pending(file)) {
		trace_kacs_file_open(file_inode(file), 0, -EACCES,
				     KACS_TR_DELETE_ON_CLOSE_PENDING);
		return -EACCES;
	}
	if (!IS_ERR(pidfd_pid(file)))
		return 0;
	if ((file->f_mode & FMODE_PATH) != 0)
		return 0;
	copy_up = pkm_kacs_copy_up_file_open(file);
	if (copy_up == PKM_KACS_COPY_UP_FILE_ALLOW)
		return 0;
	if (copy_up == PKM_KACS_COPY_UP_FILE_DENY)
		return -EACCES;
	if ((file->f_mode & FMODE_BACKING) && !pkm_kacs_copy_up_active()) {
		ret = pkm_kacs_backing_file_apply(file);
		if (ret != -ENOENT)
			return ret;
	}

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token) {
		trace_kacs_file_open(file_inode(file), 0, -EACCES,
				     KACS_TR_NO_TOKEN);
		return -EACCES;
	}

	if (pkm_kacs_native_open_request_matches(file, &desired_access,
						 &create_options)) {
		ret = pkm_kacs_stamp_native_file_granted_access_for_subject(
			subject_token, file, desired_access);
		if (ret) {
			trace_kacs_file_open(file_inode(file), desired_access,
					     ret, KACS_TR_NATIVE_STAMP);
			return (int)ret;
		}
		ret = pkm_kacs_maybe_arm_delete_on_close_for_subject(
			subject_token, file, create_options);
		trace_kacs_file_open(file_inode(file), desired_access, ret,
				     KACS_TR_NATIVE_ARM);
		return (int)ret;
	}

	ret = pkm_kacs_stamp_file_granted_access_for_subject(subject_token,
							     file);
	trace_kacs_file_open(file_inode(file), 0, ret, KACS_TR_STAMP);
	return (int)ret;
}

static int pkm_kacs_emit_file_continuous_audit(struct file *file, u8 op,
					       const char *operation,
					       size_t operation_len,
					       u32 required_access, u8 reason,
					       int decision)
{
	struct pkm_kacs_file_security *file_sec;
	const void *subject_token;
	u32 matched_access;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	int ret;

	if (!file || !file->f_security || !operation || operation_len == 0 ||
	    required_access == 0)
		return decision;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return decision;

	matched_access = file_sec->continuous_audit_mask & required_access;
	if (!matched_access) {
		pkm_kacs_trace_file_snapshot(file, op, required_access, reason,
					     decision);
		return decision;
	}

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return decision ? decision : -EACCES;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	ret = kacs_rust_emit_file_continuous_audit(
		subject_token, pip_type, pip_trust, (const u8 *)operation,
		operation_len, required_access, matched_access,
		file_sec->granted_access, decision == 0 ? 1 : 0);
	if (ret) {
		pkm_kacs_trace_file_snapshot(file, op, required_access,
					     KACS_FSR_AUDIT_EMIT_FAIL, ret);
		return ret;
	}
	pkm_kacs_trace_file_snapshot(file, op, required_access, reason,
				     decision);
	return decision;
}

static int pkm_kacs_check_file_snapshot_grant_op(struct file *file, u8 op,
						 u32 required_access,
						 const char *operation,
						 size_t operation_len)
{
	struct pkm_kacs_file_security *file_sec;
	int ret = 0;

	if (required_access == 0 || !file)
		return 0;
	if (!file->f_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return pkm_kacs_check_sysfs_file_write_for_subject(
			pkm_kacs_current_effective_token_ptr(), file,
			(required_access & KACS_FILE_WRITE_DATA) != 0);
	if ((file_sec->granted_access & required_access) != required_access)
		ret = -EACCES;

	return pkm_kacs_emit_file_continuous_audit(
		file, op, operation, operation_len, required_access,
		KACS_FSR_DECISION, ret);
}

int pkm_kacs_check_file_snapshot_grant(struct file *file,
				       u32 required_access)
{
	return pkm_kacs_check_file_snapshot_grant_op(
		file, KACS_FSOP_ACCESS, required_access,
		pkm_kacs_audit_op_file_access,
		sizeof(pkm_kacs_audit_op_file_access) - 1);
}

static bool pkm_kacs_mmap_flags_shared(unsigned long flags)
{
	unsigned long map_type = flags & MAP_TYPE;

	if (map_type == MAP_SHARED)
		return true;
#ifdef MAP_SHARED_VALIDATE
	if (map_type == MAP_SHARED_VALIDATE)
		return true;
#endif
	return false;
}

static u32 pkm_kacs_mapping_required_access(unsigned long prot, bool shared)
{
	u32 required_access = 0;

	if ((prot & PROT_READ) != 0)
		required_access |= KACS_FILE_READ_DATA;
	if ((prot & PROT_EXEC) != 0)
		required_access |= KACS_FILE_EXECUTE;
	if ((prot & PROT_WRITE) != 0)
		required_access |= shared ? KACS_FILE_WRITE_DATA :
					    KACS_FILE_READ_DATA;

	return required_access;
}

int pkm_kacs_check_mmap_snapshot(struct file *file, unsigned long prot,
				 unsigned long flags)
{
	if (file && (file->f_mode & FMODE_PATH) != 0)
		return -EBADF;

	return pkm_kacs_check_file_snapshot_grant_op(
		file, KACS_FSOP_MMAP,
		pkm_kacs_mapping_required_access(
			prot, pkm_kacs_mmap_flags_shared(flags)),
		pkm_kacs_audit_op_file_mmap,
		sizeof(pkm_kacs_audit_op_file_mmap) - 1);
}

int pkm_kacs_check_mprotect_snapshot(struct file *file,
				     unsigned long vm_flags,
				     unsigned long prot)
{
	return pkm_kacs_check_file_snapshot_grant_op(
		file, KACS_FSOP_MPROTECT,
		pkm_kacs_mapping_required_access(
			prot, (vm_flags & VM_SHARED) != 0),
		pkm_kacs_audit_op_file_mprotect,
		sizeof(pkm_kacs_audit_op_file_mprotect) - 1);
}

int pkm_kacs_check_file_permission_snapshot_for_subject(
	const void *subject_token, struct file *file, int mask)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_task_security *task_sec = NULL;
	struct pkm_kacs_file_write_intent marker = { };
	u32 required_access = 0;
	u32 audit_required_access = 0;
	int ret = 0;
	bool append_intent;
	bool write_intent;

	if (!file)
		return -EACCES;
	if (!file->f_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	if ((mask & MAY_READ) != 0)
		required_access |= KACS_FILE_READ_DATA;
	if ((mask & (MAY_EXEC | MAY_CHDIR)) != 0)
		required_access |= KACS_FILE_TRAVERSE;
	audit_required_access = required_access;

	write_intent = (mask & MAY_WRITE) != 0;
	append_intent = (mask & MAY_APPEND) != 0 ||
			(write_intent && (file->f_flags & O_APPEND) != 0);
	if (write_intent || append_intent) {
		ret = pkm_kacs_check_signed_exec_content_mutation_file(file);
		if (ret) {
			pkm_kacs_trace_file_snapshot(file, KACS_FSOP_PERMISSION,
						     required_access,
						     KACS_FSR_SIGNED_EXEC, ret);
			return ret;
		}
	}

	if (!file_sec->managed)
		return pkm_kacs_check_sysfs_file_write_for_subject(
			subject_token, file, write_intent || append_intent);

	if ((file_sec->granted_access & required_access) != required_access)
		return pkm_kacs_emit_file_continuous_audit(
			file, KACS_FSOP_PERMISSION,
			pkm_kacs_audit_op_file_permission,
			sizeof(pkm_kacs_audit_op_file_permission) - 1,
			audit_required_access, KACS_FSR_GRANT_DENY, -EACCES);

	if (write_intent && current && current->security) {
		task_sec = pkm_kacs_task(current);
		if (task_sec->write_intent.active) {
			if (task_sec->write_intent.file != file)
				return -EACCES;
			marker = task_sec->write_intent;
			task_sec->write_intent.active = 0;
			task_sec->write_intent.file = NULL;
			task_sec->write_intent.rwf_flags = 0;
			task_sec->write_intent.positioned = 0;
			return pkm_kacs_check_file_write_intent_snapshot_for_subject(
				subject_token, file, marker.rwf_flags,
				marker.positioned != 0);
		}
	}

	if (write_intent || append_intent) {
		u32 write_grants = file_sec->granted_access &
				   (KACS_FILE_WRITE_DATA |
				    KACS_FILE_APPEND_DATA);

		if (append_intent) {
			audit_required_access |= KACS_FILE_WRITE_DATA |
						 KACS_FILE_APPEND_DATA;
			if (write_grants == 0)
				ret = -EACCES;
		} else if ((file_sec->granted_access &
			    KACS_FILE_WRITE_DATA) == 0) {
			audit_required_access |= KACS_FILE_WRITE_DATA;
			ret = -EACCES;
		} else {
			audit_required_access |= KACS_FILE_WRITE_DATA;
		}
	}

	return pkm_kacs_emit_file_continuous_audit(
		file, KACS_FSOP_PERMISSION,
		pkm_kacs_audit_op_file_permission,
		sizeof(pkm_kacs_audit_op_file_permission) - 1,
		audit_required_access,
		ret ? (append_intent ? KACS_FSR_APPEND_DENY :
				       KACS_FSR_GRANT_DENY) :
		      KACS_FSR_DECISION,
		ret);
}

int pkm_kacs_check_file_permission_snapshot(struct file *file, int mask)
{
	return pkm_kacs_check_file_permission_snapshot_for_subject(
		pkm_kacs_current_effective_token_ptr(), file, mask);
}

int pkm_kacs_check_file_write_intent_snapshot_for_subject(
	const void *subject_token, struct file *file, u32 rwf_flags,
	bool positioned)
{
	struct pkm_kacs_file_security *file_sec;
	bool append_intent;
	bool noappend;
	u32 granted_access;
	u32 required_access;
	int ret = 0;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	if (!file->f_security)
		return -EACCES;

	ret = pkm_kacs_check_signed_exec_content_mutation_file(file);
	if (ret) {
		pkm_kacs_trace_file_snapshot(file, KACS_FSOP_WRITE_INTENT,
					     KACS_FILE_WRITE_DATA,
					     KACS_FSR_SIGNED_EXEC, ret);
		return ret;
	}

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return pkm_kacs_check_sysfs_file_write_for_subject(
			subject_token, file, true);

	if ((rwf_flags & RWF_APPEND) != 0 &&
	    (rwf_flags & RWF_NOAPPEND) != 0)
		return -EACCES;

	noappend = (rwf_flags & RWF_NOAPPEND) != 0;
	append_intent = !noappend &&
			(((rwf_flags & RWF_APPEND) != 0) ||
			 ((file->f_flags & O_APPEND) != 0));
	granted_access = file_sec->granted_access;

	if (noappend || (positioned && !append_intent)) {
		required_access = KACS_FILE_WRITE_DATA;
		if ((granted_access & KACS_FILE_WRITE_DATA) == 0)
			ret = -EACCES;
		return pkm_kacs_emit_file_continuous_audit(
			file, KACS_FSOP_WRITE_INTENT,
			pkm_kacs_audit_op_file_write,
			sizeof(pkm_kacs_audit_op_file_write) - 1,
			required_access,
			ret ? KACS_FSR_GRANT_DENY : KACS_FSR_DECISION, ret);
	}

	if (append_intent) {
		required_access = KACS_FILE_WRITE_DATA |
				  KACS_FILE_APPEND_DATA;
		if ((granted_access & required_access) == 0)
			ret = -EACCES;
		return pkm_kacs_emit_file_continuous_audit(
			file, KACS_FSOP_WRITE_INTENT,
			pkm_kacs_audit_op_file_write,
			sizeof(pkm_kacs_audit_op_file_write) - 1,
			required_access,
			ret ? KACS_FSR_APPEND_DENY : KACS_FSR_DECISION, ret);
	}

	required_access = KACS_FILE_WRITE_DATA;
	if ((granted_access & KACS_FILE_WRITE_DATA) == 0)
		ret = -EACCES;
	return pkm_kacs_emit_file_continuous_audit(
		file, KACS_FSOP_WRITE_INTENT, pkm_kacs_audit_op_file_write,
		sizeof(pkm_kacs_audit_op_file_write) - 1, required_access,
		ret ? KACS_FSR_GRANT_DENY : KACS_FSR_DECISION, ret);
}

int pkm_kacs_check_file_write_intent_snapshot(struct file *file,
					      u32 rwf_flags, bool positioned)
{
	return pkm_kacs_check_file_write_intent_snapshot_for_subject(
		pkm_kacs_current_effective_token_ptr(), file, rwf_flags,
		positioned);
}

enum pkm_kacs_ioctl_requirement {
	PKM_KACS_IOCTL_REQUIRE_NONE,
	PKM_KACS_IOCTL_REQUIRE_UNKNOWN,
	PKM_KACS_IOCTL_REQUIRE_ANY_DATA,
	PKM_KACS_IOCTL_REQUIRE_READ_DATA,
	PKM_KACS_IOCTL_REQUIRE_WRITE_DATA,
	PKM_KACS_IOCTL_REQUIRE_APPEND_OR_WRITE_DATA,
	PKM_KACS_IOCTL_REQUIRE_READ_ATTRIBUTES,
	PKM_KACS_IOCTL_REQUIRE_WRITE_ATTRIBUTES,
};

static unsigned int pkm_kacs_normalize_compat_ioctl_cmd(unsigned int cmd)
{
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		return FS_IOC_GETFLAGS;
	case FS_IOC32_SETFLAGS:
		return FS_IOC_SETFLAGS;
	case FS_IOC32_GETVERSION:
		return FS_IOC_GETVERSION;
	case FS_IOC32_SETVERSION:
		return FS_IOC_SETVERSION;
#if defined(CONFIG_X86_64)
	case FS_IOC_RESVSP_32:
		return FS_IOC_RESVSP;
	case FS_IOC_RESVSP64_32:
		return FS_IOC_RESVSP64;
	case FS_IOC_UNRESVSP_32:
		return FS_IOC_UNRESVSP;
	case FS_IOC_UNRESVSP64_32:
		return FS_IOC_UNRESVSP64;
	case FS_IOC_ZERO_RANGE_32:
		return FS_IOC_ZERO_RANGE;
#endif
	default:
		return cmd;
	}
}

static enum pkm_kacs_ioctl_requirement
pkm_kacs_classify_file_ioctl(unsigned int cmd, umode_t mode, bool compat)
{
	(void)compat;
	cmd = pkm_kacs_normalize_compat_ioctl_cmd(cmd);

	switch (cmd) {
	case FIOCLEX:
	case FIONCLEX:
	case FIONBIO:
	case FIOASYNC:
		return PKM_KACS_IOCTL_REQUIRE_NONE;
	case FIBMAP:
	case FS_IOC_FIEMAP:
		return PKM_KACS_IOCTL_REQUIRE_READ_DATA;
	case FIONREAD:
		if (S_ISREG(mode))
			return PKM_KACS_IOCTL_REQUIRE_READ_DATA;
		return PKM_KACS_IOCTL_REQUIRE_ANY_DATA;
	case FIGETBSZ:
	case FIOQSIZE:
	case FS_IOC_GETFLAGS:
	case FS_IOC_GETVERSION:
	case FS_IOC_FSGETXATTR:
	case FS_IOC_GETFSLABEL:
	case FS_IOC_GETFSUUID:
	case FS_IOC_GETFSSYSFSPATH:
	case FS_IOC_GETLBMD_CAP:
	case FS_IOC_GET_ENCRYPTION_PWSALT:
	case FS_IOC_GET_ENCRYPTION_POLICY:
	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
	case BLKGETSIZE64:
		return PKM_KACS_IOCTL_REQUIRE_READ_ATTRIBUTES;
	case FS_IOC_SETFLAGS:
	case FS_IOC_SETVERSION:
	case FS_IOC_FSSETXATTR:
	case FS_IOC_SETFSLABEL:
	case FS_IOC_SET_ENCRYPTION_POLICY:
	case FS_IOC_ADD_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
	case FIFREEZE:
	case FITHAW:
	case FITRIM:
		return PKM_KACS_IOCTL_REQUIRE_WRITE_ATTRIBUTES;
	case FS_IOC_RESVSP:
	case FS_IOC_RESVSP64:
		return PKM_KACS_IOCTL_REQUIRE_APPEND_OR_WRITE_DATA;
	case FS_IOC_UNRESVSP:
	case FS_IOC_UNRESVSP64:
	case FS_IOC_ZERO_RANGE:
	case FICLONE:
	case FICLONERANGE:
	case FIDEDUPERANGE:
	case BLKFLSBUF:
		return PKM_KACS_IOCTL_REQUIRE_WRITE_DATA;
	default:
		return PKM_KACS_IOCTL_REQUIRE_UNKNOWN;
	}
}

static int pkm_kacs_check_ioctl_requirement(
	u32 granted_access, enum pkm_kacs_ioctl_requirement req)
{
	switch (req) {
	case PKM_KACS_IOCTL_REQUIRE_NONE:
		return 0;
	case PKM_KACS_IOCTL_REQUIRE_UNKNOWN:
	case PKM_KACS_IOCTL_REQUIRE_ANY_DATA:
		if ((granted_access & PKM_KACS_FILE_DATA_RIGHTS) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_READ_DATA:
		if ((granted_access & KACS_FILE_READ_DATA) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_WRITE_DATA:
		if ((granted_access & KACS_FILE_WRITE_DATA) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_APPEND_OR_WRITE_DATA:
		if ((granted_access & (KACS_FILE_APPEND_DATA |
				       KACS_FILE_WRITE_DATA)) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_READ_ATTRIBUTES:
		if ((granted_access & KACS_FILE_READ_ATTRIBUTES) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_WRITE_ATTRIBUTES:
		if ((granted_access & KACS_FILE_WRITE_ATTRIBUTES) != 0)
			return 0;
		return -EACCES;
	default:
		return -EACCES;
	}
}

static u32 pkm_kacs_ioctl_requirement_mask(
	enum pkm_kacs_ioctl_requirement req)
{
	switch (req) {
	case PKM_KACS_IOCTL_REQUIRE_UNKNOWN:
	case PKM_KACS_IOCTL_REQUIRE_ANY_DATA:
		return PKM_KACS_FILE_DATA_RIGHTS;
	case PKM_KACS_IOCTL_REQUIRE_READ_DATA:
		return KACS_FILE_READ_DATA;
	case PKM_KACS_IOCTL_REQUIRE_WRITE_DATA:
		return KACS_FILE_WRITE_DATA;
	case PKM_KACS_IOCTL_REQUIRE_APPEND_OR_WRITE_DATA:
		return KACS_FILE_APPEND_DATA | KACS_FILE_WRITE_DATA;
	case PKM_KACS_IOCTL_REQUIRE_READ_ATTRIBUTES:
		return KACS_FILE_READ_ATTRIBUTES;
	case PKM_KACS_IOCTL_REQUIRE_WRITE_ATTRIBUTES:
		return KACS_FILE_WRITE_ATTRIBUTES;
	case PKM_KACS_IOCTL_REQUIRE_NONE:
	default:
		return 0;
	}
}

int pkm_kacs_check_file_ioctl_snapshot(struct file *file, unsigned int cmd,
				       unsigned long arg, bool compat)
{
	struct pkm_kacs_file_security *file_sec;
	struct inode *inode;
	enum pkm_kacs_ioctl_requirement req;
	u32 required_access;
	int ret;

	(void)arg;

	if (!file)
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return -EBADF;
	if (!file->f_security)
		return -EACCES;

	inode = file_inode(file);
	if (!inode)
		return -EACCES;

	req = pkm_kacs_classify_file_ioctl(cmd, inode->i_mode, compat);
	required_access = pkm_kacs_ioctl_requirement_mask(req);
	if (req == PKM_KACS_IOCTL_REQUIRE_UNKNOWN ||
	    req == PKM_KACS_IOCTL_REQUIRE_WRITE_DATA ||
	    req == PKM_KACS_IOCTL_REQUIRE_APPEND_OR_WRITE_DATA) {
		ret = pkm_kacs_check_signed_exec_content_mutation_file(file);
		if (ret) {
			pkm_kacs_trace_file_snapshot(file, KACS_FSOP_IOCTL,
						     required_access,
						     KACS_FSR_SIGNED_EXEC, ret);
			return ret;
		}
	}

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return 0;

	ret = pkm_kacs_check_ioctl_requirement(file_sec->granted_access, req);
	return pkm_kacs_emit_file_continuous_audit(
		file, KACS_FSOP_IOCTL, pkm_kacs_audit_op_file_ioctl,
		sizeof(pkm_kacs_audit_op_file_ioctl) - 1, required_access,
		ret ? KACS_FSR_GRANT_DENY : KACS_FSR_DECISION, ret);
}

int pkm_kacs_check_file_lock_snapshot(struct file *file, unsigned int cmd)
{
	struct pkm_kacs_file_security *file_sec;
	u32 granted_access;
	u32 required_access = 0;
	int ret = 0;

	if (!file)
		return -EACCES;
	if (!file->f_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return 0;

	granted_access = file_sec->granted_access;
	switch (cmd) {
	case F_UNLCK:
		return 0;
	case F_RDLCK:
		required_access = KACS_FILE_READ_DATA;
		if ((granted_access & required_access) == 0)
			ret = -EACCES;
		break;
	case F_WRLCK:
		required_access = KACS_FILE_WRITE_DATA |
				  KACS_FILE_APPEND_DATA;
		if ((granted_access & required_access) == 0)
			ret = -EACCES;
		break;
	default:
		return -EACCES;
	}

	return pkm_kacs_emit_file_continuous_audit(
		file, KACS_FSOP_LOCK, pkm_kacs_audit_op_file_lock,
		sizeof(pkm_kacs_audit_op_file_lock) - 1, required_access,
		ret ? KACS_FSR_GRANT_DENY : KACS_FSR_DECISION, ret);
}

enum pkm_kacs_fcntl_requirement {
	PKM_KACS_FCNTL_REQUIRE_NONE,
	PKM_KACS_FCNTL_REQUIRE_ANY_DATA,
	PKM_KACS_FCNTL_REQUIRE_READ_ATTRIBUTES,
	PKM_KACS_FCNTL_REQUIRE_WRITE_ATTRIBUTES,
	PKM_KACS_FCNTL_REQUIRE_NOTIFY,
	PKM_KACS_FCNTL_REQUIRE_SETFL,
	PKM_KACS_FCNTL_REQUIRE_DENY,
};

static enum pkm_kacs_fcntl_requirement
pkm_kacs_classify_file_fcntl(unsigned int cmd)
{
	switch (cmd) {
	case F_CREATED_QUERY:
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
	case F_DUPFD_QUERY:
	case F_GETFD:
	case F_SETFD:
	case F_GETFL:
	case F_GETOWN:
	case F_SETOWN:
	case F_GETOWN_EX:
	case F_SETOWN_EX:
	case F_GETOWNER_UIDS:
	case F_GETSIG:
	case F_SETSIG:
	case F_SETLK:
	case F_SETLKW:
	case F_SETLK64:
	case F_SETLKW64:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
	case F_SETLEASE:
	case F_SETDELEG:
		return PKM_KACS_FCNTL_REQUIRE_NONE;
	case F_SETFL:
		return PKM_KACS_FCNTL_REQUIRE_SETFL;
	case F_GETLK:
	case F_GETLK64:
	case F_OFD_GETLK:
		return PKM_KACS_FCNTL_REQUIRE_ANY_DATA;
	case F_GETLEASE:
	case F_GETDELEG:
	case F_GETPIPE_SZ:
	case F_GET_SEALS:
	case F_GET_RW_HINT:
	case F_GET_FILE_RW_HINT:
		return PKM_KACS_FCNTL_REQUIRE_READ_ATTRIBUTES;
	case F_SETPIPE_SZ:
	case F_ADD_SEALS:
	case F_SET_RW_HINT:
	case F_SET_FILE_RW_HINT:
		return PKM_KACS_FCNTL_REQUIRE_WRITE_ATTRIBUTES;
	case F_NOTIFY:
		return PKM_KACS_FCNTL_REQUIRE_NOTIFY;
	default:
		return PKM_KACS_FCNTL_REQUIRE_DENY;
	}
}

static int pkm_kacs_check_file_fcntl_notify(u32 granted_access,
					    unsigned long arg)
{
	const unsigned long known_mask = DN_ACCESS | DN_MODIFY | DN_CREATE |
					DN_DELETE | DN_RENAME | DN_ATTRIB |
					DN_MULTISHOT;
	const unsigned long event_mask = DN_ACCESS | DN_MODIFY | DN_CREATE |
					DN_DELETE | DN_RENAME | DN_ATTRIB;

	if ((arg & ~known_mask) != 0)
		return -EACCES;
	if ((arg & event_mask) == 0)
		return 0;
	if ((granted_access & KACS_FILE_LIST_DIRECTORY) != 0)
		return 0;
	return -EACCES;
}

static int pkm_kacs_check_file_fcntl_requirement(
	u32 granted_access, enum pkm_kacs_fcntl_requirement req,
	unsigned long arg)
{
	switch (req) {
	case PKM_KACS_FCNTL_REQUIRE_NONE:
	case PKM_KACS_FCNTL_REQUIRE_SETFL:
		return 0;
	case PKM_KACS_FCNTL_REQUIRE_ANY_DATA:
		if ((granted_access & PKM_KACS_FILE_DATA_RIGHTS) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_FCNTL_REQUIRE_READ_ATTRIBUTES:
		if ((granted_access & KACS_FILE_READ_ATTRIBUTES) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_FCNTL_REQUIRE_WRITE_ATTRIBUTES:
		if ((granted_access & KACS_FILE_WRITE_ATTRIBUTES) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_FCNTL_REQUIRE_NOTIFY:
		return pkm_kacs_check_file_fcntl_notify(granted_access, arg);
	case PKM_KACS_FCNTL_REQUIRE_DENY:
	default:
		return -EACCES;
	}
}

static u32 pkm_kacs_fcntl_requirement_mask(
	enum pkm_kacs_fcntl_requirement req, unsigned long arg)
{
	const unsigned long event_mask = DN_ACCESS | DN_MODIFY | DN_CREATE |
					DN_DELETE | DN_RENAME | DN_ATTRIB;

	switch (req) {
	case PKM_KACS_FCNTL_REQUIRE_ANY_DATA:
		return PKM_KACS_FILE_DATA_RIGHTS;
	case PKM_KACS_FCNTL_REQUIRE_READ_ATTRIBUTES:
		return KACS_FILE_READ_ATTRIBUTES;
	case PKM_KACS_FCNTL_REQUIRE_WRITE_ATTRIBUTES:
		return KACS_FILE_WRITE_ATTRIBUTES;
	case PKM_KACS_FCNTL_REQUIRE_NOTIFY:
		return (arg & event_mask) != 0 ?
			       KACS_FILE_LIST_DIRECTORY :
			       0;
	case PKM_KACS_FCNTL_REQUIRE_NONE:
	case PKM_KACS_FCNTL_REQUIRE_SETFL:
	case PKM_KACS_FCNTL_REQUIRE_DENY:
	default:
		return 0;
	}
}

int pkm_kacs_check_file_fcntl_snapshot(struct file *file, unsigned int cmd,
				       unsigned long arg)
{
	struct pkm_kacs_file_security *file_sec;
	enum pkm_kacs_fcntl_requirement req;
	unsigned long old_flags;
	unsigned long new_flags;
	u32 granted_access;
	u32 required_access = 0;
	int ret = 0;

	if (!file)
		return -EACCES;
	if (!file->f_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return 0;

	req = pkm_kacs_classify_file_fcntl(cmd);
	granted_access = file_sec->granted_access;
	if (req != PKM_KACS_FCNTL_REQUIRE_SETFL) {
		required_access = pkm_kacs_fcntl_requirement_mask(req, arg);
		ret = pkm_kacs_check_file_fcntl_requirement(granted_access,
							    req, arg);
		return pkm_kacs_emit_file_continuous_audit(
			file, KACS_FSOP_FCNTL, pkm_kacs_audit_op_file_fcntl,
			sizeof(pkm_kacs_audit_op_file_fcntl) - 1,
			required_access,
			ret ? KACS_FSR_GRANT_DENY : KACS_FSR_DECISION, ret);
	}

	old_flags = file->f_flags;
	new_flags = arg;
	if ((old_flags & O_APPEND) != 0 && (new_flags & O_APPEND) == 0) {
		required_access |= KACS_FILE_WRITE_DATA;
		if ((granted_access & KACS_FILE_APPEND_DATA) != 0 &&
		    (granted_access & KACS_FILE_WRITE_DATA) == 0)
			ret = -EACCES;
	}

	if ((old_flags & O_NOATIME) == 0 && (new_flags & O_NOATIME) != 0) {
		required_access |= KACS_FILE_WRITE_ATTRIBUTES;
		if ((granted_access & KACS_FILE_WRITE_ATTRIBUTES) == 0)
			ret = -EACCES;
	}

	return pkm_kacs_emit_file_continuous_audit(
		file, KACS_FSOP_FCNTL, pkm_kacs_audit_op_file_fcntl,
		sizeof(pkm_kacs_audit_op_file_fcntl) - 1, required_access,
		ret ? KACS_FSR_GRANT_DENY : KACS_FSR_DECISION, ret);
}

int pkm_kacs_check_file_truncate_snapshot(struct file *file)
{
	struct pkm_kacs_file_security *file_sec;
	int ret = 0;

	if (!file)
		return -EACCES;
	if (!file->f_security)
		return -EACCES;

	ret = pkm_kacs_check_signed_exec_content_mutation_file(file);
	if (ret) {
		pkm_kacs_trace_file_snapshot(file, KACS_FSOP_TRUNCATE,
					     KACS_FILE_WRITE_DATA,
					     KACS_FSR_SIGNED_EXEC, ret);
		return ret;
	}

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return 0;

	if ((file_sec->granted_access & KACS_FILE_WRITE_DATA) == 0)
		ret = -EACCES;
	return pkm_kacs_emit_file_continuous_audit(
		file, KACS_FSOP_TRUNCATE, pkm_kacs_audit_op_file_truncate,
		sizeof(pkm_kacs_audit_op_file_truncate) - 1,
		KACS_FILE_WRITE_DATA,
		ret ? KACS_FSR_GRANT_DENY : KACS_FSR_DECISION, ret);
}

static bool pkm_kacs_fallocate_mode_supported(int mode,
					      bool *requires_write_data)
{
	if (!requires_write_data)
		return false;
	if ((mode & ~(FALLOC_FL_MODE_MASK | FALLOC_FL_KEEP_SIZE)) != 0)
		return false;

	switch (mode & FALLOC_FL_MODE_MASK) {
	case FALLOC_FL_ALLOCATE_RANGE:
		*requires_write_data = false;
		return true;
	case FALLOC_FL_UNSHARE_RANGE:
		*requires_write_data = true;
		return true;
	case FALLOC_FL_PUNCH_HOLE:
		if ((mode & FALLOC_FL_KEEP_SIZE) == 0)
			return false;
		*requires_write_data = true;
		return true;
	case FALLOC_FL_ZERO_RANGE:
		*requires_write_data = true;
		return true;
	case FALLOC_FL_COLLAPSE_RANGE:
	case FALLOC_FL_INSERT_RANGE:
	case FALLOC_FL_WRITE_ZEROES:
		if ((mode & FALLOC_FL_KEEP_SIZE) != 0)
			return false;
		*requires_write_data = true;
		return true;
	default:
		return false;
	}
}

int pkm_kacs_check_file_fallocate_snapshot(struct file *file, int mode)
{
	struct pkm_kacs_file_security *file_sec;
	bool mode_supported;
	bool requires_write_data = false;
	u32 granted_access;
	u32 required_access;
	int ret = 0;

	if (!file)
		return -EACCES;
	if (!file->f_security)
		return -EACCES;

	mode_supported = pkm_kacs_fallocate_mode_supported(
		mode, &requires_write_data);
	if (pkm_kacs_inode_signed_exec_pinned(file_inode(file))) {
		ret = pkm_kacs_check_signed_exec_content_mutation_file(file);
		if (ret) {
			pkm_kacs_trace_file_snapshot(file, KACS_FSOP_FALLOCATE,
						     KACS_FILE_WRITE_DATA,
						     KACS_FSR_SIGNED_EXEC, ret);
			return ret;
		}
	}

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return 0;

	if (!mode_supported)
		return -EACCES;

	granted_access = file_sec->granted_access;
	if (requires_write_data) {
		required_access = KACS_FILE_WRITE_DATA;
		if ((granted_access & required_access) == 0)
			ret = -EACCES;
		return pkm_kacs_emit_file_continuous_audit(
			file, KACS_FSOP_FALLOCATE,
			pkm_kacs_audit_op_file_fallocate,
			sizeof(pkm_kacs_audit_op_file_fallocate) - 1,
			required_access,
			ret ? KACS_FSR_GRANT_DENY : KACS_FSR_DECISION, ret);
	}

	required_access = KACS_FILE_WRITE_DATA | KACS_FILE_APPEND_DATA;
	if ((granted_access & required_access) == 0)
		ret = -EACCES;
	return pkm_kacs_emit_file_continuous_audit(
		file, KACS_FSOP_FALLOCATE, pkm_kacs_audit_op_file_fallocate,
		sizeof(pkm_kacs_audit_op_file_fallocate) - 1, required_access,
		ret ? KACS_FSR_GRANT_DENY : KACS_FSR_DECISION, ret);
}
