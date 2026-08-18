/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_FILE_ACCESS_H
#define _SECURITY_PKM_KACS_FILE_ACCESS_H

#include <linux/fs.h>
#include <linux/types.h>

struct path;

int pkm_kacs_stratafs_authorize_path(const struct path *path,
				     u32 desired_access);
bool pkm_kacs_stratafs_is_descriptor_xattr(const struct inode *inode,
					   const char *name);

void pkm_kacs_init_path_anchor_file(struct file *file, const struct path *path);

int pkm_kacs_file_open(struct file *file);
int pkm_kacs_file_permission(struct file *file, int mask);
int pkm_kacs_file_ioctl(struct file *file, unsigned int cmd,
			unsigned long arg);
int pkm_kacs_file_ioctl_compat(struct file *file, unsigned int cmd,
			       unsigned long arg);
int pkm_kacs_file_lock(struct file *file, unsigned int cmd);
int pkm_kacs_file_fcntl(struct file *file, unsigned int cmd,
			unsigned long arg);
int pkm_kacs_file_truncate(struct file *file);
int pkm_kacs_file_fsync(struct file *file);

int pkm_kacs_check_sysfs_file_write_for_subject(const void *subject_token,
						const struct file *file,
						bool write_attempt);
long pkm_kacs_authorize_live_file_access_core(
	const void *subject_token, struct file *file, u32 desired_access);
long pkm_kacs_authorize_path_file_access_core(const void *subject_token,
					      const struct path *path,
					      u32 desired_access);
long pkm_kacs_stamp_native_file_granted_access_for_subject(
	const void *subject_token, struct file *file, u32 desired_access);
long pkm_kacs_stamp_file_granted_access_for_subject(
	const void *subject_token, struct file *file);
int pkm_kacs_check_file_snapshot_grant(struct file *file,
				       u32 required_access);
int pkm_kacs_check_mmap_snapshot(struct file *file, unsigned long prot,
				 unsigned long flags);
int pkm_kacs_check_mprotect_snapshot(struct file *file,
				     unsigned long vm_flags,
				     unsigned long prot);
int pkm_kacs_check_file_permission_snapshot(struct file *file, int mask);
int pkm_kacs_check_file_permission_snapshot_for_subject(
	const void *subject_token, struct file *file, int mask);
int pkm_kacs_check_file_write_intent_snapshot(struct file *file,
					      u32 rwf_flags, bool positioned);
int pkm_kacs_check_file_write_intent_snapshot_for_subject(
	const void *subject_token, struct file *file, u32 rwf_flags,
	bool positioned);
int pkm_kacs_check_file_ioctl_snapshot(struct file *file, unsigned int cmd,
				       unsigned long arg, bool compat);
int pkm_kacs_check_file_lock_snapshot(struct file *file, unsigned int cmd);
int pkm_kacs_check_file_fcntl_snapshot(struct file *file, unsigned int cmd,
				       unsigned long arg);
int pkm_kacs_check_file_truncate_snapshot(struct file *file);
int pkm_kacs_check_file_fallocate_snapshot(struct file *file, int mode);

#endif /* _SECURITY_PKM_KACS_FILE_ACCESS_H */
