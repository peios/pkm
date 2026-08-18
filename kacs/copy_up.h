/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_COPY_UP_H
#define _SECURITY_PKM_KACS_COPY_UP_H

#include <linux/types.h>

struct dentry;
struct file;
struct inode;
struct path;
struct pkm_kacs_stratafs_copy_up;
struct qstr;
struct task_struct;
struct user_namespace;
struct cred;
struct mnt_idmap;

enum pkm_kacs_copy_up_file_access {
	PKM_KACS_COPY_UP_FILE_ORDINARY = 0,
	PKM_KACS_COPY_UP_FILE_ALLOW = 1,
	PKM_KACS_COPY_UP_FILE_DENY = 2,
};

void pkm_kacs_copy_up_task_exit(struct task_struct *task);
bool pkm_kacs_copy_up_active(void);

int pkm_kacs_copy_up_dentry_create_files_as(
	struct dentry *dentry, int mode, const struct qstr *name,
	const struct cred *old, struct cred *new);
void pkm_kacs_copy_up_post_create_tmpfile(struct mnt_idmap *idmap,
					  struct inode *inode);

bool pkm_kacs_copy_up_allows_inode_permission(const struct inode *inode,
					       int mask);
bool pkm_kacs_copy_up_allows_create(const struct inode *dir,
				     const struct dentry *dentry,
				     umode_t mode);
bool pkm_kacs_copy_up_allows_link(const struct dentry *old_dentry,
				   const struct inode *dir,
				   const struct dentry *new_dentry);
bool pkm_kacs_copy_up_allows_unlink(const struct inode *dir,
				     const struct dentry *dentry,
				     bool directory);
bool pkm_kacs_copy_up_allows_rename(const struct inode *old_dir,
				     const struct dentry *old_dentry,
				     const struct inode *new_dir,
				     const struct dentry *new_dentry);
bool pkm_kacs_copy_up_allows_readlink(const struct dentry *dentry);

int pkm_kacs_copy_up_init_security(const struct inode *inode,
				    const struct inode *dir,
				    const struct qstr *qstr,
				    const u8 **sd_bytes,
				    size_t *sd_len);

enum pkm_kacs_copy_up_file_access
pkm_kacs_copy_up_file_open(struct file *file);
enum pkm_kacs_copy_up_file_access
pkm_kacs_copy_up_file_permission(const struct file *file, int mask);
enum pkm_kacs_copy_up_file_access
pkm_kacs_copy_up_file_metadata(const struct file *file, bool write);
bool pkm_kacs_copy_up_file_is_internal(const struct file *file);
void pkm_kacs_copy_up_file_release(struct file *file);

bool pkm_kacs_copy_up_allows_getattr(const struct dentry *dentry);
bool pkm_kacs_copy_up_allows_path_getattr(const struct path *path);
bool pkm_kacs_copy_up_allows_setattr(const struct dentry *dentry);
bool pkm_kacs_copy_up_allows_getxattr(const struct dentry *dentry,
				       const char *name);
bool pkm_kacs_copy_up_allows_setxattr(const struct dentry *dentry,
				       const char *name);
bool pkm_kacs_copy_up_allows_capability_setxattr(
	const struct dentry *dentry);
bool pkm_kacs_copy_up_allows_capability_use(
	const struct user_namespace *target_ns);
bool pkm_kacs_copy_up_allows_listxattr(const struct dentry *dentry);

#ifdef CONFIG_SECURITY_PKM_KUNIT
struct pkm_kacs_stratafs_copy_up *
pkm_kacs_kunit_copy_up_begin_with_sd(const struct path *provider,
				      const u8 *sd_bytes, size_t sd_len);
#endif

#endif /* _SECURITY_PKM_KACS_COPY_UP_H */
