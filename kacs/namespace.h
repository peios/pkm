/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_NAMESPACE_H
#define _SECURITY_PKM_KACS_NAMESPACE_H

#include <linux/fs.h>
#include <linux/types.h>

struct dentry;
struct inode;
struct qstr;
struct xattr;

int pkm_kacs_inode_permission(struct inode *inode, int mask);
int pkm_kacs_inode_create(struct inode *dir, struct dentry *dentry,
			  umode_t mode);
int pkm_kacs_inode_link(struct dentry *old_dentry, struct inode *dir,
			struct dentry *new_dentry);
int pkm_kacs_inode_unlink(struct inode *dir, struct dentry *dentry);
int pkm_kacs_inode_symlink(struct inode *dir, struct dentry *dentry,
			   const char *old_name);
int pkm_kacs_inode_mkdir(struct inode *dir, struct dentry *dentry,
			 umode_t mode);
int pkm_kacs_inode_rmdir(struct inode *dir, struct dentry *dentry);
int pkm_kacs_inode_mknod(struct inode *dir, struct dentry *dentry,
			 umode_t mode, dev_t dev);
int pkm_kacs_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			  struct inode *new_dir, struct dentry *new_dentry);
int pkm_kacs_inode_readlink(struct dentry *dentry);
int pkm_kacs_inode_init_security(struct inode *inode, struct inode *dir,
				 const struct qstr *qstr, struct xattr *xattrs,
				 int *xattr_count);
int pkm_kacs_inode_rename_flags(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry,
				unsigned int flags);

long pkm_kacs_check_inode_permission_live_for_subject(
	const void *subject_token, struct inode *inode, struct dentry *dentry,
	int mask);
long pkm_kacs_authorize_inode_namespace_access_for_subject(
	const void *subject_token, struct inode *inode, struct dentry *dentry,
	u32 desired_access);
long pkm_kacs_authorize_namespace_create_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *child_dentry, bool directory);
long pkm_kacs_authorize_namespace_delete_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *target_dentry);
long pkm_kacs_authorize_namespace_symlink_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *child_dentry);
long pkm_kacs_authorize_namespace_link_for_subject(
	const void *subject_token, struct dentry *old_dentry, struct inode *dir,
	struct dentry *new_dentry);
long pkm_kacs_authorize_namespace_rename_for_subject(
	const void *subject_token, struct inode *old_dir,
	struct dentry *old_dentry, struct inode *new_dir,
	struct dentry *new_dentry);
long pkm_kacs_build_legacy_created_file_sd_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *parent_dentry, bool directory, const u8 **out_sd_ptr,
	size_t *out_sd_len);

#endif /* _SECURITY_PKM_KACS_NAMESPACE_H */
