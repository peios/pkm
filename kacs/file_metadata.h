/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_FILE_METADATA_H
#define _SECURITY_PKM_KACS_FILE_METADATA_H

#include <linux/types.h>

struct cred;
struct file;
struct dentry;
struct file_kattr;
struct iattr;
struct inode;
struct mnt_idmap;
struct path;
struct posix_acl;

bool pkm_kacs_is_file_capability_xattr(const char *name);
int pkm_kacs_check_signed_exec_xattr_mutation(const struct inode *inode,
					      const char *name);

int pkm_kacs_inode_getattr(const struct path *path);
int pkm_kacs_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			   struct iattr *attr);
int pkm_kacs_inode_file_getattr(struct dentry *dentry, struct file_kattr *fa);
int pkm_kacs_inode_file_setattr(struct dentry *dentry, struct file_kattr *fa);
int pkm_kacs_inode_xattr_skipcap(const char *name);
int pkm_kacs_inode_getxattr(struct dentry *dentry, const char *name);
int pkm_kacs_inode_setxattr(struct mnt_idmap *idmap, struct dentry *dentry,
			    const char *name, const void *value, size_t size,
			    int flags);
void pkm_kacs_inode_post_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags);
int pkm_kacs_inode_removexattr(struct mnt_idmap *idmap, struct dentry *dentry,
			       const char *name);
int pkm_kacs_inode_listxattr(struct dentry *dentry);
int pkm_kacs_inode_copy_up(struct dentry *src, struct cred **new);
int pkm_kacs_inode_copy_up_xattr(struct dentry *src, const char *name);
int pkm_kacs_cred_set_pending_create_sd(struct cred *cred, u8 *sd_bytes,
					size_t sd_len);
bool pkm_kacs_pending_create_cred_sd(const u8 **bytes_out, size_t *len_out);
int pkm_kacs_inode_follow_link(struct dentry *dentry, struct inode *inode,
			       bool rcu);
int pkm_kacs_inode_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
			   const char *acl_name, struct posix_acl *kacl);
int pkm_kacs_inode_remove_acl(struct mnt_idmap *idmap, struct dentry *dentry,
			      const char *acl_name);
int pkm_kacs_inode_getsecurity(struct mnt_idmap *idmap, struct inode *inode,
			       const char *name, void **buffer, bool alloc);

void pkm_kacs_clear_current_file_metadata_decision(void);
bool pkm_kacs_consume_file_metadata_decision(const struct inode *inode,
					     u8 op_class);
bool pkm_kacs_has_file_metadata_decision(const struct inode *inode,
					 u8 op_class);

int pkm_kacs_file_sd_xattr_get(struct file *file, const char *name);
int pkm_kacs_file_sd_xattr_set(struct file *file, const char *name);
int pkm_kacs_file_sd_xattr_remove(struct file *file, const char *name);
int pkm_kacs_file_getattr(struct file *file);
int pkm_kacs_file_statfs(struct file *file);
int pkm_kacs_file_chmod(struct file *file);
int pkm_kacs_file_chown(struct file *file);
int pkm_kacs_file_utimens(struct file *file);
int pkm_kacs_file_fileattr_get(struct file *file);
int pkm_kacs_file_fileattr_set(struct file *file);
int pkm_kacs_file_truncate_metadata(struct file *file);
int pkm_kacs_file_listxattr(struct file *file);
void pkm_kacs_file_end_metadata(struct file *file);
int pkm_kacs_path_fileattr_set(const struct path *path);
void pkm_kacs_path_end_metadata(const struct path *path);
int pkm_kacs_path_access(const struct path *path, int mode);

#endif /* _SECURITY_PKM_KACS_FILE_METADATA_H */
