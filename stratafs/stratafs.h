/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _STRATAFS_INTERNAL_H
#define _STRATAFS_INTERNAL_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kacs_stratafs.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/xarray.h>

#define STRATAFS_MAGIC STRATAFS_SUPER_MAGIC
#define STRATAFS_NAME "stratafs"
#define STRATAFS_MAX_STRATA 16U

#define STRATAFS_F_CREATE BIT(0)
#define STRATAFS_F_RO BIT(1)
#define STRATAFS_F_AM BIT(2)

#define STRATAFS_XATTR_PREFIX "system.stratafs."
#define STRATAFS_XATTR_ORIGIN "system.stratafs.origin"
#define STRATAFS_XATTR_STAGING STRATAFS_STAGING_XATTR
#define STRATAFS_STAGE_MARKER_MAGIC 0x53544731U
#define STRATAFS_STAGE_MARKER_VERSION 1U

enum stratafs_route {
	STRATAFS_ROUTE_IN_PLACE = 0,
	STRATAFS_ROUTE_COPY_UP = 1,
	STRATAFS_ROUTE_READ_ONLY = 2,
};

struct stratafs_stratum {
	char *path;
	u32 flags;
};

struct stratafs_identity {
	struct inode *inode;
	unsigned long number;
};

struct stratafs_staging {
	struct list_head list;
	char *relative;
};

struct stratafs_sb_info {
	unsigned int count;
	int create_index;
	struct stratafs_stratum strata[STRATAFS_MAX_STRATA];
	struct path resolution_root;
	const struct cred *resolution_cred;
	char *display_options;
	struct mutex identity_lock;
	struct xarray identities;
	atomic64_t next_ino;
	struct mutex staging_lock;
	struct list_head staging;
	atomic64_t next_stage;
	u64 boot_cookie;
	u64 mount_cookie;
	bool mount_registered;
};

struct stratafs_stage_marker {
	__le32 magic;
	__le16 version;
	__le16 size;
	__le64 boot_cookie;
	__le64 mount_cookie;
} __packed;

struct stratafs_paths;

struct stratafs_dentry_info {
	char *relative;
	struct path provider;
	struct stratafs_paths *settled_paths;
	unsigned int provider_index;
	bool has_provider;
	bool descriptor_view;
	bool settled_origin_read_allowed;
	bool unnamed;
};

struct stratafs_inode_info {
	struct mutex rebind_lock;
	struct inode *provider;
	char *relative;
	unsigned int provider_index;
};

struct stratafs_file_info {
	struct mutex mutation_lock;
	struct file *real;
	/* Keep the former provider alive for locks taken before copy-up. */
	struct file *retired_real;
	struct path provider;
	unsigned int provider_index;
};

struct stratafs_paths {
	struct path path[STRATAFS_MAX_STRATA];
	u64 present;
};

struct stratafs_fs_context {
	struct stratafs_sb_info *sbi;
	bool seen_strata;
};

#define STRATAFS_SB(sb) ((struct stratafs_sb_info *)(sb)->s_fs_info)

struct seq_file;

/*
 * Write the ",strata=..." the mount table reports, §7.3.
 *
 * Split out of ->show_options so it can be driven from a KUnit case with a
 * seq_file and an sbi, rather than a fabricated dentry and superblock.
 */
void stratafs_show_strata(struct seq_file *m, const struct stratafs_sb_info *sbi);
#define STRATAFS_I(inode) ((struct stratafs_inode_info *)(inode)->i_private)

extern const struct dentry_operations stratafs_dentry_operations;
extern const struct inode_operations stratafs_dir_inode_operations;
extern const struct inode_operations stratafs_file_inode_operations;
extern const struct inode_operations stratafs_symlink_inode_operations;
extern const struct inode_operations stratafs_special_inode_operations;
extern const struct file_operations stratafs_file_operations;
extern const struct file_operations stratafs_dir_operations;
extern const struct super_operations stratafs_super_operations;
extern const struct xattr_handler * const stratafs_xattr_handlers[];
ssize_t stratafs_listxattr(struct dentry *dentry, char *list, size_t size);

struct dentry *stratafs_lookup(struct inode *dir, struct dentry *dentry,
			       unsigned int flags);

int stratafs_parse_strata(struct stratafs_sb_info *sbi, const char *value);
int stratafs_validate_configuration(struct stratafs_sb_info *sbi);
void stratafs_free_sbi(struct stratafs_sb_info *sbi);
int stratafs_register_live_mount(struct stratafs_sb_info *sbi);
void stratafs_unregister_live_mount(struct stratafs_sb_info *sbi);
bool stratafs_stage_owner_live(u64 boot_cookie, u64 mount_cookie);
void stratafs_recover_staging_parent(struct super_block *sb,
				     const struct path *parent);
void stratafs_recover_published_marker(struct super_block *sb,
				       const struct path *path);

int stratafs_resolve_one(const struct super_block *sb, unsigned int index,
			 const char *relative, bool follow_final,
			 struct path *result);
int stratafs_resolve_all(const struct super_block *sb, const char *relative,
			 bool follow_final, struct stratafs_paths *paths);
void stratafs_put_paths(struct stratafs_paths *paths, unsigned int count);
int stratafs_provider_index(const struct stratafs_paths *paths,
			    unsigned int count);
char *stratafs_child_relative(const char *parent, const struct qstr *name);
char *stratafs_inode_relative(struct inode *inode);

struct inode *stratafs_new_inode(struct super_block *sb,
				 const struct path *provider,
				 unsigned int provider_index,
				 const char *relative);
void stratafs_refresh_inode(struct inode *inode, const struct path *provider);
int stratafs_detach_open_file(struct file *file, const struct path *provider,
			      unsigned int provider_index);
int stratafs_settle_open_directory(struct file *file,
				   const struct stratafs_paths *participants);
int stratafs_rebind_dentry(struct dentry *dentry,
			   const struct path *provider,
			   unsigned int provider_index);
int stratafs_rebind_open_file(struct file *file, const struct path *provider,
			      unsigned int provider_index);
int stratafs_copy_up_metadata_file(struct file *file, struct dentry *dentry,
				    struct path *provider,
				    unsigned int *provider_index);
unsigned long stratafs_provider_ino(struct super_block *sb,
				    struct inode *provider);
int stratafs_getattr(struct mnt_idmap *idmap, const struct path *path,
			     struct kstat *stat, u32 request_mask,
			     unsigned int flags);
int stratafs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			     struct iattr *attr);
int stratafs_notify_change(const struct path *provider,
			   const struct iattr *attr);

int stratafs_get_provider(struct dentry *dentry, struct path *path,
			  unsigned int *index);
bool stratafs_stratum_accepts(const struct super_block *sb,
			      unsigned int index,
			      const struct path *provider);
int stratafs_route_existing(const struct super_block *sb,
			    unsigned int provider_index,
			    const struct path *provider, bool copyable);
void stratafs_audit_refusal(const struct dentry *dentry,
			    const char *operation, int provider_index,
			    int result, bool deferred);

int stratafs_copy_up_file(struct file *file);
int stratafs_copy_up_path(struct dentry *dentry, struct path *result,
			  unsigned int *index);
int stratafs_ensure_create_parent(struct dentry *parent,
				  struct path *create_parent);
int stratafs_validate_supersede_dentry(const struct dentry *outer_target);
int stratafs_provider_directory(struct super_block *sb, const char *relative,
				struct path *provider);
bool stratafs_is_staging(const struct super_block *sb, unsigned int index,
			 const char *relative);
struct stratafs_staging *stratafs_add_staging(struct super_block *sb,
					       const char *relative);
void stratafs_remove_staging(struct super_block *sb,
			     struct stratafs_staging *staging);

int stratafs_check_directory_access(struct mnt_idmap *idmap,
				    struct inode *inode, int mask);
int stratafs_check_paths_access(const struct stratafs_paths *paths,
				unsigned int count, u32 access);

int stratafs_rust_validate_flags(const u32 *flags, size_t count,
				 int *create_index);
int stratafs_rust_provider(u64 present, size_t count);
int stratafs_rust_route_existing(size_t provider, bool provider_accepts,
				 int create_index, bool create_present,
				 bool copyable, bool mount_read_only);

#endif /* _STRATAFS_INTERNAL_H */
