/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_KACS_STRATAFS_H
#define _LINUX_KACS_STRATAFS_H

#include <linux/fs.h>
#include <linux/types.h>

struct cred;
struct dentry;
struct path;

#if IS_ENABLED(CONFIG_STRATAFS_FS)
int stratafs_kacs_creation_parent(const struct path *outer_parent,
				   struct path *security_parent);
int stratafs_kacs_removal_parent(const struct path *outer_target,
				  struct path *security_parent);
int stratafs_kacs_removal_target(const struct path *outer_target,
				  struct path *security_target);
int stratafs_kacs_validate_supersede(const struct path *outer_target);
/*
 * Audit a deferred deletion refused before stratafs's unlink was entered --
 * by the access check on the merged parent that precedes ->unlink. §4.6.5
 * audits a refused deferred deletion on any non-zero result (PEI-588).
 */
void stratafs_kacs_audit_deferred_refusal(const struct dentry *outer,
					  int result);
#endif

/* Fixed by PSD-011; shared with KACS so its mount policy is immutable. */
#define STRATAFS_SUPER_MAGIC 0x53545241UL
#define STRATAFS_STAGING_XATTR "security.peios.stratafs_staging"

/*
 * Typed, kernel-private interface for StrataFS copy-up.  These symbols are
 * intentionally not exported to modules and have no userspace representation.
 * All calls are sleeping process-context calls unless documented otherwise.
 */
struct pkm_kacs_stratafs_copy_up;

/* Evaluate one lower object's descriptor under StrataFS's deny-missing class. */
int pkm_kacs_stratafs_authorize_path(const struct path *path,
				     u32 desired_access);
int pkm_kacs_stratafs_begin_create_decision(const struct path *authority,
					     u32 desired_access);
int pkm_kacs_stratafs_set_native_create_decision(
	const struct path *authority, u32 desired_access);
int pkm_kacs_stratafs_bind_create_decision(const struct inode *provider_parent,
					    const struct dentry *target);
int pkm_kacs_stratafs_mark_unnamed_link(const struct dentry *source);
void pkm_kacs_stratafs_end_create_decision(void);
bool pkm_kacs_stratafs_is_descriptor_xattr(const struct inode *inode,
					   const char *name);
/*
 * The descriptor a root with no providing stratum root serves: owned by the
 * mounter, read and traverse for everyone. getxattr semantics (PEI-575).
 */
ssize_t pkm_kacs_stratafs_bare_root_descriptor(const struct cred *mounter,
					       void *buffer, size_t size);
void pkm_kacs_stratafs_audit_copy_up(const char *relative_path,
				     u32 provider_index,
				     const char *provider_stratum,
				     u32 create_index,
				     const char *create_stratum,
				     int result);
void pkm_kacs_stratafs_audit_mutation_refused(
	const char *relative_path, const char *operation, s32 provider_index,
	const char *provider_stratum, int result, bool deferred);
ssize_t pkm_kacs_stratafs_probe_staging_marker(const struct path *path,
					       void *buffer, size_t size);
bool pkm_kacs_stratafs_delete_on_close_active(const struct dentry *outer);
/*
 * Authorise a deferred removal against the providing stratum's directory,
 * using the token that armed delete-on-close. PCSA §5.3 step 3.
 */
int pkm_kacs_stratafs_delete_on_close_authorize_parent(
	const struct dentry *outer, const struct path *parent);
int pkm_kacs_stratafs_delete_on_close_bind_provider(
	const struct dentry *outer, const struct path *parent,
	struct dentry *target);
void pkm_kacs_stratafs_delete_on_close_unbind_provider(void);
int pkm_kacs_stratafs_rebind_metadata_decision(
	const struct inode *outer, const struct inode *provider);
struct file *pkm_kacs_stratafs_metadata_file(const struct inode *outer);
void pkm_kacs_stratafs_end_metadata_decision(const struct inode *provider);
int pkm_kacs_stratafs_rebind_native_create_request(
	const struct inode *outer_parent, const struct inode *provider_parent);
void pkm_kacs_stratafs_end_native_create_request(
	const struct inode *outer_parent, const struct inode *provider_parent);
int pkm_kacs_stratafs_begin_supersede(const struct dentry *outer_target);
int pkm_kacs_stratafs_bind_supersede_source(
	const struct dentry *outer_target, const struct dentry *outer_source);
int pkm_kacs_stratafs_bind_supersede_file(
	const struct dentry *outer_source, const struct dentry *outer_target,
	const struct file *outer_file);
const struct file *pkm_kacs_stratafs_supersede_file(
	const struct dentry *outer_source, const struct dentry *outer_target);
bool pkm_kacs_stratafs_supersede_active(
	const struct dentry *outer_source, const struct dentry *outer_target);
int pkm_kacs_stratafs_begin_supersede_unlink(
	const struct inode *parent, const struct dentry *target);
int pkm_kacs_stratafs_begin_supersede_rename(
	const struct inode *old_parent, const struct dentry *old_dentry,
	const struct inode *new_parent, const struct dentry *new_dentry);
void pkm_kacs_stratafs_end_supersede_phase(void);
void pkm_kacs_stratafs_end_supersede(void);
int pkm_kacs_stratafs_begin_created_cleanup(
	const struct inode *parent, const struct dentry *target);
int pkm_kacs_stratafs_arm_created_cleanup(const struct dentry *outer);
bool pkm_kacs_stratafs_created_cleanup_active(const struct dentry *outer);
void pkm_kacs_stratafs_end_created_cleanup(void);

struct pkm_kacs_stratafs_copy_up *
pkm_kacs_stratafs_copy_up_begin(const struct path *provider);
struct pkm_kacs_stratafs_copy_up *
pkm_kacs_stratafs_copy_up_get(struct pkm_kacs_stratafs_copy_up *context);
void pkm_kacs_stratafs_copy_up_put(
	struct pkm_kacs_stratafs_copy_up *context);

int pkm_kacs_stratafs_copy_up_enter(
	struct pkm_kacs_stratafs_copy_up *context);
void pkm_kacs_stratafs_copy_up_leave(
	struct pkm_kacs_stratafs_copy_up *context);

int pkm_kacs_stratafs_copy_up_begin_source_read(
	struct pkm_kacs_stratafs_copy_up *context);
int pkm_kacs_stratafs_copy_up_resume_source_directory(
	struct pkm_kacs_stratafs_copy_up *context, struct file *directory);
int pkm_kacs_stratafs_copy_up_begin_create(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *provider,
	const struct path *destination_parent,
	struct dentry *destination,
	umode_t mode);
int pkm_kacs_stratafs_copy_up_begin_anonymous_create(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *provider,
	const struct path *destination_parent,
	umode_t mode);
int pkm_kacs_stratafs_copy_up_bind_staging(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *staging);
int pkm_kacs_stratafs_copy_up_confirm_named_create(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *created_path);
int pkm_kacs_stratafs_copy_up_rebind_staging(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *published);
int pkm_kacs_stratafs_copy_up_adopt_backing_file(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct file *outer_file,
	struct file *backing_file);
int pkm_kacs_stratafs_copy_up_begin_populate(
	struct pkm_kacs_stratafs_copy_up *context);
int pkm_kacs_stratafs_copy_up_set_capability(
	struct pkm_kacs_stratafs_copy_up *context,
	const void *value,
	size_t size);
int pkm_kacs_stratafs_copy_up_begin_publish_link(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *destination_parent,
	struct dentry *destination);
int pkm_kacs_stratafs_copy_up_begin_publish_rename(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *destination_parent,
	struct dentry *destination);
int pkm_kacs_stratafs_copy_up_finish_publish(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *published);
int pkm_kacs_stratafs_copy_up_begin_cleanup(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *parent,
	struct dentry *victim,
	bool directory);
int pkm_kacs_stratafs_copy_up_begin_orphan_cleanup(
	struct pkm_kacs_stratafs_copy_up *context,
	const struct path *parent,
	struct dentry *victim,
	bool directory);
int pkm_kacs_stratafs_copy_up_begin_orphan_marker_cleanup(
	struct pkm_kacs_stratafs_copy_up *context);
void pkm_kacs_stratafs_copy_up_end_phase(
	struct pkm_kacs_stratafs_copy_up *context);

#endif /* _LINUX_KACS_STRATAFS_H */
