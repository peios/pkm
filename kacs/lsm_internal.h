/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_LSM_INTERNAL_H
#define _SECURITY_PKM_KACS_LSM_INTERNAL_H

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <net/sock.h>

#include "token_runtime.h"

#define PKM_KACS_MAX_SD_BYTES 65535U

struct pkm_kmes_rate_bucket;
struct pkm_kacs_stratafs_copy_up;

struct pkm_kacs_native_open_request {
	const struct dentry *expected_dentry;
	const struct vfsmount *expected_mnt;
	u32 desired_access;
	u32 create_options;
	bool active;
};

struct pkm_kacs_native_create_request {
	const struct inode *expected_parent_inode;
	const u8 *sd_bytes;
	size_t sd_len;
	bool directory;
	bool active;
};

struct pkm_kacs_native_open_prepared {
	u32 desired_access;
	u32 create_disposition;
	u32 status;
	u32 create_options;
	int open_flags;
	bool directory_required;
};

struct pkm_kacs_cred_security {
	const void *token;
	struct pkm_kacs_process_state *process_state;
	u32 projected_uid;
	u32 projected_gid;
};

enum pkm_kacs_inode_sd_state {
	PKM_KACS_INODE_SD_VALID = 1,
	PKM_KACS_INODE_SD_MISSING = 2,
	PKM_KACS_INODE_SD_CORRUPT = 3,
};

enum pkm_kacs_inode_sd_source {
	PKM_KACS_INODE_SD_SOURCE_XATTR = 1,
	PKM_KACS_INODE_SD_SOURCE_MISSING = 2,
	PKM_KACS_INODE_SD_SOURCE_SYNTHETIC = 3,
	PKM_KACS_INODE_SD_SOURCE_CORRUPT = 4,
	/*
	 * A synthesized SD on a SYNTHESIZE_PERSISTENT mount that has not yet
	 * been written back to the xattr. The write-back is deferred to a
	 * task_work that runs at return-to-userspace (no FACS/VFS locks held);
	 * see pkm_kacs_inode_queue_sd_persist(). Treated like SYNTHETIC for
	 * generation invalidation until the write-back promotes the on-disk
	 * xattr to a real SOURCE_XATTR entry on the next cache miss.
	 */
	PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING = 5,
};

struct pkm_kacs_inode_sd_cache {
	struct rcu_head rcu;
	refcount_t refs;
	const u8 *bytes;
	size_t len;
	struct kacs_rust_cached_sd_layout layout;
	u32 policy_generation;
	u8 state;
	u8 source;
};

struct pkm_kacs_superblock_security {
	struct mutex lock;
	const u8 *template_sd_bytes;
	size_t template_sd_len;
	u32 policy_generation;
	u8 mount_policy;
};

struct pkm_kacs_file_security {
	u32 granted_access;
	u32 continuous_audit_mask;
	struct pkm_kacs_stratafs_copy_up *copy_up_context;
	u64 copy_up_phase_generation;
	u8 managed;
	u8 delete_on_close;
	/*
	 * The token that armed delete-on-close, held by reference.
	 *
	 * PCSA §5.3 requires the deferred removal to be authorised against the
	 * token that *requested* it, captured when the request was made -- not
	 * against whoever happens to close the file. Arm and close can be
	 * arbitrarily far apart and in different tasks, so the reference lives
	 * as long as the file blob and is dropped in ->file_release.
	 */
	const void *delete_on_close_token;
};

struct pkm_kacs_backing_file_security {
	u32 granted_access;
	u32 continuous_audit_mask;
	u8 managed;
	u8 inherited;
};

struct pkm_kacs_file_write_intent {
	struct file *file;
	u32 rwf_flags;
	u8 active;
	u8 positioned;
};

enum pkm_kacs_file_metadata_op_class {
	PKM_KACS_METADATA_OP_NONE = 0,
	PKM_KACS_METADATA_OP_GETATTR = 1,
	PKM_KACS_METADATA_OP_SETATTR = 2,
	PKM_KACS_METADATA_OP_FILEATTR_GET = 3,
	PKM_KACS_METADATA_OP_FILEATTR_SET = 4,
	PKM_KACS_METADATA_OP_GETXATTR = 5,
	PKM_KACS_METADATA_OP_SETXATTR = 6,
};

struct pkm_kacs_file_metadata_decision {
	const struct inode *inode;
	struct file *file;
	u8 op_class;
	u8 active;
};

struct pkm_kacs_inode_security {
	struct mutex lock;
	struct pkm_kacs_inode_sd_cache __rcu *sd_cache;
	atomic_t delete_on_close_lineages;
	atomic_t signed_exec_pinned;
	/* Set under ->lock while a deferred SD persist task_work is in flight. */
	bool persist_work_queued;
#ifdef CONFIG_SECURITY_PKM_KUNIT
	bool kunit_fake_xattr_enabled;
	bool kunit_fake_xattr_fail_set;
	const u8 *kunit_fake_xattr_bytes;
	size_t kunit_fake_xattr_len;
	u32 kunit_unlink_calls;
#endif
};

struct pkm_kacs_process_sd {
	refcount_t refs;
	const u8 *bytes;
	size_t len;
};

struct pkm_kacs_socket_security {
	/*
	 * The conveyed-identity register: the peer identity associated with
	 * the data this end has consumed. Initialised at connect(), advanced
	 * as the reader's position passes each conveyed token. Guarded by
	 * register_lock; readers clone under the lock.
	 */
	const void *peer_token;
	spinlock_t register_lock;
	struct pkm_kacs_process_sd *socket_sd;
	u32 max_impersonation;
	/*
	 * KACS_SO_PASS_TOKEN sender-side cache: the effective token the last
	 * derivation was made from (pinned, so its address cannot be reused)
	 * and the derived peer token attached to every send. Guarded by
	 * convey_lock, a mutex because derivation allocates.
	 */
	bool pass_token;
	/* KACS_SO_IMPERSONATION_LEVEL was set explicitly (listener default) */
	bool level_set;
	/*
	 * The identity this listener conveys to connecting clients: captured
	 * from the effective token at listen(), replaced by KACS_SO_RESTAMP.
	 * Guarded by register_lock.
	 */
	const void *listener_token;
	struct mutex convey_lock;
	const void *convey_src;
	const void *convey_token;
	u32 convey_level;
};

struct pkm_kacs_process_state {
	refcount_t refs;
	spinlock_t mitigation_lock;
	struct mutex sd_lock;
	u8 process_guid[KACS_UUID_BYTES];
	u32 pip_type;
	u32 pip_trust;
	u32 mitigation_bits;
	struct pkm_kmes_rate_bucket *kmes_rate_bucket;
	struct pkm_kacs_process_sd *process_sd;
};

struct pkm_kacs_psb_activation_context {
	struct task_struct *task;
	bool offline_allowed;
	u32 kunit_fail_activation_bits;
};

struct pkm_kacs_task_security {
	/*
	 * Set on a usermodehelper child before it execs, so the exec path can
	 * apply the PeiosTcb floor to kernel-initiated execs only. Nothing
	 * upstream distinguishes them: the child is created by
	 * user_mode_thread(), so it never carries PF_KTHREAD, and
	 * security_kernel_module_request() fires in the requesting task before
	 * this one exists. See kernel/patches/kernel/umh-mark-usermodehelper.
	 *
	 * Deliberately never cleared. It is consumed at exec but left set, so a
	 * helper that re-execs -- an interpreter for a #! helper, say -- stays
	 * under the floor rather than stepping out from under it on the second
	 * exec. The task's only purpose is to be that helper.
	 */
	bool usermodehelper;
	struct pkm_kacs_process_state *process_state;
	struct pkm_kacs_stratafs_copy_up *copy_up_context;
	const struct file *delete_on_close_file;
	const struct inode *delete_on_close_parent_inode;
	const struct dentry *delete_on_close_dentry;
	const struct inode *delete_on_close_inode;
	const struct cred *impersonation_saved_cred;
	struct pkm_kacs_native_open_request native_open;
	struct pkm_kacs_native_create_request native_create;
	struct pkm_kacs_file_write_intent write_intent;
	struct pkm_kacs_file_metadata_decision metadata_decision;
	const void *stratafs_create_subject;
	const struct inode *stratafs_create_authority;
	const struct inode *stratafs_create_parent;
	const struct dentry *stratafs_create_dentry;
	const struct dentry *stratafs_create_link_source;
	const struct inode *stratafs_create_link_inode;
	u32 stratafs_create_access;
	u8 stratafs_create_state;
	const void *stratafs_supersede_subject;
	const struct dentry *stratafs_supersede_target;
	const struct inode *stratafs_supersede_target_inode;
	const struct dentry *stratafs_supersede_source;
	const struct inode *stratafs_supersede_source_inode;
	const struct file *stratafs_supersede_file;
	const struct inode *stratafs_supersede_old_parent;
	const struct dentry *stratafs_supersede_old_dentry;
	const struct inode *stratafs_supersede_old_inode;
	const struct inode *stratafs_supersede_new_parent;
	const struct dentry *stratafs_supersede_new_dentry;
	const struct inode *stratafs_supersede_new_inode;
	u8 stratafs_supersede_state;
	u8 stratafs_supersede_phase;
	const struct inode *stratafs_cleanup_parent;
	const struct dentry *stratafs_cleanup_dentry;
	const struct inode *stratafs_cleanup_inode;
	const struct dentry *stratafs_cleanup_outer;
	const struct inode *stratafs_cleanup_outer_inode;
	const void *stratafs_cleanup_subject;
	u32 pending_exec_pip_type;
	u32 pending_exec_pip_trust;
	u8 pending_exec_pip_valid;
	/*
	 * Counter (not flag) so nested internal SD reads compose. KACS's
	 * own SD-cache populate uses __vfs_getxattr to skip
	 * security_inode_getxattr, but a stacking FS (overlayfs) can route
	 * the call back through vfs_getxattr on the real lower/upper inode,
	 * re-entering the LSM hook. inode_getxattr checks this counter and
	 * allows the canonical SD xattr read iff it's > 0 — caller-originated
	 * syscalls still see the EACCES the spec mandates.
	 */
	u8 internal_sd_read_depth;
	/*
	 * Write-side analogue of internal_sd_read_depth. KACS's own SD-xattr
	 * write uses __vfs_setxattr_noperm to skip security_inode_setxattr,
	 * but a stacking FS (overlayfs) routes the write back through
	 * vfs_setxattr on the real lower/upper inode, re-entering the LSM
	 * hook. inode_setxattr checks this counter and allows the canonical
	 * SD xattr write iff it's > 0 — caller-originated syscalls still get
	 * the EACCES the spec mandates.
	 */
	u8 internal_sd_write_depth;
};

extern struct lsm_blob_sizes pkm_blob_sizes;

bool pkm_kacs_inode_on_sysfs_mount(const struct inode *inode);
bool pkm_kacs_inode_on_unmanaged_mount(const struct inode *inode);
long pkm_kacs_require_enabled_privilege(const void *subject_token,
					u64 privilege);
long pkm_kacs_unlink_delete_on_close_file(struct file *file);
struct pkm_kacs_inode_sd_cache *pkm_kacs_inode_sd_cache_get_current(
	const struct inode *inode, const struct pkm_kacs_inode_security *sec);
void pkm_kacs_inode_sd_cache_free(struct pkm_kacs_inode_sd_cache *cache);
int pkm_kacs_authorize_path_metadata_access(const struct path *path,
					    u32 desired_access);
int pkm_kacs_authorize_dentry_metadata_access(struct dentry *dentry,
					      u32 desired_access);

static inline struct pkm_kacs_cred_security *pkm_kacs_cred(const struct cred *cred)
{
	return (struct pkm_kacs_cred_security *)((char *)cred->security +
						 pkm_blob_sizes.lbs_cred);
}

static inline struct pkm_kacs_task_security *pkm_kacs_task(
	const struct task_struct *task)
{
	return (struct pkm_kacs_task_security *)((char *)task->security +
						 pkm_blob_sizes.lbs_task);
}

static inline struct pkm_kacs_socket_security *pkm_kacs_sock(
	const struct sock *sk)
{
	return (struct pkm_kacs_socket_security *)((char *)sk->sk_security +
						   pkm_blob_sizes.lbs_sock);
}

static inline struct pkm_kacs_inode_security *pkm_kacs_inode(
	const struct inode *inode)
{
	return (struct pkm_kacs_inode_security *)((char *)inode->i_security +
						  pkm_blob_sizes.lbs_inode);
}

static inline struct pkm_kacs_file_security *pkm_kacs_file(
	const struct file *file)
{
	return (struct pkm_kacs_file_security *)((char *)file->f_security +
						 pkm_blob_sizes.lbs_file);
}

static inline struct pkm_kacs_backing_file_security *pkm_kacs_backing_file(
	const struct file *file)
{
	void *blob = backing_file_security(file);

	return (struct pkm_kacs_backing_file_security *)
		((char *)blob + pkm_blob_sizes.lbs_backing_file);
}

static inline struct pkm_kacs_superblock_security *pkm_kacs_sb(
	const struct super_block *sb)
{
	return (struct pkm_kacs_superblock_security *)((char *)sb->s_security +
						       pkm_blob_sizes.lbs_superblock);
}

struct pkm_kacs_process_sd *pkm_kacs_process_sd_get(
	struct pkm_kacs_process_sd *process_sd);
struct pkm_kacs_process_sd *pkm_kacs_process_sd_wrap_bytes(
	const u8 *bytes, size_t len);
struct pkm_kacs_process_sd *pkm_kacs_process_sd_alloc(const void *token);
void pkm_kacs_process_sd_put(struct pkm_kacs_process_sd *process_sd);
struct pkm_kacs_process_sd *pkm_kacs_socket_sd_alloc(const void *token);

#endif /* _SECURITY_PKM_KACS_LSM_INTERNAL_H */
