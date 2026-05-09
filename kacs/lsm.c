// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM boot token/session substrate.
 *
 * Slices 21, 22, 25, and 42 add the first live credential blob, boot SYSTEM
 * token attachment, narrow public token-open surface, shared process state for
 * PIP/rate/SD, and the first process-boundary token-open syscall. Wider token
 * syscalls, impersonation install/revert, and broader process/object security
 * plumbing remain deliberately out of scope here.
 */

#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/falloc.h>
#include <linux/fcntl.h>
#include <linux/fiemap.h>
#include <linux/file.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/lsm_hooks.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/refcount.h>
#include <linux/pid.h>
#include <linux/pidfd.h>
#include <linux/prctl.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/un.h>
#include <linux/vmalloc.h>
#include <linux/xattr.h>

#include <asm/ioctls.h>
#include <asm/cpufeatures.h>

#include <net/sock.h>

#include "caap_cache.h"
#include "kmes.h"
#include "token_fd.h"
#include "token_runtime.h"

#define PKM_KACS_UNMAPPED_ID 65534U
#define PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS 10000U
#define PKM_KACS_PRIVILEGE_SE_LOCK_MEMORY (1ULL << 4)
#define PKM_KACS_PRIVILEGE_SE_CREATE_TOKEN (1ULL << 2)
#define PKM_KACS_PRIVILEGE_SE_INCREASE_QUOTA (1ULL << 5)
#define PKM_KACS_PRIVILEGE_SE_ASSIGN_PRIMARY (1ULL << 3)
#define PKM_KACS_PRIVILEGE_SE_TCB (1ULL << 7)
#define PKM_KACS_PRIVILEGE_SE_SECURITY (1ULL << 8)
#define PKM_KACS_PRIVILEGE_SE_LOAD_DRIVER (1ULL << 10)
#define PKM_KACS_PRIVILEGE_SE_SYSTEMTIME (1ULL << 12)
#define PKM_KACS_PRIVILEGE_SE_DEBUG (1ULL << 20)
#define PKM_KACS_PRIVILEGE_SE_SHUTDOWN (1ULL << 19)
#define PKM_KACS_PRIVILEGE_SE_INCREASE_BASE_PRIORITY (1ULL << 14)
#define PKM_KACS_PRIVILEGE_SE_AUDIT (1ULL << 21)
#define PKM_KACS_PRIVILEGE_SE_PROFILE_SINGLE_PROCESS (1ULL << 13)
#define PKM_KACS_PRIVILEGE_SE_RESTORE (1ULL << 18)
#define PKM_KACS_PRIVILEGE_SE_CHANGE_NOTIFY (1ULL << 23)
#define PKM_KACS_PRIVILEGE_SE_CREATE_SYMBOLIC_LINK (1ULL << 35)
#define PKM_KACS_PRIVILEGE_SE_BIND_PRIVILEGED_PORT (1ULL << 63)
#define PKM_KACS_TLP_MAX_PREFIXES 64U
#define PKM_KACS_TLP_MAX_PREFIX_LEN 4096U
#define PKM_KACS_LSM_PRLIMIT_READ 1U
#define PKM_KACS_LSM_PRLIMIT_WRITE 2U
#define PKM_KACS_SOCKET_FILE_WRITE_DATA 0x00000002U
#define PKM_KACS_PEER_TOKEN_ACCESS_MASK \
	(KACS_TOKEN_QUERY | KACS_TOKEN_IMPERSONATE)

#ifndef PTRACE_MODE_GETFD
#define PTRACE_MODE_GETFD 0x20
#endif

#ifndef PTRACE_MODE_PIDFD_OPEN
#define PTRACE_MODE_PIDFD_OPEN 0x40
#endif

#ifndef PTRACE_MODE_PROC_QUERY_LIMITED
#define PTRACE_MODE_PROC_QUERY_LIMITED 0x80
#endif

#ifndef PTRACE_MODE_PROC_QUERY_INFORMATION
#define PTRACE_MODE_PROC_QUERY_INFORMATION 0x100
#endif

#define OWNER_SECURITY_INFORMATION 0x00000001U
#define GROUP_SECURITY_INFORMATION 0x00000002U
#define DACL_SECURITY_INFORMATION 0x00000004U
#define SACL_SECURITY_INFORMATION 0x00000008U
#define LABEL_SECURITY_INFORMATION 0x00000010U
#define PKM_KACS_FILE_READ_DATA 0x00000001U
#define PKM_KACS_FILE_WRITE_DATA 0x00000002U
#define PKM_KACS_FILE_APPEND_DATA 0x00000004U
#define PKM_KACS_FILE_READ_EA 0x00000008U
#define PKM_KACS_FILE_WRITE_EA 0x00000010U
#define PKM_KACS_FILE_EXECUTE 0x00000020U
#define PKM_KACS_FILE_LIST_DIRECTORY PKM_KACS_FILE_READ_DATA
#define PKM_KACS_FILE_TRAVERSE PKM_KACS_FILE_EXECUTE
#define PKM_KACS_FILE_ADD_FILE PKM_KACS_FILE_WRITE_DATA
#define PKM_KACS_FILE_ADD_SUBDIRECTORY PKM_KACS_FILE_APPEND_DATA
#define PKM_KACS_FILE_READ_ATTRIBUTES 0x00000080U
#define PKM_KACS_FILE_WRITE_ATTRIBUTES 0x00000100U
#define PKM_KACS_FILE_DELETE_CHILD 0x00000040U
#define PKM_KACS_MAX_SD_BYTES 65536U
#define PKM_KACS_OPEN_HOW_MIN_SIZE 16U

#define PKM_KACS_SD_SUPPORTED_INFO                                             \
	(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |             \
	 DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |              \
	 LABEL_SECURITY_INFORMATION)
#define PKM_KACS_SD_ALLOWED_AT_FLAGS (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)
#define PKM_KACS_OPEN_ALLOWED_AT_FLAGS (AT_SYMLINK_NOFOLLOW)
#define PKM_KACS_FILE_DATA_RIGHTS                                             \
	(PKM_KACS_FILE_READ_DATA | PKM_KACS_FILE_WRITE_DATA |                \
	 PKM_KACS_FILE_APPEND_DATA)
#define PKM_KACS_DIRECTORY_MUTATION_RIGHTS                                     \
	(PKM_KACS_FILE_WRITE_DATA | PKM_KACS_FILE_APPEND_DATA |              \
	 PKM_KACS_FILE_DELETE_CHILD)

static atomic64_t pkm_kacs_native_supersede_tmp_counter = ATOMIC64_INIT(0);

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

struct pkm_kmes_rate_bucket {
	refcount_t refs;
	spinlock_t lock;
	u64 last_refill_ns;
	u32 tokens;
#ifdef CONFIG_SECURITY_PKM_KUNIT
	bool kunit_freeze_refill;
#endif
};

struct pkm_kacs_cred_security {
	const void *token;
	struct pkm_kacs_process_state *process_state;
	u32 projected_uid;
	u32 projected_gid;
};

struct pkm_kacs_process_sd {
	refcount_t refs;
	const u8 *bytes;
	size_t len;
};

enum pkm_kacs_inode_sd_state {
	PKM_KACS_INODE_SD_VALID = 1,
	PKM_KACS_INODE_SD_MISSING = 2,
	PKM_KACS_INODE_SD_CORRUPT = 3,
};

struct pkm_kacs_inode_sd_cache {
	struct rcu_head rcu;
	const u8 *bytes;
	size_t len;
	u8 state;
};

struct pkm_kacs_superblock_security {
	u8 mount_policy;
	const u8 *template_sd_bytes;
	size_t template_sd_len;
};

struct pkm_kacs_file_security {
	u32 granted_access;
	u32 continuous_audit_mask;
	u8 managed;
	u8 delete_on_close;
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
	u8 op_class;
	u8 active;
};

struct pkm_kacs_inode_security {
	struct mutex lock;
	struct pkm_kacs_inode_sd_cache __rcu *sd_cache;
	atomic_t delete_on_close_lineages;
#ifdef CONFIG_SECURITY_PKM_KUNIT
	bool kunit_fake_xattr_enabled;
	const u8 *kunit_fake_xattr_bytes;
	size_t kunit_fake_xattr_len;
	u32 kunit_unlink_calls;
#endif
};

struct pkm_kacs_process_state {
	refcount_t refs;
	spinlock_t mitigation_lock;
	struct mutex sd_lock;
	u32 pip_type;
	u32 pip_trust;
	u32 mitigation_bits;
	struct pkm_kmes_rate_bucket *kmes_rate_bucket;
	struct pkm_kacs_process_sd *process_sd;
};

struct pkm_kacs_task_security {
	struct pkm_kacs_process_state *process_state;
	const struct cred *impersonation_saved_cred;
	struct pkm_kacs_native_open_request native_open;
	struct pkm_kacs_native_create_request native_create;
	struct pkm_kacs_file_write_intent write_intent;
	struct pkm_kacs_file_metadata_decision metadata_decision;
};

struct pkm_kacs_socket_security {
	const void *peer_token;
	struct pkm_kacs_process_sd *socket_sd;
	u32 max_impersonation;
};

struct pkm_kacs_primary_install_prepare {
	struct cred *new_real;
	struct cred *new_effective;
};

struct pkm_kacs_primary_install_work {
	struct callback_head twork;
	const void *token;
	struct task_struct *task;
};

struct pkm_kacs_primary_install_batch {
	struct pkm_kacs_primary_install_work **works;
	size_t count;
};

extern int kacs_rust_init(void);

static const struct lsm_id pkm_lsmid = {
	.name = "pkm",
	.id = 1000,
};
static const void *pkm_kacs_boot_system_token;
static struct dentry *pkm_kacs_securityfs_dir;
static struct dentry *pkm_kacs_securityfs_self;
static struct dentry *pkm_kacs_securityfs_sessions;
static DEFINE_MUTEX(pkm_kacs_tlp_cache_lock);
static char *pkm_kacs_tlp_prefixes[PKM_KACS_TLP_MAX_PREFIXES];
static size_t pkm_kacs_tlp_prefix_lens[PKM_KACS_TLP_MAX_PREFIXES];
static u32 pkm_kacs_tlp_prefix_count;

static struct lsm_blob_sizes pkm_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct pkm_kacs_cred_security),
	.lbs_task = sizeof(struct pkm_kacs_task_security),
	.lbs_sock = sizeof(struct pkm_kacs_socket_security),
	.lbs_file = sizeof(struct pkm_kacs_file_security),
	.lbs_inode = sizeof(struct pkm_kacs_inode_security),
	.lbs_superblock = sizeof(struct pkm_kacs_superblock_security),
	.lbs_xattr_count = 1,
};

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

static inline struct pkm_kacs_superblock_security *pkm_kacs_sb(
	const struct super_block *sb)
{
	return (struct pkm_kacs_superblock_security *)((char *)sb->s_security +
						       pkm_blob_sizes.lbs_superblock);
}

static struct pkm_kacs_process_state *pkm_kacs_process_state_get(
	struct pkm_kacs_process_state *state);
static void pkm_kacs_process_state_put(struct pkm_kacs_process_state *state);

static struct pkm_kacs_process_sd *pkm_kacs_process_sd_get(
	struct pkm_kacs_process_sd *process_sd)
{
	if (process_sd)
		refcount_inc(&process_sd->refs);
	return process_sd;
}

static void pkm_kacs_set_cred_process_state(struct cred *cred,
					    struct pkm_kacs_process_state *state)
{
	struct pkm_kacs_cred_security *sec;

	if (!cred)
		return;

	sec = pkm_kacs_cred(cred);
	if (sec->process_state == state)
		return;
	if (sec->process_state)
		pkm_kacs_process_state_put(sec->process_state);
	sec->process_state = state ? pkm_kacs_process_state_get(state) : NULL;
}

static int pkm_kacs_task_kill(struct task_struct *target,
			      struct kernel_siginfo *info, int sig,
			      const struct cred *cred);
static int pkm_kacs_ptrace_access_check(struct task_struct *child,
					unsigned int mode);
static int pkm_kacs_task_setnice(struct task_struct *task, int nice);
static int pkm_kacs_task_setscheduler(struct task_struct *task);
static int pkm_kacs_task_setioprio(struct task_struct *task, int ioprio);
static int pkm_kacs_task_fix_setuid(struct cred *new, const struct cred *old,
				    int flags);
static int pkm_kacs_task_fix_setgid(struct cred *new, const struct cred *old,
				    int flags);
static int pkm_kacs_task_fix_setgroups(struct cred *new,
				       const struct cred *old);
static long pkm_kacs_create_session_core(const void *subject_token,
					 const u8 *spec, size_t spec_len,
					 u64 *session_id_out);
static long pkm_kacs_create_token_core(const void *subject_token,
				       const u8 *spec, size_t spec_len);
static int pkm_kacs_task_prlimit(const struct cred *cred,
				 const struct cred *tcred,
				 unsigned int flags);
static int pkm_kacs_capset(struct cred *new, const struct cred *old,
			   const kernel_cap_t *effective,
			   const kernel_cap_t *inheritable,
			   const kernel_cap_t *permitted);
static int pkm_kacs_capable(const struct cred *cred,
			    struct user_namespace *target_ns, int cap,
			    unsigned int opts);
static int pkm_kacs_inode_alloc_security(struct inode *inode);
static int pkm_kacs_file_alloc_security(struct file *file);
static void pkm_kacs_file_release(struct file *file);
static void pkm_kacs_sb_free_security(struct super_block *sb);
static void pkm_kacs_inode_free_security_rcu(void *inode_security);
static int pkm_kacs_sb_alloc_security(struct super_block *sb);
static struct pkm_kacs_inode_sd_cache *pkm_kacs_inode_sd_cache_alloc(
	u8 state, const u8 *bytes, size_t len);
static int pkm_kacs_inode_getxattr(struct dentry *dentry, const char *name);
static int pkm_kacs_inode_setxattr(struct mnt_idmap *idmap,
				   struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags);
static int pkm_kacs_inode_removexattr(struct mnt_idmap *idmap,
				      struct dentry *dentry,
				      const char *name);
static int pkm_kacs_inode_getattr(const struct path *path);
static int pkm_kacs_inode_setattr(struct mnt_idmap *idmap,
				  struct dentry *dentry,
				  struct iattr *attr);
static int pkm_kacs_inode_file_getattr(struct dentry *dentry,
				       struct file_kattr *fa);
static int pkm_kacs_inode_file_setattr(struct dentry *dentry,
				       struct file_kattr *fa);
static int pkm_kacs_inode_listxattr(struct dentry *dentry);
static int pkm_kacs_inode_permission(struct inode *inode, int mask);
static int pkm_kacs_inode_create(struct inode *dir, struct dentry *dentry,
				 umode_t mode);
static int pkm_kacs_inode_link(struct dentry *old_dentry, struct inode *dir,
			       struct dentry *new_dentry);
static int pkm_kacs_inode_unlink(struct inode *dir, struct dentry *dentry);
static int pkm_kacs_inode_symlink(struct inode *dir, struct dentry *dentry,
				  const char *old_name);
static int pkm_kacs_inode_mkdir(struct inode *dir, struct dentry *dentry,
				umode_t mode);
static int pkm_kacs_inode_rmdir(struct inode *dir, struct dentry *dentry);
static int pkm_kacs_inode_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev);
static int pkm_kacs_inode_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry);
static int pkm_kacs_inode_readlink(struct dentry *dentry);
static int pkm_kacs_inode_init_security(struct inode *inode,
					struct inode *dir,
					const struct qstr *qstr,
					struct xattr *xattrs,
					int *xattr_count);
static int pkm_kacs_file_open(struct file *file);
static int pkm_kacs_file_permission(struct file *file, int mask);
static int pkm_kacs_file_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg);
static int pkm_kacs_file_ioctl_compat(struct file *file, unsigned int cmd,
				      unsigned long arg);
static int pkm_kacs_file_lock(struct file *file, unsigned int cmd);
static int pkm_kacs_file_fcntl(struct file *file, unsigned int cmd,
			       unsigned long arg);
static int pkm_kacs_file_truncate(struct file *file);
int pkm_kacs_file_begin_write_intent(struct file *file, u32 rwf_flags,
				     bool positioned);
void pkm_kacs_file_end_write_intent(struct file *file);
static int pkm_kacs_sk_alloc_security(struct sock *sk, int family,
				      gfp_t priority);
static void pkm_kacs_sk_free_security(struct sock *sk);
static int pkm_kacs_socket_bind(struct socket *sock, struct sockaddr *address,
				int addrlen);
static int pkm_kacs_unix_stream_connect(struct sock *sock,
					struct sock *other,
					struct sock *newsk);
static int pkm_kacs_unix_may_send(struct socket *sock, struct socket *other);
static int pkm_kacs_task_prctl(int option, unsigned long arg2,
			       unsigned long arg3, unsigned long arg4,
			       unsigned long arg5);
static int pkm_kacs_mmap_file(struct file *file, unsigned long reqprot,
			      unsigned long prot, unsigned long flags);
static int pkm_kacs_file_mprotect(struct vm_area_struct *vma,
				  unsigned long reqprot,
				  unsigned long prot);
static int pkm_kacs_check_mmap_snapshot(struct file *file,
					unsigned long prot,
					unsigned long flags);
static int pkm_kacs_check_mprotect_snapshot(struct file *file,
					    unsigned long vm_flags,
					    unsigned long prot);
static int pkm_kacs_check_file_snapshot_grant(struct file *file,
					      u32 required_access);
static int pkm_kacs_check_file_permission_snapshot(struct file *file,
						   int mask);
static bool pkm_kacs_inode_on_unmanaged_mount(const struct inode *inode);
static int pkm_kacs_authorize_path_metadata_access(const struct path *path,
						   u32 desired_access);
static int pkm_kacs_authorize_dentry_metadata_access(struct dentry *dentry,
						     u32 desired_access);
static bool pkm_kacs_consume_file_metadata_decision(
	const struct inode *inode, u8 op_class);
static bool pkm_kacs_has_file_metadata_decision(
	const struct inode *inode, u8 op_class);
static int pkm_kacs_check_file_write_intent_snapshot(struct file *file,
						     u32 rwf_flags,
						     bool positioned);
static int pkm_kacs_check_file_ioctl_snapshot(struct file *file,
					      unsigned int cmd,
					      unsigned long arg,
					      bool compat);
static int pkm_kacs_check_file_lock_snapshot(struct file *file,
					     unsigned int cmd);
static int pkm_kacs_check_file_fcntl_snapshot(struct file *file,
					      unsigned int cmd,
					      unsigned long arg);
static int pkm_kacs_check_file_truncate_snapshot(struct file *file);
static int pkm_kacs_check_file_fallocate_snapshot(struct file *file,
						  int mode);
static long pkm_kacs_check_inode_permission_live_for_subject(
	const void *subject_token, struct inode *inode, struct dentry *dentry,
	int mask);
int pkm_kacs_inode_rename_flags(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry,
				unsigned int flags);
static int pkm_kacs_bprm_check_security(struct linux_binprm *bprm);
static int pkm_kacs_bprm_creds_from_file(struct linux_binprm *bprm,
					 const struct file *file);
static long pkm_kacs_check_process_setinfo_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state);
static long pkm_kacs_check_process_affinity_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state);
static long pkm_kacs_revert_current_impersonation(void);
static void pkm_kacs_free_primary_install_work(
	struct pkm_kacs_primary_install_work *work);
static long pkm_kacs_get_sd_required_access(u32 security_info,
					    u32 *desired_access_out);
static long pkm_kacs_set_sd_required_access(u32 security_info,
					    u32 *desired_access_out);
static void pkm_kacs_init_path_anchor_file(struct file *file,
					   const struct path *path);
static long pkm_kacs_copy_open_how_from_user(
	struct kacs_open_how *out,
	const struct kacs_open_how __user *uhow, size_t howsize);
static long pkm_kacs_map_file_generic_access_mask(u32 desired,
						  u32 *mapped_out);
static long pkm_kacs_prepare_native_open(
	const struct kacs_open_how *how,
	struct pkm_kacs_native_open_prepared *prepared);
static long pkm_kacs_maybe_arm_delete_on_close_for_subject(
	const void *subject_token, struct file *file, u32 create_options);
static bool pkm_kacs_file_delete_on_close_pending(const struct file *file);
static long pkm_kacs_unlink_delete_on_close_file(struct file *file);
static long pkm_kacs_copy_creator_sd_from_user(
	const struct kacs_open_how *how,
	u8 **creator_sd_bytes_out,
	size_t *creator_sd_len_out);
static long pkm_kacs_resolve_native_open_path(
	int dirfd, const char __user *path,
	const struct pkm_kacs_native_open_prepared *prepared,
	u32 lookup_flags, struct path *resolved_path);
static void pkm_kacs_set_current_native_open_request(
	const struct path *path, u32 desired_access, u32 create_options);
static void pkm_kacs_clear_current_native_open_request(void);
static bool pkm_kacs_native_open_request_matches(struct file *file,
						 u32 *desired_access_out,
						 u32 *create_options_out);
static void pkm_kacs_set_current_native_create_request(
	const struct inode *parent_inode, bool directory, const u8 *sd_bytes,
	size_t sd_len);
static void pkm_kacs_clear_current_native_create_request(void);
static bool pkm_kacs_current_native_create_request_matches(
	const struct inode *parent_inode, bool directory,
	const u8 **sd_bytes_out, size_t *sd_len_out);
static umode_t pkm_kacs_native_create_mode(bool directory);
static long pkm_kacs_build_created_file_sd_for_subject(
	const void *subject_token, struct file *parent_file,
	const u8 *creator_sd_ptr, size_t creator_sd_len, bool directory,
	u32 desired_access, const u8 **out_sd_ptr, size_t *out_sd_len,
	u32 *granted_access_out);
static long pkm_kacs_do_native_create_open(
	int dirfd, const char __user *path,
	const struct kacs_open_how *how,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out);
static long pkm_kacs_authorize_live_file_access_core(
	const void *subject_token, struct file *file, u32 desired_access);
static long pkm_kacs_authorize_path_file_access_core(
	const void *subject_token, const struct path *path, u32 desired_access);
static long pkm_kacs_open_native_existing_path(
	const struct path *resolved_path,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out);
static long pkm_kacs_do_native_overwrite_open(
	const struct path *resolved_path,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out);
static long pkm_kacs_do_native_supersede_open(
	const void *subject_token, const struct path *resolved_path,
	const struct kacs_open_how *how,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out);
static long pkm_kacs_path_sd_lookup_flags(u32 flags,
					  unsigned int *lookup_flags_out);
static long pkm_kacs_open_path_lookup_flags(u32 flags,
					    unsigned int *lookup_flags_out);
static long pkm_kacs_query_process_sd_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state, bool self_target,
	u32 security_info, const u8 **out_sd_ptr, size_t *out_sd_len);
static long pkm_kacs_set_process_sd_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct pkm_kacs_process_state *target_state, bool self_target,
	u32 security_info, const u8 *input_sd_ptr, size_t input_sd_len);
static long pkm_kacs_inode_write_sd_xattr_locked(struct file *file,
						 const u8 *sd_bytes,
						 size_t sd_len);
static long pkm_kacs_query_file_sd_core(const void *subject_token,
					struct file *file, u32 security_info,
					const u8 **out_sd_ptr,
					size_t *out_sd_len);
static long pkm_kacs_stamp_native_file_granted_access_for_subject(
	const void *subject_token, struct file *file, u32 desired_access);
static long pkm_kacs_set_file_sd_core(const void *subject_token,
				      struct file *file, u32 security_info,
				      const u8 *input_sd_ptr,
				      size_t input_sd_len);
static void pkm_kacs_init_path_anchor_file(struct file *file,
					   const struct path *path);
static long pkm_kacs_query_path_file_sd_core(const void *subject_token,
					     const struct path *path,
					     u32 security_info,
					     const u8 **out_sd_ptr,
					     size_t *out_sd_len);
static long pkm_kacs_set_path_file_sd_core(const void *subject_token,
					   const struct path *path,
					   u32 security_info,
					   const u8 *input_sd_ptr,
					   size_t input_sd_len);
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
int pkm_kacs_file_listxattr(struct file *file);
void pkm_kacs_file_end_metadata(struct file *file);
int pkm_kacs_path_fileattr_set(const struct path *path);
void pkm_kacs_path_end_metadata(const struct path *path);
int pkm_kacs_path_access(const struct path *path, int mode);
long pkm_kacs_capable_in_cred_ns(const struct cred *cred,
				 struct user_namespace *target_ns, int cap,
				 unsigned int opts);
long pkm_kacs_prctl_capability_guard(int option, unsigned long arg2,
				     unsigned long arg3,
				     unsigned long arg4,
				     unsigned long arg5);
long pkm_kacs_sched_setaffinity(struct task_struct *task);

static struct pkm_kacs_process_sd *pkm_kacs_process_sd_wrap_bytes(
	const u8 *bytes, size_t len)
{
	struct pkm_kacs_process_sd *process_sd;

	if (!bytes || !len)
		return NULL;

	process_sd = kzalloc(sizeof(*process_sd), GFP_KERNEL);
	if (!process_sd)
		return NULL;

	refcount_set(&process_sd->refs, 1);
	process_sd->bytes = bytes;
	process_sd->len = len;
	return process_sd;
}

static struct pkm_kacs_process_sd *pkm_kacs_process_sd_alloc(const void *token)
{
	size_t len = 0;
	const u8 *bytes;

	if (!token)
		return NULL;

	bytes = kacs_rust_create_default_process_sd(token, &len);
	if (!bytes || len == 0)
		return NULL;

	return pkm_kacs_process_sd_wrap_bytes(bytes, len);
}

static struct pkm_kacs_process_sd *pkm_kacs_socket_sd_alloc(const void *token)
{
	size_t len = 0;
	const u8 *bytes;

	if (!token)
		return NULL;

	bytes = kacs_rust_create_default_socket_sd(token, &len);
	if (!bytes || len == 0)
		return NULL;

	return pkm_kacs_process_sd_wrap_bytes(bytes, len);
}

static void pkm_kacs_process_sd_put(struct pkm_kacs_process_sd *process_sd)
{
	if (!process_sd)
		return;
	if (!refcount_dec_and_test(&process_sd->refs))
		return;

	if (process_sd->bytes)
		pkm_kacs_free((void *)process_sd->bytes);
	kfree(process_sd);
}

static u32 pkm_kacs_mount_policy_for_magic(unsigned long magic)
{
	switch (magic) {
	case PROC_SUPER_MAGIC:
	case SYSFS_MAGIC:
		return PKM_KACS_MOUNT_POLICY_UNMANAGED;
	case NFS_SUPER_MAGIC:
	case MSDOS_SUPER_MAGIC:
	case EXFAT_SUPER_MAGIC:
		return PKM_KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
	default:
		return PKM_KACS_MOUNT_POLICY_DENY_MISSING;
	}
}

static u32 pkm_kacs_superblock_mount_policy(const struct super_block *sb)
{
	struct pkm_kacs_superblock_security *sec;

	if (!sb)
		return PKM_KACS_MOUNT_POLICY_DENY_MISSING;
	if (!sb->s_security)
		return pkm_kacs_mount_policy_for_magic(sb->s_magic);

	sec = pkm_kacs_sb(sb);
	switch (sec->mount_policy) {
	case PKM_KACS_MOUNT_POLICY_UNMANAGED:
	case PKM_KACS_MOUNT_POLICY_DENY_MISSING:
	case PKM_KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL:
	case PKM_KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT:
		return sec->mount_policy;
	default:
		return pkm_kacs_mount_policy_for_magic(sb->s_magic);
	}
}

static bool pkm_kacs_mount_policy_is_managed(u32 mount_policy)
{
	return mount_policy == PKM_KACS_MOUNT_POLICY_DENY_MISSING ||
	       mount_policy == PKM_KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL ||
	       mount_policy == PKM_KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT;
}

static void pkm_kacs_superblock_template_sd(const struct super_block *sb,
					    const u8 **sd_ptr_out,
					    size_t *sd_len_out)
{
	struct pkm_kacs_superblock_security *sec;

	if (sd_ptr_out)
		*sd_ptr_out = NULL;
	if (sd_len_out)
		*sd_len_out = 0;
	if (!sb || !sd_ptr_out || !sd_len_out || !sb->s_security)
		return;

	sec = pkm_kacs_sb(sb);
	if (!sec->template_sd_bytes || sec->template_sd_len == 0)
		return;

	*sd_ptr_out = sec->template_sd_bytes;
	*sd_len_out = sec->template_sd_len;
}

static long pkm_kacs_missing_file_sd_policy_result(
	const struct super_block *sb,
	struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct pkm_kacs_inode_sd_cache *cache;
	u32 policy;

	if (!cache_out)
		return -EINVAL;

	policy = pkm_kacs_superblock_mount_policy(sb);
	switch (policy) {
	case PKM_KACS_MOUNT_POLICY_DENY_MISSING:
	case PKM_KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL:
	case PKM_KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT:
		cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_MISSING,
						      NULL, 0);
		if (!cache)
			return -ENOMEM;
		*cache_out = cache;
		return 0;
	case PKM_KACS_MOUNT_POLICY_UNMANAGED:
	default:
		return -EOPNOTSUPP;
	}
}

static bool pkm_kacs_inode_is_ntfs(const struct inode *inode)
{
	return inode && inode->i_sb && inode->i_sb->s_type &&
	       inode->i_sb->s_type->name &&
	       strcmp(inode->i_sb->s_type->name, "ntfs3") == 0;
}

static const char *pkm_kacs_inode_sd_xattr_name(const struct inode *inode)
{
	if (pkm_kacs_inode_is_ntfs(inode))
		return "system.ntfs_security";

	return "security.peios.sd";
}

static bool pkm_kacs_is_canonical_sd_xattr(const struct inode *inode,
					   const char *name)
{
	if (!name)
		return false;
	if (strcmp(name, "security.peios.sd") == 0)
		return true;
	if (pkm_kacs_inode_is_ntfs(inode) &&
	    strcmp(name, "system.ntfs_security") == 0)
		return true;

	return false;
}

static struct pkm_kacs_inode_sd_cache *pkm_kacs_inode_sd_cache_alloc(
	u8 state, const u8 *bytes, size_t len)
{
	struct pkm_kacs_inode_sd_cache *cache;

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache)
		return NULL;

	cache->state = state;
	cache->bytes = bytes;
	cache->len = len;
	return cache;
}

static void pkm_kacs_inode_sd_cache_free(
	struct pkm_kacs_inode_sd_cache *cache)
{
	if (!cache)
		return;
	if (cache->bytes)
		pkm_kacs_free((void *)cache->bytes);
	kfree(cache);
}

static void pkm_kacs_inode_sd_cache_free_rcu(struct rcu_head *rcu)
{
	struct pkm_kacs_inode_sd_cache *cache;

	cache = container_of(rcu, struct pkm_kacs_inode_sd_cache, rcu);
	pkm_kacs_inode_sd_cache_free(cache);
}

static void pkm_kacs_inode_replace_sd_cache_locked(
	struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache *new_cache)
{
	struct pkm_kacs_inode_sd_cache *old_cache;

	old_cache = rcu_dereference_protected(sec->sd_cache,
					      lockdep_is_held(&sec->lock));
	rcu_assign_pointer(sec->sd_cache, new_cache);
	if (old_cache)
		call_rcu(&old_cache->rcu, pkm_kacs_inode_sd_cache_free_rcu);
}

static int pkm_kacs_inode_alloc_security(struct inode *inode)
{
	struct pkm_kacs_inode_security *sec;

	if (!inode || !inode->i_security)
		return -EINVAL;

	sec = pkm_kacs_inode(inode);
	mutex_init(&sec->lock);
	RCU_INIT_POINTER(sec->sd_cache, NULL);
	atomic_set(&sec->delete_on_close_lineages, 0);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	sec->kunit_fake_xattr_enabled = false;
	sec->kunit_fake_xattr_bytes = NULL;
	sec->kunit_fake_xattr_len = 0;
	sec->kunit_unlink_calls = 0;
#endif
	return 0;
}

static int pkm_kacs_file_alloc_security(struct file *file)
{
	struct pkm_kacs_file_security *sec;

	if (!file || !file->f_security)
		return 0;

	sec = pkm_kacs_file(file);
	sec->granted_access = 0;
	sec->continuous_audit_mask = 0;
	sec->managed = 0;
	sec->delete_on_close = 0;
	return 0;
}

static void pkm_kacs_file_release(struct file *file)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct inode *inode;
	long ret;

	if (!file || !file->f_security)
		return;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->delete_on_close)
		return;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return;

	inode_sec = pkm_kacs_inode(inode);
	ret = pkm_kacs_unlink_delete_on_close_file(file);
	if (ret && ret != -ENOENT)
		pr_warn("pkm: delete-on-close unlink failed (%ld)\n", ret);

	mutex_lock(&inode_sec->lock);
	if (atomic_read(&inode_sec->delete_on_close_lineages) > 0)
		atomic_dec(&inode_sec->delete_on_close_lineages);
	file_sec->delete_on_close = 0;
	mutex_unlock(&inode_sec->lock);
}

static int pkm_kacs_sb_alloc_security(struct super_block *sb)
{
	struct pkm_kacs_superblock_security *sec;

	if (!sb || !sb->s_security)
		return 0;

	sec = pkm_kacs_sb(sb);
	sec->mount_policy = pkm_kacs_mount_policy_for_magic(sb->s_magic);
	sec->template_sd_bytes = NULL;
	sec->template_sd_len = 0;
	return 0;
}

static void pkm_kacs_sb_free_security(struct super_block *sb)
{
	struct pkm_kacs_superblock_security *sec;

	if (!sb || !sb->s_security)
		return;

	sec = pkm_kacs_sb(sb);
	if (sec->template_sd_bytes)
		pkm_kacs_free((void *)sec->template_sd_bytes);
	sec->template_sd_bytes = NULL;
	sec->template_sd_len = 0;
}

static void pkm_kacs_inode_free_security_rcu(void *inode_security)
{
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache;

	if (!inode_security)
		return;

	sec = (struct pkm_kacs_inode_security *)((char *)inode_security +
						 pkm_blob_sizes.lbs_inode);
	cache = rcu_dereference_protected(sec->sd_cache, 1);
	RCU_INIT_POINTER(sec->sd_cache, NULL);
	atomic_set(&sec->delete_on_close_lineages, 0);
	pkm_kacs_inode_sd_cache_free(cache);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec->kunit_fake_xattr_bytes)
		kfree(sec->kunit_fake_xattr_bytes);
	sec->kunit_fake_xattr_bytes = NULL;
	sec->kunit_fake_xattr_len = 0;
	sec->kunit_fake_xattr_enabled = false;
	sec->kunit_unlink_calls = 0;
#endif
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static ssize_t pkm_kacs_kunit_fake_getxattr_locked(
	struct pkm_kacs_inode_security *sec, void *buffer, size_t size)
{
	if (!sec->kunit_fake_xattr_enabled)
		return -EOPNOTSUPP;
	if (!sec->kunit_fake_xattr_bytes || sec->kunit_fake_xattr_len == 0)
		return -ENODATA;
	if (!buffer)
		return (ssize_t)sec->kunit_fake_xattr_len;
	if (size < sec->kunit_fake_xattr_len)
		return -ERANGE;

	memcpy(buffer, sec->kunit_fake_xattr_bytes, sec->kunit_fake_xattr_len);
	return (ssize_t)sec->kunit_fake_xattr_len;
}

static long pkm_kacs_kunit_fake_setxattr_locked(
	struct pkm_kacs_inode_security *sec, const u8 *sd_bytes, size_t sd_len)
{
	const u8 *copied_bytes;

	if (!sec->kunit_fake_xattr_enabled)
		return -EOPNOTSUPP;
	if (!sd_bytes || sd_len == 0)
		return -EINVAL;

	copied_bytes = kmemdup(sd_bytes, sd_len, GFP_KERNEL);
	if (!copied_bytes)
		return -ENOMEM;

	kfree(sec->kunit_fake_xattr_bytes);
	sec->kunit_fake_xattr_bytes = copied_bytes;
	sec->kunit_fake_xattr_len = sd_len;
	return 0;
}
#endif

static long pkm_kacs_inode_read_sd_xattr_locked(
	struct file *file, struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct dentry *dentry;
	struct inode *inode;
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	const char *name;
	u8 *bytes = NULL;
	ssize_t len;
	int ret;

	if (!file || !cache_out)
		return -EINVAL;

	dentry = file_dentry(file);
	inode = file_inode(file);
	if (!dentry || !inode)
		return -EACCES;
	sec = inode->i_security ? pkm_kacs_inode(inode) : NULL;

	name = pkm_kacs_inode_sd_xattr_name(inode);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec && sec->kunit_fake_xattr_enabled)
		len = pkm_kacs_kunit_fake_getxattr_locked(sec, NULL, 0);
	else
#endif
	len = __vfs_getxattr(dentry, inode, name, NULL, 0);
	if (len == -ENODATA || len == -EOPNOTSUPP)
		return pkm_kacs_missing_file_sd_policy_result(inode->i_sb,
							      cache_out);
	if (len < 0)
		return len;
	if (len == 0 || len > PKM_KACS_MAX_SD_BYTES) {
		cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_CORRUPT,
						      NULL, 0);
		if (!cache)
			return -ENOMEM;
		*cache_out = cache;
		return 0;
	}

	bytes = pkm_kacs_zalloc(len);
	if (!bytes)
		return -ENOMEM;

#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec && sec->kunit_fake_xattr_enabled)
		ret = pkm_kacs_kunit_fake_getxattr_locked(sec, bytes, len);
	else
#endif
	ret = __vfs_getxattr(dentry, inode, name, bytes, len);
	if (ret < 0) {
		pkm_kacs_free(bytes);
		return ret;
	}
	if (ret != len || kacs_rust_validate_sd_bytes(bytes, len) != 0) {
		pkm_kacs_free(bytes);
		cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_CORRUPT,
						      NULL, 0);
		if (!cache)
			return -ENOMEM;
		*cache_out = cache;
		return 0;
	}

	cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_VALID, bytes,
					      len);
	if (!cache) {
		kvfree(bytes);
		return -ENOMEM;
	}

	*cache_out = cache;
	return 0;
}

static long pkm_kacs_inode_get_or_populate_cache_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct pkm_kacs_inode_sd_cache *cache;
	long ret;

	if (!file || !sec || !cache_out)
		return -EINVAL;

	cache = rcu_dereference_protected(sec->sd_cache,
					  lockdep_is_held(&sec->lock));
	if (cache) {
		*cache_out = cache;
		return 0;
	}

	ret = pkm_kacs_inode_read_sd_xattr_locked(file, &cache);
	if (ret)
		return ret;

	pkm_kacs_inode_replace_sd_cache_locked(sec, cache);
	*cache_out = cache;
	return 0;
}

static long pkm_kacs_inode_resolve_effective_cache_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out);

static long pkm_kacs_synthesize_missing_file_sd_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct pkm_kacs_inode_sd_cache *new_cache = NULL;
	struct pkm_kacs_inode_sd_cache *parent_cache = NULL;
	struct pkm_kacs_inode_security *parent_sec;
	struct dentry *dentry;
	struct dentry *parent_dentry;
	struct inode *inode;
	struct inode *parent_inode;
	struct file parent_file = {};
	const u8 *template_sd_ptr = NULL;
	const u8 *parent_sd_ptr = NULL;
	const u8 *new_sd_bytes = NULL;
	size_t template_sd_len = 0;
	size_t parent_sd_len = 0;
	size_t new_sd_len = 0;
	u32 mount_policy;
	long ret;

	if (!file || !sec || !cache_out)
		return -EINVAL;

	inode = file_inode(file);
	dentry = file_dentry(file);
	if (!inode || !dentry)
		return -EACCES;

	mount_policy = pkm_kacs_superblock_mount_policy(inode->i_sb);
	if (mount_policy != PKM_KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL &&
	    mount_policy != PKM_KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT)
		return -EACCES;

	parent_dentry = dentry->d_parent;
	if (parent_dentry && parent_dentry != dentry) {
		struct path parent_path;

		parent_inode = d_inode(parent_dentry);
		if (!parent_inode || !parent_inode->i_security)
			return -EACCES;

		parent_sec = pkm_kacs_inode(parent_inode);
		parent_file.f_inode = parent_inode;
		parent_path = file->f_path;
		parent_path.dentry = parent_dentry;
		*(struct path *)&parent_file.f_path = parent_path;

		mutex_lock(&parent_sec->lock);
		ret = pkm_kacs_inode_resolve_effective_cache_locked(
			&parent_file, parent_sec, &parent_cache);
		if (ret) {
			mutex_unlock(&parent_sec->lock);
			return ret;
		}
		if (parent_cache->state != PKM_KACS_INODE_SD_VALID ||
		    !parent_cache->bytes || parent_cache->len == 0) {
			mutex_unlock(&parent_sec->lock);
			return -EACCES;
		}
		parent_sd_ptr = parent_cache->bytes;
		parent_sd_len = parent_cache->len;
		pkm_kacs_superblock_template_sd(inode->i_sb, &template_sd_ptr,
						&template_sd_len);
		ret = kacs_rust_synthesize_file_sd(
			parent_sd_ptr, parent_sd_len, template_sd_ptr,
			template_sd_len, S_ISDIR(inode->i_mode), &new_sd_bytes,
			&new_sd_len);
		mutex_unlock(&parent_sec->lock);
		if (ret)
			return ret;
	} else {
		pkm_kacs_superblock_template_sd(inode->i_sb, &template_sd_ptr,
						&template_sd_len);
		ret = kacs_rust_synthesize_file_sd(
			NULL, 0, template_sd_ptr, template_sd_len,
			S_ISDIR(inode->i_mode), &new_sd_bytes, &new_sd_len);
		if (ret)
			return ret;
	}

	new_cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_VALID,
						  new_sd_bytes, new_sd_len);
	if (!new_cache) {
		pkm_kacs_free((void *)new_sd_bytes);
		return -ENOMEM;
	}

	if (mount_policy == PKM_KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT) {
		ret = pkm_kacs_inode_write_sd_xattr_locked(file, new_sd_bytes,
							   new_sd_len);
		if (ret)
			goto out;
	}

	pkm_kacs_inode_replace_sd_cache_locked(sec, new_cache);
	*cache_out = new_cache;
	new_cache = NULL;
	return 0;

out:
	pkm_kacs_inode_sd_cache_free(new_cache);
	return ret;
}

static long pkm_kacs_inode_resolve_effective_cache_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct pkm_kacs_inode_sd_cache *cache;
	u32 mount_policy;
	long ret;

	if (!file || !sec || !cache_out)
		return -EINVAL;

	ret = pkm_kacs_inode_get_or_populate_cache_locked(file, sec, &cache);
	if (ret)
		return ret;
	if (cache->state != PKM_KACS_INODE_SD_MISSING) {
		*cache_out = cache;
		return 0;
	}

	mount_policy = pkm_kacs_superblock_mount_policy(file_inode(file)->i_sb);
	if (mount_policy != PKM_KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL &&
	    mount_policy != PKM_KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT) {
		*cache_out = cache;
		return 0;
	}

	return pkm_kacs_synthesize_missing_file_sd_locked(file, sec, cache_out);
}

static long pkm_kacs_query_file_sd_bytes_core(
	const void *subject_token, const struct pkm_kacs_inode_sd_cache *cache,
	u32 security_info, const u8 **out_sd_ptr, size_t *out_sd_len)
{
	u32 desired_access;
	u32 granted = 0;
	long ret;

	if (!subject_token || !cache || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	ret = pkm_kacs_get_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;
	if (cache->state != PKM_KACS_INODE_SD_VALID || !cache->bytes ||
	    cache->len == 0)
		return -EACCES;

	ret = kacs_rust_check_file_sd_with_intent(subject_token, cache->bytes,
						  cache->len, desired_access, 0,
						  &granted);
	if (ret)
		return ret;

	return kacs_rust_query_file_sd_subset(cache->bytes, cache->len,
					      security_info, out_sd_ptr,
					      out_sd_len);
}

static long pkm_kacs_prepare_new_file_sd_core(
	const void *subject_token, const struct pkm_kacs_inode_sd_cache *cache,
	u32 security_info, const u8 *input_sd_ptr, size_t input_sd_len,
	bool authorize_live, const u8 **new_sd_ptr, size_t *new_sd_len)
{
	long ret;

	if (!subject_token || !cache || !input_sd_ptr || input_sd_len == 0 ||
	    !new_sd_ptr || !new_sd_len)
		return -EINVAL;

	*new_sd_ptr = NULL;
	*new_sd_len = 0;

	if (cache->state == PKM_KACS_INODE_SD_VALID && cache->bytes &&
	    cache->len != 0) {
		if (authorize_live) {
			u32 desired_access;
			u32 granted = 0;

			ret = pkm_kacs_set_sd_required_access(security_info,
							      &desired_access);
			if (ret)
				return ret;
			ret = kacs_rust_check_file_sd_with_intent(
				subject_token, cache->bytes, cache->len,
				desired_access, KACS_RESTORE_INTENT,
				&granted);
			if (ret)
				return ret;
		}

		return kacs_rust_merge_file_sd(subject_token, cache->bytes,
					       cache->len, security_info,
					       input_sd_ptr, input_sd_len,
					       new_sd_ptr, new_sd_len);
	}

	if (!kacs_rust_token_has_enabled_privilege(subject_token,
						   PKM_KACS_PRIVILEGE_SE_RESTORE))
		return -EACCES;

	return kacs_rust_build_replacement_file_sd(subject_token, security_info,
						   input_sd_ptr, input_sd_len,
						   new_sd_ptr, new_sd_len);
}

static long pkm_kacs_inode_write_sd_xattr_locked(struct file *file,
						 const u8 *sd_bytes,
						 size_t sd_len)
{
	struct dentry *dentry;
	struct inode *inode;
	struct pkm_kacs_inode_security *sec;
	int ret;

	if (!file || !sd_bytes || sd_len == 0)
		return -EINVAL;

	dentry = file_dentry(file);
	inode = file_inode(file);
	if (!dentry || !inode)
		return -EACCES;
	sec = inode->i_security ? pkm_kacs_inode(inode) : NULL;

#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec && sec->kunit_fake_xattr_enabled)
		return pkm_kacs_kunit_fake_setxattr_locked(sec, sd_bytes, sd_len);
#endif

	inode_lock(inode);
	ret = __vfs_setxattr_noperm(file_mnt_idmap(file), dentry,
				    pkm_kacs_inode_sd_xattr_name(inode),
				    sd_bytes, sd_len, 0);
	inode_unlock(inode);
	return ret;
}

static int pkm_kacs_inode_getattr(const struct path *path)
{
	if (!path || !path->dentry)
		return -EACCES;

	if (pkm_kacs_consume_file_metadata_decision(
		    d_inode(path->dentry), PKM_KACS_METADATA_OP_GETATTR))
		return 0;

	return pkm_kacs_authorize_path_metadata_access(
		path, PKM_KACS_FILE_READ_ATTRIBUTES);
}

static u32 pkm_kacs_inode_setattr_required_access(const struct iattr *attr)
{
	u32 required = 0;
	unsigned int ia_valid;

	if (!attr)
		return 0;

	ia_valid = attr->ia_valid;
	if ((ia_valid & ATTR_MODE) != 0)
		required |= KACS_ACCESS_WRITE_DAC;
	if ((ia_valid & (ATTR_UID | ATTR_GID)) != 0)
		required |= KACS_ACCESS_WRITE_OWNER;
	if ((ia_valid & ATTR_SIZE) != 0 &&
	    (ia_valid & ATTR_FILE) == 0)
		required |= PKM_KACS_FILE_WRITE_DATA;
	if ((ia_valid & (ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET |
			 ATTR_MTIME_SET | ATTR_CTIME_SET | ATTR_TIMES_SET |
			 ATTR_TOUCH)) != 0)
		required |= PKM_KACS_FILE_WRITE_ATTRIBUTES;

	return required;
}

static int pkm_kacs_inode_setattr(struct mnt_idmap *idmap,
				  struct dentry *dentry,
				  struct iattr *attr)
{
	u32 required_access;

	if (!dentry || !attr)
		return -EACCES;

	if (pkm_kacs_consume_file_metadata_decision(
		    d_inode(dentry), PKM_KACS_METADATA_OP_SETATTR))
		return 0;

	required_access = pkm_kacs_inode_setattr_required_access(attr);
	if (required_access == 0)
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(dentry,
							 required_access);
}

static int pkm_kacs_inode_file_getattr(struct dentry *dentry,
				       struct file_kattr *fa)
{
	if (!dentry)
		return -EACCES;

	if (pkm_kacs_consume_file_metadata_decision(
		    d_inode(dentry), PKM_KACS_METADATA_OP_FILEATTR_GET))
		return 0;
	if (pkm_kacs_has_file_metadata_decision(
		    d_inode(dentry), PKM_KACS_METADATA_OP_FILEATTR_SET))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, PKM_KACS_FILE_READ_ATTRIBUTES);
}

static int pkm_kacs_inode_file_setattr(struct dentry *dentry,
				       struct file_kattr *fa)
{
	if (!dentry)
		return -EACCES;

	if (pkm_kacs_consume_file_metadata_decision(
		    d_inode(dentry), PKM_KACS_METADATA_OP_FILEATTR_SET))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, PKM_KACS_FILE_WRITE_ATTRIBUTES);
}

static int pkm_kacs_inode_getxattr(struct dentry *dentry, const char *name)
{
	if (dentry && pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name))
		return -EACCES;

	if (!name)
		return -EACCES;

	if (pkm_kacs_consume_file_metadata_decision(
		    dentry ? d_inode(dentry) : NULL,
		    PKM_KACS_METADATA_OP_GETXATTR))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, PKM_KACS_FILE_READ_EA);
}

static int pkm_kacs_inode_setxattr(struct mnt_idmap *idmap,
				   struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags)
{
	if (dentry && pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name))
		return -EACCES;
	if (!name)
		return -EACCES;
	if (is_posix_acl_xattr(name))
		return -EACCES;

	if (pkm_kacs_consume_file_metadata_decision(
		    dentry ? d_inode(dentry) : NULL,
		    PKM_KACS_METADATA_OP_SETXATTR))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, PKM_KACS_FILE_WRITE_EA);
}

static int pkm_kacs_inode_removexattr(struct mnt_idmap *idmap,
				      struct dentry *dentry,
				      const char *name)
{
	if (dentry && pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name))
		return -EACCES;
	if (!name)
		return -EACCES;
	if (is_posix_acl_xattr(name))
		return -EACCES;

	if (pkm_kacs_consume_file_metadata_decision(
		    dentry ? d_inode(dentry) : NULL,
		    PKM_KACS_METADATA_OP_SETXATTR))
		return 0;

	return pkm_kacs_authorize_dentry_metadata_access(
		dentry, PKM_KACS_FILE_WRITE_EA);
}

static int pkm_kacs_inode_listxattr(struct dentry *dentry)
{
	if (!dentry)
		return -EACCES;

	return 0;
}

static int pkm_kacs_inode_permission(struct inode *inode, int mask)
{
	return (int)pkm_kacs_check_inode_permission_live_for_subject(
		pkm_kacs_current_effective_token_ptr(), inode, NULL, mask);
}

static void pkm_kacs_clear_file_metadata_decision(
	struct pkm_kacs_task_security *task_sec)
{
	if (!task_sec)
		return;

	task_sec->metadata_decision.inode = NULL;
	task_sec->metadata_decision.op_class = PKM_KACS_METADATA_OP_NONE;
	task_sec->metadata_decision.active = 0;
}

static int pkm_kacs_begin_file_metadata_decision(struct file *file,
						 u8 op_class)
{
	struct pkm_kacs_task_security *task_sec;
	struct inode *inode;

	if (!file || !current || !current->security ||
	    op_class == PKM_KACS_METADATA_OP_NONE)
		return -EACCES;

	inode = file_inode(file);
	if (!inode)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	if (task_sec->metadata_decision.active)
		return -EACCES;

	task_sec->metadata_decision.inode = inode;
	task_sec->metadata_decision.op_class = op_class;
	task_sec->metadata_decision.active = 1;
	return 0;
}

static int pkm_kacs_begin_inode_metadata_decision(const struct inode *inode,
						  u8 op_class)
{
	struct pkm_kacs_task_security *task_sec;

	if (!inode || !current || !current->security ||
	    op_class == PKM_KACS_METADATA_OP_NONE)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	if (task_sec->metadata_decision.active)
		return -EACCES;

	task_sec->metadata_decision.inode = inode;
	task_sec->metadata_decision.op_class = op_class;
	task_sec->metadata_decision.active = 1;
	return 0;
}

static bool pkm_kacs_has_file_metadata_decision(
	const struct inode *inode, u8 op_class)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security || !inode)
		return false;

	task_sec = pkm_kacs_task(current);
	return task_sec->metadata_decision.active &&
	       task_sec->metadata_decision.inode == inode &&
	       task_sec->metadata_decision.op_class == op_class;
}

static bool pkm_kacs_consume_file_metadata_decision(
	const struct inode *inode, u8 op_class)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return false;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->metadata_decision.active)
		return false;

	if (!inode || task_sec->metadata_decision.inode != inode ||
	    task_sec->metadata_decision.op_class != op_class)
		return false;

	pkm_kacs_clear_file_metadata_decision(task_sec);
	return true;
}

void pkm_kacs_file_end_metadata(struct file *file)
{
	struct pkm_kacs_task_security *task_sec;
	struct inode *inode;

	if (!current || !current->security)
		return;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->metadata_decision.active)
		return;

	inode = file ? file_inode(file) : NULL;
	if (!inode || task_sec->metadata_decision.inode == inode)
		pkm_kacs_clear_file_metadata_decision(task_sec);
}

static void pkm_kacs_inode_end_metadata(const struct inode *inode)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->metadata_decision.active)
		return;

	if (!inode || task_sec->metadata_decision.inode == inode)
		pkm_kacs_clear_file_metadata_decision(task_sec);
}

static int pkm_kacs_check_file_xattr_snapshot(struct file *file,
					      const char *name,
					      u32 required_access,
					      bool write_operation,
					      u8 op_class)
{
	struct inode *inode;
	int ret;

	if (!name)
		return -EACCES;
	if (!file)
		return -EACCES;

	inode = file_inode(file);
	if (inode && pkm_kacs_is_canonical_sd_xattr(inode, name))
		return -EACCES;
	if (write_operation && is_posix_acl_xattr(name))
		return -EACCES;

	ret = pkm_kacs_check_file_snapshot_grant(file, required_access);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(file, op_class);
}

int pkm_kacs_file_sd_xattr_set(struct file *file, const char *name)
{
	return pkm_kacs_check_file_xattr_snapshot(
		file, name, PKM_KACS_FILE_WRITE_EA, true,
		PKM_KACS_METADATA_OP_SETXATTR);
}

int pkm_kacs_file_sd_xattr_get(struct file *file, const char *name)
{
	return pkm_kacs_check_file_xattr_snapshot(
		file, name, PKM_KACS_FILE_READ_EA, false,
		PKM_KACS_METADATA_OP_GETXATTR);
}

int pkm_kacs_file_sd_xattr_remove(struct file *file, const char *name)
{
	return pkm_kacs_check_file_xattr_snapshot(
		file, name, PKM_KACS_FILE_WRITE_EA, true,
		PKM_KACS_METADATA_OP_SETXATTR);
}

int pkm_kacs_file_getattr(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(
		file, PKM_KACS_FILE_READ_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_GETATTR);
}

int pkm_kacs_file_statfs(struct file *file)
{
	if (!file)
		return -EACCES;
	return pkm_kacs_check_file_snapshot_grant(
		file, PKM_KACS_FILE_READ_ATTRIBUTES);
}

int pkm_kacs_file_chmod(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(file,
						 KACS_ACCESS_WRITE_DAC);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_SETATTR);
}

int pkm_kacs_file_chown(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(file,
						 KACS_ACCESS_WRITE_OWNER);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_SETATTR);
}

int pkm_kacs_file_utimens(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(
		file, PKM_KACS_FILE_WRITE_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_SETATTR);
}

int pkm_kacs_file_fileattr_get(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(
		file, PKM_KACS_FILE_READ_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_FILEATTR_GET);
}

int pkm_kacs_file_fileattr_set(struct file *file)
{
	int ret;

	if (!file)
		return -EACCES;
	ret = pkm_kacs_check_file_snapshot_grant(
		file, PKM_KACS_FILE_WRITE_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_file_metadata_decision(
		file, PKM_KACS_METADATA_OP_FILEATTR_SET);
}

int pkm_kacs_path_fileattr_set(const struct path *path)
{
	struct inode *inode;
	int ret;

	if (!path || !path->dentry)
		return -EACCES;

	inode = d_inode(path->dentry);
	if (!inode)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return 0;

	ret = pkm_kacs_authorize_path_metadata_access(
		path, PKM_KACS_FILE_WRITE_ATTRIBUTES);
	if (ret)
		return ret;

	return pkm_kacs_begin_inode_metadata_decision(
		inode, PKM_KACS_METADATA_OP_FILEATTR_SET);
}

void pkm_kacs_path_end_metadata(const struct path *path)
{
	pkm_kacs_inode_end_metadata(path && path->dentry ?
					    d_inode(path->dentry) :
					    NULL);
}

int pkm_kacs_file_listxattr(struct file *file)
{
	if (!file)
		return -EACCES;
	return 0;
}

int pkm_kacs_path_access(const struct path *path, int mode)
{
	u32 desired_access = 0;

	if (!path || !path->dentry)
		return -EACCES;
	if ((mode & ~(MAY_READ | MAY_WRITE | MAY_EXEC)) != 0)
		return -EINVAL;

	if ((mode & MAY_READ) != 0)
		desired_access |= PKM_KACS_FILE_READ_DATA;
	if ((mode & MAY_WRITE) != 0)
		desired_access |= PKM_KACS_FILE_WRITE_DATA;
	if ((mode & MAY_EXEC) != 0)
		desired_access |= PKM_KACS_FILE_EXECUTE;
	if (desired_access == 0)
		desired_access = PKM_KACS_FILE_READ_ATTRIBUTES;

	return pkm_kacs_authorize_path_metadata_access(path, desired_access);
}

static struct pkm_kacs_process_sd *pkm_kacs_process_state_get_sd(
	struct pkm_kacs_process_state *state)
{
	struct pkm_kacs_process_sd *process_sd;
	unsigned long flags;

	if (!state)
		return NULL;

	spin_lock_irqsave(&state->mitigation_lock, flags);
	process_sd = pkm_kacs_process_sd_get(state->process_sd);
	spin_unlock_irqrestore(&state->mitigation_lock, flags);
	return process_sd;
}

static void pkm_kacs_process_state_replace_sd_locked(
	struct pkm_kacs_process_state *state,
	struct pkm_kacs_process_sd *new_sd)
{
	struct pkm_kacs_process_sd *old_sd;
	unsigned long flags;

	if (!state || !new_sd)
		return;

	spin_lock_irqsave(&state->mitigation_lock, flags);
	old_sd = state->process_sd;
	state->process_sd = new_sd;
	spin_unlock_irqrestore(&state->mitigation_lock, flags);

	pkm_kacs_process_sd_put(old_sd);
}

static void pkm_kacs_process_state_replace_sd(
	struct pkm_kacs_process_state *state,
	struct pkm_kacs_process_sd *new_sd)
{
	if (!state || !new_sd)
		return;

	mutex_lock(&state->sd_lock);
	pkm_kacs_process_state_replace_sd_locked(state, new_sd);
	mutex_unlock(&state->sd_lock);
}

static void pkm_kacs_socket_peer_token_drop(struct pkm_kacs_socket_security *sec)
{
	if (!sec || !sec->peer_token)
		return;

	kacs_rust_token_drop(sec->peer_token);
	sec->peer_token = NULL;
}

static bool pkm_kacs_socket_type_supported(int type)
{
	return type == SOCK_STREAM || type == SOCK_SEQPACKET;
}

static bool pkm_kacs_socket_level_valid(u32 level)
{
	switch (level) {
	case KACS_LEVEL_ANONYMOUS:
	case KACS_LEVEL_IDENTIFICATION:
	case KACS_LEVEL_IMPERSONATION:
	case KACS_LEVEL_DELEGATION:
		return true;
	default:
		return false;
	}
}

static bool pkm_kacs_sockaddr_is_abstract_unix(const struct sockaddr *address,
					       int addrlen)
{
	const struct sockaddr_un *sun = (const struct sockaddr_un *)address;

	if (!address || addrlen < offsetof(struct sockaddr_un, sun_path) + 1)
		return false;
	if (address->sa_family != AF_UNIX)
		return false;

	return sun->sun_path[0] == '\0';
}

static struct pkm_kmes_rate_bucket *pkm_kmes_rate_bucket_alloc(void)
{
	struct pkm_kmes_rate_bucket *bucket;

	bucket = kzalloc(sizeof(*bucket), GFP_KERNEL);
	if (!bucket)
		return NULL;

	refcount_set(&bucket->refs, 1);
	spin_lock_init(&bucket->lock);
	bucket->last_refill_ns = ktime_get_ns();
	bucket->tokens = PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS;
	return bucket;
}

static void pkm_kmes_rate_bucket_put(struct pkm_kmes_rate_bucket *bucket)
{
	if (!bucket)
		return;
	if (refcount_dec_and_test(&bucket->refs))
		kfree(bucket);
}

static struct pkm_kacs_process_state *pkm_kacs_process_state_alloc(
	const void *primary_token, u32 pip_type, u32 pip_trust,
	u32 mitigation_bits)
{
	struct pkm_kacs_process_state *state;
	struct pkm_kmes_rate_bucket *bucket;
	struct pkm_kacs_process_sd *process_sd;

	if (!primary_token)
		return NULL;

	bucket = pkm_kmes_rate_bucket_alloc();
	if (!bucket)
		return NULL;

	process_sd = pkm_kacs_process_sd_alloc(primary_token);
	if (!process_sd) {
		pkm_kmes_rate_bucket_put(bucket);
		return NULL;
	}

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_process_sd_put(process_sd);
		pkm_kmes_rate_bucket_put(bucket);
		return NULL;
	}

	refcount_set(&state->refs, 1);
	spin_lock_init(&state->mitigation_lock);
	mutex_init(&state->sd_lock);
	state->pip_type = pip_type;
	state->pip_trust = pip_trust;
	state->mitigation_bits = mitigation_bits;
	state->kmes_rate_bucket = bucket;
	state->process_sd = process_sd;
	return state;
}

static struct pkm_kacs_process_state *pkm_kacs_process_state_get(
	struct pkm_kacs_process_state *state)
{
	if (state)
		refcount_inc(&state->refs);
	return state;
}

static void pkm_kacs_process_state_put(struct pkm_kacs_process_state *state)
{
	if (!state)
		return;
	if (!refcount_dec_and_test(&state->refs))
		return;

	pkm_kacs_process_sd_put(state->process_sd);
	pkm_kmes_rate_bucket_put(state->kmes_rate_bucket);
	kfree(state);
}

static struct pkm_kacs_process_state *pkm_kacs_current_process_state(void)
{
	if (!current || !current->security)
		return NULL;

	return pkm_kacs_task(current)->process_state;
}

static u32 pkm_kacs_process_state_mitigation_bits(
	const struct pkm_kacs_process_state *state)
{
	if (!state)
		return 0;

	return READ_ONCE(state->mitigation_bits);
}

static bool pkm_kacs_clone_is_blocked_by_no_child(u32 mitigation_bits,
						   u64 clone_flags)
{
	if ((clone_flags & CLONE_THREAD) != 0)
		return false;

	return (mitigation_bits & KACS_MIT_NO_CHILD) != 0;
}

static struct pkm_kacs_process_state *pkm_kacs_inherit_process_state(
	u64 clone_flags)
{
	struct pkm_kacs_process_state *parent_state;
	const void *primary_token;
	u32 mitigation_bits;

	parent_state = pkm_kacs_current_process_state();
	if (!parent_state)
		return NULL;

	mitigation_bits = pkm_kacs_process_state_mitigation_bits(parent_state);

	if ((clone_flags & CLONE_THREAD) != 0)
		return pkm_kacs_process_state_get(parent_state);

	primary_token = pkm_kacs_current_primary_token_ptr();
	if (!primary_token)
		return NULL;

	return pkm_kacs_process_state_alloc(primary_token,
					    READ_ONCE(parent_state->pip_type),
					    READ_ONCE(parent_state->pip_trust),
					    mitigation_bits);
}

static void pkm_kmes_rate_bucket_refill(struct pkm_kmes_rate_bucket *bucket,
					 u64 now_ns, u32 rate)
{
	u64 elapsed_ns;
	u64 added;
	u64 consumed_ns;
	u64 tokens;

	if (!bucket || rate == 0)
		return;
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (bucket->kunit_freeze_refill)
		return;
#endif
	if (bucket->tokens >= rate) {
		bucket->tokens = rate;
		bucket->last_refill_ns = now_ns;
		return;
	}

	elapsed_ns = now_ns - bucket->last_refill_ns;
	if (elapsed_ns == 0)
		return;

	added = div_u64(elapsed_ns * (u64)rate, NSEC_PER_SEC);
	if (added == 0)
		return;

	tokens = bucket->tokens + added;
	if (tokens > rate)
		tokens = rate;
	bucket->tokens = (u32)tokens;

	consumed_ns = div_u64(added * NSEC_PER_SEC, rate);
	if (consumed_ns > elapsed_ns)
		consumed_ns = elapsed_ns;
	bucket->last_refill_ns += consumed_ns;
}

static int pkm_kmes_rate_bucket_reserve(struct pkm_kmes_rate_bucket *bucket,
					u32 count)
{
	unsigned long flags;
	u64 now_ns;

	if (!bucket || count == 0)
		return -EPERM;

	now_ns = ktime_get_ns();
	spin_lock_irqsave(&bucket->lock, flags);
	pkm_kmes_rate_bucket_refill(bucket, now_ns,
				    PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS);
	if (bucket->tokens < count) {
		spin_unlock_irqrestore(&bucket->lock, flags);
		return -EAGAIN;
	}
	bucket->tokens -= count;
	spin_unlock_irqrestore(&bucket->lock, flags);
	return 0;
}

static void pkm_kmes_rate_bucket_refund(struct pkm_kmes_rate_bucket *bucket,
					 u32 count)
{
	unsigned long flags;
	u64 tokens;

	if (!bucket || count == 0)
		return;

	spin_lock_irqsave(&bucket->lock, flags);
	tokens = bucket->tokens + (u64)count;
	if (tokens > PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS)
		tokens = PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS;
	bucket->tokens = (u32)tokens;
	spin_unlock_irqrestore(&bucket->lock, flags);
}

static u64 pkm_kacs_allow_cap_mask_u64(void)
{
	return (1ULL << CAP_CHOWN) | (1ULL << CAP_DAC_OVERRIDE) |
	       (1ULL << CAP_DAC_READ_SEARCH) | (1ULL << CAP_FOWNER) |
	       (1ULL << CAP_FSETID) | (1ULL << CAP_KILL) |
	       (1ULL << CAP_SETGID) | (1ULL << CAP_SETUID) |
	       (1ULL << CAP_NET_BROADCAST) | (1ULL << CAP_IPC_OWNER) |
	       (1ULL << CAP_LEASE);
}

static void pkm_kacs_raise_allow_kernel_caps(kernel_cap_t *caps)
{
	if (!caps)
		return;

	cap_raise(*caps, CAP_CHOWN);
	cap_raise(*caps, CAP_DAC_OVERRIDE);
	cap_raise(*caps, CAP_DAC_READ_SEARCH);
	cap_raise(*caps, CAP_FOWNER);
	cap_raise(*caps, CAP_FSETID);
	cap_raise(*caps, CAP_KILL);
	cap_raise(*caps, CAP_SETGID);
	cap_raise(*caps, CAP_SETUID);
	cap_raise(*caps, CAP_NET_BROADCAST);
	cap_raise(*caps, CAP_IPC_OWNER);
	cap_raise(*caps, CAP_LEASE);
}

static void pkm_kacs_raise_allow_compat_caps(struct cred *cred)
{
	if (!cred)
		return;

	pkm_kacs_raise_allow_kernel_caps(&cred->cap_effective);
	pkm_kacs_raise_allow_kernel_caps(&cred->cap_permitted);
	pkm_kacs_raise_allow_kernel_caps(&cred->cap_inheritable);
	pkm_kacs_raise_allow_kernel_caps(&cred->cap_bset);
}

static void pkm_kacs_reset_allow_compat_caps(struct cred *cred)
{
	if (!cred)
		return;

	cred->cap_effective = CAP_EMPTY_SET;
	cred->cap_permitted = CAP_EMPTY_SET;
	cred->cap_inheritable = CAP_EMPTY_SET;
	cap_clear(cred->cap_ambient);
	pkm_kacs_raise_allow_compat_caps(cred);
}

static void pkm_kacs_copy_exec_compat_caps(struct cred *new,
					   const struct cred *old)
{
	if (!new || !old)
		return;

	new->cap_effective = old->cap_effective;
	new->cap_permitted = old->cap_permitted;
	new->cap_inheritable = old->cap_inheritable;
	new->cap_ambient = old->cap_ambient;
	new->cap_bset = old->cap_bset;
	pkm_kacs_raise_allow_compat_caps(new);
}

static bool pkm_kacs_allow_caps_present(const kernel_cap_t *caps)
{
	if (!caps)
		return false;

	return cap_raised(*caps, CAP_CHOWN) &&
	       cap_raised(*caps, CAP_DAC_OVERRIDE) &&
	       cap_raised(*caps, CAP_DAC_READ_SEARCH) &&
	       cap_raised(*caps, CAP_FOWNER) &&
	       cap_raised(*caps, CAP_FSETID) &&
	       cap_raised(*caps, CAP_KILL) &&
	       cap_raised(*caps, CAP_SETGID) &&
	       cap_raised(*caps, CAP_SETUID) &&
	       cap_raised(*caps, CAP_NET_BROADCAST) &&
	       cap_raised(*caps, CAP_IPC_OWNER) &&
	       cap_raised(*caps, CAP_LEASE);
}

static u64 pkm_kacs_kernel_cap_to_u64(const kernel_cap_t *caps)
{
	u64 mask = 0;
	int cap;

	if (!caps)
		return 0;

	for (cap = 0; cap <= CAP_LAST_CAP && cap < 64; cap++) {
		if (cap_raised(*caps, cap))
			mask |= 1ULL << cap;
	}

	return mask;
}

static kernel_cap_t pkm_kacs_u64_to_kernel_cap(u64 mask)
{
	kernel_cap_t caps = CAP_EMPTY_SET;
	int cap;

	for (cap = 0; cap <= CAP_LAST_CAP && cap < 64; cap++) {
		if ((mask & (1ULL << cap)) != 0)
			cap_raise(caps, cap);
	}

	return caps;
}

static bool pkm_kacs_cap_is_allow(int cap)
{
	switch (cap) {
	case CAP_CHOWN:
	case CAP_DAC_OVERRIDE:
	case CAP_DAC_READ_SEARCH:
	case CAP_FOWNER:
	case CAP_FSETID:
	case CAP_KILL:
	case CAP_SETGID:
	case CAP_SETUID:
	case CAP_NET_BROADCAST:
	case CAP_IPC_OWNER:
	case CAP_LEASE:
		return true;
	default:
		return false;
	}
}

static u64 pkm_kacs_cap_required_privilege(int cap)
{
	switch (cap) {
	case CAP_LINUX_IMMUTABLE:
	case CAP_NET_ADMIN:
	case CAP_NET_RAW:
	case CAP_SYS_RAWIO:
	case CAP_SYS_CHROOT:
	case CAP_SYS_PACCT:
	case CAP_SYS_ADMIN:
	case CAP_SYS_TTY_CONFIG:
	case CAP_MKNOD:
	case CAP_SYSLOG:
	case CAP_WAKE_ALARM:
	case CAP_BLOCK_SUSPEND:
	case CAP_BPF:
	case CAP_CHECKPOINT_RESTORE:
		return PKM_KACS_PRIVILEGE_SE_TCB;
	case CAP_NET_BIND_SERVICE:
		return PKM_KACS_PRIVILEGE_SE_BIND_PRIVILEGED_PORT;
	case CAP_IPC_LOCK:
		return PKM_KACS_PRIVILEGE_SE_LOCK_MEMORY;
	case CAP_SYS_MODULE:
		return PKM_KACS_PRIVILEGE_SE_LOAD_DRIVER;
	case CAP_SYS_PTRACE:
		return PKM_KACS_PRIVILEGE_SE_DEBUG;
	case CAP_SYS_BOOT:
		return PKM_KACS_PRIVILEGE_SE_SHUTDOWN;
	case CAP_SYS_NICE:
		return PKM_KACS_PRIVILEGE_SE_INCREASE_BASE_PRIORITY;
	case CAP_SYS_RESOURCE:
		return PKM_KACS_PRIVILEGE_SE_INCREASE_QUOTA;
	case CAP_SYS_TIME:
		return PKM_KACS_PRIVILEGE_SE_SYSTEMTIME;
	case CAP_AUDIT_WRITE:
		return PKM_KACS_PRIVILEGE_SE_AUDIT;
	case CAP_AUDIT_CONTROL:
	case CAP_MAC_ADMIN:
	case CAP_AUDIT_READ:
		return PKM_KACS_PRIVILEGE_SE_SECURITY;
	case CAP_PERFMON:
		return PKM_KACS_PRIVILEGE_SE_PROFILE_SINGLE_PROCESS;
	default:
		return 0;
	}
}

static long pkm_kacs_check_capability_for_token(const void *subject_token,
						int cap)
{
	u64 privilege;

	if (!cap_valid(cap))
		return -EINVAL;
	if (pkm_kacs_cap_is_allow(cap))
		return 0;
	if (cap == CAP_SETPCAP || cap == CAP_SETFCAP || cap == CAP_MAC_OVERRIDE)
		return -EPERM;

	privilege = pkm_kacs_cap_required_privilege(cap);
	if (privilege == 0)
		return -EPERM;
	if (!subject_token)
		return -EPERM;
	if (!kacs_rust_token_has_enabled_privilege(subject_token, privilege))
		return -EPERM;
	if (!kacs_rust_token_mark_privileges_used(subject_token, privilege))
		return -EPERM;

	return 0;
}

static long pkm_kacs_capset_core(const void *subject_token, struct cred *new,
				 const kernel_cap_t *effective,
				 const kernel_cap_t *inheritable,
				 const kernel_cap_t *permitted)
{
	if (!subject_token || !new || !effective || !inheritable || !permitted)
		return -EPERM;
	if (!pkm_kacs_allow_caps_present(effective) ||
	    !pkm_kacs_allow_caps_present(inheritable) ||
	    !pkm_kacs_allow_caps_present(permitted))
		return -EPERM;

	new->cap_effective = *effective;
	new->cap_inheritable = *inheritable;
	new->cap_permitted = *permitted;
	pkm_kacs_raise_allow_compat_caps(new);
	return 0;
}

static long pkm_kacs_prctl_capability_guard_core(const void *subject_token,
						 u64 ambient_mask, int option,
						 unsigned long arg2,
						 unsigned long arg3,
						 unsigned long arg4,
						 unsigned long arg5)
{
	(void)arg4;
	(void)arg5;

	switch (option) {
	case PR_CAPBSET_READ:
		return 0;
	case PR_CAPBSET_DROP:
		if (!subject_token)
			return -EPERM;
		if (!cap_valid(arg2))
			return 0;
		return pkm_kacs_cap_is_allow((int)arg2) ? -EPERM : 0;
	case PR_CAP_AMBIENT:
		if (!subject_token)
			return -EPERM;
		switch (arg2) {
		case PR_CAP_AMBIENT_IS_SET:
			return 0;
		case PR_CAP_AMBIENT_CLEAR_ALL:
			return (ambient_mask & pkm_kacs_allow_cap_mask_u64()) != 0 ?
				       -EPERM :
				       0;
		case PR_CAP_AMBIENT_RAISE:
		case PR_CAP_AMBIENT_LOWER:
			if (!cap_valid(arg3))
				return 0;
			return pkm_kacs_cap_is_allow((int)arg3) ? -EPERM : 0;
		default:
			return 0;
		}
	default:
		return 0;
	}
}

static void pkm_kacs_stamp_projected_ids(struct pkm_kacs_cred_security *sec)
{
	if (!sec->token) {
		sec->projected_uid = PKM_KACS_UNMAPPED_ID;
		sec->projected_gid = PKM_KACS_UNMAPPED_ID;
		return;
	}

	sec->projected_uid = kacs_rust_token_projected_uid(sec->token);
	sec->projected_gid = kacs_rust_token_projected_gid(sec->token);
}

static int pkm_kacs_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	struct pkm_kacs_cred_security *new_sec = pkm_kacs_cred(new);
	const struct pkm_kacs_cred_security *old_sec = pkm_kacs_cred(old);

	(void)gfp;
	if (old_sec->token)
		new_sec->token = kacs_rust_token_deep_copy(old_sec->token);
	else
		new_sec->token = NULL;
	if (old_sec->process_state)
		new_sec->process_state =
			pkm_kacs_process_state_get(old_sec->process_state);
	else
		new_sec->process_state = NULL;

	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_raise_allow_compat_caps(new);
	return 0;
}

static void pkm_kacs_cred_transfer(struct cred *new, const struct cred *old)
{
	struct pkm_kacs_cred_security *new_sec = pkm_kacs_cred(new);
	const struct pkm_kacs_cred_security *old_sec = pkm_kacs_cred(old);

	if (old_sec->token)
		new_sec->token = kacs_rust_token_deep_copy(old_sec->token);
	else
		new_sec->token = NULL;
	if (old_sec->process_state)
		new_sec->process_state =
			pkm_kacs_process_state_get(old_sec->process_state);
	else
		new_sec->process_state = NULL;

	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_raise_allow_compat_caps(new);
}

static int pkm_kacs_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct pkm_kacs_cred_security *sec = pkm_kacs_cred(cred);

	(void)gfp;
	sec->token = NULL;
	sec->process_state = NULL;
	sec->projected_uid = PKM_KACS_UNMAPPED_ID;
	sec->projected_gid = PKM_KACS_UNMAPPED_ID;
	return 0;
}

static void pkm_kacs_cred_free(struct cred *cred)
{
	struct pkm_kacs_cred_security *sec = pkm_kacs_cred(cred);

	if (sec->token)
		kacs_rust_token_drop(sec->token);
	if (sec->process_state)
		pkm_kacs_process_state_put(sec->process_state);
}

static long pkm_kacs_stamp_file_granted_access_for_subject(
	const void *subject_token, struct file *file);

static int pkm_kacs_file_open(struct file *file)
{
	const void *subject_token;
	u32 desired_access = 0;
	u32 create_options = 0;
	long ret;

	if (!file)
		return -EACCES;
	if (pkm_kacs_file_delete_on_close_pending(file))
		return -EACCES;
	if ((file->f_mode & FMODE_PATH) != 0)
		return 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	if (pkm_kacs_native_open_request_matches(file, &desired_access,
						 &create_options)) {
		ret = pkm_kacs_stamp_native_file_granted_access_for_subject(
			subject_token, file, desired_access);
		if (ret)
			return (int)ret;
		ret = pkm_kacs_maybe_arm_delete_on_close_for_subject(
			subject_token, file, create_options);
		return (int)ret;
	}

	return (int)pkm_kacs_stamp_file_granted_access_for_subject(
		subject_token, file);
}

static int pkm_kacs_file_permission(struct file *file, int mask)
{
	return pkm_kacs_check_file_permission_snapshot(file, mask);
}

static int pkm_kacs_file_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	return pkm_kacs_check_file_ioctl_snapshot(file, cmd, arg, false);
}

static int pkm_kacs_file_ioctl_compat(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	return pkm_kacs_check_file_ioctl_snapshot(file, cmd, arg, true);
}

static int pkm_kacs_file_lock(struct file *file, unsigned int cmd)
{
	return pkm_kacs_check_file_lock_snapshot(file, cmd);
}

static int pkm_kacs_file_fcntl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	return pkm_kacs_check_file_fcntl_snapshot(file, cmd, arg);
}

static int pkm_kacs_file_truncate(struct file *file)
{
	return pkm_kacs_check_file_truncate_snapshot(file);
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

	ret = security_file_permission(file, MAY_WRITE);
	if (ret)
		return ret;

	return pkm_kacs_check_file_fallocate_snapshot(file, mode);
}

static int pkm_kacs_task_alloc(struct task_struct *task, u64 clone_flags)
{
	struct pkm_kacs_task_security *new_sec;
	struct pkm_kacs_process_state *state;
	struct pkm_kacs_process_state *parent_state;

	if (!task || !task->security)
		return -EACCES;

	new_sec = pkm_kacs_task(task);
	new_sec->process_state = NULL;
	new_sec->impersonation_saved_cred = NULL;
	new_sec->native_open.expected_dentry = NULL;
	new_sec->native_open.expected_mnt = NULL;
	new_sec->native_open.desired_access = 0;
	new_sec->native_open.create_options = 0;
	new_sec->native_open.active = false;
	new_sec->native_create.expected_parent_inode = NULL;
	new_sec->native_create.sd_bytes = NULL;
	new_sec->native_create.sd_len = 0;
	new_sec->native_create.directory = false;
	new_sec->native_create.active = false;
	new_sec->metadata_decision.inode = NULL;
	new_sec->metadata_decision.op_class = PKM_KACS_METADATA_OP_NONE;
	new_sec->metadata_decision.active = 0;

	parent_state = pkm_kacs_current_process_state();
	if (parent_state &&
	    pkm_kacs_clone_is_blocked_by_no_child(
		    pkm_kacs_process_state_mitigation_bits(parent_state),
		    clone_flags))
		return -EACCES;

	state = pkm_kacs_inherit_process_state(clone_flags);
	if (!state)
		return -ENOMEM;

	new_sec->process_state = state;
	pkm_kacs_set_cred_process_state((struct cred *)task->real_cred, state);
	if (task->cred != task->real_cred)
		pkm_kacs_set_cred_process_state((struct cred *)task->cred, state);
	return 0;
}

static void pkm_kacs_task_free(struct task_struct *task)
{
	struct pkm_kacs_task_security *sec;

	if (!task || !task->security)
		return;

	sec = pkm_kacs_task(task);
	pkm_kacs_process_state_put(sec->process_state);
	sec->process_state = NULL;
	sec->impersonation_saved_cred = NULL;
}

static struct security_hook_list pkm_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, pkm_kacs_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, pkm_kacs_cred_transfer),
	LSM_HOOK_INIT(cred_alloc_blank, pkm_kacs_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, pkm_kacs_cred_free),
	LSM_HOOK_INIT(sb_alloc_security, pkm_kacs_sb_alloc_security),
	LSM_HOOK_INIT(sb_free_security, pkm_kacs_sb_free_security),
	LSM_HOOK_INIT(inode_alloc_security, pkm_kacs_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security_rcu, pkm_kacs_inode_free_security_rcu),
	LSM_HOOK_INIT(inode_getattr, pkm_kacs_inode_getattr),
	LSM_HOOK_INIT(inode_setattr, pkm_kacs_inode_setattr),
	LSM_HOOK_INIT(inode_file_getattr, pkm_kacs_inode_file_getattr),
	LSM_HOOK_INIT(inode_file_setattr, pkm_kacs_inode_file_setattr),
	LSM_HOOK_INIT(inode_getxattr, pkm_kacs_inode_getxattr),
	LSM_HOOK_INIT(inode_setxattr, pkm_kacs_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr, pkm_kacs_inode_removexattr),
	LSM_HOOK_INIT(inode_listxattr, pkm_kacs_inode_listxattr),
	LSM_HOOK_INIT(inode_permission, pkm_kacs_inode_permission),
	LSM_HOOK_INIT(inode_create, pkm_kacs_inode_create),
	LSM_HOOK_INIT(inode_link, pkm_kacs_inode_link),
	LSM_HOOK_INIT(inode_unlink, pkm_kacs_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, pkm_kacs_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, pkm_kacs_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, pkm_kacs_inode_rmdir),
	LSM_HOOK_INIT(inode_mknod, pkm_kacs_inode_mknod),
	LSM_HOOK_INIT(inode_rename, pkm_kacs_inode_rename),
	LSM_HOOK_INIT(inode_readlink, pkm_kacs_inode_readlink),
	LSM_HOOK_INIT(inode_init_security, pkm_kacs_inode_init_security),
	LSM_HOOK_INIT(file_alloc_security, pkm_kacs_file_alloc_security),
	LSM_HOOK_INIT(file_release, pkm_kacs_file_release),
	LSM_HOOK_INIT(file_open, pkm_kacs_file_open),
	LSM_HOOK_INIT(file_permission, pkm_kacs_file_permission),
	LSM_HOOK_INIT(file_ioctl, pkm_kacs_file_ioctl),
	LSM_HOOK_INIT(file_ioctl_compat, pkm_kacs_file_ioctl_compat),
	LSM_HOOK_INIT(file_lock, pkm_kacs_file_lock),
	LSM_HOOK_INIT(file_fcntl, pkm_kacs_file_fcntl),
	LSM_HOOK_INIT(file_truncate, pkm_kacs_file_truncate),
	LSM_HOOK_INIT(task_alloc, pkm_kacs_task_alloc),
	LSM_HOOK_INIT(task_free, pkm_kacs_task_free),
	LSM_HOOK_INIT(sk_alloc_security, pkm_kacs_sk_alloc_security),
	LSM_HOOK_INIT(sk_free_security, pkm_kacs_sk_free_security),
	LSM_HOOK_INIT(socket_bind, pkm_kacs_socket_bind),
	LSM_HOOK_INIT(unix_stream_connect, pkm_kacs_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send, pkm_kacs_unix_may_send),
	LSM_HOOK_INIT(task_kill, pkm_kacs_task_kill),
	LSM_HOOK_INIT(ptrace_access_check, pkm_kacs_ptrace_access_check),
	LSM_HOOK_INIT(task_setnice, pkm_kacs_task_setnice),
	LSM_HOOK_INIT(task_setscheduler, pkm_kacs_task_setscheduler),
	LSM_HOOK_INIT(task_setioprio, pkm_kacs_task_setioprio),
	LSM_HOOK_INIT(task_fix_setuid, pkm_kacs_task_fix_setuid),
	LSM_HOOK_INIT(task_fix_setgid, pkm_kacs_task_fix_setgid),
	LSM_HOOK_INIT(task_fix_setgroups, pkm_kacs_task_fix_setgroups),
	LSM_HOOK_INIT(task_prlimit, pkm_kacs_task_prlimit),
	LSM_HOOK_INIT(capable, pkm_kacs_capable),
	LSM_HOOK_INIT(capset, pkm_kacs_capset),
	LSM_HOOK_INIT(task_prctl, pkm_kacs_task_prctl),
	LSM_HOOK_INIT(mmap_file, pkm_kacs_mmap_file),
	LSM_HOOK_INIT(file_mprotect, pkm_kacs_file_mprotect),
	LSM_HOOK_INIT(bprm_check_security, pkm_kacs_bprm_check_security),
	LSM_HOOK_INIT(bprm_creds_from_file, pkm_kacs_bprm_creds_from_file),
};

void *pkm_kacs_zalloc(size_t size)
{
	return kzalloc(size, GFP_KERNEL);
}

void pkm_kacs_free(void *ptr)
{
	kfree(ptr);
}

const void *pkm_kacs_current_effective_token_ptr(void)
{
	return pkm_kacs_cred(current_cred())->token;
}

const void *pkm_kacs_current_primary_token_ptr(void)
{
	return pkm_kacs_cred(current_real_cred())->token;
}

static long pkm_kacs_prepare_current_token_cred(const void *token,
						struct cred **out)
{
	struct pkm_kacs_cred_security *new_sec;
	const void *token_ref;
	struct cred *new;

	if (!token || !out)
		return -EINVAL;

	*out = NULL;
	token_ref = kacs_rust_token_clone(token);
	if (!token_ref)
		return -EACCES;

	new = prepare_creds();
	if (!new) {
		kacs_rust_token_drop(token_ref);
		return -ENOMEM;
	}

	new_sec = pkm_kacs_cred(new);
	if (new_sec->token)
		kacs_rust_token_drop(new_sec->token);
	new_sec->token = token_ref;
	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_raise_allow_compat_caps(new);
	*out = new;
	return 0;
}

static void pkm_kacs_abort_primary_install_prepare(
	struct pkm_kacs_primary_install_prepare *prepared)
{
	if (!prepared)
		return;

	if (prepared->new_effective)
		abort_creds(prepared->new_effective);
	if (prepared->new_real)
		abort_creds(prepared->new_real);
	prepared->new_effective = NULL;
	prepared->new_real = NULL;
}

static long pkm_kacs_prepare_current_primary_install(
	const void *new_primary_token,
	struct pkm_kacs_primary_install_prepare *prepared)
{
	struct pkm_kacs_task_security *task_sec;
	long ret;

	if (!new_primary_token || !prepared || !current || !current->security)
		return -EACCES;

	memset(prepared, 0, sizeof(*prepared));
	task_sec = pkm_kacs_task(current);

	ret = pkm_kacs_prepare_current_token_cred(new_primary_token,
						  &prepared->new_real);
	if (ret)
		return ret;

	if (!task_sec->impersonation_saved_cred)
		return 0;

	ret = pkm_kacs_prepare_current_token_cred(
		pkm_kacs_current_effective_token_ptr(),
		&prepared->new_effective);
	if (ret) {
		pkm_kacs_abort_primary_install_prepare(prepared);
		return ret;
	}

	return 0;
}

static long pkm_kacs_apply_current_primary_install(
	struct pkm_kacs_primary_install_prepare *prepared)
{
	struct pkm_kacs_task_security *task_sec;

	if (!prepared || !prepared->new_real || !current || !current->security)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	if (prepared->new_effective) {
		long ret;

		ret = pkm_kacs_revert_current_impersonation();
		if (ret)
			return ret;
	}

	commit_creds(prepared->new_real);
	prepared->new_real = NULL;

	if (prepared->new_effective) {
		task_sec->impersonation_saved_cred =
			override_creds(prepared->new_effective);
		prepared->new_effective = NULL;
	}

	return 0;
}

const void *pkm_kacs_boot_system_token_ptr(void)
{
	return pkm_kacs_boot_system_token;
}

int pkm_kacs_current_pip_context(u32 *pip_type, u32 *pip_trust)
{
	struct pkm_kacs_process_state *state;

	if (!pip_type || !pip_trust)
		return -EINVAL;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	*pip_type = READ_ONCE(state->pip_type);
	*pip_trust = READ_ONCE(state->pip_trust);
	return 0;
}

static long pkm_kacs_authorize_socket_sd_access(
	const void *subject_token,
	const struct pkm_kacs_process_sd *socket_sd, u32 desired_access)
{
	u32 granted = 0;

	if (!subject_token || !socket_sd || !socket_sd->bytes || !socket_sd->len)
		return -EACCES;

	return kacs_rust_check_socket_sd(subject_token, socket_sd->bytes,
					 socket_sd->len, desired_access,
					 &granted);
}

static void pkm_kacs_restore_capability_sets(struct cred *new,
					     const struct cred *old)
{
	if (!new || !old)
		return;

	new->cap_inheritable = old->cap_inheritable;
	new->cap_permitted = old->cap_permitted;
	new->cap_effective = old->cap_effective;
	new->cap_bset = old->cap_bset;
	new->cap_ambient = old->cap_ambient;
}

static void pkm_kacs_restore_uid_state(struct cred *new,
				       const struct cred *old)
{
	struct user_struct *old_user;

	if (!new || !old)
		return;

	new->uid = old->uid;
	new->euid = old->euid;
	new->suid = old->suid;
	new->fsuid = old->fsuid;
	pkm_kacs_restore_capability_sets(new, old);

	if (new->user == old->user)
		return;

	old_user = get_uid(old->user);
	free_uid(new->user);
	new->user = old_user;
}

static void pkm_kacs_restore_gid_state(struct cred *new,
				       const struct cred *old)
{
	if (!new || !old)
		return;

	new->gid = old->gid;
	new->egid = old->egid;
	new->sgid = old->sgid;
	new->fsgid = old->fsgid;
	pkm_kacs_restore_capability_sets(new, old);
}

static void pkm_kacs_restore_groups_state(struct cred *new,
					  const struct cred *old)
{
	if (!new || !old)
		return;

	set_groups(new, old->group_info);
	pkm_kacs_restore_capability_sets(new, old);
}

static long pkm_kacs_task_fix_setid_common(const void *subject_token)
{
	if (!subject_token)
		return -EACCES;
	if (kacs_rust_token_has_enabled_privilege(
		    subject_token, PKM_KACS_PRIVILEGE_SE_ASSIGN_PRIMARY))
		return -EOPNOTSUPP;

	return 0;
}

static long pkm_kacs_task_fix_setuid_core(const void *subject_token,
					  struct cred *new,
					  const struct cred *old,
					  int flags)
{
	long ret;

	if (!new || !old)
		return -EINVAL;

	switch (flags) {
	case LSM_SETID_RE:
	case LSM_SETID_ID:
	case LSM_SETID_RES:
	case LSM_SETID_FS:
		break;
	default:
		return -EINVAL;
	}

	ret = pkm_kacs_task_fix_setid_common(subject_token);
	if (ret)
		return ret;

	pkm_kacs_restore_uid_state(new, old);
	return 0;
}

static long pkm_kacs_task_fix_setgid_core(const void *subject_token,
					  struct cred *new,
					  const struct cred *old,
					  int flags)
{
	long ret;

	if (!new || !old)
		return -EINVAL;

	switch (flags) {
	case LSM_SETID_RE:
	case LSM_SETID_ID:
	case LSM_SETID_RES:
	case LSM_SETID_FS:
		break;
	default:
		return -EINVAL;
	}

	ret = pkm_kacs_task_fix_setid_common(subject_token);
	if (ret)
		return ret;

	pkm_kacs_restore_gid_state(new, old);
	return 0;
}

static long pkm_kacs_task_fix_setgroups_core(const void *subject_token,
					     struct cred *new,
					     const struct cred *old)
{
	long ret;

	if (!new || !old)
		return -EINVAL;

	ret = pkm_kacs_task_fix_setid_common(subject_token);
	if (ret)
		return ret;

	pkm_kacs_restore_groups_state(new, old);
	return 0;
}

int pkm_kacs_task_fix_setuid(struct cred *new, const struct cred *old,
			     int flags)
{
	return (int)pkm_kacs_task_fix_setuid_core(
		pkm_kacs_current_effective_token_ptr(), new, old, flags);
}

int pkm_kacs_task_fix_setgid(struct cred *new, const struct cred *old,
			     int flags)
{
	return (int)pkm_kacs_task_fix_setgid_core(
		pkm_kacs_current_effective_token_ptr(), new, old, flags);
}

int pkm_kacs_task_fix_setgroups(struct cred *new, const struct cred *old)
{
	return (int)pkm_kacs_task_fix_setgroups_core(
		pkm_kacs_current_effective_token_ptr(), new, old);
}

kuid_t pkm_kacs_current_fsuid_kuid(void)
{
	const struct cred *cred = current_cred();
	const struct pkm_kacs_cred_security *sec;

	if (!cred || !cred->security)
		return cred ? cred->fsuid : GLOBAL_ROOT_UID;

	sec = pkm_kacs_cred(cred);
	if (!sec->token)
		return cred->fsuid;

	return KUIDT_INIT(sec->projected_uid);
}
EXPORT_SYMBOL_GPL(pkm_kacs_current_fsuid_kuid);

kgid_t pkm_kacs_current_fsgid_kgid(void)
{
	const struct cred *cred = current_cred();
	const struct pkm_kacs_cred_security *sec;

	if (!cred || !cred->security)
		return cred ? cred->fsgid : GLOBAL_ROOT_GID;

	sec = pkm_kacs_cred(cred);
	if (!sec->token)
		return cred->fsgid;

	return KGIDT_INIT(sec->projected_gid);
}
EXPORT_SYMBOL_GPL(pkm_kacs_current_fsgid_kgid);

void pkm_kacs_current_fsuid_fsgid(kuid_t *fsuid, kgid_t *fsgid)
{
	if (fsuid)
		*fsuid = pkm_kacs_current_fsuid_kuid();
	if (fsgid)
		*fsgid = pkm_kacs_current_fsgid_kgid();
}
EXPORT_SYMBOL_GPL(pkm_kacs_current_fsuid_fsgid);

static long pkm_kacs_create_captured_peer_token(
	const void *client_token, u32 max_impersonation,
	const void **out_token)
{
	if (!client_token || !out_token)
		return -EACCES;
	if (!pkm_kacs_socket_level_valid(max_impersonation))
		return -EINVAL;

	*out_token = NULL;
	if (max_impersonation == KACS_LEVEL_ANONYMOUS)
		return kacs_rust_create_anonymous_impersonation_token(
			(void *)out_token);

	return kacs_rust_create_peer_impersonation_token(client_token,
							 max_impersonation,
							 (void *)out_token);
}

static long pkm_kacs_capture_peer_token_core(
	const struct pkm_kacs_socket_security *client_sec,
	struct pkm_kacs_socket_security *accepted_sec,
	const void *client_token)
{
	const void *peer_token = NULL;
	long ret;

	if (!client_sec || !accepted_sec || !client_token)
		return -EACCES;

	ret = pkm_kacs_create_captured_peer_token(client_token,
						  client_sec->max_impersonation,
						  &peer_token);
	if (ret)
		return ret;
	if (!peer_token)
		return -EACCES;

	pkm_kacs_socket_peer_token_drop(accepted_sec);
	accepted_sec->peer_token = peer_token;
	return 0;
}

static long pkm_kacs_bind_abstract_socket_core(
	struct pkm_kacs_socket_security *sec, const void *subject_token)
{
	struct pkm_kacs_process_sd *socket_sd;

	if (!sec || !subject_token)
		return -EACCES;
	if (sec->socket_sd)
		return 0;

	socket_sd = pkm_kacs_socket_sd_alloc(subject_token);
	if (!socket_sd)
		return -ENOMEM;

	sec->socket_sd = socket_sd;
	return 0;
}

static long pkm_kacs_unix_stream_connect_core(
	const struct pkm_kacs_socket_security *client_sec,
	const struct pkm_kacs_socket_security *server_sec,
	struct pkm_kacs_socket_security *accepted_sec,
	const void *client_token)
{
	long ret;

	if (!client_sec || !server_sec || !accepted_sec || !client_token)
		return -EACCES;

	if (server_sec->socket_sd) {
		ret = pkm_kacs_authorize_socket_sd_access(
			client_token, server_sec->socket_sd,
			PKM_KACS_SOCKET_FILE_WRITE_DATA);
		if (ret)
			return ret;
	}

	return pkm_kacs_capture_peer_token_core(client_sec, accepted_sec,
						client_token);
}

static long pkm_kacs_unix_may_send_core(
	const struct pkm_kacs_socket_security *target_sec,
	const void *subject_token)
{
	if (!target_sec)
		return -EACCES;
	if (!target_sec->socket_sd)
		return 0;

	return pkm_kacs_authorize_socket_sd_access(
		subject_token, target_sec->socket_sd,
		PKM_KACS_SOCKET_FILE_WRITE_DATA);
}

static long pkm_kacs_set_socket_impersonation_level_core(
	struct socket *sock, struct pkm_kacs_socket_security *sec, u32 level)
{
	if (!sock || !sock->sk || !sec)
		return -EACCES;
	if (sock->sk->sk_family != AF_UNIX ||
	    !pkm_kacs_socket_type_supported(sock->type))
		return -EACCES;
	if (!pkm_kacs_socket_level_valid(level))
		return -EINVAL;
	if (sock->state != SS_UNCONNECTED || sec->peer_token)
		return -EACCES;

	sec->max_impersonation = level;
	return 0;
}

static long pkm_kacs_open_peer_token_core(
	const struct pkm_kacs_socket_security *sec)
{
	if (!sec || !sec->peer_token)
		return -EACCES;

	return pkm_kacs_open_token_fd_with_fixed_access(
		sec->peer_token, PKM_KACS_PEER_TOKEN_ACCESS_MASK);
}

static long pkm_kacs_impersonate_peer_core(
	const struct pkm_kacs_socket_security *sec)
{
	if (!sec || !sec->peer_token)
		return -EACCES;

	return pkm_kacs_impersonate_token_for_current(sec->peer_token);
}

static int pkm_kacs_sk_alloc_security(struct sock *sk, int family,
				      gfp_t priority)
{
	struct pkm_kacs_socket_security *sec;

	(void)family;
	(void)priority;
	if (!sk || !sk->sk_security)
		return -EACCES;

	sec = pkm_kacs_sock(sk);
	sec->peer_token = NULL;
	sec->socket_sd = NULL;
	sec->max_impersonation = KACS_LEVEL_IMPERSONATION;
	return 0;
}

static void pkm_kacs_sk_free_security(struct sock *sk)
{
	struct pkm_kacs_socket_security *sec;

	if (!sk || !sk->sk_security)
		return;

	sec = pkm_kacs_sock(sk);
	pkm_kacs_socket_peer_token_drop(sec);
	pkm_kacs_process_sd_put(sec->socket_sd);
	sec->socket_sd = NULL;
	sec->max_impersonation = KACS_LEVEL_IMPERSONATION;
}

static int pkm_kacs_socket_bind(struct socket *sock, struct sockaddr *address,
				int addrlen)
{
	struct pkm_kacs_socket_security *sec;
	const void *subject_token;

	if (!sock || !sock->sk)
		return -EACCES;
	if (sock->sk->sk_family != AF_UNIX ||
	    !pkm_kacs_sockaddr_is_abstract_unix(address, addrlen))
		return 0;

	sec = pkm_kacs_sock(sock->sk);
	if (!sec)
		return -EACCES;
	if (sec->socket_sd)
		return 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	return pkm_kacs_bind_abstract_socket_core(sec, subject_token);
}

static int pkm_kacs_unix_stream_connect(struct sock *sock,
					struct sock *other,
					struct sock *newsk)
{
	struct pkm_kacs_socket_security *client_sec;
	struct pkm_kacs_socket_security *server_sec;
	struct pkm_kacs_socket_security *accepted_sec;
	const void *client_token;
	long ret;

	if (!sock || !other || !newsk)
		return -EACCES;
	if (sock->sk_family != AF_UNIX || other->sk_family != AF_UNIX ||
	    newsk->sk_family != AF_UNIX)
		return -EACCES;
	if (!pkm_kacs_socket_type_supported(sock->sk_type))
		return -EACCES;
	if (!sock->sk_security || !other->sk_security || !newsk->sk_security)
		return -EACCES;

	client_sec = pkm_kacs_sock(sock);
	server_sec = pkm_kacs_sock(other);
	accepted_sec = pkm_kacs_sock(newsk);
	client_token = pkm_kacs_current_effective_token_ptr();
	if (!client_sec || !server_sec || !accepted_sec || !client_token)
		return -EACCES;

	ret = pkm_kacs_unix_stream_connect_core(client_sec, server_sec,
						accepted_sec, client_token);
	return ret;
}

static int pkm_kacs_unix_may_send(struct socket *sock, struct socket *other)
{
	struct pkm_kacs_socket_security *target_sec;
	const void *subject_token;

	if (!sock || !other || !sock->sk || !other->sk)
		return -EACCES;
	if (sock->sk->sk_family != AF_UNIX || other->sk->sk_family != AF_UNIX)
		return -EACCES;
	if (!sock->sk->sk_security || !other->sk->sk_security)
		return -EACCES;

	target_sec = pkm_kacs_sock(other->sk);
	if (!target_sec)
		return -EACCES;
	if (!target_sec->socket_sd)
		return 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	return pkm_kacs_unix_may_send_core(target_sec, subject_token);
}

static bool pkm_kacs_ibt_supported(void)
{
	return cpu_feature_enabled(X86_FEATURE_IBT);
}

static bool pkm_kacs_shstk_supported(void)
{
	return cpu_feature_enabled(X86_FEATURE_SHSTK);
}

static long pkm_kacs_normalize_requested_mitigations(
	u32 requested_mitigations, bool ibt_supported, bool shstk_supported,
	u32 *normalized_out)
{
	u32 normalized = requested_mitigations;

	if (!normalized_out)
		return -EINVAL;
	if (requested_mitigations & ~KACS_MIT_ALL)
		return -EINVAL;
	if (requested_mitigations & KACS_MIT_LSV)
		return -EOPNOTSUPP;

	if ((normalized & KACS_MIT_CFI) != 0)
		normalized |= KACS_MIT_CFIF | KACS_MIT_CFIB;
	normalized &= ~KACS_MIT_CFI;

	if ((normalized & KACS_MIT_CFIF) != 0 && !ibt_supported)
		return -ENODEV;
	if ((normalized & KACS_MIT_CFIB) != 0 && !shstk_supported)
		return -ENODEV;

	*normalized_out = normalized;
	return 0;
}

static long pkm_kacs_apply_psb_mitigations_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct pkm_kacs_process_state *target_state, bool self_target,
	u32 requested_mitigations, bool ibt_supported, bool shstk_supported,
	u32 *result_mitigation_bits_out)
{
	unsigned long flags;
	u32 normalized_bits;
	u32 result_bits;
	long ret;

	if (!target_state)
		return -EACCES;

	ret = pkm_kacs_normalize_requested_mitigations(
		requested_mitigations, ibt_supported, shstk_supported,
		&normalized_bits);
	if (ret)
		return ret;

	if (!self_target) {
		ret = pkm_kacs_check_process_setinfo_core(
			subject_token, caller_state, target_state);
		if (ret)
			return ret;
	}

	spin_lock_irqsave(&target_state->mitigation_lock, flags);
	target_state->mitigation_bits |= normalized_bits;
	result_bits = target_state->mitigation_bits;
	spin_unlock_irqrestore(&target_state->mitigation_lock, flags);

	if (result_mitigation_bits_out)
		*result_mitigation_bits_out = result_bits;

	return 0;
}

static int pkm_kacs_check_wxp_mmap_core(u32 mitigation_bits,
					unsigned long prot)
{
	if ((mitigation_bits & KACS_MIT_WXP) == 0)
		return 0;
	if ((prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0)
		return -EACCES;

	return 0;
}

static int pkm_kacs_check_wxp_mprotect_core(u32 mitigation_bits,
					    unsigned long vm_flags,
					    unsigned long prot)
{
	if ((mitigation_bits & KACS_MIT_WXP) == 0)
		return 0;
	if ((prot & PROT_WRITE) != 0 && (prot & PROT_EXEC) != 0)
		return -EACCES;
	if ((vm_flags & VM_WRITE) != 0 && (prot & PROT_EXEC) != 0)
		return -EACCES;
	if ((vm_flags & VM_EXEC) != 0 && (prot & PROT_WRITE) != 0)
		return -EACCES;

	return 0;
}

static void pkm_kacs_tlp_clear_prefixes_locked(void)
{
	u32 i;

	for (i = 0; i < pkm_kacs_tlp_prefix_count; i++) {
		kfree(pkm_kacs_tlp_prefixes[i]);
		pkm_kacs_tlp_prefixes[i] = NULL;
		pkm_kacs_tlp_prefix_lens[i] = 0;
	}
	pkm_kacs_tlp_prefix_count = 0;
}

static long pkm_kacs_tlp_replace_prefixes_kernel(
	const char * const *prefixes, const size_t *prefix_lens, u32 count)
{
	char *new_prefixes[PKM_KACS_TLP_MAX_PREFIXES] = {};
	size_t new_lens[PKM_KACS_TLP_MAX_PREFIXES] = {};
	u32 i;
	long ret = 0;

	if (count > PKM_KACS_TLP_MAX_PREFIXES)
		return -EINVAL;
	if (count != 0 && (!prefixes || !prefix_lens))
		return -EINVAL;

	for (i = 0; i < count; i++) {
		size_t len = prefix_lens[i];
		char *copy;

		if (!prefixes[i] || len == 0 ||
		    len > PKM_KACS_TLP_MAX_PREFIX_LEN) {
			ret = -EINVAL;
			goto out_free;
		}
		if (prefixes[i][0] != '/' || prefixes[i][len - 1] != '/') {
			ret = -EINVAL;
			goto out_free;
		}
		if (memchr(prefixes[i], '\0', len)) {
			ret = -EINVAL;
			goto out_free;
		}

		copy = kmalloc(len + 1, GFP_KERNEL);
		if (!copy) {
			ret = -ENOMEM;
			goto out_free;
		}
		memcpy(copy, prefixes[i], len);
		copy[len] = '\0';
		new_prefixes[i] = copy;
		new_lens[i] = len;
	}

	mutex_lock(&pkm_kacs_tlp_cache_lock);
	pkm_kacs_tlp_clear_prefixes_locked();
	for (i = 0; i < count; i++) {
		pkm_kacs_tlp_prefixes[i] = new_prefixes[i];
		pkm_kacs_tlp_prefix_lens[i] = new_lens[i];
		new_prefixes[i] = NULL;
		new_lens[i] = 0;
	}
	pkm_kacs_tlp_prefix_count = count;
	mutex_unlock(&pkm_kacs_tlp_cache_lock);

	return 0;

out_free:
	for (i = 0; i < count; i++)
		kfree(new_prefixes[i]);
	return ret;
}

static bool pkm_kacs_tlp_path_allowed(const char *path, size_t path_len)
{
	bool allowed = false;
	u32 i;

	mutex_lock(&pkm_kacs_tlp_cache_lock);
	for (i = 0; i < pkm_kacs_tlp_prefix_count; i++) {
		size_t prefix_len = pkm_kacs_tlp_prefix_lens[i];

		if (path_len >= prefix_len &&
		    memcmp(path, pkm_kacs_tlp_prefixes[i], prefix_len) == 0) {
			allowed = true;
			break;
		}
	}
	mutex_unlock(&pkm_kacs_tlp_cache_lock);

	return allowed;
}

static int pkm_kacs_check_tlp_path_core(u32 mitigation_bits,
					bool file_backed,
					bool executable_transition,
					const char *path, size_t path_len)
{
	if ((mitigation_bits & KACS_MIT_TLP) == 0)
		return 0;
	if (!executable_transition)
		return 0;
	if (!file_backed)
		return 0;
	if (!path || path_len == 0)
		return -EACCES;
	if (!pkm_kacs_tlp_path_allowed(path, path_len))
		return -EACCES;

	return 0;
}

static int pkm_kacs_check_tlp_file_core(u32 mitigation_bits,
					struct file *file,
					bool executable_transition)
{
	char *path_buf;
	char *resolved;
	size_t path_len;
	int ret;

	if ((mitigation_bits & KACS_MIT_TLP) == 0)
		return 0;
	if (!executable_transition)
		return 0;
	if (!file)
		return 0;

	path_buf = __getname();
	if (!path_buf)
		return -ENOMEM;

	resolved = d_path(&file->f_path, path_buf, PATH_MAX);
	if (IS_ERR(resolved)) {
		ret = -EACCES;
		goto out_putname;
	}

	path_len = strnlen(resolved,
			   (size_t)(path_buf + PATH_MAX - resolved));
	ret = pkm_kacs_check_tlp_path_core(mitigation_bits, true, true,
					   resolved, path_len);

out_putname:
	__putname(path_buf);
	return ret;
}

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

static int pkm_kacs_emit_file_continuous_audit(struct file *file,
					       const char *operation,
					       size_t operation_len,
					       u32 required_access,
					       int decision)
{
	struct pkm_kacs_file_security *file_sec;
	const void *subject_token;
	u32 matched_access;
	int ret;

	if (!file || !file->f_security || !operation || operation_len == 0 ||
	    required_access == 0)
		return decision;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return decision;

	matched_access = file_sec->continuous_audit_mask & required_access;
	if (!matched_access)
		return decision;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return decision ? decision : -EACCES;

	ret = kacs_rust_emit_file_continuous_audit(
		subject_token, (const u8 *)operation, operation_len,
		required_access,
		matched_access, file_sec->granted_access,
		decision == 0 ? 1 : 0);
	if (ret)
		return ret;
	return decision;
}

static int pkm_kacs_check_file_snapshot_grant_op(struct file *file,
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
		return 0;
	if ((file_sec->granted_access & required_access) != required_access)
		ret = -EACCES;

	return pkm_kacs_emit_file_continuous_audit(
		file, operation, operation_len, required_access, ret);
}

static int pkm_kacs_check_file_snapshot_grant(struct file *file,
					      u32 required_access)
{
	return pkm_kacs_check_file_snapshot_grant_op(
		file, required_access, pkm_kacs_audit_op_file_access,
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
		required_access |= PKM_KACS_FILE_READ_DATA;
	if ((prot & PROT_EXEC) != 0)
		required_access |= PKM_KACS_FILE_EXECUTE;
	if ((prot & PROT_WRITE) != 0)
		required_access |= shared ? PKM_KACS_FILE_WRITE_DATA :
					    PKM_KACS_FILE_READ_DATA;

	return required_access;
}

static int pkm_kacs_check_mmap_snapshot(struct file *file,
					unsigned long prot,
					unsigned long flags)
{
	return pkm_kacs_check_file_snapshot_grant_op(
		file,
		pkm_kacs_mapping_required_access(
			prot, pkm_kacs_mmap_flags_shared(flags)),
		pkm_kacs_audit_op_file_mmap,
		sizeof(pkm_kacs_audit_op_file_mmap) - 1);
}

static int pkm_kacs_check_mprotect_snapshot(struct file *file,
					    unsigned long vm_flags,
					    unsigned long prot)
{
	return pkm_kacs_check_file_snapshot_grant_op(
		file, pkm_kacs_mapping_required_access(
			      prot, (vm_flags & VM_SHARED) != 0),
		pkm_kacs_audit_op_file_mprotect,
		sizeof(pkm_kacs_audit_op_file_mprotect) - 1);
}

static int pkm_kacs_check_file_permission_snapshot(struct file *file,
						   int mask)
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
	if (!file_sec->managed)
		return 0;

	if ((mask & MAY_READ) != 0)
		required_access |= PKM_KACS_FILE_READ_DATA;
	if ((mask & (MAY_EXEC | MAY_CHDIR)) != 0)
		required_access |= PKM_KACS_FILE_TRAVERSE;
	audit_required_access = required_access;

	if ((file_sec->granted_access & required_access) != required_access)
		return pkm_kacs_emit_file_continuous_audit(
			file, pkm_kacs_audit_op_file_permission,
			sizeof(pkm_kacs_audit_op_file_permission) - 1,
			audit_required_access, -EACCES);

	write_intent = (mask & MAY_WRITE) != 0;
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
			return pkm_kacs_check_file_write_intent_snapshot(
				file, marker.rwf_flags, marker.positioned != 0);
		}
	}

	append_intent = (mask & MAY_APPEND) != 0 ||
			(write_intent && (file->f_flags & O_APPEND) != 0);
	if (write_intent || append_intent) {
		u32 write_grants = file_sec->granted_access &
				   (PKM_KACS_FILE_WRITE_DATA |
				    PKM_KACS_FILE_APPEND_DATA);

		if (append_intent) {
			audit_required_access |= PKM_KACS_FILE_WRITE_DATA |
						 PKM_KACS_FILE_APPEND_DATA;
			if (write_grants == 0)
				ret = -EACCES;
		} else if ((file_sec->granted_access &
			    PKM_KACS_FILE_WRITE_DATA) == 0) {
			audit_required_access |= PKM_KACS_FILE_WRITE_DATA;
			ret = -EACCES;
		} else {
			audit_required_access |= PKM_KACS_FILE_WRITE_DATA;
		}
	}

	return pkm_kacs_emit_file_continuous_audit(
		file, pkm_kacs_audit_op_file_permission,
		sizeof(pkm_kacs_audit_op_file_permission) - 1,
		audit_required_access, ret);
}

static int pkm_kacs_check_file_write_intent_snapshot(struct file *file,
						     u32 rwf_flags,
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
	if (!file->f_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return 0;

	if ((rwf_flags & RWF_APPEND) != 0 &&
	    (rwf_flags & RWF_NOAPPEND) != 0)
		return -EACCES;

	noappend = (rwf_flags & RWF_NOAPPEND) != 0;
	append_intent = !noappend &&
			(((rwf_flags & RWF_APPEND) != 0) ||
			 ((file->f_flags & O_APPEND) != 0));
	granted_access = file_sec->granted_access;

	if (noappend || (positioned && !append_intent)) {
		required_access = PKM_KACS_FILE_WRITE_DATA;
		if ((granted_access & PKM_KACS_FILE_WRITE_DATA) == 0)
			ret = -EACCES;
		return pkm_kacs_emit_file_continuous_audit(
			file, pkm_kacs_audit_op_file_write,
			sizeof(pkm_kacs_audit_op_file_write) - 1,
			required_access, ret);
	}

	if (append_intent) {
		required_access = PKM_KACS_FILE_WRITE_DATA |
				  PKM_KACS_FILE_APPEND_DATA;
		if ((granted_access & required_access) == 0)
			ret = -EACCES;
		return pkm_kacs_emit_file_continuous_audit(
			file, pkm_kacs_audit_op_file_write,
			sizeof(pkm_kacs_audit_op_file_write) - 1,
			required_access, ret);
	}

	required_access = PKM_KACS_FILE_WRITE_DATA;
	if ((granted_access & PKM_KACS_FILE_WRITE_DATA) == 0)
		ret = -EACCES;
	return pkm_kacs_emit_file_continuous_audit(
		file, pkm_kacs_audit_op_file_write,
		sizeof(pkm_kacs_audit_op_file_write) - 1, required_access,
		ret);
}

enum pkm_kacs_ioctl_requirement {
	PKM_KACS_IOCTL_REQUIRE_NONE,
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
		return PKM_KACS_IOCTL_REQUIRE_ANY_DATA;
	}
}

static int pkm_kacs_check_ioctl_requirement(u32 granted_access,
					    enum pkm_kacs_ioctl_requirement req)
{
	switch (req) {
	case PKM_KACS_IOCTL_REQUIRE_NONE:
		return 0;
	case PKM_KACS_IOCTL_REQUIRE_ANY_DATA:
		if ((granted_access & PKM_KACS_FILE_DATA_RIGHTS) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_READ_DATA:
		if ((granted_access & PKM_KACS_FILE_READ_DATA) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_WRITE_DATA:
		if ((granted_access & PKM_KACS_FILE_WRITE_DATA) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_APPEND_OR_WRITE_DATA:
		if ((granted_access & (PKM_KACS_FILE_APPEND_DATA |
				       PKM_KACS_FILE_WRITE_DATA)) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_READ_ATTRIBUTES:
		if ((granted_access & PKM_KACS_FILE_READ_ATTRIBUTES) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_IOCTL_REQUIRE_WRITE_ATTRIBUTES:
		if ((granted_access & PKM_KACS_FILE_WRITE_ATTRIBUTES) != 0)
			return 0;
		return -EACCES;
	default:
		return -EACCES;
	}
}

static u32 pkm_kacs_ioctl_requirement_mask(enum pkm_kacs_ioctl_requirement req)
{
	switch (req) {
	case PKM_KACS_IOCTL_REQUIRE_ANY_DATA:
		return PKM_KACS_FILE_DATA_RIGHTS;
	case PKM_KACS_IOCTL_REQUIRE_READ_DATA:
		return PKM_KACS_FILE_READ_DATA;
	case PKM_KACS_IOCTL_REQUIRE_WRITE_DATA:
		return PKM_KACS_FILE_WRITE_DATA;
	case PKM_KACS_IOCTL_REQUIRE_APPEND_OR_WRITE_DATA:
		return PKM_KACS_FILE_APPEND_DATA | PKM_KACS_FILE_WRITE_DATA;
	case PKM_KACS_IOCTL_REQUIRE_READ_ATTRIBUTES:
		return PKM_KACS_FILE_READ_ATTRIBUTES;
	case PKM_KACS_IOCTL_REQUIRE_WRITE_ATTRIBUTES:
		return PKM_KACS_FILE_WRITE_ATTRIBUTES;
	case PKM_KACS_IOCTL_REQUIRE_NONE:
	default:
		return 0;
	}
}

static int pkm_kacs_check_file_ioctl_snapshot(struct file *file,
					      unsigned int cmd,
					      unsigned long arg,
					      bool compat)
{
	struct pkm_kacs_file_security *file_sec;
	struct inode *inode;
	enum pkm_kacs_ioctl_requirement req;
	u32 required_access;
	int ret;

	(void)arg;

	if (!file)
		return -EACCES;
	if (!file->f_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return 0;

	inode = file_inode(file);
	if (!inode)
		return -EACCES;

	req = pkm_kacs_classify_file_ioctl(cmd, inode->i_mode, compat);
	required_access = pkm_kacs_ioctl_requirement_mask(req);
	ret = pkm_kacs_check_ioctl_requirement(file_sec->granted_access, req);
	return pkm_kacs_emit_file_continuous_audit(
		file, pkm_kacs_audit_op_file_ioctl,
		sizeof(pkm_kacs_audit_op_file_ioctl) - 1, required_access,
		ret);
}

static int pkm_kacs_check_file_lock_snapshot(struct file *file,
					     unsigned int cmd)
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
		required_access = PKM_KACS_FILE_READ_DATA;
		if ((granted_access & required_access) == 0)
			ret = -EACCES;
		break;
	case F_WRLCK:
		required_access = PKM_KACS_FILE_WRITE_DATA |
				  PKM_KACS_FILE_APPEND_DATA;
		if ((granted_access & required_access) == 0)
			ret = -EACCES;
		break;
	default:
		return -EACCES;
	}

	return pkm_kacs_emit_file_continuous_audit(
		file, pkm_kacs_audit_op_file_lock,
		sizeof(pkm_kacs_audit_op_file_lock) - 1, required_access,
		ret);
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
	if ((granted_access & PKM_KACS_FILE_LIST_DIRECTORY) != 0)
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
		if ((granted_access & PKM_KACS_FILE_READ_ATTRIBUTES) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_FCNTL_REQUIRE_WRITE_ATTRIBUTES:
		if ((granted_access & PKM_KACS_FILE_WRITE_ATTRIBUTES) != 0)
			return 0;
		return -EACCES;
	case PKM_KACS_FCNTL_REQUIRE_NOTIFY:
		return pkm_kacs_check_file_fcntl_notify(granted_access, arg);
	case PKM_KACS_FCNTL_REQUIRE_DENY:
	default:
		return -EACCES;
	}
}

static u32 pkm_kacs_fcntl_requirement_mask(enum pkm_kacs_fcntl_requirement req,
					   unsigned long arg)
{
	const unsigned long event_mask = DN_ACCESS | DN_MODIFY | DN_CREATE |
					DN_DELETE | DN_RENAME | DN_ATTRIB;

	switch (req) {
	case PKM_KACS_FCNTL_REQUIRE_ANY_DATA:
		return PKM_KACS_FILE_DATA_RIGHTS;
	case PKM_KACS_FCNTL_REQUIRE_READ_ATTRIBUTES:
		return PKM_KACS_FILE_READ_ATTRIBUTES;
	case PKM_KACS_FCNTL_REQUIRE_WRITE_ATTRIBUTES:
		return PKM_KACS_FILE_WRITE_ATTRIBUTES;
	case PKM_KACS_FCNTL_REQUIRE_NOTIFY:
		return (arg & event_mask) != 0 ?
			       PKM_KACS_FILE_LIST_DIRECTORY :
			       0;
	case PKM_KACS_FCNTL_REQUIRE_NONE:
	case PKM_KACS_FCNTL_REQUIRE_SETFL:
	case PKM_KACS_FCNTL_REQUIRE_DENY:
	default:
		return 0;
	}
}

static int pkm_kacs_check_file_fcntl_snapshot(struct file *file,
					      unsigned int cmd,
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
			file, pkm_kacs_audit_op_file_fcntl,
			sizeof(pkm_kacs_audit_op_file_fcntl) - 1,
			required_access, ret);
	}

	old_flags = file->f_flags;
	new_flags = arg;
	if ((old_flags & O_APPEND) != 0 && (new_flags & O_APPEND) == 0) {
		required_access |= PKM_KACS_FILE_WRITE_DATA;
		if ((granted_access & PKM_KACS_FILE_APPEND_DATA) != 0 &&
		    (granted_access & PKM_KACS_FILE_WRITE_DATA) == 0)
			ret = -EACCES;
	}

	if ((old_flags & O_NOATIME) == 0 && (new_flags & O_NOATIME) != 0) {
		required_access |= PKM_KACS_FILE_WRITE_ATTRIBUTES;
		if ((granted_access & PKM_KACS_FILE_WRITE_ATTRIBUTES) == 0)
			ret = -EACCES;
	}

	return pkm_kacs_emit_file_continuous_audit(
		file, pkm_kacs_audit_op_file_fcntl,
		sizeof(pkm_kacs_audit_op_file_fcntl) - 1, required_access,
		ret);
}

static int pkm_kacs_check_file_truncate_snapshot(struct file *file)
{
	struct pkm_kacs_file_security *file_sec;
	int ret = 0;

	if (!file)
		return -EACCES;
	if (!file->f_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return 0;

	if ((file_sec->granted_access & PKM_KACS_FILE_WRITE_DATA) == 0)
		ret = -EACCES;
	return pkm_kacs_emit_file_continuous_audit(
		file, pkm_kacs_audit_op_file_truncate,
		sizeof(pkm_kacs_audit_op_file_truncate) - 1,
		PKM_KACS_FILE_WRITE_DATA, ret);
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

static int pkm_kacs_check_file_fallocate_snapshot(struct file *file,
						  int mode)
{
	struct pkm_kacs_file_security *file_sec;
	bool requires_write_data = false;
	u32 granted_access;
	u32 required_access;
	int ret = 0;

	if (!file)
		return -EACCES;
	if (!file->f_security)
		return -EACCES;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->managed)
		return 0;

	if (!pkm_kacs_fallocate_mode_supported(mode, &requires_write_data))
		return -EACCES;

	granted_access = file_sec->granted_access;
	if (requires_write_data) {
		required_access = PKM_KACS_FILE_WRITE_DATA;
		if ((granted_access & required_access) == 0)
			ret = -EACCES;
		return pkm_kacs_emit_file_continuous_audit(
			file, pkm_kacs_audit_op_file_fallocate,
			sizeof(pkm_kacs_audit_op_file_fallocate) - 1,
			required_access, ret);
	}

	required_access = PKM_KACS_FILE_WRITE_DATA | PKM_KACS_FILE_APPEND_DATA;
	if ((granted_access & required_access) == 0)
		ret = -EACCES;
	return pkm_kacs_emit_file_continuous_audit(
		file, pkm_kacs_audit_op_file_fallocate,
		sizeof(pkm_kacs_audit_op_file_fallocate) - 1,
		required_access, ret);
}

static int pkm_kacs_check_task_prctl_mitigations_core(
	u32 mitigation_bits, int option, unsigned long arg2,
	unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	(void)arg4;
	(void)arg5;

	if ((mitigation_bits & KACS_MIT_SML) != 0 &&
	    option == PR_SET_SPECULATION_CTRL &&
	    (arg3 & PR_SPEC_ENABLE) != 0)
		return -EACCES;

#ifdef PR_SET_SHADOW_STACK_STATUS
	if ((mitigation_bits & KACS_MIT_CFIB) != 0 &&
	    option == PR_SET_SHADOW_STACK_STATUS &&
	    (arg2 & PR_SHADOW_STACK_ENABLE) == 0)
		return -EACCES;
#endif

#ifndef ARCH_SHSTK_DISABLE
#define ARCH_SHSTK_DISABLE 0x5002
#endif
#ifndef ARCH_SHSTK_UNLOCK
#define ARCH_SHSTK_UNLOCK 0x5004
#endif
	if ((mitigation_bits & KACS_MIT_CFIB) != 0 &&
	    (option == ARCH_SHSTK_DISABLE || option == ARCH_SHSTK_UNLOCK))
		return -EACCES;

	return -ENOSYS;
}

static int pkm_kacs_check_pie_bprm_core(u32 mitigation_bits,
					const u8 *buf, size_t len)
{
	u16 elf_type;

	if ((mitigation_bits & KACS_MIT_PIE) == 0)
		return 0;
	if (!buf || len < 18)
		return 0;
	if (buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' ||
	    buf[3] != 'F')
		return 0;

	elf_type = (u16)buf[16] | ((u16)buf[17] << 8);
	if (elf_type == ET_EXEC)
		return -EACCES;

	return 0;
}

int pkm_kmes_current_process_rate_reserve(u32 count)
{
	struct pkm_kacs_process_state *state;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EPERM;

	return pkm_kmes_rate_bucket_reserve(state->kmes_rate_bucket, count);
}

void pkm_kmes_current_process_rate_refund(u32 count)
{
	struct pkm_kacs_process_state *state;

	if (count == 0)
		return;

	state = pkm_kacs_current_process_state();
	if (!state)
		return;

	pkm_kmes_rate_bucket_refund(state->kmes_rate_bucket, count);
}

static bool pkm_kacs_pip_dominates(u32 caller_pip_type, u32 caller_pip_trust,
				   u32 target_pip_type, u32 target_pip_trust)
{
	if (target_pip_type == 0)
		return true;

	return caller_pip_type >= target_pip_type &&
	       caller_pip_trust >= target_pip_trust;
}

static long pkm_kacs_authorize_process_sd_access(
	const void *subject_token,
	const struct pkm_kacs_process_sd *process_sd, u32 desired_access)
{
	u32 granted = 0;
	int ret;

	if (!subject_token || !process_sd || !process_sd->bytes || !process_sd->len)
		return -EACCES;

	ret = kacs_rust_check_process_sd(subject_token, process_sd->bytes,
					 process_sd->len, desired_access,
					 &granted);
	if (!ret)
		return 0;
	if (ret != -EACCES)
		return ret;
	if (!kacs_rust_token_has_enabled_privilege(subject_token,
						   PKM_KACS_PRIVILEGE_SE_DEBUG))
		return -EACCES;
	if (!kacs_rust_token_mark_privileges_used(
		    subject_token, PKM_KACS_PRIVILEGE_SE_DEBUG))
		return -EACCES;

	return 0;
}

static long pkm_kacs_require_enabled_privilege(const void *subject_token,
					       u64 privilege)
{
	if (!subject_token || privilege == 0)
		return -EPERM;
	if (!kacs_rust_token_has_enabled_privilege(subject_token, privilege))
		return -EPERM;
	if (!kacs_rust_token_mark_privileges_used(subject_token, privilege))
		return -EPERM;

	return 0;
}

int pkm_kacs_open_by_handle_at(void)
{
	return (int)pkm_kacs_require_enabled_privilege(
		pkm_kacs_current_effective_token_ptr(),
		PKM_KACS_PRIVILEGE_SE_CHANGE_NOTIFY);
}

static long pkm_kacs_authorize_process_sd_access_nondebug(
	const void *subject_token,
	const struct pkm_kacs_process_sd *process_sd, u32 desired_access,
	u32 privilege_intent)
{
	u32 granted = 0;

	if (!subject_token || !process_sd || !process_sd->bytes || !process_sd->len)
		return -EACCES;

	return kacs_rust_check_process_sd_with_intent(
		subject_token, process_sd->bytes, process_sd->len,
		desired_access, privilege_intent, &granted);
}

static long pkm_kacs_validate_sd_security_info(u32 security_info)
{
	if (security_info == 0 ||
	    (security_info & ~PKM_KACS_SD_SUPPORTED_INFO) != 0)
		return -EINVAL;
	if ((security_info & SACL_SECURITY_INFORMATION) != 0 &&
	    (security_info & LABEL_SECURITY_INFORMATION) != 0)
		return -EINVAL;

	return 0;
}

static long pkm_kacs_get_sd_required_access(u32 security_info,
					    u32 *desired_access_out)
{
	u32 desired_access = 0;
	long ret;

	if (!desired_access_out)
		return -EINVAL;

	ret = pkm_kacs_validate_sd_security_info(security_info);
	if (ret)
		return ret;

	if ((security_info &
	     (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
	      DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION)) != 0)
		desired_access |= KACS_ACCESS_READ_CONTROL;
	if ((security_info & SACL_SECURITY_INFORMATION) != 0)
		desired_access |= KACS_ACCESS_ACCESS_SYSTEM_SECURITY;

	*desired_access_out = desired_access;
	return 0;
}

static long pkm_kacs_set_sd_required_access(u32 security_info,
					    u32 *desired_access_out)
{
	u32 desired_access = 0;
	long ret;

	if (!desired_access_out)
		return -EINVAL;

	ret = pkm_kacs_validate_sd_security_info(security_info);
	if (ret)
		return ret;

	if ((security_info &
	     (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
	      LABEL_SECURITY_INFORMATION)) != 0)
		desired_access |= KACS_ACCESS_WRITE_OWNER;
	if ((security_info & DACL_SECURITY_INFORMATION) != 0)
		desired_access |= KACS_ACCESS_WRITE_DAC;
	if ((security_info & SACL_SECURITY_INFORMATION) != 0)
		desired_access |= KACS_ACCESS_ACCESS_SYSTEM_SECURITY;

	*desired_access_out = desired_access;
	return 0;
}

static long pkm_kacs_enforce_cross_process_pip(
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state, bool self_target)
{
	if (self_target)
		return 0;
	if (!caller_state || !target_state)
		return -EACCES;
	if (!pkm_kacs_pip_dominates(READ_ONCE(caller_state->pip_type),
				    READ_ONCE(caller_state->pip_trust),
				    READ_ONCE(target_state->pip_type),
				    READ_ONCE(target_state->pip_trust)))
		return -EACCES;

	return 0;
}

static long pkm_kacs_validate_empty_path_target(const char __user *path,
						u32 flags)
{
	char ch = '\0';

	if ((flags & ~PKM_KACS_SD_ALLOWED_AT_FLAGS) != 0)
		return -EINVAL;
	if ((flags & AT_EMPTY_PATH) == 0)
		return -EOPNOTSUPP;
	if (!path)
		return -EFAULT;
	if (copy_from_user(&ch, path, sizeof(ch)))
		return -EFAULT;
	if (ch != '\0')
		return -EOPNOTSUPP;

	return 0;
}

static long pkm_kacs_copy_open_how_from_user(
	struct kacs_open_how *out,
	const struct kacs_open_how __user *uhow, size_t howsize)
{
	int ret;

	if (!out || !uhow)
		return -EINVAL;
	if (howsize < PKM_KACS_OPEN_HOW_MIN_SIZE)
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

	valid_mask = PKM_KACS_FILE_READ_DATA | PKM_KACS_FILE_WRITE_DATA |
		     PKM_KACS_FILE_APPEND_DATA | PKM_KACS_FILE_READ_EA |
		     PKM_KACS_FILE_WRITE_EA | PKM_KACS_FILE_EXECUTE |
		     PKM_KACS_FILE_DELETE_CHILD |
		     PKM_KACS_FILE_READ_ATTRIBUTES |
		     PKM_KACS_FILE_WRITE_ATTRIBUTES | KACS_ACCESS_DELETE |
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
	if ((desired & KACS_ACCESS_MAXIMUM_ALLOWED) != 0)
		return -EINVAL;

	mapped = desired;
	if ((mapped & KACS_ACCESS_GENERIC_READ) != 0) {
		mapped &= ~KACS_ACCESS_GENERIC_READ;
		mapped |= PKM_KACS_FILE_READ_DATA |
			  PKM_KACS_FILE_READ_ATTRIBUTES |
			  PKM_KACS_FILE_READ_EA |
			  KACS_ACCESS_READ_CONTROL |
			  KACS_ACCESS_SYNCHRONIZE;
	}
	if ((mapped & KACS_ACCESS_GENERIC_WRITE) != 0) {
		mapped &= ~KACS_ACCESS_GENERIC_WRITE;
		mapped |= PKM_KACS_FILE_WRITE_DATA |
			  PKM_KACS_FILE_APPEND_DATA |
			  PKM_KACS_FILE_WRITE_ATTRIBUTES |
			  PKM_KACS_FILE_WRITE_EA |
			  KACS_ACCESS_READ_CONTROL |
			  KACS_ACCESS_SYNCHRONIZE;
	}
	if ((mapped & KACS_ACCESS_GENERIC_EXECUTE) != 0) {
		mapped &= ~KACS_ACCESS_GENERIC_EXECUTE;
		mapped |= PKM_KACS_FILE_EXECUTE |
			  PKM_KACS_FILE_READ_ATTRIBUTES |
			  KACS_ACCESS_READ_CONTROL |
			  KACS_ACCESS_SYNCHRONIZE;
	}
	if ((mapped & KACS_ACCESS_GENERIC_ALL) != 0) {
		mapped &= ~KACS_ACCESS_GENERIC_ALL;
		mapped |= PKM_KACS_FILE_READ_DATA |
			  PKM_KACS_FILE_WRITE_DATA |
			  PKM_KACS_FILE_APPEND_DATA |
			  PKM_KACS_FILE_READ_EA |
			  PKM_KACS_FILE_WRITE_EA |
			  PKM_KACS_FILE_EXECUTE |
			  PKM_KACS_FILE_DELETE_CHILD |
			  PKM_KACS_FILE_READ_ATTRIBUTES |
			  PKM_KACS_FILE_WRITE_ATTRIBUTES |
			  KACS_ACCESS_DELETE |
			  KACS_ACCESS_READ_CONTROL |
			  KACS_ACCESS_WRITE_DAC |
			  KACS_ACCESS_WRITE_OWNER |
			  KACS_ACCESS_SYNCHRONIZE;
	}

	*mapped_out = mapped;
	return 0;
}

static long pkm_kacs_prepare_native_open(
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
	if (how->create_disposition > KACS_FILE_OVERWRITE_IF)
		return -EINVAL;
	if (how->create_disposition == KACS_FILE_OPEN &&
	    (how->sd_ptr != 0 || how->sd_len != 0))
		return -EOPNOTSUPP;
	if (how->create_disposition == KACS_FILE_OVERWRITE &&
	    (how->sd_ptr != 0 || how->sd_len != 0))
		return -EINVAL;

	ret = pkm_kacs_map_file_generic_access_mask(how->desired_access,
						    &desired_access);
	if (ret)
		return ret;
	if ((desired_access & PKM_KACS_FILE_DELETE_CHILD) != 0)
		return -EOPNOTSUPP;

	data_mask = PKM_KACS_FILE_READ_DATA |
		    PKM_KACS_FILE_WRITE_DATA |
		    PKM_KACS_FILE_APPEND_DATA;
	has_read = (desired_access & PKM_KACS_FILE_READ_DATA) != 0;
	has_write = (desired_access &
		     (PKM_KACS_FILE_WRITE_DATA |
		      PKM_KACS_FILE_APPEND_DATA)) != 0;
	has_execute = (desired_access & PKM_KACS_FILE_EXECUTE) != 0;
	if ((desired_access & data_mask) == 0 && !has_execute)
		return -EINVAL;
	if (how->create_disposition == KACS_FILE_OVERWRITE &&
	    (desired_access & PKM_KACS_FILE_WRITE_DATA) == 0)
		return -EINVAL;
	if ((how->create_disposition == KACS_FILE_SUPERSEDE ||
	     how->create_disposition == KACS_FILE_OVERWRITE ||
	     how->create_disposition == KACS_FILE_OVERWRITE_IF) &&
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
	if ((desired_access & PKM_KACS_FILE_APPEND_DATA) != 0 &&
	    (desired_access & PKM_KACS_FILE_WRITE_DATA) == 0)
		open_flags |= O_APPEND;
	if (has_execute)
		open_flags |= __FMODE_EXEC;
	if ((how->create_options & KACS_CREATE_OPT_DIRECTORY) != 0)
		open_flags |= O_DIRECTORY;

	prepared->desired_access = desired_access;
	prepared->create_disposition = how->create_disposition;
	switch (how->create_disposition) {
	case KACS_FILE_OVERWRITE:
	case KACS_FILE_OVERWRITE_IF:
		prepared->status = KACS_STATUS_OVERWRITTEN;
		break;
	case KACS_FILE_SUPERSEDE:
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

static void pkm_kacs_set_current_native_open_request(
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

static void pkm_kacs_clear_current_native_open_request(void)
{
	pkm_kacs_set_current_native_open_request(NULL, 0, 0);
}

static bool pkm_kacs_native_open_request_matches(struct file *file,
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

static bool pkm_kacs_file_delete_on_close_pending(const struct file *file)
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
			subject_token, &parent_file, PKM_KACS_FILE_DELETE_CHILD);
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
		subject_token, &parent_file, PKM_KACS_FILE_DELETE_CHILD);
	path_put(&parent_path);
	return ret;
}

static long pkm_kacs_unlink_delete_on_close_file(struct file *file)
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

static long pkm_kacs_maybe_arm_delete_on_close_for_subject(
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
	    PKM_KACS_MOUNT_POLICY_UNMANAGED)
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

static void pkm_kacs_set_current_native_create_request(
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

static void pkm_kacs_clear_current_native_create_request(void)
{
	pkm_kacs_set_current_native_create_request(NULL, false, NULL, 0);
}

static bool pkm_kacs_current_native_create_request_matches(
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

static umode_t pkm_kacs_native_create_mode(bool directory)
{
	return directory ? (S_IFDIR | 0700) : (S_IFREG | 0600);
}

static bool pkm_kacs_special_node_mode_supported(umode_t mode)
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

static bool pkm_kacs_existing_file_object_mode_supported(umode_t mode)
{
	return S_ISREG(mode) || pkm_kacs_special_node_mode_supported(mode);
}

static long pkm_kacs_path_sd_lookup_flags(u32 flags,
					  unsigned int *lookup_flags_out)
{
	unsigned int lookup_flags = 0;

	if (!lookup_flags_out)
		return -EINVAL;
	if ((flags & ~PKM_KACS_SD_ALLOWED_AT_FLAGS) != 0)
		return -EINVAL;
	if ((flags & AT_EMPTY_PATH) != 0)
		return -EOPNOTSUPP;

	if ((flags & AT_SYMLINK_NOFOLLOW) == 0)
		lookup_flags |= LOOKUP_FOLLOW;

	*lookup_flags_out = lookup_flags;
	return 0;
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

static long pkm_kacs_build_created_file_sd_for_subject(
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
	parent_right = directory ? PKM_KACS_FILE_ADD_SUBDIRECTORY :
				   PKM_KACS_FILE_ADD_FILE;

	mutex_lock(&parent_sec->lock);
	ret = pkm_kacs_inode_resolve_effective_cache_locked(parent_file, parent_sec,
							    &parent_cache);
	if (ret)
		goto out_unlock;
	if (parent_cache->state != PKM_KACS_INODE_SD_VALID ||
	    !parent_cache->bytes || parent_cache->len == 0) {
		ret = -EACCES;
		goto out_unlock;
	}

	ret = kacs_rust_check_file_sd_with_intent(subject_token, parent_cache->bytes,
						  parent_cache->len, parent_right,
						  0, &granted_access);
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
			desired_access, 0, &granted_access);
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

static long pkm_kacs_authorize_live_file_access_core(
	const void *subject_token, struct file *file, u32 desired_access)
{
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct inode *inode;
	u32 granted_access = 0;
	long ret;

	if (!subject_token || !file || desired_access == 0)
		return -EINVAL;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    PKM_KACS_MOUNT_POLICY_UNMANAGED)
		return -EOPNOTSUPP;

	sec = pkm_kacs_inode(inode);
	mutex_lock(&sec->lock);
	ret = pkm_kacs_inode_resolve_effective_cache_locked(file, sec, &cache);
	if (!ret) {
		if (cache->state != PKM_KACS_INODE_SD_VALID || !cache->bytes ||
		    cache->len == 0) {
			ret = -EACCES;
		} else {
			ret = kacs_rust_check_file_sd_with_intent(
				subject_token, cache->bytes, cache->len,
				desired_access, 0, &granted_access);
		}
	}
	mutex_unlock(&sec->lock);
	return ret;
}

static long pkm_kacs_authorize_path_file_access_core(
	const void *subject_token, const struct path *path, u32 desired_access)
{
	struct file file = {};

	if (!path)
		return -EINVAL;

	pkm_kacs_init_path_anchor_file(&file, path);
	return pkm_kacs_authorize_live_file_access_core(subject_token, &file,
							desired_access);
}

static bool pkm_kacs_inode_permission_is_traverse(struct inode *inode, int mask)
{
	int permission_mask = mask & ~MAY_NOT_BLOCK;

	if (!inode || !S_ISDIR(inode->i_mode))
		return false;
	if ((permission_mask & MAY_EXEC) == 0)
		return false;
	if ((permission_mask & (MAY_OPEN | MAY_ACCESS)) != 0)
		return false;

	return true;
}

static long pkm_kacs_authorize_inode_file_access_core(
	const void *subject_token, struct inode *inode, struct dentry *dentry,
	u32 desired_access)
{
	struct vfsmount mnt = {};
	struct dentry *alias = NULL;
	struct path path = {};
	struct file file = {};
	long ret;

	if (!subject_token || !inode || desired_access == 0)
		return -EINVAL;
	if (!inode->i_security)
		return -EACCES;

	if (!dentry) {
		alias = d_find_any_alias(inode);
		if (!alias)
			return -EACCES;
		dentry = alias;
	}

	mnt.mnt_root = dentry;
	mnt.mnt_sb = inode->i_sb;
	mnt.mnt_idmap = &nop_mnt_idmap;
	path.mnt = &mnt;
	path.dentry = dentry;
	pkm_kacs_init_path_anchor_file(&file, &path);

	ret = pkm_kacs_authorize_live_file_access_core(subject_token, &file,
						       desired_access);
	if (alias)
		dput(alias);
	return ret;
}

static long pkm_kacs_check_inode_permission_live_for_subject(
	const void *subject_token, struct inode *inode, struct dentry *dentry,
	int mask)
{
	bool explicit_chdir;

	if (!pkm_kacs_inode_permission_is_traverse(inode, mask))
		return 0;
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return 0;
	if (!subject_token)
		return -EACCES;

	explicit_chdir = (mask & MAY_CHDIR) != 0;
	if (!explicit_chdir &&
	    kacs_rust_token_has_enabled_privilege(
		    subject_token, PKM_KACS_PRIVILEGE_SE_CHANGE_NOTIFY)) {
		if (!kacs_rust_token_mark_privileges_used(
			    subject_token, PKM_KACS_PRIVILEGE_SE_CHANGE_NOTIFY))
			return -EACCES;
		return 0;
	}

	if ((mask & MAY_NOT_BLOCK) != 0)
		return -ECHILD;

	return pkm_kacs_authorize_inode_file_access_core(
		subject_token, inode, dentry, PKM_KACS_FILE_TRAVERSE);
}

static bool pkm_kacs_inode_on_unmanaged_mount(const struct inode *inode)
{
	return inode &&
	       pkm_kacs_superblock_mount_policy(inode->i_sb) ==
		       PKM_KACS_MOUNT_POLICY_UNMANAGED;
}

static struct dentry *pkm_kacs_parent_dentry_for_inode(
	struct inode *parent_inode, struct dentry *child_dentry)
{
	struct dentry *parent_dentry;

	if (!parent_inode || !child_dentry)
		return NULL;

	parent_dentry = child_dentry->d_parent;
	if (!parent_dentry || d_inode(parent_dentry) != parent_inode)
		return NULL;

	return parent_dentry;
}

static long pkm_kacs_authorize_inode_namespace_access_for_subject(
	const void *subject_token, struct inode *inode, struct dentry *dentry,
	u32 desired_access)
{
	if (!inode || desired_access == 0)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return 0;
	if (!subject_token)
		return -EACCES;

	return pkm_kacs_authorize_inode_file_access_core(
		subject_token, inode, dentry, desired_access);
}

static long pkm_kacs_authorize_parent_namespace_access_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *child_dentry, u32 desired_access)
{
	struct dentry *parent_dentry;

	if (!parent_inode || desired_access == 0)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(parent_inode))
		return 0;

	parent_dentry = pkm_kacs_parent_dentry_for_inode(parent_inode,
							  child_dentry);
	return pkm_kacs_authorize_inode_namespace_access_for_subject(
		subject_token, parent_inode, parent_dentry, desired_access);
}

static long pkm_kacs_authorize_namespace_delete_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *target_dentry)
{
	struct inode *target_inode;
	long ret;

	if (!target_dentry)
		return -EACCES;

	target_inode = d_inode(target_dentry);
	if (!target_inode)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(target_inode) &&
	    pkm_kacs_inode_on_unmanaged_mount(parent_inode))
		return 0;

	ret = pkm_kacs_authorize_inode_namespace_access_for_subject(
		subject_token, target_inode, target_dentry, KACS_ACCESS_DELETE);
	if (ret != -EACCES)
		return ret;

	return pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, parent_inode, target_dentry,
		PKM_KACS_FILE_DELETE_CHILD);
}

static long pkm_kacs_authorize_namespace_create_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *child_dentry, bool directory)
{
	u32 desired_access = directory ? PKM_KACS_FILE_ADD_SUBDIRECTORY :
					 PKM_KACS_FILE_ADD_FILE;

	return pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, parent_inode, child_dentry, desired_access);
}

static long pkm_kacs_authorize_namespace_symlink_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *child_dentry)
{
	long ret;

	ret = pkm_kacs_authorize_namespace_create_for_subject(
		subject_token, parent_inode, child_dentry, false);
	if (ret)
		return ret;
	if (pkm_kacs_inode_on_unmanaged_mount(parent_inode))
		return 0;

	return pkm_kacs_require_enabled_privilege(
		subject_token, PKM_KACS_PRIVILEGE_SE_CREATE_SYMBOLIC_LINK);
}

static long pkm_kacs_authorize_namespace_link_for_subject(
	const void *subject_token, struct dentry *old_dentry, struct inode *dir,
	struct dentry *new_dentry)
{
	struct inode *source_inode;
	long ret;

	if (!old_dentry || !dir || !new_dentry)
		return -EACCES;

	ret = pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, dir, new_dentry, PKM_KACS_FILE_ADD_FILE);
	if (ret)
		return ret;

	source_inode = d_inode(old_dentry);
	if (!source_inode)
		return -EACCES;

	return pkm_kacs_authorize_inode_namespace_access_for_subject(
		subject_token, source_inode, old_dentry,
		PKM_KACS_FILE_WRITE_ATTRIBUTES);
}

static long pkm_kacs_authorize_namespace_rename_for_subject(
	const void *subject_token, struct inode *old_dir,
	struct dentry *old_dentry, struct inode *new_dir,
	struct dentry *new_dentry)
{
	struct inode *source_inode;
	u32 add_access;
	long ret;

	if (!old_dir || !old_dentry || !new_dir || !new_dentry)
		return -EACCES;

	source_inode = d_inode(old_dentry);
	if (!source_inode)
		return -EACCES;

	ret = pkm_kacs_authorize_namespace_delete_for_subject(
		subject_token, old_dir, old_dentry);
	if (ret)
		return ret;

	add_access = S_ISDIR(source_inode->i_mode) ?
			     PKM_KACS_FILE_ADD_SUBDIRECTORY :
			     PKM_KACS_FILE_ADD_FILE;
	ret = pkm_kacs_authorize_parent_namespace_access_for_subject(
		subject_token, new_dir, new_dentry, add_access);
	if (ret)
		return ret;

	if (d_is_positive(new_dentry)) {
		ret = pkm_kacs_authorize_namespace_delete_for_subject(
			subject_token, new_dir, new_dentry);
		if (ret)
			return ret;
	}

	return 0;
}

static long pkm_kacs_build_legacy_created_file_sd_for_subject(
	const void *subject_token, struct inode *parent_inode,
	struct dentry *parent_dentry, bool directory, const u8 **out_sd_ptr,
	size_t *out_sd_len)
{
	struct vfsmount mnt = {};
	struct dentry *alias = NULL;
	struct path parent_path = {};
	struct file parent_file = {};
	long ret;

	if (!subject_token || !parent_inode || !out_sd_ptr || !out_sd_len)
		return -EINVAL;
	if (pkm_kacs_inode_on_unmanaged_mount(parent_inode))
		return -EOPNOTSUPP;

	if (!parent_dentry) {
		alias = d_find_any_alias(parent_inode);
		if (!alias)
			return -EACCES;
		parent_dentry = alias;
	}
	if (d_inode(parent_dentry) != parent_inode) {
		ret = -EACCES;
		goto out;
	}

	mnt.mnt_root = parent_dentry;
	mnt.mnt_sb = parent_inode->i_sb;
	mnt.mnt_idmap = &nop_mnt_idmap;
	parent_path.mnt = &mnt;
	parent_path.dentry = parent_dentry;
	pkm_kacs_init_path_anchor_file(&parent_file, &parent_path);

	ret = pkm_kacs_build_created_file_sd_for_subject(
		subject_token, &parent_file, NULL, 0, directory, 0,
		out_sd_ptr, out_sd_len, NULL);
out:
	if (alias)
		dput(alias);
	return ret;
}

int pkm_kacs_inode_rename_flags(struct inode *old_dir,
				struct dentry *old_dentry,
				struct inode *new_dir,
				struct dentry *new_dentry,
				unsigned int flags)
{
	(void)old_dentry;
	(void)new_dentry;

	if ((flags & RENAME_WHITEOUT) == 0)
		return 0;
	if (pkm_kacs_inode_on_unmanaged_mount(old_dir) &&
	    pkm_kacs_inode_on_unmanaged_mount(new_dir))
		return 0;

	return -EOPNOTSUPP;
}

static int pkm_kacs_inode_create(struct inode *dir, struct dentry *dentry,
				 umode_t mode)
{
	(void)mode;
	return (int)pkm_kacs_authorize_namespace_create_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry, false);
}

static int pkm_kacs_inode_mkdir(struct inode *dir, struct dentry *dentry,
				umode_t mode)
{
	(void)mode;
	return (int)pkm_kacs_authorize_namespace_create_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry, true);
}

static int pkm_kacs_inode_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev)
{
	(void)dev;

	if (!pkm_kacs_inode_on_unmanaged_mount(dir) &&
	    !pkm_kacs_special_node_mode_supported(mode))
		return -EOPNOTSUPP;

	return (int)pkm_kacs_authorize_namespace_create_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry, false);
}

static int pkm_kacs_inode_symlink(struct inode *dir, struct dentry *dentry,
				  const char *old_name)
{
	(void)old_name;
	return (int)pkm_kacs_authorize_namespace_symlink_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry);
}

static int pkm_kacs_inode_link(struct dentry *old_dentry, struct inode *dir,
			       struct dentry *new_dentry)
{
	return (int)pkm_kacs_authorize_namespace_link_for_subject(
		pkm_kacs_current_effective_token_ptr(), old_dentry, dir,
		new_dentry);
}

static int pkm_kacs_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return (int)pkm_kacs_authorize_namespace_delete_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry);
}

static int pkm_kacs_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return (int)pkm_kacs_authorize_namespace_delete_for_subject(
		pkm_kacs_current_effective_token_ptr(), dir, dentry);
}

static int pkm_kacs_inode_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry)
{
	return (int)pkm_kacs_authorize_namespace_rename_for_subject(
		pkm_kacs_current_effective_token_ptr(), old_dir, old_dentry,
		new_dir, new_dentry);
}

static int pkm_kacs_inode_readlink(struct dentry *dentry)
{
	struct inode *inode;

	if (!dentry)
		return -EACCES;

	inode = d_inode(dentry);
	return (int)pkm_kacs_authorize_inode_namespace_access_for_subject(
		pkm_kacs_current_effective_token_ptr(), inode, dentry,
		PKM_KACS_FILE_READ_DATA);
}

static int pkm_kacs_authorize_path_metadata_access(const struct path *path,
						   u32 desired_access)
{
	const void *subject_token;

	if (!path || !path->dentry || desired_access == 0)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(d_inode(path->dentry)))
		return 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	return (int)pkm_kacs_authorize_path_file_access_core(
		subject_token, path, desired_access);
}

static int pkm_kacs_authorize_dentry_metadata_access(struct dentry *dentry,
						     u32 desired_access)
{
	struct vfsmount mnt = {};
	struct path path = {};
	struct file file = {};
	const void *subject_token;
	struct inode *inode;

	if (!dentry || desired_access == 0)
		return -EACCES;

	inode = d_inode(dentry);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_inode_on_unmanaged_mount(inode))
		return 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	mnt.mnt_root = dentry;
	mnt.mnt_sb = inode->i_sb;
	mnt.mnt_idmap = &nop_mnt_idmap;
	path.mnt = &mnt;
	path.dentry = dentry;
	pkm_kacs_init_path_anchor_file(&file, &path);

	return (int)pkm_kacs_authorize_live_file_access_core(
		subject_token, &file, desired_access);
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

static long pkm_kacs_do_native_overwrite_open(
	const struct path *resolved_path,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out)
{
	struct file *file = NULL;
	struct inode *inode;
	long ret;

	if (!resolved_path || !prepared || !file_out || !status_out)
		return -EINVAL;

	if ((prepared->desired_access & PKM_KACS_FILE_WRITE_DATA) == 0)
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

static long pkm_kacs_do_native_supersede_open(
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
			PKM_KACS_FILE_DELETE_CHILD);
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
			(unsigned long long)atomic64_inc_return(
				&pkm_kacs_native_supersede_tmp_counter));
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

static int pkm_kacs_inode_init_security(struct inode *inode, struct inode *dir,
					const struct qstr *qstr,
					struct xattr *xattrs,
					int *xattr_count)
{
	struct xattr *xattr;
	const void *subject_token;
	const u8 *sd_bytes = NULL;
	size_t sd_len = 0;
	u8 *copied_bytes;
	bool allocated_sd = false;
	long ret;

	(void)qstr;
	if (!inode || !dir || !xattrs || !xattr_count)
		return -EOPNOTSUPP;
	if (pkm_kacs_inode_is_ntfs(inode))
		return -EOPNOTSUPP;
	if (!pkm_kacs_current_native_create_request_matches(
		    dir, S_ISDIR(inode->i_mode), &sd_bytes, &sd_len)) {
		subject_token = pkm_kacs_current_effective_token_ptr();
		if (!subject_token)
			return -EACCES;
		ret = pkm_kacs_build_legacy_created_file_sd_for_subject(
			subject_token, dir, NULL, S_ISDIR(inode->i_mode),
			&sd_bytes, &sd_len);
		if (ret)
			return ret;
		allocated_sd = true;
	}
	if (!sd_bytes || sd_len == 0)
		return allocated_sd ? -EACCES : -EOPNOTSUPP;

	copied_bytes = kmemdup(sd_bytes, sd_len, GFP_NOFS);
	if (allocated_sd)
		pkm_kacs_free((void *)sd_bytes);
	if (!copied_bytes)
		return -ENOMEM;

	xattr = lsm_get_xattr_slot(xattrs, xattr_count);
	if (!xattr) {
		kfree(copied_bytes);
		return -ENOMEM;
	}

	xattr->name = "peios.sd";
	xattr->value = copied_bytes;
	xattr->value_len = sd_len;
	return 0;
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

	child_path.mnt = parent_path.mnt;
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

static long pkm_kacs_resolve_pidfd_process_target(
	int dirfd, const char __user *path, u32 flags,
	const void **subject_token_out,
	struct pkm_kacs_process_state **caller_state_out,
	struct task_struct **task_out,
	struct pkm_kacs_process_state **target_state_out, bool *self_target_out)
{
	struct pkm_kacs_process_state *caller_state;
	const void *subject_token;
	unsigned int pidfd_flags = 0;
	struct file *pidfd_file;
	struct task_struct *task;
	struct pid *pid;
	long ret;

	if (!subject_token_out || !caller_state_out || !task_out ||
	    !target_state_out || !self_target_out)
		return -EINVAL;

	ret = pkm_kacs_validate_empty_path_target(path, flags);
	if (ret)
		return ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	caller_state = pkm_kacs_current_process_state();
	if (!subject_token || !caller_state)
		return -EACCES;

	pidfd_file = fget_raw(dirfd);
	if (!pidfd_file)
		return -EBADF;

	pid = pidfd_pid(pidfd_file);
	if (IS_ERR(pid)) {
		fput(pidfd_file);
		return -EOPNOTSUPP;
	}

	get_pid(pid);
	pidfd_flags = pidfd_file->f_flags;
	fput(pidfd_file);
	(void)pidfd_flags;

	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!task)
		return -ESRCH;
	if (!task->security || !pkm_kacs_task(task)->process_state) {
		put_task_struct(task);
		return -EACCES;
	}

	*subject_token_out = subject_token;
	*caller_state_out = caller_state;
	*task_out = task;
	*target_state_out = pkm_kacs_task(task)->process_state;
	*self_target_out = (*target_state_out == caller_state);
	return 0;
}

static bool pkm_kacs_file_is_pidfd(const struct file *file)
{
	struct pid *pid;

	if (!file)
		return false;

	pid = pidfd_pid((struct file *)file);
	return !IS_ERR(pid);
}

static long pkm_kacs_resolve_file_target(
	int dirfd, const char __user *path, u32 flags,
	const void **subject_token_out, struct file **file_out)
{
	const void *subject_token;
	struct file *file;
	long ret;

	if (!subject_token_out || !file_out)
		return -EINVAL;

	ret = pkm_kacs_validate_empty_path_target(path, flags);
	if (ret)
		return ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	file = fget_raw(dirfd);
	if (!file)
		return -EBADF;
	if (pkm_kacs_file_is_pidfd(file) || !file_dentry(file) ||
	    !file_inode(file)) {
		fput(file);
		return -EOPNOTSUPP;
	}

	*subject_token_out = subject_token;
	*file_out = file;
	return 0;
}

static long pkm_kacs_resolve_path_file_target(
	int dirfd, const char __user *path, u32 flags,
	const void **subject_token_out, struct path *path_out)
{
	const void *subject_token;
	unsigned int lookup_flags = 0;
	long ret;

	if (!subject_token_out || !path_out)
		return -EINVAL;
	if (!path)
		return -EFAULT;

	ret = pkm_kacs_path_sd_lookup_flags(flags, &lookup_flags);
	if (ret)
		return ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	ret = user_path_at(dirfd, path, lookup_flags, path_out);
	if (ret)
		return ret;
	if (!path_out->dentry || !d_inode(path_out->dentry)) {
		path_put(path_out);
		return -EACCES;
	}

	*subject_token_out = subject_token;
	return 0;
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
	    PKM_KACS_MOUNT_POLICY_UNMANAGED) {
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
		   (prepared->desired_access & PKM_KACS_FILE_EXECUTE) != 0) {
		path_put(resolved_path);
		return -EACCES;
	}

	return 0;
}

static long pkm_kacs_build_legacy_open_access_masks(const struct file *file,
						    u32 *core_access_out,
						    u32 *requested_access_out)
{
	struct inode *inode;
	u32 core_access = 0;
	u32 compat_access = PKM_KACS_FILE_READ_EA |
			    KACS_ACCESS_READ_CONTROL |
			    PKM_KACS_FILE_WRITE_ATTRIBUTES |
			    PKM_KACS_FILE_WRITE_EA |
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

		core_access = PKM_KACS_FILE_READ_ATTRIBUTES |
			      PKM_KACS_FILE_TRAVERSE;
		compat_access |= PKM_KACS_FILE_LIST_DIRECTORY;
	} else {
		if (!(S_ISREG(inode->i_mode) || S_ISCHR(inode->i_mode) ||
		      S_ISBLK(inode->i_mode) || S_ISFIFO(inode->i_mode) ||
		      S_ISSOCK(inode->i_mode)))
			return -EACCES;

		switch (mode) {
		case FMODE_READ:
			core_access = PKM_KACS_FILE_READ_DATA |
				      PKM_KACS_FILE_READ_ATTRIBUTES;
			break;
		case FMODE_WRITE:
			core_access = PKM_KACS_FILE_WRITE_DATA |
				      PKM_KACS_FILE_READ_ATTRIBUTES;
			break;
		case FMODE_READ | FMODE_WRITE:
			core_access = PKM_KACS_FILE_READ_DATA |
				      PKM_KACS_FILE_WRITE_DATA |
				      PKM_KACS_FILE_READ_ATTRIBUTES;
			break;
		default:
			return -EACCES;
		}

		compat_access |= PKM_KACS_FILE_EXECUTE;
		if ((file->f_flags & O_APPEND) != 0) {
			core_access &= ~PKM_KACS_FILE_WRITE_DATA;
			core_access |= PKM_KACS_FILE_APPEND_DATA;
			compat_access |= PKM_KACS_FILE_WRITE_DATA;
		}
		if ((file->f_flags & O_TRUNC) != 0)
			core_access |= PKM_KACS_FILE_WRITE_DATA;
	}

	*core_access_out = core_access;
	*requested_access_out = core_access | compat_access;
	return 0;
}

static long pkm_kacs_stamp_native_file_granted_access_for_subject(
	const void *subject_token, struct file *file, u32 desired_access)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct inode *inode;
	u32 granted_access = 0;
	u32 continuous_audit_mask = 0;
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

	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    PKM_KACS_MOUNT_POLICY_UNMANAGED)
		return -EOPNOTSUPP;

	inode_sec = pkm_kacs_inode(inode);
	mutex_lock(&inode_sec->lock);
	ret = pkm_kacs_inode_resolve_effective_cache_locked(file, inode_sec,
							    &cache);
	if (!ret) {
		if (cache->state != PKM_KACS_INODE_SD_VALID || !cache->bytes ||
		    cache->len == 0) {
			ret = -EACCES;
		} else {
			ret = kacs_rust_check_file_sd_with_intent_audit(
				subject_token, cache->bytes, cache->len,
				desired_access, 0, &granted_access,
				&continuous_audit_mask);
			if (!ret) {
				file_sec->granted_access = granted_access;
				file_sec->continuous_audit_mask =
					continuous_audit_mask;
				file_sec->managed = 1;
				if ((desired_access &
				     PKM_KACS_FILE_EXECUTE) != 0)
					file->f_mode |= FMODE_EXEC;
				if (!S_ISDIR(inode->i_mode)) {
					if ((desired_access &
					     PKM_KACS_FILE_READ_DATA) == 0)
						file->f_mode &= ~FMODE_READ;
					if ((desired_access &
					     (PKM_KACS_FILE_WRITE_DATA |
					      PKM_KACS_FILE_APPEND_DATA)) == 0)
						file->f_mode &= ~FMODE_WRITE;
				}
			}
		}
	}
	mutex_unlock(&inode_sec->lock);
	return ret;
}

static long pkm_kacs_stamp_file_granted_access_for_subject(
	const void *subject_token, struct file *file)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct inode *inode;
	u32 mount_policy;
	u32 core_access = 0;
	u32 requested_access = 0;
	u32 granted_access = 0;
	u32 continuous_audit_mask = 0;
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
	if (!pkm_kacs_mount_policy_is_managed(mount_policy))
		return 0;

	ret = pkm_kacs_build_legacy_open_access_masks(file, &core_access,
						      &requested_access);
	if (ret)
		return ret;

	inode_sec = pkm_kacs_inode(inode);
	mutex_lock(&inode_sec->lock);
	ret = pkm_kacs_inode_resolve_effective_cache_locked(file, inode_sec,
							    &cache);
	if (!ret) {
		if (cache->state != PKM_KACS_INODE_SD_VALID || !cache->bytes ||
		    cache->len == 0) {
			ret = -EACCES;
		} else {
			ret = kacs_rust_granted_file_sd_with_intent_audit(
				subject_token, cache->bytes, cache->len,
				requested_access, 0, &granted_access,
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
	}
	mutex_unlock(&inode_sec->lock);
	return ret;
}

static long pkm_kacs_resolve_tokenfd_target(int dirfd,
					    const char __user *path,
					    u32 flags,
					    const void **subject_token_out,
					    const void **target_token_out)
{
	const void *subject_token;
	const void *target_token = NULL;
	long ret;

	if (!subject_token_out || !target_token_out)
		return -EINVAL;

	ret = pkm_kacs_validate_empty_path_target(path, flags);
	if (ret)
		return ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	ret = pkm_kacs_token_fd_clone_token(dirfd, &target_token, NULL);
	if (ret == -EINVAL)
		return -EOPNOTSUPP;
	if (ret)
		return ret;

	*subject_token_out = subject_token;
	*target_token_out = target_token;
	return 0;
}

static long pkm_kacs_query_token_sd_core(const void *subject_token,
					 const void *target_token,
					 u32 security_info,
					 const u8 **out_sd_ptr,
					 size_t *out_sd_len)
{
	u32 desired_access;
	u32 granted = 0;
	long ret;

	if (!subject_token || !target_token || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	ret = pkm_kacs_get_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	ret = kacs_rust_check_token_sd_with_intent(subject_token, target_token,
						   desired_access, 0,
						   &granted);
	if (ret)
		return ret;

	return kacs_rust_query_token_sd_subset(target_token, security_info,
					       out_sd_ptr, out_sd_len);
}

static long pkm_kacs_set_token_sd_core(const void *subject_token,
				       const void *target_token,
				       u32 security_info,
				       const u8 *input_sd_ptr,
				       size_t input_sd_len)
{
	u32 desired_access;
	u32 granted = 0;
	long ret;

	if (!subject_token || !target_token || !input_sd_ptr || input_sd_len == 0)
		return -EINVAL;

	ret = pkm_kacs_set_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	ret = kacs_rust_check_token_sd_with_intent(subject_token, target_token,
						   desired_access,
						   KACS_RESTORE_INTENT,
						   &granted);
	if (ret)
		return ret;

	return kacs_rust_set_token_sd(subject_token, target_token, security_info,
				      input_sd_ptr, input_sd_len);
}

static long pkm_kacs_query_process_sd_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state, bool self_target,
	u32 security_info, const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_process_sd *process_sd;
	u32 desired_access;
	long ret;

	if (!out_sd_ptr || !out_sd_len)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	ret = pkm_kacs_get_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	process_sd = pkm_kacs_process_state_get_sd(
		(struct pkm_kacs_process_state *)target_state);
	if (!process_sd)
		return -EACCES;

	ret = pkm_kacs_authorize_process_sd_access_nondebug(
		subject_token, process_sd, desired_access, 0);
	if (!ret)
		ret = pkm_kacs_enforce_cross_process_pip(caller_state,
							 target_state,
							 self_target);
	if (!ret)
		ret = kacs_rust_query_process_sd_subset(
			process_sd->bytes, process_sd->len, security_info,
			out_sd_ptr, out_sd_len);

	pkm_kacs_process_sd_put(process_sd);
	return ret;
}

static long pkm_kacs_set_process_sd_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct pkm_kacs_process_state *target_state, bool self_target,
	u32 security_info, const u8 *input_sd_ptr, size_t input_sd_len)
{
	struct pkm_kacs_process_sd *process_sd = NULL;
	struct pkm_kacs_process_sd *new_sd = NULL;
	const u8 *new_sd_bytes = NULL;
	size_t new_sd_len = 0;
	u32 desired_access;
	long ret;

	if (!subject_token || !caller_state || !target_state || !input_sd_ptr ||
	    input_sd_len == 0)
		return -EINVAL;

	ret = pkm_kacs_set_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	mutex_lock(&target_state->sd_lock);
	process_sd = pkm_kacs_process_sd_get(target_state->process_sd);
	if (!process_sd) {
		ret = -EACCES;
		goto out_unlock;
	}

	ret = pkm_kacs_authorize_process_sd_access_nondebug(
		subject_token, process_sd, desired_access, KACS_RESTORE_INTENT);
	if (ret)
		goto out_process_sd;
	ret = pkm_kacs_enforce_cross_process_pip(caller_state, target_state,
							 self_target);
	if (ret)
		goto out_process_sd;
	ret = kacs_rust_merge_process_sd(subject_token, process_sd->bytes,
					 process_sd->len, security_info,
					 input_sd_ptr, input_sd_len,
					 &new_sd_bytes, &new_sd_len);
	if (ret)
		goto out_process_sd;

	new_sd = pkm_kacs_process_sd_wrap_bytes(new_sd_bytes, new_sd_len);
	if (!new_sd) {
		pkm_kacs_free((void *)new_sd_bytes);
		ret = -ENOMEM;
		goto out_process_sd;
	}

	pkm_kacs_process_state_replace_sd_locked(target_state, new_sd);
	new_sd = NULL;
	ret = 0;

out_process_sd:
	pkm_kacs_process_sd_put(process_sd);
out_unlock:
	mutex_unlock(&target_state->sd_lock);
	pkm_kacs_process_sd_put(new_sd);
	return ret;
}

static long pkm_kacs_query_file_sd_core(const void *subject_token,
					struct file *file, u32 security_info,
					const u8 **out_sd_ptr,
					size_t *out_sd_len)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct inode *inode;
	u32 desired_access = 0;
	bool use_live_access_check;
	long ret;

	if (!file || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    PKM_KACS_MOUNT_POLICY_UNMANAGED)
		return -EOPNOTSUPP;

	ret = pkm_kacs_get_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	use_live_access_check = (file->f_mode & FMODE_PATH) != 0;
	if (!use_live_access_check) {
		if (!file->f_security)
			return -EACCES;
		file_sec = pkm_kacs_file(file);
		if (!file_sec->managed)
			return -EOPNOTSUPP;
		if ((file_sec->granted_access & desired_access) != desired_access)
			return -EACCES;
		if (!subject_token)
			return -EACCES;
	}

	sec = pkm_kacs_inode(inode);
	mutex_lock(&sec->lock);
	ret = pkm_kacs_inode_resolve_effective_cache_locked(file, sec, &cache);
	if (!ret) {
		if (use_live_access_check) {
			ret = pkm_kacs_query_file_sd_bytes_core(subject_token,
								cache,
								security_info,
								out_sd_ptr,
								out_sd_len);
		} else if (cache->state != PKM_KACS_INODE_SD_VALID ||
			   !cache->bytes || cache->len == 0) {
			ret = -EACCES;
		} else {
			ret = kacs_rust_query_file_sd_subset(
				cache->bytes, cache->len, security_info,
				out_sd_ptr, out_sd_len);
		}
	}
	mutex_unlock(&sec->lock);
	return ret;
}

static void pkm_kacs_init_path_anchor_file(struct file *file,
					   const struct path *path)
{
	if (!file || !path)
		return;

	memset(file, 0, sizeof(*file));
	file->f_inode = d_inode(path->dentry);
	file->f_mode = FMODE_PATH;
	*(struct path *)&file->f_path = *path;
}

static long pkm_kacs_query_path_file_sd_core(const void *subject_token,
					     const struct path *path,
					     u32 security_info,
					     const u8 **out_sd_ptr,
					     size_t *out_sd_len)
{
	struct file file = {};

	if (!path)
		return -EINVAL;

	pkm_kacs_init_path_anchor_file(&file, path);
	return pkm_kacs_query_file_sd_core(subject_token, &file, security_info,
					   out_sd_ptr, out_sd_len);
}

static long pkm_kacs_set_file_sd_core(const void *subject_token,
				      struct file *file, u32 security_info,
				      const u8 *input_sd_ptr,
				      size_t input_sd_len)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct pkm_kacs_inode_sd_cache *new_cache = NULL;
	struct inode *inode;
	const u8 *new_sd_bytes = NULL;
	size_t new_sd_len = 0;
	bool used_restore_bypass = false;
	bool use_live_access_check;
	u32 desired_access = 0;
	long ret;

	if (!subject_token || !file || !input_sd_ptr || input_sd_len == 0)
		return -EINVAL;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    PKM_KACS_MOUNT_POLICY_UNMANAGED)
		return -EOPNOTSUPP;

	ret = pkm_kacs_set_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	use_live_access_check = (file->f_mode & FMODE_PATH) != 0;
	if (!use_live_access_check) {
		if (!file->f_security)
			return -EACCES;
		file_sec = pkm_kacs_file(file);
		if (!file_sec->managed)
			return -EOPNOTSUPP;
		if ((file_sec->granted_access & desired_access) != desired_access)
			return -EACCES;
	}

	sec = pkm_kacs_inode(inode);
	mutex_lock(&sec->lock);
	ret = pkm_kacs_inode_resolve_effective_cache_locked(file, sec, &cache);
	if (ret)
		goto out_unlock;

	ret = pkm_kacs_prepare_new_file_sd_core(subject_token, cache,
						security_info, input_sd_ptr,
						input_sd_len,
						use_live_access_check,
						&new_sd_bytes, &new_sd_len);
	if (ret)
		goto out_unlock;
	used_restore_bypass = cache->state != PKM_KACS_INODE_SD_VALID;

	new_cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_VALID,
						  new_sd_bytes, new_sd_len);
	if (!new_cache) {
		ret = -ENOMEM;
		goto out_bytes;
	}

	ret = pkm_kacs_inode_write_sd_xattr_locked(file, new_sd_bytes,
						   new_sd_len);
	if (ret)
		goto out_bytes;
	if (used_restore_bypass)
		(void)kacs_rust_token_mark_privileges_used(
			subject_token, PKM_KACS_PRIVILEGE_SE_RESTORE);

	pkm_kacs_inode_replace_sd_cache_locked(sec, new_cache);
	new_cache = NULL;
	new_sd_bytes = NULL;
	ret = 0;
	goto out_unlock;

out_bytes:
	if (!new_cache && new_sd_bytes)
		pkm_kacs_free((void *)new_sd_bytes);
out_unlock:
	mutex_unlock(&sec->lock);
	pkm_kacs_inode_sd_cache_free(new_cache);
	return ret;
}

static long pkm_kacs_set_path_file_sd_core(const void *subject_token,
					   const struct path *path,
					   u32 security_info,
					   const u8 *input_sd_ptr,
					   size_t input_sd_len)
{
	struct file file = {};

	if (!path)
		return -EINVAL;

	pkm_kacs_init_path_anchor_file(&file, path);
	return pkm_kacs_set_file_sd_core(subject_token, &file, security_info,
					 input_sd_ptr, input_sd_len);
}

static long pkm_kacs_authorize_process_access_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *target_state, u32 caller_pip_type,
	u32 caller_pip_trust, u32 desired_process_access)
{
	struct pkm_kacs_process_sd *process_sd;
	long ret;

	if (!subject_token || !target_state)
		return -EACCES;

	process_sd = pkm_kacs_process_state_get_sd(
		(struct pkm_kacs_process_state *)target_state);
	if (!process_sd)
		return -EACCES;

	ret = pkm_kacs_authorize_process_sd_access(subject_token, process_sd,
						   desired_process_access);
	pkm_kacs_process_sd_put(process_sd);
	if (ret)
		return ret;
	if (!pkm_kacs_pip_dominates(caller_pip_type, caller_pip_trust,
				    READ_ONCE(target_state->pip_type),
				    READ_ONCE(target_state->pip_trust)))
		return -EACCES;

	return 0;
}

static long pkm_kacs_open_process_token_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *target_state,
	const void *target_token, u32 caller_pip_type, u32 caller_pip_trust,
	u32 access_mask)
{
	long ret;

	ret = pkm_kacs_validate_token_open_access_mask(access_mask);
	if (ret)
		return ret;
	if (!target_token)
		return -EACCES;

	ret = pkm_kacs_authorize_process_access_core(
		subject_token, target_state, caller_pip_type, caller_pip_trust,
		KACS_PROCESS_QUERY_INFORMATION);
	if (ret)
		return ret;

	return pkm_kacs_open_token_fd_for_subject_checked(subject_token,
							  target_token,
							  access_mask);
}

static long pkm_kacs_authorize_process_token_inspection_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	bool self_target)
{
	if (!subject_token || !caller_state || !target_state)
		return -EACCES;
	if (self_target)
		return 0;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust),
		KACS_PROCESS_QUERY_INFORMATION);
}

static long pkm_kacs_open_process_token_inspection_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	const void *target_token, bool self_target)
{
	long ret;

	if (!target_token)
		return -EACCES;

	ret = pkm_kacs_authorize_process_token_inspection_core(
		subject_token, caller_state, target_state, self_target);
	if (ret)
		return ret;

	return pkm_kacs_open_token_fd_with_fixed_access(target_token,
							KACS_TOKEN_QUERY);
}

static int pkm_kacs_bind_process_token_inspection_file(
	struct file *file,
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state,
	const void *target_token, bool self_target)
{
	long ret;

	ret = pkm_kacs_authorize_process_token_inspection_core(
		subject_token, caller_state, target_state, self_target);
	if (ret)
		return (int)ret;

	return pkm_kacs_bind_query_token_file(file, target_token);
}

static long pkm_kacs_create_session_core(const void *subject_token,
					 const u8 *spec, size_t spec_len,
					 u64 *session_id_out)
{
	u64 session_id = 0;
	long ret;

	if (!spec || !session_id_out)
		return -EINVAL;

	ret = pkm_kacs_require_enabled_privilege(subject_token,
						 PKM_KACS_PRIVILEGE_SE_TCB);
	if (ret)
		return ret;

	ret = kacs_rust_create_session(spec, spec_len, ktime_get_real_seconds(),
				       &session_id);
	if (ret)
		return ret;
	if (session_id > LONG_MAX)
		return -ERANGE;

	*session_id_out = session_id;
	return 0;
}

static long pkm_kacs_create_token_core(const void *subject_token,
				       const u8 *spec, size_t spec_len)
{
	const void *new_token = NULL;
	long fd;
	long ret;

	if (!subject_token || !spec)
		return -EINVAL;

	if (!kacs_rust_token_has_enabled_privilege(
		    subject_token, PKM_KACS_PRIVILEGE_SE_CREATE_TOKEN))
		return -EPERM;

	ret = kacs_rust_create_token(subject_token, spec, spec_len,
				     ktime_get_real_seconds(), &new_token);
	if (ret)
		return ret;
	if (!new_token)
		return -EACCES;

	fd = pkm_kacs_open_token_fd_with_fixed_access(new_token,
						      KACS_TOKEN_ALL_ACCESS);
	kacs_rust_token_drop(new_token);
	if (fd < 0)
		return fd;
	if (!kacs_rust_token_mark_privileges_used(
		    subject_token, PKM_KACS_PRIVILEGE_SE_CREATE_TOKEN))
		return -EPERM;
	return fd;
}

static long pkm_kacs_signal_to_process_access(int sig, u32 *desired_access)
{
	if (!desired_access)
		return -EINVAL;
	if (sig == 0)
		return -EACCES;
	if (sig < 0 || sig > SIGRTMAX)
		return -EINVAL;

	switch (sig) {
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGILL:
	case SIGTRAP:
	case SIGABRT:
	case SIGBUS:
	case SIGFPE:
	case SIGKILL:
	case SIGUSR1:
	case SIGSEGV:
	case SIGUSR2:
	case SIGPIPE:
	case SIGALRM:
	case SIGTERM:
	case SIGSTKFLT:
	case SIGXCPU:
	case SIGXFSZ:
	case SIGVTALRM:
	case SIGPROF:
	case SIGIO:
	case SIGPWR:
	case SIGSYS:
		*desired_access = KACS_PROCESS_TERMINATE;
		return 0;
	case SIGCONT:
	case SIGSTOP:
	case SIGTSTP:
	case SIGTTIN:
	case SIGTTOU:
		*desired_access = KACS_PROCESS_SUSPEND_RESUME;
		return 0;
	case SIGCHLD:
	case SIGURG:
	case SIGWINCH:
		*desired_access = KACS_PROCESS_SIGNAL;
		return 0;
	default:
		if (sig >= SIGRTMIN) {
			*desired_access = KACS_PROCESS_TERMINATE;
			return 0;
		}
		return -EACCES;
	}
}

static long pkm_kacs_ptrace_mode_to_process_access(unsigned int mode,
						   u32 *desired_access)
{
	bool is_pidfd_open_mode;
	bool is_getfd_mode;
	bool is_proc_query_limited_mode;
	bool is_proc_query_information_mode;
	bool is_read_mode;
	bool is_attach_mode;

	if (!desired_access)
		return -EINVAL;

	is_pidfd_open_mode = (mode & PTRACE_MODE_PIDFD_OPEN) != 0;
	is_getfd_mode = (mode & PTRACE_MODE_GETFD) != 0;
	is_proc_query_limited_mode =
		(mode & PTRACE_MODE_PROC_QUERY_LIMITED) != 0;
	is_proc_query_information_mode =
		(mode & PTRACE_MODE_PROC_QUERY_INFORMATION) != 0;
	is_read_mode = (mode & PTRACE_MODE_READ) != 0;
	is_attach_mode = (mode & PTRACE_MODE_ATTACH) != 0;
	if (is_pidfd_open_mode) {
		if (!is_read_mode || is_attach_mode || is_getfd_mode)
			return -EACCES;
		*desired_access = KACS_PROCESS_QUERY_LIMITED;
		return 0;
	}
	if (is_getfd_mode) {
		if (is_read_mode || !is_attach_mode)
			return -EACCES;
		*desired_access = KACS_PROCESS_DUP_HANDLE;
		return 0;
	}
	if (is_proc_query_limited_mode || is_proc_query_information_mode) {
		if (is_proc_query_limited_mode &&
		    is_proc_query_information_mode)
			return -EACCES;
		if (!is_read_mode || is_attach_mode || is_getfd_mode ||
		    is_pidfd_open_mode)
			return -EACCES;

		*desired_access = is_proc_query_information_mode ?
					  KACS_PROCESS_QUERY_INFORMATION :
					  KACS_PROCESS_QUERY_LIMITED;
		return 0;
	}
	if (is_read_mode == is_attach_mode)
		return -EACCES;

	*desired_access = is_attach_mode ? KACS_PROCESS_VM_WRITE :
					     KACS_PROCESS_VM_READ;
	return 0;
}

static long pkm_kacs_prlimit_flags_to_process_access(unsigned int flags,
						     u32 *desired_access)
{
	if (!desired_access)
		return -EINVAL;

	switch (flags) {
	case PKM_KACS_LSM_PRLIMIT_READ:
		*desired_access = KACS_PROCESS_QUERY_INFORMATION;
		return 0;
	case PKM_KACS_LSM_PRLIMIT_WRITE:
		*desired_access = KACS_PROCESS_SET_INFORMATION;
		return 0;
	default:
		return -EACCES;
	}
}

static long pkm_kacs_check_process_setinfo_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state)
{
	if (!caller_state || !target_state)
		return -EACCES;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust),
		KACS_PROCESS_SET_INFORMATION);
}

static long pkm_kacs_check_process_affinity_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state)
{
	if (!subject_token || !caller_state || !target_state)
		return -EACCES;
	if (caller_state == target_state)
		return 0;
	if (!kacs_rust_token_has_enabled_privilege(
		    subject_token,
		    PKM_KACS_PRIVILEGE_SE_INCREASE_BASE_PRIORITY))
		return -EACCES;
	if (!kacs_rust_token_mark_privileges_used(
		    subject_token,
		    PKM_KACS_PRIVILEGE_SE_INCREASE_BASE_PRIORITY))
		return -EACCES;

	return pkm_kacs_check_process_setinfo_core(subject_token, caller_state,
						   target_state);
}

long pkm_kacs_sched_setaffinity(struct task_struct *task)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;

	if (!task || !task->security)
		return -EACCES;

	caller_state = pkm_kacs_current_process_state();
	target_state = pkm_kacs_task(task)->process_state;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;

	return pkm_kacs_check_process_affinity_core(subject_token, caller_state,
						    target_state);
}

static int pkm_kacs_task_kill(struct task_struct *target,
			      struct kernel_siginfo *info, int sig,
			      const struct cred *cred)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	u32 desired_access;
	long ret;

	(void)info;

	if (!target || !target->security)
		return -EACCES;
	if (!cred)
		return 0;
	if (target == current)
		return 0;

	caller_state = pkm_kacs_current_process_state();
	target_state = pkm_kacs_task(target)->process_state;
	subject_token = pkm_kacs_cred(cred)->token;
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;

	ret = pkm_kacs_signal_to_process_access(sig, &desired_access);
	if (ret)
		return ret;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), desired_access);
}

static int pkm_kacs_ptrace_access_check(struct task_struct *child,
					unsigned int mode)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	u32 desired_access;
	long ret;

	if (!child || !child->security)
		return -EACCES;
	if (child == current)
		return 0;

	caller_state = pkm_kacs_current_process_state();
	target_state = pkm_kacs_task(child)->process_state;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;

	ret = pkm_kacs_ptrace_mode_to_process_access(mode, &desired_access);
	if (ret)
		return ret;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), desired_access);
}

static int pkm_kacs_task_setnice(struct task_struct *task, int nice)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;

	(void)nice;

	if (!task || !task->security)
		return -EACCES;

	caller_state = pkm_kacs_current_process_state();
	target_state = pkm_kacs_task(task)->process_state;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;
	if (caller_state == target_state)
		return 0;

	return pkm_kacs_check_process_setinfo_core(subject_token, caller_state,
						   target_state);
}

static int pkm_kacs_task_setscheduler(struct task_struct *task)
{
	return pkm_kacs_task_setnice(task, 0);
}

static int pkm_kacs_task_setioprio(struct task_struct *task, int ioprio)
{
	(void)ioprio;
	return pkm_kacs_task_setnice(task, 0);
}

static int pkm_kacs_task_prlimit(const struct cred *cred,
				 const struct cred *tcred,
				 unsigned int flags)
{
	const struct pkm_kacs_cred_security *caller_sec;
	const struct pkm_kacs_cred_security *target_sec;
	const struct pkm_kacs_process_state *caller_state;
	const struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	u32 desired_access;
	long ret;

	if (!cred || !tcred)
		return -EACCES;

	caller_sec = pkm_kacs_cred(cred);
	target_sec = pkm_kacs_cred(tcred);
	caller_state = caller_sec->process_state;
	target_state = target_sec->process_state;
	subject_token = caller_sec->token;
	if (!caller_state || !target_state || !subject_token)
		return -EACCES;
	if (caller_state == target_state)
		return 0;

	ret = pkm_kacs_prlimit_flags_to_process_access(flags, &desired_access);
	if (ret)
		return ret;

	return pkm_kacs_authorize_process_access_core(
		subject_token, target_state, READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), desired_access);
}

long pkm_kacs_capable_in_cred_ns(const struct cred *cred,
				 struct user_namespace *target_ns, int cap,
				 unsigned int opts)
{
	const struct pkm_kacs_cred_security *sec;

	(void)target_ns;
	(void)opts;

	if (!cred)
		return -EPERM;

	sec = pkm_kacs_cred(cred);
	return pkm_kacs_check_capability_for_token(sec ? sec->token : NULL, cap);
}

static int pkm_kacs_capable(const struct cred *cred,
			    struct user_namespace *target_ns, int cap,
			    unsigned int opts)
{
	return pkm_kacs_capable_in_cred_ns(cred, target_ns, cap, opts);
}

static int pkm_kacs_capset(struct cred *new, const struct cred *old,
			   const kernel_cap_t *effective,
			   const kernel_cap_t *inheritable,
			   const kernel_cap_t *permitted)
{
	const void *subject_token;

	(void)old;
	subject_token = pkm_kacs_current_effective_token_ptr();
	return pkm_kacs_capset_core(subject_token, new, effective,
				    inheritable, permitted);
}

long pkm_kacs_prctl_capability_guard(int option, unsigned long arg2,
				     unsigned long arg3,
				     unsigned long arg4,
				     unsigned long arg5)
{
	const struct cred *cred = current_cred();
	const struct pkm_kacs_cred_security *sec;
	u64 ambient_mask = 0;

	if (!cred)
		return -EPERM;

	sec = pkm_kacs_cred(cred);
	ambient_mask = pkm_kacs_kernel_cap_to_u64(&cred->cap_ambient);
	return pkm_kacs_prctl_capability_guard_core(
		sec ? sec->token : NULL, ambient_mask, option, arg2, arg3,
		arg4, arg5);
}

static int pkm_kacs_task_prctl(int option, unsigned long arg2,
			       unsigned long arg3, unsigned long arg4,
			       unsigned long arg5)
{
	struct pkm_kacs_process_state *state;
	long ret;

	ret = pkm_kacs_prctl_capability_guard(option, arg2, arg3, arg4,
					      arg5);
	if (ret)
		return ret;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	return pkm_kacs_check_task_prctl_mitigations_core(
		pkm_kacs_process_state_mitigation_bits(state), option, arg2,
		arg3, arg4, arg5);
}

static int pkm_kacs_mmap_file(struct file *file, unsigned long reqprot,
			      unsigned long prot, unsigned long flags)
{
	struct pkm_kacs_process_state *state;
	int ret;

	(void)reqprot;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	ret = pkm_kacs_check_wxp_mmap_core(
		pkm_kacs_process_state_mitigation_bits(state), prot);
	if (ret)
		return ret;

	ret = pkm_kacs_check_tlp_file_core(
		pkm_kacs_process_state_mitigation_bits(state), file,
		(prot & PROT_EXEC) != 0);
	if (ret)
		return ret;

	return pkm_kacs_check_mmap_snapshot(file, prot, flags);
}

static int pkm_kacs_file_mprotect(struct vm_area_struct *vma,
				  unsigned long reqprot,
				  unsigned long prot)
{
	struct pkm_kacs_process_state *state;
	int ret;

	(void)reqprot;
	if (!vma)
		return -EACCES;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	ret = pkm_kacs_check_wxp_mprotect_core(
		pkm_kacs_process_state_mitigation_bits(state),
		vma->vm_flags, prot);
	if (ret)
		return ret;

	ret = pkm_kacs_check_tlp_file_core(
		pkm_kacs_process_state_mitigation_bits(state), vma->vm_file,
		(prot & PROT_EXEC) != 0 && (vma->vm_flags & VM_EXEC) == 0);
	if (ret)
		return ret;

	return pkm_kacs_check_mprotect_snapshot(vma->vm_file, vma->vm_flags,
						prot);
}

static int pkm_kacs_bprm_check_security(struct linux_binprm *bprm)
{
	struct pkm_kacs_process_state *state;

	if (!bprm)
		return -EACCES;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	return pkm_kacs_check_pie_bprm_core(
		pkm_kacs_process_state_mitigation_bits(state),
		(const u8 *)bprm->buf, sizeof(bprm->buf));
}

static long pkm_kacs_install_token_ref_on_cred(struct cred *cred,
					       const void *token_ref)
{
	struct pkm_kacs_cred_security *sec;

	if (!cred || !cred->security || !token_ref)
		return -EACCES;

	sec = pkm_kacs_cred(cred);
	if (sec->token)
		kacs_rust_token_drop(sec->token);
	sec->token = token_ref;
	pkm_kacs_stamp_projected_ids(sec);
	pkm_kacs_raise_allow_compat_caps(cred);
	return 0;
}

static long pkm_kacs_exec_file_integrity_label(const struct file *file,
					       u32 *integrity_out)
{
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_security *sec;
	struct inode *inode;
	long ret;

	if (!file || !integrity_out)
		return -EACCES;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;

	sec = pkm_kacs_inode(inode);
	mutex_lock(&sec->lock);
	ret = pkm_kacs_inode_resolve_effective_cache_locked(
		(struct file *)file, sec, &cache);
	if (!ret) {
		if (cache->state != PKM_KACS_INODE_SD_VALID ||
		    !cache->bytes || cache->len == 0) {
			ret = -EACCES;
		} else {
			ret = kacs_rust_file_sd_integrity_label(
				cache->bytes, cache->len, integrity_out);
		}
	}
	mutex_unlock(&sec->lock);
	return ret;
}

static long pkm_kacs_apply_exec_primary_token(const void *primary_token,
					      const struct file *file,
					      struct cred *new,
					      bool require_file_for_npm)
{
	const void *exec_token = NULL;
	u32 file_integrity = 0;
	long ret;

	if (!primary_token || !new)
		return -EACCES;

	if (kacs_rust_token_has_new_process_min(primary_token)) {
		if (!file) {
			if (require_file_for_npm)
				return -EACCES;
		} else {
			ret = pkm_kacs_exec_file_integrity_label(
				file, &file_integrity);
			if (ret)
				return ret;

			ret = kacs_rust_token_new_process_min_exec(
				primary_token, file_integrity, &exec_token);
			if (ret)
				return ret;
		}
	}

	if (!exec_token) {
		exec_token = kacs_rust_token_clone(primary_token);
		if (!exec_token)
			return -EACCES;
	}

	ret = pkm_kacs_install_token_ref_on_cred(new, exec_token);
	if (ret)
		kacs_rust_token_drop(exec_token);
	return ret;
}

static long pkm_kacs_bprm_creds_from_file_core(const void *subject_token,
					       const void *primary_token,
					       const struct file *file,
					       struct cred *new,
					       const struct cred *old,
					       bool require_file_for_npm)
{
	bool uid_changed;
	bool gid_changed;
	struct user_struct *old_user;
	long ret;

	if (!new || !old)
		return -EACCES;

	uid_changed = !uid_eq(new->euid, old->euid);
	gid_changed = !gid_eq(new->egid, old->egid);

	if ((uid_changed || gid_changed) && !subject_token)
		return -EACCES;
	if ((uid_changed || gid_changed) &&
	    kacs_rust_token_has_enabled_privilege(
		    subject_token, PKM_KACS_PRIVILEGE_SE_ASSIGN_PRIMARY))
		return -EOPNOTSUPP;

	pkm_kacs_copy_exec_compat_caps(new, old);

	if (uid_changed) {
		new->uid = new->euid;
		new->suid = new->euid;
		new->fsuid = old->fsuid;

		if (new->user != old->user) {
			old_user = get_uid(old->user);
			free_uid(new->user);
			new->user = old_user;
		}
	}

	if (gid_changed) {
		new->gid = new->egid;
		new->sgid = new->egid;
		new->fsgid = old->fsgid;
	}

	ret = pkm_kacs_apply_exec_primary_token(primary_token, file, new,
					       require_file_for_npm);
	if (ret)
		return ret;

	return 0;
}

static int pkm_kacs_bprm_creds_from_file(struct linux_binprm *bprm,
					 const struct file *file)
{
	if (!bprm || !bprm->cred)
		return -EACCES;

	return (int)pkm_kacs_bprm_creds_from_file_core(
		pkm_kacs_current_effective_token_ptr(),
		pkm_kacs_current_primary_token_ptr(), file, bprm->cred,
		current_cred(), true);
}

static long pkm_kacs_open_process_token_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task, u32 access_mask)
{
	const struct cred *target_real_cred;
	struct pkm_kacs_process_state *target_state;
	const void *target_token;
	long ret;

	if (!subject_token || !caller_state || !task || !task->security)
		return -EACCES;

	target_state = pkm_kacs_task(task)->process_state;
	if (!target_state)
		return -EACCES;

	target_real_cred = get_task_cred(task);
	target_token = pkm_kacs_cred(target_real_cred)->token;
	if (!target_token) {
		put_cred(target_real_cred);
		return -EACCES;
	}

	ret = pkm_kacs_open_process_token_core(
		subject_token, target_state, target_token,
		READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), access_mask);
	put_cred(target_real_cred);
	return ret;
}

static long pkm_kacs_open_process_token_inspection_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task)
{
	const struct cred *target_real_cred;
	struct pkm_kacs_process_state *target_state;
	const void *target_token;
	long ret;
	bool self_target;

	if (!subject_token || !caller_state || !task || !task->security)
		return -EACCES;

	target_state = pkm_kacs_task(task)->process_state;
	if (!target_state)
		return -EACCES;
	self_target = caller_state == target_state;

	target_real_cred = get_task_cred(task);
	target_token = pkm_kacs_cred(target_real_cred)->token;
	if (!target_token) {
		put_cred(target_real_cred);
		return -EACCES;
	}

	ret = pkm_kacs_open_process_token_inspection_core(
		subject_token, caller_state, target_state, target_token,
		self_target);
	put_cred(target_real_cred);
	return ret;
}

static long pkm_kacs_revert_current_impersonation(void)
{
	struct pkm_kacs_task_security *task_sec;

	if (!current || !current->security)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->impersonation_saved_cred)
		return 0;

	revert_creds(task_sec->impersonation_saved_cred);
	task_sec->impersonation_saved_cred = NULL;
	return 0;
}

static void pkm_kacs_free_primary_install_work(
	struct pkm_kacs_primary_install_work *work)
{
	if (!work)
		return;

	if (work->token)
		kacs_rust_token_drop(work->token);
	if (work->task)
		put_task_struct(work->task);
	kfree(work);
}

static void pkm_kacs_discard_prepared_primary_installs(
	struct pkm_kacs_primary_install_batch *batch)
{
	size_t i;

	if (!batch)
		return;

	for (i = 0; i < batch->count; i++)
		pkm_kacs_free_primary_install_work(batch->works[i]);
	kfree(batch->works);
	batch->works = NULL;
	batch->count = 0;
}

static void pkm_kacs_primary_install_task_work(struct callback_head *twork)
{
	struct pkm_kacs_primary_install_prepare prepared = { };
	struct pkm_kacs_primary_install_work *work =
		container_of(twork, struct pkm_kacs_primary_install_work, twork);
	long ret;

	ret = pkm_kacs_prepare_current_primary_install(work->token, &prepared);
	if (!ret)
		ret = pkm_kacs_apply_current_primary_install(&prepared);
	if (ret)
		pkm_kacs_abort_primary_install_prepare(&prepared);
	if (ret == -ENOMEM &&
	    task_work_add(current, &work->twork, TWA_SIGNAL) == 0)
		return;
	if (ret)
		pr_warn("pkm: queued primary-token install failed (%ld)\n", ret);

	pkm_kacs_free_primary_install_work(work);
}

static long pkm_kacs_prepare_sibling_primary_installs(
	const void *token,
	struct pkm_kacs_primary_install_batch *batch)
{
	struct task_struct **tasks = NULL;
	struct task_struct *leader;
	struct task_struct *task;
	unsigned int capacity;
	size_t count = 0;
	size_t i;
	long ret = 0;

	if (!token || !batch || !current || !current->signal)
		return -EACCES;

	memset(batch, 0, sizeof(*batch));
	capacity = READ_ONCE(current->signal->nr_threads);
	if (capacity <= 1)
		return 0;

	tasks = kcalloc(capacity - 1, sizeof(*tasks), GFP_KERNEL);
	if (!tasks)
		return -ENOMEM;

	leader = current->group_leader;
	rcu_read_lock();
	if (leader && leader != current &&
	    (READ_ONCE(leader->flags) & PF_EXITING) == 0) {
		get_task_struct(leader);
		tasks[count++] = leader;
	}
	for_each_thread(leader, task) {
		if (task == current || task == leader)
			continue;
		if ((READ_ONCE(task->flags) & PF_EXITING) != 0)
			continue;
		if (count >= capacity - 1) {
			ret = -EAGAIN;
			break;
		}
		get_task_struct(task);
		tasks[count++] = task;
	}
	rcu_read_unlock();
	if (ret)
		goto out_cleanup_tasks;

	batch->works = kcalloc(count, sizeof(*batch->works), GFP_KERNEL);
	if (!batch->works) {
		ret = -ENOMEM;
		goto out_cleanup_tasks;
	}

	for (i = 0; i < count; i++) {
		struct pkm_kacs_primary_install_work *work;
		const void *token_ref;

		work = kzalloc(sizeof(*work), GFP_KERNEL);
		if (!work) {
			ret = -ENOMEM;
			goto out_cleanup_batch;
		}

		token_ref = kacs_rust_token_clone(token);
		if (!token_ref) {
			kfree(work);
			ret = -ENOMEM;
			goto out_cleanup_batch;
		}

		init_task_work(&work->twork, pkm_kacs_primary_install_task_work);
		work->token = token_ref;
		work->task = tasks[i];
		tasks[i] = NULL;
		batch->works[i] = work;
	}

	batch->count = count;
	kfree(tasks);
	return 0;

out_cleanup_batch:
	batch->count = count;
	pkm_kacs_discard_prepared_primary_installs(batch);
out_cleanup_tasks:
	for (i = 0; i < count; i++) {
		if (tasks[i])
			put_task_struct(tasks[i]);
	}
	kfree(tasks);
	return ret;
}

static void pkm_kacs_queue_prepared_primary_installs(
	struct pkm_kacs_primary_install_batch *batch)
{
	size_t i;

	if (!batch)
		return;

	for (i = 0; i < batch->count; i++) {
		struct pkm_kacs_primary_install_work *work = batch->works[i];
		long ret;

		if (!work)
			continue;
		if ((READ_ONCE(work->task->flags) & PF_EXITING) != 0) {
			pkm_kacs_free_primary_install_work(work);
			batch->works[i] = NULL;
			continue;
		}

		ret = task_work_add(work->task, &work->twork, TWA_SIGNAL);
		if (ret < 0) {
			pr_warn("pkm: sibling primary-token queue failed (%ld)\n",
				ret);
			pkm_kacs_free_primary_install_work(work);
			batch->works[i] = NULL;
			continue;
		}

		batch->works[i] = NULL;
	}

	kfree(batch->works);
	batch->works = NULL;
	batch->count = 0;
}

int pkm_kacs_install_current_primary_token(const void *token)
{
	struct pkm_kacs_primary_install_prepare prepared = { };
	struct pkm_kacs_primary_install_batch sibling_batch = { };
	struct pkm_kacs_process_state *state;
	struct pkm_kacs_process_sd *new_sd = NULL;
	const void *old_primary_token;
	long ret;

	if (!token || !current || !current->security)
		return -EACCES;

	state = pkm_kacs_current_process_state();
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	if (!state || !old_primary_token)
		return -EACCES;

	ret = pkm_kacs_prepare_sibling_primary_installs(token, &sibling_batch);
	if (ret)
		return ret;

	ret = pkm_kacs_prepare_current_primary_install(token, &prepared);
	if (ret) {
		pkm_kacs_discard_prepared_primary_installs(&sibling_batch);
		return ret;
	}

	if (!kacs_rust_token_same_user_sid(old_primary_token, token)) {
		new_sd = pkm_kacs_process_sd_alloc(token);
		if (!new_sd) {
			pkm_kacs_abort_primary_install_prepare(&prepared);
			pkm_kacs_discard_prepared_primary_installs(&sibling_batch);
			return -ENOMEM;
		}
	}

	ret = pkm_kacs_apply_current_primary_install(&prepared);
	if (ret) {
		pkm_kacs_abort_primary_install_prepare(&prepared);
		pkm_kacs_process_sd_put(new_sd);
		pkm_kacs_discard_prepared_primary_installs(&sibling_batch);
		return ret;
	}

	if (new_sd)
		pkm_kacs_process_state_replace_sd(state, new_sd);

	pkm_kacs_queue_prepared_primary_installs(&sibling_batch);
	return 0;
}

int pkm_kacs_install_impersonation_token(const void *token)
{
	struct pkm_kacs_task_security *task_sec;
	struct pkm_kacs_cred_security *new_sec;
	struct cred *new;
	long ret;

	if (!token || !current || !current->security)
		return -EACCES;

	task_sec = pkm_kacs_task(current);
	ret = pkm_kacs_revert_current_impersonation();
	if (ret)
		return ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	new_sec = pkm_kacs_cred(new);
	if (new_sec->token)
		kacs_rust_token_drop(new_sec->token);
	new_sec->token = token;
	pkm_kacs_stamp_projected_ids(new_sec);
	pkm_kacs_raise_allow_compat_caps(new);

	task_sec->impersonation_saved_cred = override_creds(new);
	return 0;
}

int pkm_kacs_revert_impersonation(void)
{
	return pkm_kacs_revert_current_impersonation();
}

static const struct cred *pkm_kacs_get_task_effective_cred(
	struct task_struct *task)
{
	const struct cred *cred;

	if (!task)
		return NULL;

	rcu_read_lock();
	cred = rcu_dereference(task->cred);
	if (cred)
		get_cred(cred);
	rcu_read_unlock();
	return cred;
}

static long pkm_kacs_open_thread_token_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task, u32 access_mask)
{
	const struct cred *target_effective_cred;
	struct pkm_kacs_process_state *target_state;
	const void *target_token;
	long ret;

	if (!subject_token || !caller_state || !task || !task->security)
		return -EACCES;

	target_state = pkm_kacs_task(task)->process_state;
	if (!target_state)
		return -EACCES;

	target_effective_cred = pkm_kacs_get_task_effective_cred(task);
	if (!target_effective_cred)
		return -EACCES;

	target_token = pkm_kacs_cred(target_effective_cred)->token;
	if (!target_token) {
		put_cred(target_effective_cred);
		return -EACCES;
	}

	ret = pkm_kacs_open_process_token_core(
		subject_token, target_state, target_token,
		READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust), access_mask);
	put_cred(target_effective_cred);
	return ret;
}

static long pkm_kacs_open_thread_token_inspection_task(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct task_struct *task)
{
	const struct cred *target_effective_cred;
	struct pkm_kacs_process_state *target_state;
	const void *target_token;
	long ret;
	bool self_target;

	if (!subject_token || !caller_state || !task || !task->security)
		return -EACCES;

	target_state = pkm_kacs_task(task)->process_state;
	if (!target_state)
		return -EACCES;
	self_target = caller_state == target_state;

	target_effective_cred = pkm_kacs_get_task_effective_cred(task);
	if (!target_effective_cred)
		return -EACCES;

	target_token = pkm_kacs_cred(target_effective_cred)->token;
	if (!target_token) {
		put_cred(target_effective_cred);
		return -EACCES;
	}

	ret = pkm_kacs_open_process_token_inspection_core(
		subject_token, caller_state, target_state, target_token,
		self_target);
	put_cred(target_effective_cred);
	return ret;
}

int pkm_kacs_proc_open_process_token_file(struct file *file,
					  struct task_struct *task)
{
	struct pkm_kacs_process_state *caller_state;
	const struct cred *target_real_cred;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	const void *target_token;
	int ret;
	bool self_target;

	if (!file || !task || !task->security)
		return -EACCES;

	caller_state = pkm_kacs_current_process_state();
	subject_token = pkm_kacs_current_effective_token_ptr();
	target_state = pkm_kacs_task(task)->process_state;
	if (!caller_state || !subject_token || !target_state)
		return -EACCES;
	self_target = caller_state == target_state;

	target_real_cred = get_task_cred(task);
	target_token = pkm_kacs_cred(target_real_cred)->token;
	if (!target_token) {
		put_cred(target_real_cred);
		return -EACCES;
	}

	ret = pkm_kacs_bind_process_token_inspection_file(
		file, subject_token, caller_state, target_state, target_token,
		self_target);
	put_cred(target_real_cred);
	return ret;
}

int pkm_kacs_proc_open_thread_token_file(struct file *file,
					 struct task_struct *task)
{
	struct pkm_kacs_process_state *caller_state;
	const struct cred *target_effective_cred;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	const void *target_token;
	int ret;
	bool self_target;

	if (!file || !task || !task->security)
		return -EACCES;

	caller_state = pkm_kacs_current_process_state();
	subject_token = pkm_kacs_current_effective_token_ptr();
	target_state = pkm_kacs_task(task)->process_state;
	if (!caller_state || !subject_token || !target_state)
		return -EACCES;
	self_target = caller_state == target_state;

	target_effective_cred = pkm_kacs_get_task_effective_cred(task);
	if (!target_effective_cred)
		return -EACCES;

	target_token = pkm_kacs_cred(target_effective_cred)->token;
	if (!target_token) {
		put_cred(target_effective_cred);
		return -EACCES;
	}

	ret = pkm_kacs_bind_process_token_inspection_file(
		file, subject_token, caller_state, target_state, target_token,
		self_target);
	put_cred(target_effective_cred);
	return ret;
}

int pkm_kacs_securityfs_open_self_token_file(struct file *file)
{
	const void *subject_token;

	if (!file)
		return -EINVAL;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	return pkm_kacs_bind_query_token_file(file, subject_token);
}

static int pkm_kacs_securityfs_self_open(struct inode *inode,
					 struct file *file)
{
	(void)inode;
	return pkm_kacs_securityfs_open_self_token_file(file);
}

static const struct file_operations pkm_kacs_securityfs_self_fops = {
	.open = pkm_kacs_securityfs_self_open,
	.llseek = noop_llseek,
};

static ssize_t pkm_kacs_securityfs_sessions_read(struct file *file,
						 char __user *buf,
						 size_t count, loff_t *ppos)
{
	const void *subject_token;
	size_t required = 0;
	u8 *kbuf;
	int ret;
	ssize_t copied;

	(void)file;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	ret = kacs_rust_check_securityfs_sessions_read(subject_token);
	if (ret)
		return ret;

	ret = kacs_rust_securityfs_sessions_listing(NULL, 0, &required);
	if (ret)
		return ret;
	if (*ppos >= required || !required)
		return 0;

	kbuf = kvzalloc(required, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = kacs_rust_securityfs_sessions_listing(kbuf, required, &required);
	if (ret) {
		kvfree(kbuf);
		return ret;
	}

	copied = simple_read_from_buffer(buf, count, ppos, kbuf, required);
	kvfree(kbuf);
	return copied;
}

static const struct file_operations pkm_kacs_securityfs_sessions_fops = {
	.read = pkm_kacs_securityfs_sessions_read,
	.llseek = default_llseek,
};

static int __init pkm_kacs_securityfs_init(void)
{
	int ret;

	if (pkm_kacs_securityfs_dir || pkm_kacs_securityfs_self ||
	    pkm_kacs_securityfs_sessions)
		return 0;

	pkm_kacs_securityfs_dir = securityfs_create_dir("kacs", NULL);
	if (IS_ERR(pkm_kacs_securityfs_dir)) {
		ret = PTR_ERR(pkm_kacs_securityfs_dir);
		pkm_kacs_securityfs_dir = NULL;
		pr_err("pkm: securityfs kacs dir init failed (%d)\n", ret);
		return ret;
	}

	pkm_kacs_securityfs_self = securityfs_create_file(
		"self", 0444, pkm_kacs_securityfs_dir, NULL,
		&pkm_kacs_securityfs_self_fops);
	if (IS_ERR(pkm_kacs_securityfs_self)) {
		ret = PTR_ERR(pkm_kacs_securityfs_self);
		pkm_kacs_securityfs_self = NULL;
		securityfs_remove(pkm_kacs_securityfs_dir);
		pkm_kacs_securityfs_dir = NULL;
		pr_err("pkm: securityfs kacs/self init failed (%d)\n", ret);
		return ret;
	}

	pkm_kacs_securityfs_sessions = securityfs_create_file(
		"sessions", 0444, pkm_kacs_securityfs_dir, NULL,
		&pkm_kacs_securityfs_sessions_fops);
	if (IS_ERR(pkm_kacs_securityfs_sessions)) {
		ret = PTR_ERR(pkm_kacs_securityfs_sessions);
		pkm_kacs_securityfs_sessions = NULL;
		securityfs_remove(pkm_kacs_securityfs_self);
		pkm_kacs_securityfs_self = NULL;
		securityfs_remove(pkm_kacs_securityfs_dir);
		pkm_kacs_securityfs_dir = NULL;
		pr_err("pkm: securityfs kacs/sessions init failed (%d)\n",
		       ret);
		return ret;
	}

	return 0;
}

static long pkm_kacs_lookup_peer_socket(
	int sock_fd, struct socket **sock_out,
	struct pkm_kacs_socket_security **sec_out)
{
	struct socket *sock;
	int err = 0;

	if (!sock_out || !sec_out)
		return -EINVAL;

	*sock_out = NULL;
	*sec_out = NULL;

	sock = sockfd_lookup(sock_fd, &err);
	if (!sock)
		return err ? err : -EBADF;
	if (!sock->sk || !sock->sk->sk_security ||
	    sock->sk->sk_family != AF_UNIX ||
	    !pkm_kacs_socket_type_supported(sock->type)) {
		sockfd_put(sock);
		return -EACCES;
	}

	*sock_out = sock;
	*sec_out = pkm_kacs_sock(sock->sk);
	return 0;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static struct pkm_kacs_process_sd *pkm_kacs_kunit_read_only_socket_sd_alloc(
	const void *token)
{
	struct pkm_kacs_process_sd *socket_sd;
	size_t len = 0;
	const u8 *bytes;

	if (!token)
		return NULL;

	bytes = kacs_rust_kunit_create_read_only_socket_sd(token, &len);
	if (!bytes || len == 0)
		return NULL;

	socket_sd = kzalloc(sizeof(*socket_sd), GFP_KERNEL);
	if (!socket_sd) {
		pkm_kacs_free((void *)bytes);
		return NULL;
	}

	refcount_set(&socket_sd->refs, 1);
	socket_sd->bytes = bytes;
	socket_sd->len = len;
	return socket_sd;
}

static void pkm_kacs_kunit_socket_snapshot(
	const struct pkm_kacs_socket_security *sec,
	struct pkm_kacs_kunit_socket_view *out)
{
	if (!out)
		return;

	out->peer_token = sec ? sec->peer_token : NULL;
	out->socket_sd_ptr = sec && sec->socket_sd ? sec->socket_sd->bytes : NULL;
	out->socket_sd_len = sec && sec->socket_sd ? sec->socket_sd->len : 0;
	out->max_impersonation = sec ? sec->max_impersonation : 0;
}

static int pkm_kacs_kunit_init_socket(struct socket *sock, struct sock *sk,
				      void **blob_out, u32 socket_type,
				      u32 connected)
{
	size_t blob_len;
	void *blob;

	if (!sock || !sk || !blob_out)
		return -EINVAL;

	blob_len = pkm_blob_sizes.lbs_sock +
		sizeof(struct pkm_kacs_socket_security);
	blob = kzalloc(blob_len, GFP_KERNEL);
	if (!blob)
		return -ENOMEM;

	memset(sock, 0, sizeof(*sock));
	memset(sk, 0, sizeof(*sk));

	sk->sk_family = AF_UNIX;
	sk->sk_type = socket_type;
	sk->sk_security = blob;

	sock->type = socket_type;
	sock->state = connected ? SS_CONNECTED : SS_UNCONNECTED;
	sock->sk = sk;

	*blob_out = blob;
	return pkm_kacs_sk_alloc_security(sk, AF_UNIX, GFP_KERNEL);
}

static void pkm_kacs_kunit_cleanup_socket(struct sock *sk, void *blob)
{
	pkm_kacs_sk_free_security(sk);
	kfree(blob);
}

struct pkm_kacs_kunit_peer_capture_state {
	struct socket client_sock;
	struct socket listener_sock;
	struct socket accepted_sock;
	struct sock client_sk;
	struct sock listener_sk;
	struct sock accepted_sk;
	void *client_blob;
	void *listener_blob;
	void *accepted_blob;
};

long pkm_kacs_kunit_bind_abstract_socket_for_subject(
	const void *subject_token,
	struct pkm_kacs_kunit_socket_view *first_out,
	struct pkm_kacs_kunit_socket_view *second_out)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	long ret;

	if (!subject_token)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, SOCK_STREAM, 0);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);

	ret = pkm_kacs_bind_abstract_socket_core(sec, subject_token);
	pkm_kacs_kunit_socket_snapshot(sec, first_out);
	if (ret) {
		pkm_kacs_kunit_cleanup_socket(&sk, blob);
		return ret;
	}

	ret = pkm_kacs_bind_abstract_socket_core(sec, subject_token);
	pkm_kacs_kunit_socket_snapshot(sec, second_out);
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_set_socket_impersonation_level(
	u32 socket_type, u32 connected, u32 level,
	struct pkm_kacs_kunit_socket_view *out)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	long ret;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, socket_type,
					 connected);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);

	ret = pkm_kacs_set_socket_impersonation_level_core(&sock, sec, level);
	pkm_kacs_kunit_socket_snapshot(sec, out);
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_capture_peer_socket_for_subject(
	const void *client_token, u32 socket_type, u32 max_impersonation,
	u32 abstract_socket, u32 allow_write, const void **captured_token_out,
	struct pkm_kacs_kunit_socket_view *listener_out,
	struct pkm_kacs_kunit_socket_view *accepted_out)
{
	struct pkm_kacs_kunit_peer_capture_state *state;
	struct pkm_kacs_socket_security *client_sec;
	struct pkm_kacs_socket_security *listener_sec;
	struct pkm_kacs_socket_security *accepted_sec;
	const void *bind_token;
	long ret;

	if (captured_token_out)
		*captured_token_out = NULL;
	if (!client_token)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = pkm_kacs_kunit_init_socket(&state->client_sock, &state->client_sk,
					 &state->client_blob, socket_type, 0);
	if (ret)
		goto out_free_state;
	ret = pkm_kacs_kunit_init_socket(&state->listener_sock,
					 &state->listener_sk,
					 &state->listener_blob, socket_type, 0);
	if (ret)
		goto out;
	ret = pkm_kacs_kunit_init_socket(&state->accepted_sock,
					 &state->accepted_sk,
					 &state->accepted_blob, socket_type, 1);
	if (ret)
		goto out;
	client_sec = pkm_kacs_sock(&state->client_sk);
	listener_sec = pkm_kacs_sock(&state->listener_sk);
	accepted_sec = pkm_kacs_sock(&state->accepted_sk);

	ret = pkm_kacs_set_socket_impersonation_level_core(&state->client_sock,
							    client_sec,
							    max_impersonation);
	if (ret)
		goto out;

	if (abstract_socket) {
		bind_token = pkm_kacs_current_effective_token_ptr();
		if (!bind_token) {
			ret = -EACCES;
			goto out;
		}
		if (allow_write) {
			ret = pkm_kacs_bind_abstract_socket_core(listener_sec,
								 bind_token);
			if (ret)
				goto out;
		} else {
			listener_sec->socket_sd =
				pkm_kacs_kunit_read_only_socket_sd_alloc(
					bind_token);
			if (!listener_sec->socket_sd) {
				ret = -ENOMEM;
				goto out;
			}
		}
	}

	ret = pkm_kacs_unix_stream_connect_core(client_sec, listener_sec,
						accepted_sec, client_token);
	if (ret)
		goto out;

	if (captured_token_out) {
		*captured_token_out =
			kacs_rust_token_clone(accepted_sec->peer_token);
		if (!*captured_token_out) {
			ret = -EACCES;
			goto out;
		}
	}

out:
	pkm_kacs_kunit_socket_snapshot(state->listener_blob ?
				       pkm_kacs_sock(&state->listener_sk) : NULL,
				       listener_out);
	pkm_kacs_kunit_socket_snapshot(state->accepted_blob ?
				       pkm_kacs_sock(&state->accepted_sk) : NULL,
				       accepted_out);
	if (state->accepted_blob)
		pkm_kacs_kunit_cleanup_socket(&state->accepted_sk,
					      state->accepted_blob);
	if (state->listener_blob)
		pkm_kacs_kunit_cleanup_socket(&state->listener_sk,
					      state->listener_blob);
	if (state->client_blob)
		pkm_kacs_kunit_cleanup_socket(&state->client_sk,
					      state->client_blob);
out_free_state:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_unix_dgram_send_for_subject(
	const void *subject_token, u32 abstract_socket, u32 allow_write,
	struct pkm_kacs_kunit_socket_view *sender_out,
	struct pkm_kacs_kunit_socket_view *target_out)
{
	struct socket sender_sock;
	struct socket target_sock;
	struct sock sender_sk;
	struct sock target_sk;
	struct pkm_kacs_socket_security *target_sec;
	void *sender_blob = NULL;
	void *target_blob = NULL;
	long ret;

	if (!subject_token)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_socket(&sender_sock, &sender_sk,
					 &sender_blob, SOCK_DGRAM, 0);
	if (ret)
		return ret;

	ret = pkm_kacs_kunit_init_socket(&target_sock, &target_sk,
					 &target_blob, SOCK_DGRAM, 0);
	if (ret)
		goto out_sender;

	target_sec = pkm_kacs_sock(&target_sk);
	if (abstract_socket) {
		if (allow_write) {
			ret = pkm_kacs_bind_abstract_socket_core(target_sec,
								 subject_token);
			if (ret)
				goto out_target;
		} else {
			target_sec->socket_sd =
				pkm_kacs_kunit_read_only_socket_sd_alloc(
					subject_token);
			if (!target_sec->socket_sd) {
				ret = -ENOMEM;
				goto out_target;
			}
		}
	}

	ret = pkm_kacs_unix_may_send(&sender_sock, &target_sock);

out_target:
	pkm_kacs_kunit_socket_snapshot(pkm_kacs_sock(&sender_sk), sender_out);
	pkm_kacs_kunit_socket_snapshot(pkm_kacs_sock(&target_sk), target_out);
	pkm_kacs_kunit_cleanup_socket(&target_sk, target_blob);
out_sender:
	pkm_kacs_kunit_cleanup_socket(&sender_sk, sender_blob);
	return ret;
}

long pkm_kacs_kunit_open_peer_token_for_socket_type(u32 socket_type,
						    u32 connected,
						    const void *peer_token)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	long ret;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, socket_type,
					 connected);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	if (connected && pkm_kacs_socket_type_supported(socket_type) &&
	    peer_token)
		sec->peer_token = kacs_rust_token_clone(peer_token);
	if (connected && pkm_kacs_socket_type_supported(socket_type))
		ret = pkm_kacs_open_peer_token_core(sec);
	else
		ret = -EACCES;
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_open_peer_token_for_socket(u32 connected,
					       const void *peer_token)
{
	return pkm_kacs_kunit_open_peer_token_for_socket_type(
		SOCK_STREAM, connected, peer_token);
}

long pkm_kacs_kunit_impersonate_peer_for_socket_type(u32 socket_type,
						     u32 connected,
						     const void *peer_token)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	long ret;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, socket_type,
					 connected);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	if (connected && pkm_kacs_socket_type_supported(socket_type) &&
	    peer_token)
		sec->peer_token = kacs_rust_token_clone(peer_token);
	if (connected && pkm_kacs_socket_type_supported(socket_type))
		ret = pkm_kacs_impersonate_peer_core(sec);
	else
		ret = -EACCES;
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_impersonate_peer_for_socket(u32 connected,
						const void *peer_token)
{
	return pkm_kacs_kunit_impersonate_peer_for_socket_type(
		SOCK_STREAM, connected, peer_token);
}

void pkm_kacs_kunit_set_current_pip_context(u32 pip_type, u32 pip_trust)
{
	struct pkm_kacs_process_state *state;

	state = pkm_kacs_current_process_state();
	if (!state)
		return;

	WRITE_ONCE(state->pip_type, pip_type);
	WRITE_ONCE(state->pip_trust, pip_trust);
}

int pkm_kmes_kunit_set_current_process_rate_tokens(u32 tokens)
{
	struct pkm_kacs_process_state *state;
	unsigned long flags;

	if (tokens > PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS)
		return -EINVAL;

	state = pkm_kacs_current_process_state();
	if (!state || !state->kmes_rate_bucket)
		return -EACCES;

	spin_lock_irqsave(&state->kmes_rate_bucket->lock, flags);
	state->kmes_rate_bucket->tokens = tokens;
	state->kmes_rate_bucket->last_refill_ns = ktime_get_ns();
	spin_unlock_irqrestore(&state->kmes_rate_bucket->lock, flags);
	return 0;
}

int pkm_kmes_kunit_set_current_process_rate_refill_frozen(bool frozen)
{
	struct pkm_kacs_process_state *state;
	unsigned long flags;

	state = pkm_kacs_current_process_state();
	if (!state || !state->kmes_rate_bucket)
		return -EACCES;

	spin_lock_irqsave(&state->kmes_rate_bucket->lock, flags);
	state->kmes_rate_bucket->kunit_freeze_refill = frozen;
	spin_unlock_irqrestore(&state->kmes_rate_bucket->lock, flags);
	return 0;
}

int pkm_kmes_kunit_get_current_process_rate_tokens(u32 *tokens_out)
{
	struct pkm_kacs_process_state *state;
	unsigned long flags;

	if (!tokens_out)
		return -EINVAL;
	state = pkm_kacs_current_process_state();
	if (!state || !state->kmes_rate_bucket)
		return -EACCES;

	spin_lock_irqsave(&state->kmes_rate_bucket->lock, flags);
	*tokens_out = state->kmes_rate_bucket->tokens;
	spin_unlock_irqrestore(&state->kmes_rate_bucket->lock, flags);
	return 0;
}

int pkm_kacs_kunit_set_current_process_mitigation_bits(u32 mitigation_bits)
{
	struct pkm_kacs_process_state *state;
	unsigned long flags;

	if ((mitigation_bits & ~KACS_MIT_ALL) != 0)
		return -EINVAL;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	spin_lock_irqsave(&state->mitigation_lock, flags);
	state->mitigation_bits = mitigation_bits;
	spin_unlock_irqrestore(&state->mitigation_lock, flags);
	return 0;
}

const void *pkm_kacs_kunit_current_process_state_ptr(void)
{
	return pkm_kacs_current_process_state();
}

const void *pkm_kacs_kunit_inherit_current_process_state(u64 clone_flags)
{
	return pkm_kacs_inherit_process_state(clone_flags);
}

void pkm_kacs_kunit_put_process_state(const void *state_ptr)
{
	pkm_kacs_process_state_put((struct pkm_kacs_process_state *)state_ptr);
}

int pkm_kacs_kunit_process_state_snapshot(
	const void *state_ptr,
	struct pkm_kacs_kunit_process_state_view *out)
{
	const struct pkm_kacs_process_state *state = state_ptr;

	if (!state || !out)
		return -EINVAL;

	out->state_ptr = state;
	out->process_sd_ptr = state->process_sd ? state->process_sd->bytes : NULL;
	out->process_sd_len = state->process_sd ? state->process_sd->len : 0;
	out->rate_bucket_ptr = state->kmes_rate_bucket;
	out->pip_type = READ_ONCE(state->pip_type);
	out->pip_trust = READ_ONCE(state->pip_trust);
	out->mitigation_bits = pkm_kacs_process_state_mitigation_bits(state);
	return 0;
}

long pkm_kacs_kunit_create_session_for_subject(const void *subject_token,
					       const u8 *spec, size_t spec_len,
					       u64 *session_id_out)
{
	return pkm_kacs_create_session_core(subject_token, spec, spec_len,
					    session_id_out);
}

long pkm_kacs_kunit_create_token_for_subject(const void *subject_token,
					     const u8 *spec, size_t spec_len)
{
	return pkm_kacs_create_token_core(subject_token, spec, spec_len);
}

long pkm_kacs_kunit_open_process_token_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_open_process_token_core(
		args->subject_token, &target_state, args->target_token,
		args->caller_pip_type, args->caller_pip_trust,
		args->access_mask);
}

long pkm_kacs_kunit_open_process_token_inspection_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_open_process_token_inspection_core(
		args->subject_token, &caller_state, &target_state,
		args->target_token, args->self_target != 0);
}

long pkm_kacs_kunit_open_thread_token_inspection_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args)
{
	return pkm_kacs_kunit_open_process_token_inspection_for_subject(args);
}

long pkm_kacs_kunit_open_self_token_inspection_for_subject(void)
{
	const void *subject_token = pkm_kacs_current_effective_token_ptr();

	if (!subject_token)
		return -EACCES;

	return pkm_kacs_open_token_fd_with_fixed_access(subject_token,
							KACS_TOKEN_QUERY);
}

long pkm_kacs_kunit_read_securityfs_sessions_for_subject(
	const void *subject_token, u8 *buf, size_t buf_len,
	size_t *required_out)
{
	long ret;

	if (!subject_token)
		return -EACCES;

	ret = kacs_rust_check_securityfs_sessions_read(subject_token);
	if (ret)
		return ret;

	return kacs_rust_securityfs_sessions_listing(buf, buf_len,
						    required_out);
}

long pkm_kacs_kunit_check_signal_for_subject(
	const struct pkm_kacs_kunit_process_signal_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state target_state = {};
	u32 desired_access;
	long ret;

	if (!args)
		return -EINVAL;
	if (args->kernel_originated)
		return 0;

	ret = pkm_kacs_signal_to_process_access(args->sig, &desired_access);
	if (ret)
		return ret;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_authorize_process_access_core(
		args->subject_token, &target_state, args->caller_pip_type,
		args->caller_pip_trust, desired_access);
}

long pkm_kacs_kunit_check_ptrace_for_subject(
	const struct pkm_kacs_kunit_process_ptrace_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state target_state = {};
	u32 desired_access;
	long ret;

	if (!args)
		return -EINVAL;

	ret = pkm_kacs_ptrace_mode_to_process_access(args->mode,
						     &desired_access);
	if (ret)
		return ret;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_authorize_process_access_core(
		args->subject_token, &target_state, args->caller_pip_type,
		args->caller_pip_trust, desired_access);
}

long pkm_kacs_kunit_check_process_setinfo_for_subject(
	const struct pkm_kacs_kunit_process_setinfo_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;
	if (args->self_target)
		return 0;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_check_process_setinfo_core(args->subject_token,
						   &caller_state,
						   &target_state);
}

long pkm_kacs_kunit_check_process_affinity_for_subject(
	const struct pkm_kacs_kunit_process_affinity_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;
	if (args->same_process)
		return 0;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_check_process_affinity_core(args->subject_token,
						    &caller_state,
						    &target_state);
}

long pkm_kacs_kunit_check_prlimit_for_subject(
	const struct pkm_kacs_kunit_process_prlimit_check_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state target_state = {};
	u32 desired_access;
	long ret;

	if (!args)
		return -EINVAL;
	if (args->self_target)
		return 0;

	ret = pkm_kacs_prlimit_flags_to_process_access(args->flags,
						       &desired_access);
	if (ret)
		return ret;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_authorize_process_access_core(
		args->subject_token, &target_state, args->caller_pip_type,
		args->caller_pip_trust, desired_access);
}

long pkm_kacs_kunit_get_process_sd_for_subject(
	const struct pkm_kacs_kunit_process_sd_get_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;
	spin_lock_init(&target_state.mitigation_lock);

	return pkm_kacs_query_process_sd_core(
		args->subject_token, &caller_state, &target_state,
		args->self_target != 0, args->security_info, out_sd_ptr,
		out_sd_len);
}

long pkm_kacs_kunit_set_process_sd_for_subject(
	const struct pkm_kacs_kunit_process_sd_set_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};
	struct pkm_kacs_process_sd *current_sd = NULL;
	const u8 *copied_bytes;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len || !args->input_sd_ptr ||
	    args->input_sd_len == 0)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	if (!args->target_process_sd_ptr || args->target_process_sd_len == 0)
		return -EINVAL;

	copied_bytes = kmemdup(args->target_process_sd_ptr,
			       args->target_process_sd_len, GFP_KERNEL);
	if (!copied_bytes)
		return -ENOMEM;

	current_sd = pkm_kacs_process_sd_wrap_bytes(copied_bytes,
						       args->target_process_sd_len);
	if (!current_sd) {
		kfree(copied_bytes);
		return -ENOMEM;
	}

	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = current_sd;
	spin_lock_init(&target_state.mitigation_lock);
	mutex_init(&target_state.sd_lock);

	ret = pkm_kacs_set_process_sd_core(
		args->subject_token, &caller_state, &target_state,
		args->self_target != 0, args->security_info, args->input_sd_ptr,
		args->input_sd_len);
	if (ret)
		goto out;
	if (!target_state.process_sd || !target_state.process_sd->bytes ||
	    target_state.process_sd->len == 0) {
		ret = -EACCES;
		goto out;
	}

	copied_bytes = kmemdup(target_state.process_sd->bytes,
			       target_state.process_sd->len, GFP_KERNEL);
	if (!copied_bytes) {
		ret = -ENOMEM;
		goto out;
	}

	*out_sd_ptr = copied_bytes;
	*out_sd_len = target_state.process_sd->len;
	ret = 0;

out:
	pkm_kacs_process_sd_put(target_state.process_sd);
	return ret;
}

static struct pkm_kacs_inode_sd_cache *pkm_kacs_kunit_file_sd_cache_alloc(
	const u8 *sd_ptr, size_t sd_len, u32 state)
{
	const u8 *copied_bytes = NULL;

	switch (state) {
	case PKM_KACS_KUNIT_FILE_SD_VALID:
		if (!sd_ptr || sd_len == 0)
			return NULL;
		copied_bytes = kmemdup(sd_ptr, sd_len, GFP_KERNEL);
		if (!copied_bytes)
			return NULL;
		return pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_VALID,
						      copied_bytes, sd_len);
	case PKM_KACS_KUNIT_FILE_SD_MISSING:
		return pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_MISSING,
						      NULL, 0);
	case PKM_KACS_KUNIT_FILE_SD_CORRUPT:
		return pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_CORRUPT,
						      NULL, 0);
	default:
		return NULL;
	}
}

long pkm_kacs_kunit_get_file_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_get_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_inode_sd_cache *cache;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	ret = pkm_kacs_query_file_sd_bytes_core(args->subject_token, cache,
						args->security_info, out_sd_ptr,
						out_sd_len);
	pkm_kacs_inode_sd_cache_free(cache);
	return ret;
}

long pkm_kacs_kunit_set_file_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_inode_sd_cache *cache;
	const u8 *result_sd = NULL;
	size_t result_sd_len = 0;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len || !args->input_sd_ptr ||
	    args->input_sd_len == 0)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	ret = pkm_kacs_prepare_new_file_sd_core(args->subject_token, cache,
						args->security_info,
						args->input_sd_ptr,
						args->input_sd_len, true,
						&result_sd,
						&result_sd_len);
	if (!ret) {
		if (args->target_file_sd_state != PKM_KACS_KUNIT_FILE_SD_VALID)
			(void)kacs_rust_token_mark_privileges_used(
				args->subject_token,
				PKM_KACS_PRIVILEGE_SE_RESTORE);
		*out_sd_ptr = result_sd;
		*out_sd_len = result_sd_len;
	}

	pkm_kacs_inode_sd_cache_free(cache);
	return ret;
}

struct pkm_kacs_kunit_file_mount_state {
	struct vfsmount mnt;
	struct super_block sb;
	struct inode inode;
	struct dentry dentry;
	struct file file;
	void *sb_blob;
	void *file_blob;
	void *inode_blob;
};

static int pkm_kacs_kunit_init_file_mount_state_ex(
	struct pkm_kacs_kunit_file_mount_state *state, u64 magic,
	struct pkm_kacs_inode_sd_cache *cache, u32 policy_override,
	const u8 *template_sd_ptr, size_t template_sd_len, umode_t mode,
	bool fake_xattr_enabled);
static void pkm_kacs_kunit_cleanup_file_mount_state(
	struct pkm_kacs_kunit_file_mount_state *state);

long pkm_kacs_kunit_open_file_for_subject_audit(
	const struct pkm_kacs_kunit_file_open_args *args,
	u32 *granted_access_out, u32 *continuous_audit_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_file_security *file_sec;
	u64 magic;
	umode_t mode;
	long ret;

	if (!args)
		return -EINVAL;

	if (granted_access_out)
		*granted_access_out = 0;
	if (continuous_audit_out)
		*continuous_audit_out = 0;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	magic = args->mount_magic ? args->mount_magic : TMPFS_MAGIC;
	mode = args->inode_mode ? args->inode_mode : S_IFREG;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic, cache, args->mount_policy_override, NULL, 0,
		mode, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_free;
	}

	state->file.f_mode = args->file_mode ? args->file_mode : FMODE_READ;
	state->file.f_flags = args->file_flags;
	ret = pkm_kacs_stamp_file_granted_access_for_subject(
		args->subject_token, &state->file);
	if (!ret && (granted_access_out || continuous_audit_out)) {
		file_sec = pkm_kacs_file(&state->file);
		if (granted_access_out)
			*granted_access_out = file_sec && file_sec->managed ?
						      file_sec->granted_access :
						      0;
		if (continuous_audit_out)
			*continuous_audit_out =
				file_sec && file_sec->managed ?
					file_sec->continuous_audit_mask :
					0;
	}

	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_open_file_for_subject(
	const struct pkm_kacs_kunit_file_open_args *args,
	u32 *granted_access_out)
{
	return pkm_kacs_kunit_open_file_for_subject_audit(
		args, granted_access_out, NULL);
}

long pkm_kacs_kunit_native_open_for_subject(
	const struct pkm_kacs_kunit_native_open_args *args,
	u32 *granted_access_out, u32 *status_out, u32 *file_mode_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_kunit_file_mount_state *parent_state = NULL;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_sd_cache *parent_cache = NULL;
	struct pkm_kacs_native_open_prepared prepared = {};
	struct pkm_kacs_file_security *file_sec;
	struct file parent_file = {};
	const u8 *created_sd = NULL;
	size_t created_sd_len = 0;
	struct inode *inode;
	u64 magic;
	umode_t mode;
	long delete_ret;
	long ret;

	if (!args)
		return -EINVAL;
	if (granted_access_out)
		*granted_access_out = 0;
	if (status_out)
		*status_out = 0;
	if (file_mode_out)
		*file_mode_out = 0;

	ret = pkm_kacs_prepare_native_open(
		&(struct kacs_open_how){
			.desired_access = args->desired_access,
			.create_disposition = args->create_disposition,
			.create_options = args->create_options,
			.flags = args->flags,
			.sd_ptr = (u64)(uintptr_t)args->input_sd_ptr,
			.sd_len = (u32)args->input_sd_len,
		},
		&prepared);
	if (ret)
		return ret;
	if ((prepared.create_options & KACS_CREATE_OPT_DELETE_ON_CLOSE) != 0)
		return -EOPNOTSUPP;
	if (args->create_disposition == KACS_FILE_CREATE)
		return -EEXIST;
	if ((args->create_disposition == KACS_FILE_OPEN_IF ||
	     args->create_disposition == KACS_FILE_OVERWRITE_IF) &&
	    args->input_sd_ptr && args->input_sd_len != 0)
		return -EINVAL;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	magic = args->mount_magic ? args->mount_magic : TMPFS_MAGIC;
	mode = args->inode_mode ? args->inode_mode : S_IFREG;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic, cache, args->mount_policy_override, NULL, 0,
		mode, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_free;
	}

	if (args->create_disposition == KACS_FILE_SUPERSEDE) {
		parent_cache = pkm_kacs_kunit_file_sd_cache_alloc(
			args->parent_file_sd_ptr, args->parent_file_sd_len,
			args->parent_file_sd_state);
		if (!parent_cache) {
			ret = -EINVAL;
			goto out_cleanup;
		}
		parent_state = kzalloc(sizeof(*parent_state), GFP_KERNEL);
		if (!parent_state) {
			pkm_kacs_inode_sd_cache_free(parent_cache);
			ret = -ENOMEM;
			goto out_cleanup;
		}
		ret = pkm_kacs_kunit_init_file_mount_state_ex(
			parent_state, magic, parent_cache,
			args->mount_policy_override, NULL, 0, S_IFDIR, true);
		if (ret) {
			pkm_kacs_inode_sd_cache_free(parent_cache);
			goto out_parent_free;
		}
	}

	inode = file_inode(&state->file);
	if (!inode) {
		ret = -EACCES;
		goto out_parent_cleanup;
	}
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    PKM_KACS_MOUNT_POLICY_UNMANAGED) {
		ret = -EOPNOTSUPP;
		goto out_parent_cleanup;
	}
	if ((args->flags & AT_SYMLINK_NOFOLLOW) != 0 &&
	    S_ISLNK(inode->i_mode)) {
		ret = -ELOOP;
		goto out_parent_cleanup;
	}
	if (args->create_disposition == KACS_FILE_SUPERSEDE ||
	    args->create_disposition == KACS_FILE_OVERWRITE ||
	    args->create_disposition == KACS_FILE_OVERWRITE_IF) {
		if (!S_ISREG(inode->i_mode)) {
			ret = -EOPNOTSUPP;
			goto out_parent_cleanup;
		}
	} else if (S_ISDIR(inode->i_mode)) {
		if ((prepared.desired_access &
		     PKM_KACS_DIRECTORY_MUTATION_RIGHTS) != 0) {
			ret = -EOPNOTSUPP;
			goto out_parent_cleanup;
		}
	} else if (prepared.directory_required) {
		ret = -ENOTDIR;
		goto out_parent_cleanup;
	} else if (!pkm_kacs_existing_file_object_mode_supported(
			   inode->i_mode)) {
		ret = -EACCES;
		goto out_parent_cleanup;
	} else if (!S_ISREG(inode->i_mode) &&
		   (prepared.desired_access & PKM_KACS_FILE_EXECUTE) != 0) {
		ret = -EACCES;
		goto out_parent_cleanup;
	}
	if ((args->create_disposition == KACS_FILE_OVERWRITE ||
	     args->create_disposition == KACS_FILE_OVERWRITE_IF) &&
	    (prepared.desired_access & PKM_KACS_FILE_WRITE_DATA) == 0) {
		ret = -EINVAL;
		goto out_parent_cleanup;
	}

	if (args->create_disposition == KACS_FILE_SUPERSEDE) {
		pkm_kacs_init_path_anchor_file(
			&parent_file,
			&(struct path){
				.mnt = &parent_state->mnt,
				.dentry = &parent_state->dentry,
			});
		ret = pkm_kacs_build_created_file_sd_for_subject(
			args->subject_token, &parent_file, args->input_sd_ptr,
			args->input_sd_len, false, prepared.desired_access,
			&created_sd, &created_sd_len, granted_access_out);
		if (ret)
			goto out_parent_cleanup;

		delete_ret = pkm_kacs_authorize_live_file_access_core(
			args->subject_token, &state->file, KACS_ACCESS_DELETE);
		if (delete_ret == -EACCES) {
			delete_ret = pkm_kacs_authorize_live_file_access_core(
				args->subject_token, &parent_file,
				PKM_KACS_FILE_DELETE_CHILD);
		}
		if (delete_ret) {
			ret = delete_ret;
			goto out_parent_cleanup;
		}

		if (status_out)
			*status_out = KACS_STATUS_SUPERSEDED;
		ret = 0;
		goto out_parent_cleanup;
	}

	state->file.f_flags = prepared.open_flags;
	state->file.f_mode = OPEN_FMODE(prepared.open_flags);
	ret = pkm_kacs_stamp_native_file_granted_access_for_subject(
		args->subject_token, &state->file, prepared.desired_access);
	if (!ret) {
		file_sec = pkm_kacs_file(&state->file);
		if (granted_access_out)
			*granted_access_out = file_sec && file_sec->managed ?
						      file_sec->granted_access :
						      0;
		if (status_out)
			*status_out = prepared.status;
		if (file_mode_out)
			*file_mode_out = state->file.f_mode;
	}

out_parent_cleanup:
	if (created_sd)
		pkm_kacs_free((void *)created_sd);
	if (parent_state)
		pkm_kacs_kunit_cleanup_file_mount_state(parent_state);
out_parent_free:
	kfree(parent_state);
out_cleanup:
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_native_create_for_subject(
	const struct pkm_kacs_kunit_native_create_args *args,
	const u8 **created_sd_out, size_t *created_sd_len_out,
	u32 *granted_access_out, u32 *status_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_native_open_prepared prepared = {};
	struct kacs_open_how how = {};
	u64 magic;
	long ret;

	if (!args || !created_sd_out || !created_sd_len_out)
		return -EINVAL;

	*created_sd_out = NULL;
	*created_sd_len_out = 0;
	if (granted_access_out)
		*granted_access_out = 0;
	if (status_out)
		*status_out = 0;

	how.desired_access = args->desired_access;
	how.create_disposition = args->create_disposition;
	how.create_options = args->create_options;
	how.flags = args->flags;
	how.sd_ptr = (u64)(uintptr_t)args->creator_sd_ptr;
	how.sd_len = (u32)args->creator_sd_len;

	ret = pkm_kacs_prepare_native_open(&how, &prepared);
	if (ret)
		return ret;
	if (args->create_disposition != KACS_FILE_CREATE &&
	    args->create_disposition != KACS_FILE_OPEN_IF &&
	    args->create_disposition != KACS_FILE_OVERWRITE_IF &&
	    args->create_disposition != KACS_FILE_SUPERSEDE)
		return -EINVAL;
	if (prepared.directory_required &&
	    (prepared.desired_access & PKM_KACS_DIRECTORY_MUTATION_RIGHTS) != 0)
		return -EOPNOTSUPP;
	if ((prepared.create_options & KACS_CREATE_OPT_DELETE_ON_CLOSE) != 0)
		return -EOPNOTSUPP;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->parent_file_sd_ptr,
						   args->parent_file_sd_len,
						   args->parent_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	magic = args->mount_magic ? args->mount_magic : TMPFS_MAGIC;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic, cache, args->mount_policy_override, NULL, 0,
		S_IFDIR, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_free;
	}

	ret = pkm_kacs_build_created_file_sd_for_subject(
		args->subject_token, &state->file, args->creator_sd_ptr,
		args->creator_sd_len, prepared.directory_required,
		prepared.desired_access, created_sd_out, created_sd_len_out,
		granted_access_out);
	if (!ret && status_out)
		*status_out = KACS_STATUS_CREATED;

	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_delete_on_close_for_subject(
	const struct pkm_kacs_kunit_native_open_args *args,
	struct pkm_kacs_kunit_delete_on_close_result *out)
{
	struct pkm_kacs_kunit_file_mount_state *state = NULL;
	struct pkm_kacs_kunit_file_mount_state *parent_state = NULL;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct pkm_kacs_inode_sd_cache *parent_cache = NULL;
	struct pkm_kacs_native_open_prepared prepared = {};
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct file reopened = {};
	void *reopen_blob = NULL;
	const u8 *created_sd = NULL;
	size_t created_sd_len = 0;
	u64 magic;
	umode_t mode;
	bool create_branch;
	long ret;

	if (!args || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	if ((args->create_options & KACS_CREATE_OPT_DELETE_ON_CLOSE) == 0)
		return -EINVAL;

	ret = pkm_kacs_prepare_native_open(
		&(struct kacs_open_how){
			.desired_access = args->desired_access,
			.create_disposition = args->create_disposition,
			.create_options = args->create_options,
			.flags = args->flags,
			.sd_ptr = (u64)(uintptr_t)args->input_sd_ptr,
			.sd_len = (u32)args->input_sd_len,
		},
		&prepared);
	if (ret)
		return ret;
	if (prepared.directory_required)
		return -EOPNOTSUPP;

	create_branch = args->create_disposition == KACS_FILE_CREATE;
	if (!create_branch &&
	    (args->create_disposition == KACS_FILE_OPEN_IF ||
	     args->create_disposition == KACS_FILE_OVERWRITE_IF ||
	     args->create_disposition == KACS_FILE_SUPERSEDE) &&
	    args->target_file_sd_state == PKM_KACS_KUNIT_FILE_SD_MISSING)
		create_branch = true;

	magic = args->mount_magic ? args->mount_magic : TMPFS_MAGIC;
	mode = args->inode_mode ? args->inode_mode : S_IFREG;

	if (create_branch) {
		parent_cache = pkm_kacs_kunit_file_sd_cache_alloc(
			args->parent_file_sd_ptr, args->parent_file_sd_len,
			args->parent_file_sd_state);
		if (!parent_cache)
			return -EINVAL;

		parent_state = kzalloc(sizeof(*parent_state), GFP_KERNEL);
		if (!parent_state) {
			pkm_kacs_inode_sd_cache_free(parent_cache);
			return -ENOMEM;
		}

		ret = pkm_kacs_kunit_init_file_mount_state_ex(
			parent_state, magic, parent_cache,
			args->mount_policy_override, NULL, 0, S_IFDIR, true);
		if (ret) {
			pkm_kacs_inode_sd_cache_free(parent_cache);
			goto out;
		}

		ret = pkm_kacs_build_created_file_sd_for_subject(
			args->subject_token, &parent_state->file, args->input_sd_ptr,
			args->input_sd_len, false, prepared.desired_access,
			&created_sd, &created_sd_len, NULL);
		if (ret)
			goto out;

		cache = pkm_kacs_kunit_file_sd_cache_alloc(
			created_sd, created_sd_len, PKM_KACS_KUNIT_FILE_SD_VALID);
		if (!cache) {
			ret = -EINVAL;
			goto out;
		}

		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state) {
			pkm_kacs_inode_sd_cache_free(cache);
			ret = -ENOMEM;
			goto out;
		}

		ret = pkm_kacs_kunit_init_file_mount_state_ex(
			state, magic, cache, args->mount_policy_override, NULL, 0,
			mode, true);
		if (ret) {
			pkm_kacs_inode_sd_cache_free(cache);
			goto out;
		}
		state->dentry.d_parent = &parent_state->dentry;
		out->status = KACS_STATUS_CREATED;
	} else {
		if ((args->create_disposition == KACS_FILE_OPEN_IF ||
		     args->create_disposition == KACS_FILE_OVERWRITE_IF) &&
		    args->input_sd_ptr && args->input_sd_len != 0)
			return -EINVAL;
		if (args->create_disposition != KACS_FILE_OPEN &&
		    args->create_disposition != KACS_FILE_OPEN_IF &&
		    args->create_disposition != KACS_FILE_OVERWRITE &&
		    args->create_disposition != KACS_FILE_OVERWRITE_IF)
			return -EOPNOTSUPP;

		cache = pkm_kacs_kunit_file_sd_cache_alloc(
			args->target_file_sd_ptr, args->target_file_sd_len,
			args->target_file_sd_state);
		if (!cache)
			return -EINVAL;

		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state) {
			pkm_kacs_inode_sd_cache_free(cache);
			return -ENOMEM;
		}

		ret = pkm_kacs_kunit_init_file_mount_state_ex(
			state, magic, cache, args->mount_policy_override, NULL, 0,
			mode, true);
		if (ret) {
			pkm_kacs_inode_sd_cache_free(cache);
			goto out;
		}

		if (args->parent_file_sd_ptr && args->parent_file_sd_len != 0) {
			parent_cache = pkm_kacs_kunit_file_sd_cache_alloc(
				args->parent_file_sd_ptr, args->parent_file_sd_len,
				args->parent_file_sd_state);
			if (!parent_cache) {
				ret = -EINVAL;
				goto out;
			}
			parent_state = kzalloc(sizeof(*parent_state), GFP_KERNEL);
			if (!parent_state) {
				pkm_kacs_inode_sd_cache_free(parent_cache);
				ret = -ENOMEM;
				goto out;
			}
			ret = pkm_kacs_kunit_init_file_mount_state_ex(
				parent_state, magic, parent_cache,
				args->mount_policy_override, NULL, 0, S_IFDIR, true);
			if (ret) {
				pkm_kacs_inode_sd_cache_free(parent_cache);
				goto out;
			}
			state->dentry.d_parent = &parent_state->dentry;
		}
		out->status = prepared.status;
	}

	if (!S_ISREG(state->inode.i_mode)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	state->file.f_flags = prepared.open_flags;
	state->file.f_mode = OPEN_FMODE(prepared.open_flags);
	ret = pkm_kacs_stamp_native_file_granted_access_for_subject(
		args->subject_token, &state->file, prepared.desired_access);
	if (ret)
		goto out;

	ret = pkm_kacs_maybe_arm_delete_on_close_for_subject(
		args->subject_token, &state->file, prepared.create_options);
	if (ret)
		goto out;

	file_sec = pkm_kacs_file(&state->file);
	out->granted_access = file_sec && file_sec->managed ?
				      file_sec->granted_access :
				      0;

	inode_sec = pkm_kacs_inode(&state->inode);
	out->pending_before_release =
		(u32)atomic_read(&inode_sec->delete_on_close_lineages);

	reopen_blob = kzalloc(pkm_blob_sizes.lbs_file +
				      sizeof(struct pkm_kacs_file_security),
			      GFP_KERNEL);
	if (!reopen_blob) {
		ret = -ENOMEM;
		goto out;
	}

	reopened.f_inode = &state->inode;
	reopened.f_security = reopen_blob;
	reopened.f_mode = FMODE_READ;
	reopened.f_flags = 0;
	*(struct path *)&reopened.f_path = (struct path){
		.mnt = &state->mnt,
		.dentry = &state->dentry,
	};
	ret = pkm_kacs_file_alloc_security(&reopened);
	if (ret)
		goto out;

	out->reopen_result = pkm_kacs_stamp_file_granted_access_for_subject(
		args->subject_token, &reopened);

	pkm_kacs_file_release(&state->file);
	out->pending_after_release =
		(u32)atomic_read(&inode_sec->delete_on_close_lineages);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	out->unlink_calls = inode_sec->kunit_unlink_calls;
#endif
	ret = 0;

out:
	kfree(reopen_blob);
	if (created_sd)
		pkm_kacs_free((void *)created_sd);
	if (state)
		pkm_kacs_kunit_cleanup_file_mount_state(state);
	kfree(state);
	if (parent_state)
		pkm_kacs_kunit_cleanup_file_mount_state(parent_state);
	kfree(parent_state);
	return ret;
}

long pkm_kacs_kunit_get_cached_file_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_get_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_file_security *file_sec;
	u64 magic;
	umode_t mode;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	magic = args->mount_magic ? args->mount_magic : TMPFS_MAGIC;
	mode = args->inode_mode ? args->inode_mode : S_IFREG;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic, cache, args->mount_policy_override, NULL, 0,
		mode, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_free;
	}

	state->file.f_mode = args->file_mode ? args->file_mode : FMODE_READ;
	state->file.f_flags = args->file_flags;
	file_sec = pkm_kacs_file(&state->file);
	file_sec->granted_access = args->cached_granted_access;
	file_sec->managed = 1;

	ret = pkm_kacs_query_file_sd_core(args->subject_token, &state->file,
					  args->security_info, out_sd_ptr,
					  out_sd_len);
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_set_cached_file_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_security *inode_sec;
	struct pkm_kacs_inode_sd_cache *live_cache;
	struct pkm_kacs_file_security *file_sec;
	u64 magic;
	umode_t mode;
	const u8 *result_sd = NULL;
	size_t result_sd_len = 0;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len || !args->input_sd_ptr ||
	    args->input_sd_len == 0)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	magic = args->mount_magic ? args->mount_magic : TMPFS_MAGIC;
	mode = args->inode_mode ? args->inode_mode : S_IFREG;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic, cache, args->mount_policy_override, NULL, 0,
		mode, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_free;
	}

	state->file.f_mode = args->file_mode ? args->file_mode : FMODE_READ;
	state->file.f_flags = args->file_flags;
	file_sec = pkm_kacs_file(&state->file);
	file_sec->granted_access = args->cached_granted_access;
	file_sec->managed = 1;

	ret = pkm_kacs_set_file_sd_core(args->subject_token, &state->file,
					args->security_info,
					args->input_sd_ptr,
					args->input_sd_len);
	if (ret)
		goto out_cleanup;

	inode_sec = pkm_kacs_inode(&state->inode);
	mutex_lock(&inode_sec->lock);
	live_cache = rcu_dereference_protected(inode_sec->sd_cache,
					       lockdep_is_held(&inode_sec->lock));
	if (!live_cache || live_cache->state != PKM_KACS_INODE_SD_VALID ||
	    !live_cache->bytes || live_cache->len == 0) {
		ret = -EACCES;
	} else {
		result_sd = kmemdup(live_cache->bytes, live_cache->len,
				    GFP_KERNEL);
		if (!result_sd) {
			ret = -ENOMEM;
		} else {
			result_sd_len = live_cache->len;
		}
	}
	mutex_unlock(&inode_sec->lock);
	if (!ret) {
		*out_sd_ptr = result_sd;
		*out_sd_len = result_sd_len;
	}

out_cleanup:
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

u32 pkm_kacs_kunit_classify_file_sd_bytes(const u8 *sd_ptr, size_t sd_len)
{
	if (!sd_ptr || sd_len == 0)
		return PKM_KACS_KUNIT_FILE_SD_MISSING;
	if (kacs_rust_validate_sd_bytes(sd_ptr, sd_len) != 0)
		return PKM_KACS_KUNIT_FILE_SD_CORRUPT;

	return PKM_KACS_KUNIT_FILE_SD_VALID;
}

static int pkm_kacs_kunit_init_file_mount_state_ex(
	struct pkm_kacs_kunit_file_mount_state *state, u64 magic,
	struct pkm_kacs_inode_sd_cache *cache, u32 policy_override,
	const u8 *template_sd_ptr, size_t template_sd_len, umode_t mode,
	bool fake_xattr_enabled)
{
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_superblock_security *sb_sec;
	size_t sb_blob_len;
	size_t file_blob_len;
	size_t inode_blob_len;
	int ret;

	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));
	sb_blob_len = pkm_blob_sizes.lbs_superblock +
		sizeof(struct pkm_kacs_superblock_security);
	file_blob_len = pkm_blob_sizes.lbs_file +
		sizeof(struct pkm_kacs_file_security);
	inode_blob_len = pkm_blob_sizes.lbs_inode +
		sizeof(struct pkm_kacs_inode_security);

	state->sb_blob = kzalloc(sb_blob_len, GFP_KERNEL);
	if (!state->sb_blob)
		return -ENOMEM;
	state->inode_blob = kzalloc(inode_blob_len, GFP_KERNEL);
	if (!state->inode_blob) {
		kfree(state->sb_blob);
		state->sb_blob = NULL;
		return -ENOMEM;
	}
	state->file_blob = kzalloc(file_blob_len, GFP_KERNEL);
	if (!state->file_blob) {
		kfree(state->inode_blob);
		kfree(state->sb_blob);
		state->inode_blob = NULL;
		state->sb_blob = NULL;
		return -ENOMEM;
	}

	state->sb.s_magic = (unsigned long)magic;
	state->sb.s_security = state->sb_blob;
	ret = pkm_kacs_sb_alloc_security(&state->sb);
	if (ret)
		goto out_err;
	sb_sec = pkm_kacs_sb(&state->sb);
	if (policy_override != 0)
		sb_sec->mount_policy = policy_override;
	if (template_sd_ptr && template_sd_len != 0) {
		const u8 *copied_bytes = kmemdup(template_sd_ptr,
						 template_sd_len,
						 GFP_KERNEL);

		if (!copied_bytes) {
			ret = -ENOMEM;
			goto out_err;
		}
		sb_sec->template_sd_bytes = copied_bytes;
		sb_sec->template_sd_len = template_sd_len;
	}

	state->inode.i_sb = &state->sb;
	state->inode.i_mode = mode;
	state->inode.i_security = state->inode_blob;
	ret = pkm_kacs_inode_alloc_security(&state->inode);
	if (ret)
		goto out_err;

	state->dentry.d_inode = &state->inode;
	state->dentry.d_parent = &state->dentry;
	if (S_ISDIR(mode))
		state->dentry.d_flags = DCACHE_DIRECTORY_TYPE;
	else if (S_ISLNK(mode))
		state->dentry.d_flags = DCACHE_SYMLINK_TYPE;
	else if (S_ISREG(mode))
		state->dentry.d_flags = DCACHE_REGULAR_TYPE;
	else
		state->dentry.d_flags = DCACHE_SPECIAL_TYPE;
	state->mnt.mnt_root = &state->dentry;
	state->mnt.mnt_sb = &state->sb;
	state->mnt.mnt_flags = 0;
	state->mnt.mnt_idmap = &nop_mnt_idmap;
	state->file.f_inode = &state->inode;
	state->file.f_security = state->file_blob;
	state->file.f_mode = FMODE_PATH;
	*(struct path *)&state->file.f_path = (struct path){
		.mnt = &state->mnt,
		.dentry = &state->dentry,
	};
	ret = pkm_kacs_file_alloc_security(&state->file);
	if (ret)
		goto out_err;

	sec = pkm_kacs_inode(&state->inode);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	sec->kunit_fake_xattr_enabled = fake_xattr_enabled;
#endif
	if (cache)
		RCU_INIT_POINTER(sec->sd_cache, cache);

	return 0;

out_err:
	pkm_kacs_sb_free_security(&state->sb);
	if (state->inode.i_security)
		pkm_kacs_inode_free_security_rcu(state->inode.i_security);
	kfree(state->file_blob);
	kfree(state->inode_blob);
	kfree(state->sb_blob);
	state->file_blob = NULL;
	state->inode_blob = NULL;
	state->sb_blob = NULL;
	return ret;
}

static int pkm_kacs_kunit_init_file_mount_state(
	struct pkm_kacs_kunit_file_mount_state *state, u64 magic,
	struct pkm_kacs_inode_sd_cache *cache)
{
	return pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic, cache, 0, NULL, 0, S_IFREG, false);
}

static void pkm_kacs_kunit_cleanup_file_mount_state(
	struct pkm_kacs_kunit_file_mount_state *state)
{
	if (!state)
		return;

	if (state->inode.i_security)
		pkm_kacs_inode_free_security_rcu(state->inode.i_security);
	pkm_kacs_sb_free_security(&state->sb);
	kfree(state->file_blob);
	kfree(state->inode_blob);
	kfree(state->sb_blob);
	memset(state, 0, sizeof(*state));
}

u32 pkm_kacs_kunit_mount_policy_for_magic(u64 magic)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	u32 policy;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return 0;

	if (pkm_kacs_kunit_init_file_mount_state(state, magic, NULL) != 0) {
		kfree(state);
		return 0;
	}

	policy = pkm_kacs_superblock_mount_policy(&state->sb);
	pkm_kacs_kunit_cleanup_file_mount_state(state);
	kfree(state);
	return policy;
}

long pkm_kacs_kunit_missing_file_sd_result_for_magic(u64 magic)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	long ret;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = pkm_kacs_kunit_init_file_mount_state(state, magic, NULL);
	if (ret)
		goto out_free;

	ret = pkm_kacs_missing_file_sd_policy_result(&state->sb, &cache);
	if (!ret && cache) {
		ret = cache->state;
		pkm_kacs_inode_sd_cache_free(cache);
	}

	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_get_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_get_args *args, u64 magic,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	ret = pkm_kacs_kunit_init_file_mount_state(state, magic, cache);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_free;
	}

	ret = pkm_kacs_query_file_sd_core(args->subject_token, &state->file,
					  args->security_info, out_sd_ptr,
					  out_sd_len);
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_set_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args, u64 magic)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	long ret;

	if (!args || !args->input_sd_ptr || args->input_sd_len == 0)
		return -EINVAL;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	ret = pkm_kacs_kunit_init_file_mount_state(state, magic, cache);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_free;
	}

	ret = pkm_kacs_set_file_sd_core(args->subject_token, &state->file,
					args->security_info,
					args->input_sd_ptr,
					args->input_sd_len);
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_get_path_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_get_args *args, u64 magic, u32 flags,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	unsigned int lookup_flags = 0;
	umode_t mode;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	ret = pkm_kacs_path_sd_lookup_flags(flags, &lookup_flags);
	if (ret)
		return ret;
	(void)lookup_flags;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	mode = args->inode_mode ? args->inode_mode : S_IFREG;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic ? magic : TMPFS_MAGIC, cache,
		args->mount_policy_override, NULL, 0, mode, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_free;
	}

	ret = pkm_kacs_query_path_file_sd_core(args->subject_token,
					       &state->file.f_path,
					       args->security_info,
					       out_sd_ptr, out_sd_len);
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_set_path_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args, u64 magic, u32 flags)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	unsigned int lookup_flags = 0;
	umode_t mode;
	long ret;

	if (!args || !args->input_sd_ptr || args->input_sd_len == 0)
		return -EINVAL;

	ret = pkm_kacs_path_sd_lookup_flags(flags, &lookup_flags);
	if (ret)
		return ret;
	(void)lookup_flags;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	mode = args->inode_mode ? args->inode_mode : S_IFREG;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic ? magic : TMPFS_MAGIC, cache,
		args->mount_policy_override, NULL, 0, mode, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_free;
	}

	ret = pkm_kacs_set_path_file_sd_core(args->subject_token,
					     &state->file.f_path,
					     args->security_info,
					     args->input_sd_ptr,
					     args->input_sd_len);
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_query_missing_file_sd_on_policy_mount(
	const struct pkm_kacs_kunit_missing_file_sd_query_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len, u32 *xattr_written_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_security *sec;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len || !xattr_written_out)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;
	*xattr_written_out = 0;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, TMPFS_MAGIC, NULL, args->mount_policy,
		args->template_sd_ptr, args->template_sd_len,
		args->mode ? args->mode : S_IFREG, true);
	if (ret)
		goto out_free;

	ret = pkm_kacs_query_file_sd_core(args->subject_token, &state->file,
					  args->security_info, out_sd_ptr,
					  out_sd_len);
	if (!ret) {
		sec = pkm_kacs_inode(&state->inode);
#ifdef CONFIG_SECURITY_PKM_KUNIT
		*xattr_written_out = sec->kunit_fake_xattr_bytes &&
				     sec->kunit_fake_xattr_len != 0;
#endif
	}

	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

static int pkm_kacs_kunit_inode_sd_xattr_check(u32 op, const char *name,
					       u32 ntfs)
{
	struct file_system_type fs_type = {};
	struct pkm_kacs_kunit_file_mount_state state = {};
	int ret;

	fs_type.name = ntfs ? "ntfs3" : "tmpfs";
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_UNMANAGED,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;
	state.sb.s_type = &fs_type;

	switch (op) {
	case 1:
		ret = pkm_kacs_inode_getxattr(&state.dentry, name);
		break;
	case 2:
		ret = pkm_kacs_inode_setxattr(NULL, &state.dentry, name,
					      NULL, 0, 0);
		break;
	case 3:
		ret = pkm_kacs_inode_removexattr(NULL, &state.dentry, name);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_inode_sd_xattr_get(const char *name, u32 ntfs)
{
	return pkm_kacs_kunit_inode_sd_xattr_check(1, name, ntfs);
}

int pkm_kacs_kunit_inode_sd_xattr_set(const char *name, u32 ntfs)
{
	return pkm_kacs_kunit_inode_sd_xattr_check(2, name, ntfs);
}

int pkm_kacs_kunit_inode_sd_xattr_remove(const char *name, u32 ntfs)
{
	return pkm_kacs_kunit_inode_sd_xattr_check(3, name, ntfs);
}

static int pkm_kacs_kunit_file_sd_xattr_check(u32 op, const char *name,
					      u32 ntfs)
{
	struct file_system_type fs_type = {};
	struct super_block sb = {};
	struct inode inode = {};
	struct dentry dentry = {};
	struct file file = {};
	struct path path = {};
	void *file_blob;
	size_t file_blob_len;
	int ret;

	file_blob_len = pkm_blob_sizes.lbs_file +
		sizeof(struct pkm_kacs_file_security);
	file_blob = kzalloc(file_blob_len, GFP_KERNEL);
	if (!file_blob)
		return -ENOMEM;

	fs_type.name = ntfs ? "ntfs3" : "tmpfs";
	sb.s_type = &fs_type;
	inode.i_sb = &sb;
	dentry.d_inode = &inode;
	file.f_inode = &inode;
	file.f_security = file_blob;
	path.dentry = &dentry;
	*(struct path *)&file.f_path = path;
	pkm_kacs_file(&file)->managed = 0;

	switch (op) {
	case 1:
		ret = pkm_kacs_file_sd_xattr_get(&file, name);
		break;
	case 2:
		ret = pkm_kacs_file_sd_xattr_set(&file, name);
		break;
	case 3:
		ret = pkm_kacs_file_sd_xattr_remove(&file, name);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	pkm_kacs_file_end_metadata(&file);
	kfree(file_blob);
	return ret;
}

int pkm_kacs_kunit_file_sd_xattr_get(const char *name, u32 ntfs)
{
	return pkm_kacs_kunit_file_sd_xattr_check(1, name, ntfs);
}

int pkm_kacs_kunit_file_sd_xattr_set(const char *name, u32 ntfs)
{
	return pkm_kacs_kunit_file_sd_xattr_check(2, name, ntfs);
}

int pkm_kacs_kunit_file_sd_xattr_remove(const char *name, u32 ntfs)
{
	return pkm_kacs_kunit_file_sd_xattr_check(3, name, ntfs);
}

long pkm_kacs_kunit_get_token_sd_for_subject(int token_fd,
					     const void *subject_token,
					     u32 security_info,
					     const u8 **out_sd_ptr,
					     size_t *out_sd_len)
{
	const void *target_token = NULL;
	long ret;

	if (!subject_token || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	ret = pkm_kacs_token_fd_clone_token(token_fd, &target_token, NULL);
	if (ret)
		return ret;

	ret = pkm_kacs_query_token_sd_core(subject_token, target_token,
					   security_info, out_sd_ptr,
					   out_sd_len);
	kacs_rust_token_drop(target_token);
	return ret;
}

long pkm_kacs_kunit_set_token_sd_for_subject(int token_fd,
					     const void *subject_token,
					     u32 security_info,
					     const u8 *input_sd_ptr,
					     size_t input_sd_len,
					     const u8 **out_sd_ptr,
					     size_t *out_sd_len)
{
	const void *target_token = NULL;
	long ret;

	if (!subject_token || !input_sd_ptr || input_sd_len == 0 || !out_sd_ptr ||
	    !out_sd_len)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	ret = pkm_kacs_token_fd_clone_token(token_fd, &target_token, NULL);
	if (ret)
		return ret;

	ret = pkm_kacs_set_token_sd_core(subject_token, target_token,
					 security_info, input_sd_ptr,
					 input_sd_len);
	if (!ret)
		ret = kacs_rust_query_token_sd_subset(target_token,
						      security_info,
						      out_sd_ptr,
						      out_sd_len);

	kacs_rust_token_drop(target_token);
	return ret;
}

long pkm_kacs_kunit_open_current_thread_token_for_subject(
	const void *subject_token, u32 access_mask)
{
	struct pkm_kacs_process_state *caller_state;

	if (!subject_token)
		return -EINVAL;

	caller_state = pkm_kacs_current_process_state();
	if (!caller_state)
		return -EACCES;

	return pkm_kacs_open_thread_token_task(subject_token, caller_state,
					       current, access_mask);
}

long pkm_kacs_kunit_set_current_psb(u32 requested_mitigations)
{
	struct pkm_kacs_process_state *state;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	return pkm_kacs_apply_psb_mitigations_core(
		pkm_kacs_current_effective_token_ptr(), state, state, true,
		requested_mitigations, pkm_kacs_ibt_supported(),
		pkm_kacs_shstk_supported(), NULL);
}

long pkm_kacs_kunit_set_psb_for_subject(
	const struct pkm_kacs_kunit_set_psb_args *args,
	u32 *result_mitigation_bits_out)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state caller_state = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
	refcount_set(&process_sd.refs, 1);
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.mitigation_bits = args->initial_mitigation_bits;
	target_state.process_sd = &process_sd;
	spin_lock_init(&target_state.mitigation_lock);

	return pkm_kacs_apply_psb_mitigations_core(
		args->subject_token, &caller_state, &target_state,
		args->self_target != 0, args->requested_mitigations,
		args->ibt_supported != 0, args->shstk_supported != 0,
		result_mitigation_bits_out);
}

int pkm_kacs_kunit_check_no_child_process(u32 mitigation_bits,
					  u64 clone_flags)
{
	return pkm_kacs_clone_is_blocked_by_no_child(mitigation_bits,
						     clone_flags) ?
		       -EACCES :
		       0;
}

int pkm_kacs_kunit_check_wxp_mmap(u32 mitigation_bits, unsigned long prot)
{
	return pkm_kacs_check_wxp_mmap_core(mitigation_bits, prot);
}

int pkm_kacs_kunit_check_wxp_mprotect(u32 mitigation_bits,
				      unsigned long vm_flags,
				      unsigned long prot)
{
	return pkm_kacs_check_wxp_mprotect_core(mitigation_bits, vm_flags,
						prot);
}

long pkm_kacs_kunit_replace_tlp_prefixes(const char * const *prefixes,
					 const size_t *prefix_lens,
					 u32 count)
{
	return pkm_kacs_tlp_replace_prefixes_kernel(prefixes, prefix_lens,
						    count);
}

void pkm_kacs_kunit_clear_tlp_prefixes(void)
{
	mutex_lock(&pkm_kacs_tlp_cache_lock);
	pkm_kacs_tlp_clear_prefixes_locked();
	mutex_unlock(&pkm_kacs_tlp_cache_lock);
}

int pkm_kacs_kunit_check_tlp_mmap_path(u32 mitigation_bits,
				       unsigned long prot,
				       const char *path,
				       u32 file_backed)
{
	return pkm_kacs_check_tlp_path_core(
		mitigation_bits, file_backed != 0, (prot & PROT_EXEC) != 0,
		path, path ? strlen(path) : 0);
}

int pkm_kacs_kunit_check_tlp_mprotect_path(u32 mitigation_bits,
					   unsigned long vm_flags,
					   unsigned long prot,
					   const char *path,
					   u32 file_backed)
{
	return pkm_kacs_check_tlp_path_core(
		mitigation_bits, file_backed != 0,
		(prot & PROT_EXEC) != 0 && (vm_flags & VM_EXEC) == 0,
		path, path ? strlen(path) : 0);
}

int pkm_kacs_kunit_check_mmap_snapshot(u32 managed, u32 granted_access,
				       unsigned long prot,
				       unsigned long flags)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;

	ret = pkm_kacs_check_mmap_snapshot(&state.file, prot, flags);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_mprotect_snapshot(u32 managed, u32 granted_access,
					   unsigned long vm_flags,
					   unsigned long prot)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;

	ret = pkm_kacs_check_mprotect_snapshot(&state.file, vm_flags, prot);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_permission_snapshot(u32 managed,
						  u32 granted_access,
						  int file_flags,
						  int mask)
{
	return pkm_kacs_kunit_check_file_permission_snapshot_audit(
		managed, granted_access, 0, file_flags, mask);
}

int pkm_kacs_kunit_check_file_permission_snapshot_audit(u32 managed,
							u32 granted_access,
							u32 continuous_audit,
							int file_flags,
							int mask)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;
	file_sec->continuous_audit_mask = continuous_audit;
	state.file.f_flags = file_flags;

	ret = pkm_kacs_check_file_permission_snapshot(&state.file, mask);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_write_intent_snapshot(u32 managed,
						    u32 granted_access,
						    int file_flags,
						    u32 rwf_flags,
						    bool positioned)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;
	state.file.f_flags = file_flags;

	ret = pkm_kacs_check_file_write_intent_snapshot(
		&state.file, rwf_flags, positioned);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_permission_write_intent(
	u32 managed, u32 granted_access, int file_flags, u32 rwf_flags,
	bool positioned)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;
	state.file.f_flags = file_flags;

	ret = pkm_kacs_file_begin_write_intent(&state.file, rwf_flags,
					       positioned);
	if (!ret) {
		ret = pkm_kacs_check_file_permission_snapshot(&state.file,
							      MAY_WRITE);
		pkm_kacs_file_end_write_intent(&state.file);
	}

	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_permission_write_intent_mismatch(void)
{
	struct pkm_kacs_kunit_file_mount_state first = { };
	struct pkm_kacs_kunit_file_mount_state second = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&first, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&second, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		goto out_first;

	file_sec = pkm_kacs_file(&first.file);
	file_sec->managed = 1;
	file_sec->granted_access = PKM_KACS_FILE_APPEND_DATA;
	file_sec = pkm_kacs_file(&second.file);
	file_sec->managed = 1;
	file_sec->granted_access = PKM_KACS_FILE_APPEND_DATA;

	ret = pkm_kacs_file_begin_write_intent(&first.file, 0, true);
	if (!ret) {
		ret = pkm_kacs_check_file_permission_snapshot(&second.file,
							      MAY_WRITE);
		pkm_kacs_file_end_write_intent(&first.file);
	}

	pkm_kacs_kunit_cleanup_file_mount_state(&second);
out_first:
	pkm_kacs_kunit_cleanup_file_mount_state(&first);
	return ret;
}

static int pkm_kacs_kunit_call_file_metadata_op(struct file *file, u32 op,
						const char *name)
{
	switch (op) {
	case PKM_KACS_KUNIT_FILE_METADATA_GETATTR:
		return pkm_kacs_file_getattr(file);
	case PKM_KACS_KUNIT_FILE_METADATA_STATFS:
		return pkm_kacs_file_statfs(file);
	case PKM_KACS_KUNIT_FILE_METADATA_CHMOD:
		return pkm_kacs_file_chmod(file);
	case PKM_KACS_KUNIT_FILE_METADATA_CHOWN:
		return pkm_kacs_file_chown(file);
	case PKM_KACS_KUNIT_FILE_METADATA_UTIMENS:
		return pkm_kacs_file_utimens(file);
	case PKM_KACS_KUNIT_FILE_METADATA_FILEATTR_GET:
		return pkm_kacs_file_fileattr_get(file);
	case PKM_KACS_KUNIT_FILE_METADATA_FILEATTR_SET:
		return pkm_kacs_file_fileattr_set(file);
	case PKM_KACS_KUNIT_FILE_METADATA_XATTR_GET:
		return pkm_kacs_file_sd_xattr_get(file, name);
	case PKM_KACS_KUNIT_FILE_METADATA_XATTR_SET:
		return pkm_kacs_file_sd_xattr_set(file, name);
	case PKM_KACS_KUNIT_FILE_METADATA_XATTR_REMOVE:
		return pkm_kacs_file_sd_xattr_remove(file, name);
	case PKM_KACS_KUNIT_FILE_METADATA_XATTR_LIST:
		return pkm_kacs_file_listxattr(file);
	default:
		return -EINVAL;
	}
}

int pkm_kacs_kunit_check_file_metadata_snapshot(u32 managed,
						u32 granted_access, u32 op,
						const char *name)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;

	ret = pkm_kacs_kunit_call_file_metadata_op(&state.file, op, name);
	pkm_kacs_file_end_metadata(&state.file);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_metadata_null(u32 op, const char *name)
{
	return pkm_kacs_kunit_call_file_metadata_op(NULL, op, name);
}

static int pkm_kacs_kunit_call_path_metadata_op(
	struct pkm_kacs_kunit_file_mount_state *state, u32 op, u32 mode,
	const char *name)
{
	struct path path;
	struct iattr attr = {};
	int ret;

	if (!state)
		return -EINVAL;

	path.mnt = &state->mnt;
	path.dentry = &state->dentry;

	switch (op) {
	case PKM_KACS_KUNIT_PATH_METADATA_GETATTR:
		return pkm_kacs_inode_getattr(&path);
	case PKM_KACS_KUNIT_PATH_METADATA_SETATTR_CHMOD:
		attr.ia_valid = ATTR_MODE;
		return pkm_kacs_inode_setattr(&nop_mnt_idmap, &state->dentry,
					      &attr);
	case PKM_KACS_KUNIT_PATH_METADATA_SETATTR_CHOWN:
		attr.ia_valid = ATTR_UID;
		return pkm_kacs_inode_setattr(&nop_mnt_idmap, &state->dentry,
					      &attr);
	case PKM_KACS_KUNIT_PATH_METADATA_SETATTR_UTIMENS:
		attr.ia_valid = ATTR_ATIME | ATTR_MTIME | ATTR_TIMES_SET;
		return pkm_kacs_inode_setattr(&nop_mnt_idmap, &state->dentry,
					      &attr);
	case PKM_KACS_KUNIT_PATH_METADATA_SETATTR_TRUNCATE:
		attr.ia_valid = ATTR_SIZE;
		return pkm_kacs_inode_setattr(&nop_mnt_idmap, &state->dentry,
					      &attr);
	case PKM_KACS_KUNIT_PATH_METADATA_FILEATTR_GET:
		return pkm_kacs_inode_file_getattr(&state->dentry, NULL);
	case PKM_KACS_KUNIT_PATH_METADATA_FILEATTR_SET:
		ret = pkm_kacs_path_fileattr_set(&path);
		if (ret)
			return ret;
		ret = pkm_kacs_inode_file_getattr(&state->dentry, NULL);
		if (!ret)
			ret = pkm_kacs_inode_file_setattr(&state->dentry,
							  NULL);
		pkm_kacs_path_end_metadata(&path);
		return ret;
	case PKM_KACS_KUNIT_PATH_METADATA_XATTR_GET:
		return pkm_kacs_inode_getxattr(&state->dentry, name);
	case PKM_KACS_KUNIT_PATH_METADATA_XATTR_SET:
		return pkm_kacs_inode_setxattr(&nop_mnt_idmap, &state->dentry,
					       name, NULL, 0, 0);
	case PKM_KACS_KUNIT_PATH_METADATA_XATTR_REMOVE:
		return pkm_kacs_inode_removexattr(&nop_mnt_idmap,
						  &state->dentry, name);
	case PKM_KACS_KUNIT_PATH_METADATA_XATTR_LIST:
		return pkm_kacs_inode_listxattr(&state->dentry);
	case PKM_KACS_KUNIT_PATH_METADATA_ACCESS:
		return pkm_kacs_path_access(&path, (int)mode);
	default:
		return -EINVAL;
	}
}

int pkm_kacs_kunit_check_path_metadata_live(const u8 *target_file_sd_ptr,
					    size_t target_file_sd_len,
					    u32 target_file_sd_state, u32 op,
					    u32 mode, const char *name)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_inode_sd_cache *cache;
	int ret;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(target_file_sd_ptr,
						   target_file_sd_len,
						   target_file_sd_state);
	if (!cache)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, cache, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		return ret;
	}

	ret = pkm_kacs_kunit_call_path_metadata_op(&state, op, mode, name);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_inode_permission_live(
	const u8 *target_file_sd_ptr, size_t target_file_sd_len,
	u32 target_file_sd_state, u32 mount_policy,
	const void *subject_token, int mask)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_inode_sd_cache *cache;
	int ret;

	if (!subject_token)
		return -EINVAL;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(target_file_sd_ptr,
						   target_file_sd_len,
						   target_file_sd_state);
	if (!cache)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, cache, mount_policy, NULL, 0, S_IFDIR,
		true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		return ret;
	}

	ret = (int)pkm_kacs_check_inode_permission_live_for_subject(
		subject_token, &state.inode, &state.dentry, mask);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_open_by_handle_for_subject(
	const void *subject_token)
{
	return (int)pkm_kacs_require_enabled_privilege(
		subject_token, PKM_KACS_PRIVILEGE_SE_CHANGE_NOTIFY);
}

static int pkm_kacs_kunit_init_namespace_state(
	struct pkm_kacs_kunit_file_mount_state *state,
	const u8 *sd_ptr, size_t sd_len, u32 sd_state, u64 magic,
	u32 mount_policy, umode_t mode)
{
	struct pkm_kacs_inode_sd_cache *cache;
	int ret;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(sd_ptr, sd_len, sd_state);
	if (!cache)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic, cache, mount_policy, NULL, 0, mode, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		return ret;
	}

	return 0;
}

static int pkm_kacs_kunit_namespace_maybe_build_created_sd(
	const struct pkm_kacs_kunit_namespace_args *args,
	struct pkm_kacs_kunit_file_mount_state *parent, bool directory,
	const u8 **created_sd_out, size_t *created_sd_len_out)
{
	long ret;

	if (!created_sd_out || !created_sd_len_out)
		return 0;

	*created_sd_out = NULL;
	*created_sd_len_out = 0;
	ret = pkm_kacs_build_legacy_created_file_sd_for_subject(
		args->subject_token, &parent->inode, &parent->dentry,
		directory, created_sd_out, created_sd_len_out);
	return (int)ret;
}

int pkm_kacs_kunit_check_namespace_live(
	const struct pkm_kacs_kunit_namespace_args *args,
	const u8 **created_sd_out, size_t *created_sd_len_out)
{
	struct pkm_kacs_kunit_file_mount_state source = {};
	struct pkm_kacs_kunit_file_mount_state old_parent = {};
	struct pkm_kacs_kunit_file_mount_state new_parent = {};
	struct pkm_kacs_kunit_file_mount_state target = {};
	struct dentry negative = {};
	struct dentry create_child = {};
	struct dentry *new_dentry;
	u32 policy;
	u64 magic;
	umode_t source_mode;
	umode_t target_mode;
	umode_t mknod_mode;
	bool source_ready = false;
	bool old_parent_ready = false;
	bool new_parent_ready = false;
	bool target_ready = false;
	int ret = 0;

	if (!args || !args->subject_token)
		return -EINVAL;
	if (created_sd_out)
		*created_sd_out = NULL;
	if (created_sd_len_out)
		*created_sd_len_out = 0;

	magic = args->mount_magic ? args->mount_magic : TMPFS_MAGIC;
	policy = args->mount_policy_override ?
			 args->mount_policy_override :
			 PKM_KACS_MOUNT_POLICY_DENY_MISSING;
	source_mode = args->source_mode ? args->source_mode : S_IFREG;
	target_mode = args->target_mode ? args->target_mode : S_IFREG;
	mknod_mode = args->target_mode_set ? args->target_mode : S_IFIFO;

	if (args->old_parent_sd_state != 0) {
		ret = pkm_kacs_kunit_init_namespace_state(
			&old_parent, args->old_parent_sd_ptr,
			args->old_parent_sd_len, args->old_parent_sd_state,
			magic, policy, S_IFDIR);
		if (ret)
			goto out;
		old_parent_ready = true;
	}
	if (args->new_parent_sd_state != 0) {
		ret = pkm_kacs_kunit_init_namespace_state(
			&new_parent, args->new_parent_sd_ptr,
			args->new_parent_sd_len, args->new_parent_sd_state,
			magic, policy, S_IFDIR);
		if (ret)
			goto out;
		new_parent_ready = true;
	}
	if (args->source_sd_state != 0) {
		ret = pkm_kacs_kunit_init_namespace_state(
			&source, args->source_sd_ptr, args->source_sd_len,
			args->source_sd_state, magic, policy, source_mode);
		if (ret)
			goto out;
		source_ready = true;
	}
	if (args->target_sd_state != 0) {
		ret = pkm_kacs_kunit_init_namespace_state(
			&target, args->target_sd_ptr, args->target_sd_len,
			args->target_sd_state, magic, policy, target_mode);
		if (ret)
			goto out;
		target_ready = true;
	}

	if (source_ready && old_parent_ready)
		source.dentry.d_parent = &old_parent.dentry;
	if (target_ready && new_parent_ready)
		target.dentry.d_parent = &new_parent.dentry;
	if (old_parent_ready)
		create_child.d_parent = &old_parent.dentry;
	if (new_parent_ready)
		negative.d_parent = &new_parent.dentry;

	switch (args->op) {
	case PKM_KACS_KUNIT_NAMESPACE_CREATE_FILE:
		if (!old_parent_ready) {
			ret = -EINVAL;
			break;
		}
		ret = (int)pkm_kacs_authorize_namespace_create_for_subject(
			args->subject_token, &old_parent.inode, &create_child,
			false);
		if (!ret)
			ret = pkm_kacs_kunit_namespace_maybe_build_created_sd(
				args, &old_parent, false, created_sd_out,
				created_sd_len_out);
		break;
	case PKM_KACS_KUNIT_NAMESPACE_MKDIR:
		if (!old_parent_ready) {
			ret = -EINVAL;
			break;
		}
		ret = (int)pkm_kacs_authorize_namespace_create_for_subject(
			args->subject_token, &old_parent.inode, &create_child,
			true);
		if (!ret)
			ret = pkm_kacs_kunit_namespace_maybe_build_created_sd(
				args, &old_parent, true, created_sd_out,
				created_sd_len_out);
		break;
	case PKM_KACS_KUNIT_NAMESPACE_MKNOD:
		if (!old_parent_ready) {
			ret = -EINVAL;
			break;
		}
		if (!pkm_kacs_inode_on_unmanaged_mount(&old_parent.inode) &&
		    !pkm_kacs_special_node_mode_supported(mknod_mode)) {
			ret = -EOPNOTSUPP;
			break;
		}
		ret = (int)pkm_kacs_authorize_namespace_create_for_subject(
			args->subject_token, &old_parent.inode, &create_child,
			false);
		if (!ret)
			ret = pkm_kacs_kunit_namespace_maybe_build_created_sd(
				args, &old_parent, false, created_sd_out,
				created_sd_len_out);
		break;
	case PKM_KACS_KUNIT_NAMESPACE_SYMLINK:
		if (!old_parent_ready) {
			ret = -EINVAL;
			break;
		}
		ret = (int)pkm_kacs_authorize_namespace_symlink_for_subject(
			args->subject_token, &old_parent.inode, &create_child);
		if (!ret)
			ret = pkm_kacs_kunit_namespace_maybe_build_created_sd(
				args, &old_parent, false, created_sd_out,
				created_sd_len_out);
		break;
	case PKM_KACS_KUNIT_NAMESPACE_LINK:
		if (!source_ready || !new_parent_ready) {
			ret = -EINVAL;
			break;
		}
		ret = (int)pkm_kacs_authorize_namespace_link_for_subject(
			args->subject_token, &source.dentry, &new_parent.inode,
			&negative);
		break;
	case PKM_KACS_KUNIT_NAMESPACE_UNLINK:
	case PKM_KACS_KUNIT_NAMESPACE_RMDIR:
		if (!source_ready || !old_parent_ready) {
			ret = -EINVAL;
			break;
		}
		ret = (int)pkm_kacs_authorize_namespace_delete_for_subject(
			args->subject_token, &old_parent.inode,
			&source.dentry);
		break;
	case PKM_KACS_KUNIT_NAMESPACE_RENAME:
		if (!source_ready || !old_parent_ready || !new_parent_ready) {
			ret = -EINVAL;
			break;
		}
		new_dentry = target_ready ? &target.dentry : &negative;
		ret = (int)pkm_kacs_authorize_namespace_rename_for_subject(
			args->subject_token, &old_parent.inode, &source.dentry,
			&new_parent.inode, new_dentry);
		break;
	case PKM_KACS_KUNIT_NAMESPACE_READLINK:
		if (!source_ready) {
			ret = -EINVAL;
			break;
		}
		ret = (int)pkm_kacs_authorize_inode_namespace_access_for_subject(
			args->subject_token, &source.inode, &source.dentry,
			PKM_KACS_FILE_READ_DATA);
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	if (target_ready)
		pkm_kacs_kunit_cleanup_file_mount_state(&target);
	if (source_ready)
		pkm_kacs_kunit_cleanup_file_mount_state(&source);
	if (new_parent_ready)
		pkm_kacs_kunit_cleanup_file_mount_state(&new_parent);
	if (old_parent_ready)
		pkm_kacs_kunit_cleanup_file_mount_state(&old_parent);
	return ret;
}

int pkm_kacs_kunit_check_namespace_rename_flags(
	const struct pkm_kacs_kunit_namespace_args *args, unsigned int flags)
{
	struct pkm_kacs_kunit_file_mount_state old_parent = {};
	struct pkm_kacs_kunit_file_mount_state new_parent = {};
	u32 policy;
	u64 magic;
	bool old_ready = false;
	bool new_ready = false;
	int ret;

	if (!args)
		return -EINVAL;

	magic = args->mount_magic ? args->mount_magic : TMPFS_MAGIC;
	policy = args->mount_policy_override ?
			 args->mount_policy_override :
			 PKM_KACS_MOUNT_POLICY_DENY_MISSING;

	ret = pkm_kacs_kunit_init_namespace_state(
		&old_parent, args->old_parent_sd_ptr,
		args->old_parent_sd_len, args->old_parent_sd_state, magic,
		policy, S_IFDIR);
	if (ret)
		goto out;
	old_ready = true;
	ret = pkm_kacs_kunit_init_namespace_state(
		&new_parent, args->new_parent_sd_ptr,
		args->new_parent_sd_len, args->new_parent_sd_state, magic,
		policy, S_IFDIR);
	if (ret)
		goto out;
	new_ready = true;

	ret = pkm_kacs_inode_rename_flags(&old_parent.inode, NULL,
					  &new_parent.inode, NULL, flags);
out:
	if (new_ready)
		pkm_kacs_kunit_cleanup_file_mount_state(&new_parent);
	if (old_ready)
		pkm_kacs_kunit_cleanup_file_mount_state(&old_parent);
	return ret;
}

int pkm_kacs_kunit_check_file_ioctl_snapshot(u32 managed, u32 granted_access,
					     umode_t mode, unsigned int cmd,
					     bool compat)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, mode, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;

	ret = pkm_kacs_check_file_ioctl_snapshot(&state.file, cmd, 0, compat);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_ioctl_null(void)
{
	return pkm_kacs_check_file_ioctl_snapshot(NULL, FS_IOC_GETFLAGS, 0,
						  false);
}

int pkm_kacs_kunit_check_file_lock_snapshot(u32 managed, u32 granted_access,
					    unsigned int cmd)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;

	ret = pkm_kacs_check_file_lock_snapshot(&state.file, cmd);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_fcntl_snapshot(u32 managed, u32 granted_access,
					     int file_flags,
					     unsigned int cmd,
					     unsigned long arg)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;
	state.file.f_flags = file_flags;

	ret = pkm_kacs_check_file_fcntl_snapshot(&state.file, cmd, arg);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_fcntl_null(void)
{
	return pkm_kacs_check_file_fcntl_snapshot(NULL, F_SETFL, 0);
}

int pkm_kacs_kunit_check_file_truncate_snapshot(u32 managed,
						u32 granted_access)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;

	ret = pkm_kacs_check_file_truncate_snapshot(&state.file);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_truncate_null(void)
{
	return pkm_kacs_check_file_truncate_snapshot(NULL);
}

int pkm_kacs_kunit_check_file_fallocate_snapshot(u32 managed,
						 u32 granted_access,
						 int mode)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, PKM_KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;

	ret = pkm_kacs_check_file_fallocate_snapshot(&state.file, mode);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_fallocate_null(void)
{
	return pkm_kacs_check_file_fallocate_snapshot(NULL, 0);
}

int pkm_kacs_kunit_check_task_prctl_mitigations(
	u32 mitigation_bits, int option, unsigned long arg2,
	unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	return pkm_kacs_check_task_prctl_mitigations_core(
		mitigation_bits, option, arg2, arg3, arg4, arg5);
}

int pkm_kacs_kunit_check_pie_bprm(u32 mitigation_bits, const u8 *buf,
				  size_t len)
{
	return pkm_kacs_check_pie_bprm_core(mitigation_bits, buf, len);
}

u64 pkm_kacs_kunit_allow_cap_mask(void)
{
	return pkm_kacs_allow_cap_mask_u64();
}

long pkm_kacs_kunit_check_capability_for_subject(const void *subject_token,
						 int cap)
{
	return pkm_kacs_check_capability_for_token(subject_token, cap);
}

long pkm_kacs_kunit_check_capset_for_subject(const void *subject_token,
					     u64 effective_mask,
					     u64 inheritable_mask,
					     u64 permitted_mask)
{
	struct cred new = {};
	kernel_cap_t effective;
	kernel_cap_t inheritable;
	kernel_cap_t permitted;

	effective = pkm_kacs_u64_to_kernel_cap(effective_mask);
	inheritable = pkm_kacs_u64_to_kernel_cap(inheritable_mask);
	permitted = pkm_kacs_u64_to_kernel_cap(permitted_mask);

	return pkm_kacs_capset_core(subject_token, &new, &effective,
				    &inheritable, &permitted);
}

long pkm_kacs_kunit_check_prctl_capability_guard_for_subject(
	const void *subject_token, u64 ambient_mask, int option,
	unsigned long arg2, unsigned long arg3, unsigned long arg4,
	unsigned long arg5)
{
	return pkm_kacs_prctl_capability_guard_core(
		subject_token, ambient_mask, option, arg2, arg3, arg4,
		arg5);
}

int pkm_kacs_kunit_reproject_exec_caps(
	u64 effective_mask, u64 inheritable_mask, u64 permitted_mask,
	u64 ambient_mask, u64 *effective_out, u64 *inheritable_out,
	u64 *permitted_out, u64 *ambient_out)
{
	struct linux_binprm bprm = {};
	struct cred *new;
	int ret;

	if (!effective_out || !inheritable_out || !permitted_out ||
	    !ambient_out)
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	new->cap_effective = pkm_kacs_u64_to_kernel_cap(effective_mask);
	new->cap_inheritable = pkm_kacs_u64_to_kernel_cap(inheritable_mask);
	new->cap_permitted = pkm_kacs_u64_to_kernel_cap(permitted_mask);
	new->cap_ambient = pkm_kacs_u64_to_kernel_cap(ambient_mask);
	new->cap_bset = current_cred()->cap_bset;
	bprm.cred = new;

	if (pkm_kacs_bprm_creds_from_file_core(
		    pkm_kacs_current_effective_token_ptr(),
		    pkm_kacs_current_primary_token_ptr(), NULL, bprm.cred,
		    current_cred(), false)) {
		ret = -EACCES;
		goto out;
	}

	*effective_out = pkm_kacs_kernel_cap_to_u64(&new->cap_effective);
	*inheritable_out = pkm_kacs_kernel_cap_to_u64(&new->cap_inheritable);
	*permitted_out = pkm_kacs_kernel_cap_to_u64(&new->cap_permitted);
	*ambient_out = pkm_kacs_kernel_cap_to_u64(&new->cap_ambient);
	ret = 0;

out:
	abort_creds(new);
	return ret;
}

long pkm_kacs_kunit_check_exec_setid_compat_for_subject(
	const void *subject_token, u32 exec_mask,
	struct pkm_kacs_kunit_exec_setid_view *out)
{
	static const u32 old_uid = 1234U;
	static const u32 old_gid = 2234U;
	static const u32 old_fsuid = 3234U;
	static const u32 old_fsgid = 4234U;
	static const u32 exec_uid = 5000U;
	static const u32 exec_gid = 6000U;
	struct cred *old;
	struct cred *new;
	struct pkm_kacs_cred_security *old_sec;
	const struct cred *saved_old;
	const struct cred *saved_new;
	const void *token_ref = NULL;
	long ret;

	if (!out)
		return -EINVAL;
	if (exec_mask & ~0x3U)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	old = prepare_creds();
	if (!old)
		return -ENOMEM;

	old->uid = KUIDT_INIT(old_uid);
	old->euid = KUIDT_INIT(old_uid);
	old->suid = KUIDT_INIT(old_uid);
	old->fsuid = KUIDT_INIT(old_fsuid);
	old->gid = KGIDT_INIT(old_gid);
	old->egid = KGIDT_INIT(old_gid);
	old->sgid = KGIDT_INIT(old_gid);
	old->fsgid = KGIDT_INIT(old_fsgid);

	old_sec = pkm_kacs_cred(old);
	if (old_sec->token) {
		kacs_rust_token_drop(old_sec->token);
		old_sec->token = NULL;
	}
	if (subject_token) {
		token_ref = kacs_rust_token_clone(subject_token);
		if (!token_ref) {
			abort_creds(old);
			return -ENOMEM;
		}
		old_sec->token = token_ref;
	}
	pkm_kacs_stamp_projected_ids(old_sec);

	saved_old = override_creds(old);
	new = prepare_creds();
	if (!new) {
		revert_creds(saved_old);
		abort_creds(old);
		return -ENOMEM;
	}

	if (exec_mask & 0x1U) {
		new->euid = KUIDT_INIT(exec_uid);
		new->suid = KUIDT_INIT(exec_uid);
		new->fsuid = KUIDT_INIT(exec_uid);
	}
	if (exec_mask & 0x2U) {
		new->egid = KGIDT_INIT(exec_gid);
		new->sgid = KGIDT_INIT(exec_gid);
		new->fsgid = KGIDT_INIT(exec_gid);
	}

	ret = pkm_kacs_bprm_creds_from_file_core(
		subject_token, subject_token, NULL, new, old, false);
	if (!ret) {
		out->uid = __kuid_val(new->uid);
		out->euid = __kuid_val(new->euid);
		out->suid = __kuid_val(new->suid);
		out->fsuid = __kuid_val(new->fsuid);
		out->gid = __kgid_val(new->gid);
		out->egid = __kgid_val(new->egid);
		out->sgid = __kgid_val(new->sgid);
		out->fsgid = __kgid_val(new->fsgid);

		saved_new = override_creds(new);
		out->projected_fsuid = __kuid_val(pkm_kacs_current_fsuid_kuid());
		out->projected_fsgid = __kgid_val(pkm_kacs_current_fsgid_kgid());
		revert_creds(saved_new);
	}

	abort_creds(new);
	revert_creds(saved_old);
	abort_creds(old);
	return ret;
}

long pkm_kacs_kunit_check_exec_new_process_min(
	const struct pkm_kacs_kunit_exec_new_process_min_args *args,
	struct pkm_kacs_boot_snapshot *snapshot_out, u32 *changed_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_cred_security *old_sec;
	struct pkm_kacs_cred_security *new_sec;
	const struct cred *saved_old;
	const void *token_ref;
	struct cred *old;
	struct cred *new;
	u64 magic;
	long ret;

	if (!args || !snapshot_out || !changed_out)
		return -EINVAL;
	if (!args->primary_token)
		return -EACCES;

	memset(snapshot_out, 0, sizeof(*snapshot_out));
	*changed_out = 0;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_inode_sd_cache_free(cache);
		return -ENOMEM;
	}

	magic = args->mount_magic ? args->mount_magic : TMPFS_MAGIC;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic, cache, args->mount_policy_override, NULL, 0,
		S_IFREG, true);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		goto out_state;
	}

	old = prepare_creds();
	if (!old) {
		ret = -ENOMEM;
		goto out_mount;
	}

	old_sec = pkm_kacs_cred(old);
	if (old_sec->token) {
		kacs_rust_token_drop(old_sec->token);
		old_sec->token = NULL;
	}
	token_ref = kacs_rust_token_clone(args->primary_token);
	if (!token_ref) {
		abort_creds(old);
		ret = -ENOMEM;
		goto out_mount;
	}
	old_sec->token = token_ref;
	pkm_kacs_stamp_projected_ids(old_sec);

	saved_old = override_creds(old);
	new = prepare_creds();
	if (!new) {
		revert_creds(saved_old);
		abort_creds(old);
		ret = -ENOMEM;
		goto out_mount;
	}

	ret = pkm_kacs_bprm_creds_from_file_core(
		args->subject_token, args->primary_token, &state->file, new,
		old, true);
	if (!ret) {
		new_sec = pkm_kacs_cred(new);
		if (!new_sec->token) {
			ret = -EACCES;
		} else if (!kacs_rust_kunit_token_snapshot(new_sec->token,
							   snapshot_out)) {
			ret = -EACCES;
		} else {
			*changed_out = new_sec->token != args->primary_token;
		}
	}

	abort_creds(new);
	revert_creds(saved_old);
	abort_creds(old);

out_mount:
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_state:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_check_setuid_fixup_for_subject(const void *subject_token,
						   int flags)
{
	struct cred *new;
	const struct cred *old = current_cred();
	struct user_struct *new_user;
	long ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	new->uid = KUIDT_INIT(4242);
	new->euid = KUIDT_INIT(4243);
	new->suid = KUIDT_INIT(4244);
	new->fsuid = KUIDT_INIT(4245);
	new->cap_effective = CAP_EMPTY_SET;
	new->cap_inheritable = CAP_EMPTY_SET;
	new->cap_permitted = CAP_EMPTY_SET;
	new->cap_bset = CAP_EMPTY_SET;
	new->cap_ambient = CAP_EMPTY_SET;

	new_user = alloc_uid(KUIDT_INIT(65534));
	if (!new_user) {
		abort_creds(new);
		return -ENOMEM;
	}
	free_uid(new->user);
	new->user = new_user;

	ret = pkm_kacs_task_fix_setuid_core(subject_token, new, old, flags);
	if (!ret) {
		if (!uid_eq(new->uid, old->uid) || !uid_eq(new->euid, old->euid) ||
		    !uid_eq(new->suid, old->suid) ||
		    !uid_eq(new->fsuid, old->fsuid) ||
		    new->user != old->user ||
		    memcmp(&new->cap_effective, &old->cap_effective,
			   sizeof(new->cap_effective)) != 0 ||
		    memcmp(&new->cap_inheritable, &old->cap_inheritable,
			   sizeof(new->cap_inheritable)) != 0 ||
		    memcmp(&new->cap_permitted, &old->cap_permitted,
			   sizeof(new->cap_permitted)) != 0 ||
		    memcmp(&new->cap_bset, &old->cap_bset,
			   sizeof(new->cap_bset)) != 0 ||
		    memcmp(&new->cap_ambient, &old->cap_ambient,
			   sizeof(new->cap_ambient)) != 0)
			ret = -EBADE;
	}

	abort_creds(new);
	return ret;
}

long pkm_kacs_kunit_check_setgid_fixup_for_subject(const void *subject_token,
						   int flags)
{
	struct cred *new;
	const struct cred *old = current_cred();
	long ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	new->gid = KGIDT_INIT(4342);
	new->egid = KGIDT_INIT(4343);
	new->sgid = KGIDT_INIT(4344);
	new->fsgid = KGIDT_INIT(4345);
	new->cap_effective = CAP_EMPTY_SET;
	new->cap_inheritable = CAP_EMPTY_SET;
	new->cap_permitted = CAP_EMPTY_SET;
	new->cap_bset = CAP_EMPTY_SET;
	new->cap_ambient = CAP_EMPTY_SET;

	ret = pkm_kacs_task_fix_setgid_core(subject_token, new, old, flags);
	if (!ret) {
		if (!gid_eq(new->gid, old->gid) ||
		    !gid_eq(new->egid, old->egid) ||
		    !gid_eq(new->sgid, old->sgid) ||
		    !gid_eq(new->fsgid, old->fsgid) ||
		    memcmp(&new->cap_effective, &old->cap_effective,
			   sizeof(new->cap_effective)) != 0 ||
		    memcmp(&new->cap_inheritable, &old->cap_inheritable,
			   sizeof(new->cap_inheritable)) != 0 ||
		    memcmp(&new->cap_permitted, &old->cap_permitted,
			   sizeof(new->cap_permitted)) != 0 ||
		    memcmp(&new->cap_bset, &old->cap_bset,
			   sizeof(new->cap_bset)) != 0 ||
		    memcmp(&new->cap_ambient, &old->cap_ambient,
			   sizeof(new->cap_ambient)) != 0)
			ret = -EBADE;
	}

	abort_creds(new);
	return ret;
}

long pkm_kacs_kunit_check_setgroups_fixup_for_subject(const void *subject_token)
{
	struct cred *new;
	const struct cred *old = current_cred();
	struct group_info *groups;
	long ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	groups = groups_alloc(1);
	if (!groups) {
		abort_creds(new);
		return -ENOMEM;
	}
	groups->gid[0] = KGIDT_INIT(65534);
	set_groups(new, groups);
	put_group_info(groups);
	new->cap_effective = CAP_EMPTY_SET;
	new->cap_inheritable = CAP_EMPTY_SET;
	new->cap_permitted = CAP_EMPTY_SET;
	new->cap_bset = CAP_EMPTY_SET;
	new->cap_ambient = CAP_EMPTY_SET;

	ret = pkm_kacs_task_fix_setgroups_core(subject_token, new, old);
	if (!ret) {
		if (new->group_info != old->group_info ||
		    memcmp(&new->cap_effective, &old->cap_effective,
			   sizeof(new->cap_effective)) != 0 ||
		    memcmp(&new->cap_inheritable, &old->cap_inheritable,
			   sizeof(new->cap_inheritable)) != 0 ||
		    memcmp(&new->cap_permitted, &old->cap_permitted,
			   sizeof(new->cap_permitted)) != 0 ||
		    memcmp(&new->cap_bset, &old->cap_bset,
			   sizeof(new->cap_bset)) != 0 ||
		    memcmp(&new->cap_ambient, &old->cap_ambient,
			   sizeof(new->cap_ambient)) != 0)
			ret = -EBADE;
	}

	abort_creds(new);
	return ret;
}

int pkm_kacs_kunit_projected_fsids_for_subject(const void *subject_token,
					       u32 raw_fsuid, u32 raw_fsgid,
					       u32 *fsuid_out,
					       u32 *fsgid_out)
{
	struct cred *new;
	struct pkm_kacs_cred_security *sec;
	const struct cred *saved;
	const void *token_ref = NULL;

	if (!fsuid_out || !fsgid_out)
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	new->fsuid = KUIDT_INIT(raw_fsuid);
	new->fsgid = KGIDT_INIT(raw_fsgid);
	sec = pkm_kacs_cred(new);
	if (sec->token) {
		kacs_rust_token_drop(sec->token);
		sec->token = NULL;
	}
	if (subject_token) {
		token_ref = kacs_rust_token_clone(subject_token);
		if (!token_ref) {
			abort_creds(new);
			return -ENOMEM;
		}
		sec->token = token_ref;
	}
	pkm_kacs_stamp_projected_ids(sec);

	saved = override_creds(new);
	*fsuid_out = __kuid_val(pkm_kacs_current_fsuid_kuid());
	*fsgid_out = __kgid_val(pkm_kacs_current_fsgid_kgid());
	revert_creds(saved);
	abort_creds(new);
	return 0;
}
#endif

int pkm_kacs_resolve_ctx_from_token(const void *token,
				    struct pkm_kacs_resolved_ctx *out)
{
	u32 pip_type;
	u32 pip_trust;
	int ret;

	if (!out)
		return -EINVAL;
	if (!token)
		return -EACCES;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	out->kind = PKM_KACS_RESOLVED_CTX_TOKEN;
	out->_reserved = 0;
	out->token = token;
	out->caap_cache = NULL;
	out->default_pip_type = pip_type;
	out->default_pip_trust = pip_trust;
	return 0;
}

int pkm_kacs_resolve_current_effective_ctx(struct pkm_kacs_resolved_ctx *out)
{
	return pkm_kacs_resolve_ctx_from_token(
		pkm_kacs_current_effective_token_ptr(), out);
}

int pkm_kacs_resolve_current_primary_ctx(struct pkm_kacs_resolved_ctx *out)
{
	return pkm_kacs_resolve_ctx_from_token(
		pkm_kacs_current_primary_token_ptr(), out);
}

SYSCALL_DEFINE2(kacs_create_token, const void __user *, spec, size_t, spec_len)
{
	const void *subject_token;
	u8 *spec_bytes;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;
	if (!spec)
		return -EINVAL;

	spec_bytes = memdup_user(spec, spec_len);
	if (IS_ERR(spec_bytes))
		return PTR_ERR(spec_bytes);

	ret = pkm_kacs_create_token_core(subject_token, spec_bytes, spec_len);
	kfree(spec_bytes);
	return ret;
}

SYSCALL_DEFINE2(kacs_create_session, const void __user *, spec, size_t, spec_len)
{
	const void *subject_token;
	u8 *spec_bytes;
	u64 session_id = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;
	if (!spec)
		return -EINVAL;

	spec_bytes = memdup_user(spec, spec_len);
	if (IS_ERR(spec_bytes))
		return PTR_ERR(spec_bytes);

	ret = pkm_kacs_create_session_core(subject_token, spec_bytes, spec_len,
					   &session_id);
	kfree(spec_bytes);
	if (ret)
		return ret;

	return (long)session_id;
}

SYSCALL_DEFINE2(kacs_set_psb, int, pidfd, u32, mitigations)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	struct task_struct *task = NULL;
	struct pid *pid;
	unsigned int pidfd_flags = 0;
	bool self_target;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	caller_state = pkm_kacs_current_process_state();
	if (!subject_token || !caller_state)
		return -EACCES;

	if (pidfd == -1) {
		target_state = caller_state;
		self_target = true;
	} else {
		pid = pidfd_get_pid(pidfd, &pidfd_flags);
		if (IS_ERR(pid))
			return PTR_ERR(pid);
		(void)pidfd_flags;

		task = get_pid_task(pid, PIDTYPE_PID);
		put_pid(pid);
		if (!task)
			return -ESRCH;
		if (!task->security) {
			put_task_struct(task);
			return -EACCES;
		}

		target_state = pkm_kacs_task(task)->process_state;
		self_target = target_state == caller_state;
	}

	ret = pkm_kacs_apply_psb_mitigations_core(
		subject_token, caller_state, target_state, self_target,
		mitigations, pkm_kacs_ibt_supported(),
		pkm_kacs_shstk_supported(), NULL);
	if (task)
		put_task_struct(task);

	return ret;
}

SYSCALL_DEFINE2(kacs_open_process_token, int, pidfd, u32, access_mask)
{
	struct pkm_kacs_process_state *caller_state;
	const void *subject_token;
	struct task_struct *task;
	struct pid *pid;
	unsigned int pidfd_flags = 0;
	long ret;

	ret = pkm_kacs_validate_token_open_access_mask(access_mask);
	if (ret)
		return ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	caller_state = pkm_kacs_current_process_state();
	if (!subject_token || !caller_state)
		return -EACCES;

	pid = pidfd_get_pid(pidfd, &pidfd_flags);
	if (IS_ERR(pid))
		return PTR_ERR(pid);
	(void)pidfd_flags;

	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!task)
		return -ESRCH;

	ret = pkm_kacs_open_process_token_task(subject_token, caller_state, task,
					       access_mask);
	put_task_struct(task);
	return ret;
}

SYSCALL_DEFINE3(kacs_open_thread_token, int, pidfd, int, tid, u32, access_mask)
{
	struct pkm_kacs_process_state *caller_state;
	const void *subject_token;
	struct task_struct *process_task;
	struct task_struct *thread_task;
	struct pid *pid;
	struct pid *thread_pid;
	unsigned int pidfd_flags = 0;
	long ret;

	ret = pkm_kacs_validate_token_open_access_mask(access_mask);
	if (ret)
		return ret;
	if (tid <= 0)
		return -EINVAL;

	subject_token = pkm_kacs_current_effective_token_ptr();
	caller_state = pkm_kacs_current_process_state();
	if (!subject_token || !caller_state)
		return -EACCES;

	pid = pidfd_get_pid(pidfd, &pidfd_flags);
	if (IS_ERR(pid))
		return PTR_ERR(pid);
	(void)pidfd_flags;

	process_task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!process_task)
		return -ESRCH;

	thread_pid = find_get_pid(tid);
	if (!thread_pid) {
		put_task_struct(process_task);
		return -ESRCH;
	}

	thread_task = get_pid_task(thread_pid, PIDTYPE_PID);
	put_pid(thread_pid);
	if (!thread_task) {
		put_task_struct(process_task);
		return -ESRCH;
	}

	if (!same_thread_group(process_task, thread_task)) {
		put_task_struct(thread_task);
		put_task_struct(process_task);
		return -ESRCH;
	}

	ret = pkm_kacs_open_thread_token_task(subject_token, caller_state,
					      thread_task, access_mask);
	put_task_struct(thread_task);
	put_task_struct(process_task);
	return ret;
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

	if (prepared.create_disposition == KACS_FILE_CREATE)
		goto do_create;

	ret = pkm_kacs_resolve_native_open_path(dirfd, path, &prepared,
						 how.flags, &resolved_path);
	if (!ret) {
		if ((prepared.create_disposition == KACS_FILE_OPEN_IF ||
		     prepared.create_disposition == KACS_FILE_OVERWRITE_IF) &&
		    (how.sd_ptr != 0 || how.sd_len != 0)) {
			path_put(&resolved_path);
			return -EINVAL;
		}
		switch (prepared.create_disposition) {
		case KACS_FILE_OVERWRITE:
		case KACS_FILE_OVERWRITE_IF:
			ret = pkm_kacs_do_native_overwrite_open(
				&resolved_path, &prepared, &file, &status);
			break;
		case KACS_FILE_SUPERSEDE:
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
	    (prepared.create_disposition != KACS_FILE_OPEN_IF &&
	     prepared.create_disposition != KACS_FILE_OVERWRITE_IF &&
	     prepared.create_disposition != KACS_FILE_SUPERSEDE))
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

SYSCALL_DEFINE6(kacs_get_sd, int, dirfd, const char __user *, path,
		u32, security_info, void __user *, buf, u32, buf_len,
		u32, flags)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	const void *target_token = NULL;
	struct file *file = NULL;
	struct path resolved_path = {};
	struct task_struct *task = NULL;
	const u8 *result_sd = NULL;
	size_t result_len = 0;
	bool self_target;
	bool resolved_path_valid = false;
	long ret;

	ret = pkm_kacs_resolve_tokenfd_target(dirfd, path, flags, &subject_token,
					      &target_token);
	if (!ret) {
		ret = pkm_kacs_query_token_sd_core(subject_token, target_token,
						   security_info, &result_sd,
						   &result_len);
		goto out;
	}
	if (ret != -EOPNOTSUPP)
		return ret;

	ret = pkm_kacs_resolve_file_target(dirfd, path, flags, &subject_token,
					   &file);
	if (!ret) {
		ret = pkm_kacs_query_file_sd_core(subject_token, file,
						  security_info, &result_sd,
						  &result_len);
		fput(file);
		file = NULL;
		goto out;
	}
	if (ret != -EOPNOTSUPP)
		return ret;

	ret = pkm_kacs_resolve_pidfd_process_target(
		dirfd, path, flags, &subject_token, &caller_state, &task,
		&target_state, &self_target);
	if (!ret) {
		ret = pkm_kacs_query_process_sd_core(subject_token, caller_state,
						     target_state,
						     self_target,
						     security_info,
						     &result_sd,
						     &result_len);
		put_task_struct(task);
		task = NULL;
		if (ret)
			goto out;
	} else {
		if (ret != -EOPNOTSUPP)
			return ret;

		ret = pkm_kacs_resolve_path_file_target(dirfd, path, flags,
							&subject_token,
							&resolved_path);
		if (ret)
			return ret;
		resolved_path_valid = true;
		ret = pkm_kacs_query_path_file_sd_core(subject_token,
						       &resolved_path,
						       security_info,
						       &result_sd,
						       &result_len);
		if (ret)
			goto out;
	}

	if (buf_len != 0 && result_len <= buf_len) {
		if (!buf || copy_to_user(buf, result_sd, result_len)) {
			ret = -EFAULT;
			goto out;
		}
	}

	ret = (long)result_len;

out:
	if (result_sd)
		pkm_kacs_free((void *)result_sd);
	if (target_token)
		kacs_rust_token_drop(target_token);
	if (file)
		fput(file);
	if (resolved_path_valid)
		path_put(&resolved_path);
	return ret;
}

SYSCALL_DEFINE6(kacs_set_sd, int, dirfd, const char __user *, path,
		u32, security_info, const void __user *, sd_buf, u32, sd_len,
		u32, flags)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	const void *target_token = NULL;
	struct file *file = NULL;
	struct path resolved_path = {};
	struct task_struct *task = NULL;
	u8 *input_sd = NULL;
	bool self_target;
	bool resolved_path_valid = false;
	long ret;

	if (!sd_buf || sd_len == 0 || sd_len > PKM_KACS_MAX_SD_BYTES)
		return -EINVAL;

	ret = pkm_kacs_resolve_tokenfd_target(dirfd, path, flags, &subject_token,
					      &target_token);
	if (!ret) {
		input_sd = memdup_user(sd_buf, sd_len);
		if (IS_ERR(input_sd)) {
			ret = PTR_ERR(input_sd);
			input_sd = NULL;
			goto out;
		}
		ret = pkm_kacs_set_token_sd_core(subject_token, target_token,
						 security_info, input_sd,
						 sd_len);
		goto out;
	}
	if (ret != -EOPNOTSUPP)
		goto out;

	ret = pkm_kacs_resolve_file_target(dirfd, path, flags, &subject_token,
					   &file);
	if (!ret) {
		input_sd = memdup_user(sd_buf, sd_len);
		if (IS_ERR(input_sd)) {
			ret = PTR_ERR(input_sd);
			input_sd = NULL;
			goto out;
		}

		ret = pkm_kacs_set_file_sd_core(subject_token, file,
						security_info, input_sd,
						sd_len);
		goto out;
	}
	if (ret != -EOPNOTSUPP)
		goto out;

	ret = pkm_kacs_resolve_pidfd_process_target(
		dirfd, path, flags, &subject_token, &caller_state, &task,
		&target_state, &self_target);
	if (!ret) {
		input_sd = memdup_user(sd_buf, sd_len);
		if (IS_ERR(input_sd)) {
			ret = PTR_ERR(input_sd);
			input_sd = NULL;
			goto out;
		}

		ret = pkm_kacs_set_process_sd_core(subject_token, caller_state,
						   target_state, self_target,
						   security_info, input_sd,
						   sd_len);
	} else {
		if (ret != -EOPNOTSUPP)
			goto out;

		ret = pkm_kacs_resolve_path_file_target(dirfd, path, flags,
							&subject_token,
							&resolved_path);
		if (ret)
			goto out;
		resolved_path_valid = true;

		input_sd = memdup_user(sd_buf, sd_len);
		if (IS_ERR(input_sd)) {
			ret = PTR_ERR(input_sd);
			input_sd = NULL;
			goto out;
		}

		ret = pkm_kacs_set_path_file_sd_core(subject_token,
						     &resolved_path,
						     security_info,
						     input_sd, sd_len);
	}

out:
	kfree(input_sd);
	if (target_token)
		kacs_rust_token_drop(target_token);
	if (file)
		fput(file);
	if (task)
		put_task_struct(task);
	if (resolved_path_valid)
		path_put(&resolved_path);
	return ret;
}

SYSCALL_DEFINE2(kacs_set_impersonation_level, int, sock_fd, u32, level)
{
	struct pkm_kacs_socket_security *sec;
	struct socket *sock;
	long ret;

	ret = pkm_kacs_lookup_peer_socket(sock_fd, &sock, &sec);
	if (ret)
		return ret;

	ret = pkm_kacs_set_socket_impersonation_level_core(sock, sec, level);
	sockfd_put(sock);
	return ret;
}

SYSCALL_DEFINE1(kacs_open_peer_token, int, sock_fd)
{
	struct pkm_kacs_socket_security *sec;
	struct socket *sock;
	long ret;

	ret = pkm_kacs_lookup_peer_socket(sock_fd, &sock, &sec);
	if (ret)
		return ret;
	if (sock->state != SS_CONNECTED) {
		sockfd_put(sock);
		return -EACCES;
	}

	ret = pkm_kacs_open_peer_token_core(sec);
	sockfd_put(sock);
	return ret;
}

SYSCALL_DEFINE1(kacs_impersonate_peer, int, sock_fd)
{
	struct pkm_kacs_socket_security *sec;
	struct socket *sock;
	long ret;

	ret = pkm_kacs_lookup_peer_socket(sock_fd, &sock, &sec);
	if (ret)
		return ret;
	if (sock->state != SS_CONNECTED) {
		sockfd_put(sock);
		return -EACCES;
	}

	ret = pkm_kacs_impersonate_peer_core(sec);
	sockfd_put(sock);
	return ret;
}

SYSCALL_DEFINE0(kacs_revert)
{
	return pkm_kacs_revert_current_impersonation();
}

static int __init pkm_init(void)
{
	const void *system_token;
	struct pkm_kacs_cred_security *sec;
	struct pkm_kacs_task_security *task_sec;
	int ret;

	if (IS_ENABLED(CONFIG_SECURITY_SELINUX) ||
	    IS_ENABLED(CONFIG_SECURITY_APPARMOR) ||
	    IS_ENABLED(CONFIG_SECURITY_SMACK) ||
	    IS_ENABLED(CONFIG_SECURITY_TOMOYO) ||
	    IS_ENABLED(CONFIG_BPF_LSM)) {
		pr_err("pkm: conflicting MAC or BPF LSM detected\n");
		return -EINVAL;
	}

	security_add_hooks(pkm_hooks, ARRAY_SIZE(pkm_hooks), &pkm_lsmid);

	ret = kacs_rust_init();
	if (ret) {
		pr_err("pkm: slow-track Rust init failed (%d)\n", ret);
		return ret;
	}

	ret = pkm_kacs_caap_cache_init();
	if (ret) {
		pr_err("pkm: CAAP cache init failed (%d)\n", ret);
		return ret;
	}

	ret = pkm_kmes_init();
	if (ret) {
		pr_err("pkm: KMES init failed (%d)\n", ret);
		return ret;
	}

	system_token = kacs_rust_create_boot_system_token();
	if (!system_token)
		return -ENOMEM;
	pkm_kacs_boot_system_token = system_token;

	task_sec = pkm_kacs_task(current);
	if (!task_sec->process_state) {
		task_sec->process_state = pkm_kacs_process_state_alloc(
			system_token, 0, 0, 0);
		if (!task_sec->process_state)
			return -ENOMEM;
	}
	pkm_kacs_set_cred_process_state((struct cred *)current->real_cred,
					task_sec->process_state);
	if (current->cred != current->real_cred)
		pkm_kacs_set_cred_process_state((struct cred *)current->cred,
						task_sec->process_state);

	sec = pkm_kacs_cred(current_cred());
	sec->token = system_token;
	pkm_kacs_stamp_projected_ids(sec);
	pkm_kacs_reset_allow_compat_caps((struct cred *)current_cred());

	if (current_cred() != current_real_cred()) {
		struct pkm_kacs_cred_security *real_sec =
			pkm_kacs_cred(current_real_cred());

		real_sec->token = kacs_rust_token_clone(system_token);
		pkm_kacs_stamp_projected_ids(real_sec);
		pkm_kacs_reset_allow_compat_caps(
			(struct cred *)current_real_cred());
	}

	pr_info("pkm: slow-track kernel scaffold initialized\n");
	return 0;
}

DEFINE_LSM(pkm) = {
	.id = &pkm_lsmid,
	.init = pkm_init,
	.blobs = &pkm_blob_sizes,
};

late_initcall(pkm_kacs_securityfs_init);
