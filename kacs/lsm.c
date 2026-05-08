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
#include <linux/file.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/lsm_hooks.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
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
#include <linux/xattr.h>

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
#define PKM_KACS_PRIVILEGE_SE_BIND_PRIVILEGED_PORT (1ULL << 63)
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
#define PKM_KACS_MAX_SD_BYTES 65536U

#define PKM_KACS_SD_SUPPORTED_INFO                                             \
	(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |             \
	 DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |              \
	 LABEL_SECURITY_INFORMATION)
#define PKM_KACS_SD_ALLOWED_AT_FLAGS (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)

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
};

struct pkm_kacs_inode_security {
	struct mutex lock;
	struct pkm_kacs_inode_sd_cache __rcu *sd_cache;
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

static struct lsm_blob_sizes pkm_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct pkm_kacs_cred_security),
	.lbs_task = sizeof(struct pkm_kacs_task_security),
	.lbs_sock = sizeof(struct pkm_kacs_socket_security),
	.lbs_inode = sizeof(struct pkm_kacs_inode_security),
	.lbs_superblock = sizeof(struct pkm_kacs_superblock_security),
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
static int pkm_kacs_sk_alloc_security(struct sock *sk, int family,
				      gfp_t priority);
static void pkm_kacs_sk_free_security(struct sock *sk);
static int pkm_kacs_socket_bind(struct socket *sock, struct sockaddr *address,
				int addrlen);
static int pkm_kacs_unix_stream_connect(struct sock *sock,
					struct sock *other,
					struct sock *newsk);
static int pkm_kacs_task_prctl(int option, unsigned long arg2,
			       unsigned long arg3, unsigned long arg4,
			       unsigned long arg5);
static int pkm_kacs_mmap_file(struct file *file, unsigned long reqprot,
			      unsigned long prot, unsigned long flags);
static int pkm_kacs_file_mprotect(struct vm_area_struct *vma,
				  unsigned long reqprot,
				  unsigned long prot);
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
static long pkm_kacs_query_file_sd_core(const void *subject_token,
					struct file *file, u32 security_info,
					const u8 **out_sd_ptr,
					size_t *out_sd_len);
static long pkm_kacs_set_file_sd_core(const void *subject_token,
				      struct file *file, u32 security_info,
				      const u8 *input_sd_ptr,
				      size_t input_sd_len);
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
		cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_MISSING,
						      NULL, 0);
		if (!cache)
			return -ENOMEM;
		*cache_out = cache;
		return 0;
	case PKM_KACS_MOUNT_POLICY_UNMANAGED:
	case PKM_KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL:
	case PKM_KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT:
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
	return 0;
}

static int pkm_kacs_sb_alloc_security(struct super_block *sb)
{
	struct pkm_kacs_superblock_security *sec;

	if (!sb || !sb->s_security)
		return 0;

	sec = pkm_kacs_sb(sb);
	sec->mount_policy = pkm_kacs_mount_policy_for_magic(sb->s_magic);
	return 0;
}

static void pkm_kacs_inode_free_security_rcu(void *inode_security)
{
	struct pkm_kacs_inode_security *sec = inode_security;
	struct pkm_kacs_inode_sd_cache *cache;

	if (!sec)
		return;

	cache = rcu_dereference_protected(sec->sd_cache, 1);
	RCU_INIT_POINTER(sec->sd_cache, NULL);
	pkm_kacs_inode_sd_cache_free(cache);
}

static long pkm_kacs_inode_read_sd_xattr_locked(
	struct file *file, struct pkm_kacs_inode_sd_cache **cache_out)
{
	struct dentry *dentry;
	struct inode *inode;
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

	name = pkm_kacs_inode_sd_xattr_name(inode);
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
	const u8 **new_sd_ptr, size_t *new_sd_len)
{
	u32 desired_access;
	u32 granted = 0;
	long ret;

	if (!subject_token || !cache || !input_sd_ptr || input_sd_len == 0 ||
	    !new_sd_ptr || !new_sd_len)
		return -EINVAL;

	*new_sd_ptr = NULL;
	*new_sd_len = 0;

	ret = pkm_kacs_set_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	if (cache->state == PKM_KACS_INODE_SD_VALID && cache->bytes &&
	    cache->len != 0) {
		ret = kacs_rust_check_file_sd_with_intent(
			subject_token, cache->bytes, cache->len,
			desired_access, KACS_RESTORE_INTENT, &granted);
		if (ret)
			return ret;

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
	int ret;

	if (!file || !sd_bytes || sd_len == 0)
		return -EINVAL;

	dentry = file_dentry(file);
	inode = file_inode(file);
	if (!dentry || !inode)
		return -EACCES;

	inode_lock(inode);
	ret = __vfs_setxattr_noperm(file_mnt_idmap(file), dentry,
				    pkm_kacs_inode_sd_xattr_name(inode),
				    sd_bytes, sd_len, 0);
	inode_unlock(inode);
	return ret;
}

static int pkm_kacs_inode_getxattr(struct dentry *dentry, const char *name)
{
	if (dentry && pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name))
		return -EACCES;

	return 0;
}

static int pkm_kacs_inode_setxattr(struct mnt_idmap *idmap,
				   struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags)
{
	if (dentry && pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name))
		return -EACCES;

	return 0;
}

static int pkm_kacs_inode_removexattr(struct mnt_idmap *idmap,
				      struct dentry *dentry,
				      const char *name)
{
	if (dentry && pkm_kacs_is_canonical_sd_xattr(d_inode(dentry), name))
		return -EACCES;

	return 0;
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
	LSM_HOOK_INIT(inode_alloc_security, pkm_kacs_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security_rcu, pkm_kacs_inode_free_security_rcu),
	LSM_HOOK_INIT(inode_getxattr, pkm_kacs_inode_getxattr),
	LSM_HOOK_INIT(inode_setxattr, pkm_kacs_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr, pkm_kacs_inode_removexattr),
	LSM_HOOK_INIT(task_alloc, pkm_kacs_task_alloc),
	LSM_HOOK_INIT(task_free, pkm_kacs_task_free),
	LSM_HOOK_INIT(sk_alloc_security, pkm_kacs_sk_alloc_security),
	LSM_HOOK_INIT(sk_free_security, pkm_kacs_sk_free_security),
	LSM_HOOK_INIT(socket_bind, pkm_kacs_socket_bind),
	LSM_HOOK_INIT(unix_stream_connect, pkm_kacs_unix_stream_connect),
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
	if (requested_mitigations & (KACS_MIT_TLP | KACS_MIT_LSV))
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

static long pkm_kacs_resolve_opath_file_target(
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
	if ((file->f_mode & FMODE_PATH) == 0) {
		fput(file);
		return -EOPNOTSUPP;
	}
	if (!file_dentry(file) || !file_inode(file)) {
		fput(file);
		return -EACCES;
	}

	*subject_token_out = subject_token;
	*file_out = file;
	return 0;
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
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct inode *inode;
	long ret;

	if (!subject_token || !file || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    PKM_KACS_MOUNT_POLICY_UNMANAGED)
		return -EOPNOTSUPP;

	sec = pkm_kacs_inode(inode);
	mutex_lock(&sec->lock);
	ret = pkm_kacs_inode_get_or_populate_cache_locked(file, sec, &cache);
	if (!ret)
		ret = pkm_kacs_query_file_sd_bytes_core(subject_token, cache,
							security_info,
							out_sd_ptr,
							out_sd_len);
	mutex_unlock(&sec->lock);
	return ret;
}

static long pkm_kacs_set_file_sd_core(const void *subject_token,
				      struct file *file, u32 security_info,
				      const u8 *input_sd_ptr,
				      size_t input_sd_len)
{
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct pkm_kacs_inode_sd_cache *new_cache = NULL;
	struct inode *inode;
	const u8 *new_sd_bytes = NULL;
	size_t new_sd_len = 0;
	bool used_restore_bypass = false;
	long ret;

	if (!subject_token || !file || !input_sd_ptr || input_sd_len == 0)
		return -EINVAL;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    PKM_KACS_MOUNT_POLICY_UNMANAGED)
		return -EOPNOTSUPP;

	sec = pkm_kacs_inode(inode);
	mutex_lock(&sec->lock);
	ret = pkm_kacs_inode_get_or_populate_cache_locked(file, sec, &cache);
	if (ret)
		goto out_unlock;

	ret = pkm_kacs_prepare_new_file_sd_core(subject_token, cache,
						security_info, input_sd_ptr,
						input_sd_len, &new_sd_bytes,
						&new_sd_len);
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
	if (new_sd_bytes)
		pkm_kacs_free((void *)new_sd_bytes);
out_unlock:
	mutex_unlock(&sec->lock);
	pkm_kacs_inode_sd_cache_free(new_cache);
	return ret;
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

	(void)file;
	(void)reqprot;
	(void)flags;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	return pkm_kacs_check_wxp_mmap_core(
		pkm_kacs_process_state_mitigation_bits(state), prot);
}

static int pkm_kacs_file_mprotect(struct vm_area_struct *vma,
				  unsigned long reqprot,
				  unsigned long prot)
{
	struct pkm_kacs_process_state *state;

	(void)reqprot;
	if (!vma)
		return -EACCES;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	return pkm_kacs_check_wxp_mprotect_core(
		pkm_kacs_process_state_mitigation_bits(state),
		vma->vm_flags, prot);
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

static long pkm_kacs_bprm_creds_from_file_core(const void *subject_token,
					       struct cred *new,
					       const struct cred *old)
{
	bool uid_changed;
	bool gid_changed;
	struct user_struct *old_user;

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

	return 0;
}

static int pkm_kacs_bprm_creds_from_file(struct linux_binprm *bprm,
					 const struct file *file)
{
	(void)file;
	if (!bprm || !bprm->cred)
		return -EACCES;

	return (int)pkm_kacs_bprm_creds_from_file_core(
		pkm_kacs_current_effective_token_ptr(), bprm->cred,
		current_cred());
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

long pkm_kacs_kunit_open_peer_token_for_socket(u32 connected,
					       const void *peer_token)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	long ret;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, SOCK_STREAM,
					 connected);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	if (peer_token)
		sec->peer_token = kacs_rust_token_clone(peer_token);
	if (connected)
		ret = pkm_kacs_open_peer_token_core(sec);
	else
		ret = -EACCES;
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
}

long pkm_kacs_kunit_impersonate_peer_for_socket(u32 connected,
						const void *peer_token)
{
	struct socket sock;
	struct sock sk;
	struct pkm_kacs_socket_security *sec;
	void *blob = NULL;
	long ret;

	ret = pkm_kacs_kunit_init_socket(&sock, &sk, &blob, SOCK_STREAM,
					 connected);
	if (ret)
		return ret;
	sec = pkm_kacs_sock(&sk);
	if (peer_token)
		sec->peer_token = kacs_rust_token_clone(peer_token);
	if (connected)
		ret = pkm_kacs_impersonate_peer_core(sec);
	else
		ret = -EACCES;
	pkm_kacs_kunit_cleanup_socket(&sk, blob);
	return ret;
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
						args->input_sd_len, &result_sd,
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

u32 pkm_kacs_kunit_classify_file_sd_bytes(const u8 *sd_ptr, size_t sd_len)
{
	if (!sd_ptr || sd_len == 0)
		return PKM_KACS_KUNIT_FILE_SD_MISSING;
	if (kacs_rust_validate_sd_bytes(sd_ptr, sd_len) != 0)
		return PKM_KACS_KUNIT_FILE_SD_CORRUPT;

	return PKM_KACS_KUNIT_FILE_SD_VALID;
}

struct pkm_kacs_kunit_file_mount_state {
	struct super_block sb;
	struct inode inode;
	struct dentry dentry;
	struct file file;
	void *sb_blob;
	void *inode_blob;
};

static int pkm_kacs_kunit_init_file_mount_state(
	struct pkm_kacs_kunit_file_mount_state *state, u64 magic,
	struct pkm_kacs_inode_sd_cache *cache)
{
	struct pkm_kacs_inode_security *sec;
	size_t sb_blob_len;
	size_t inode_blob_len;
	int ret;

	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));
	sb_blob_len = pkm_blob_sizes.lbs_superblock +
		sizeof(struct pkm_kacs_superblock_security);
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

	state->sb.s_magic = (unsigned long)magic;
	state->sb.s_security = state->sb_blob;
	ret = pkm_kacs_sb_alloc_security(&state->sb);
	if (ret)
		goto out_err;

	state->inode.i_sb = &state->sb;
	state->inode.i_security = state->inode_blob;
	ret = pkm_kacs_inode_alloc_security(&state->inode);
	if (ret)
		goto out_err;

	state->dentry.d_inode = &state->inode;
	state->file.f_inode = &state->inode;
	*(struct path *)&state->file.f_path = (struct path){
		.dentry = &state->dentry,
	};

	if (cache) {
		sec = pkm_kacs_inode(&state->inode);
		RCU_INIT_POINTER(sec->sd_cache, cache);
	}

	return 0;

out_err:
	if (state->inode.i_security)
		pkm_kacs_inode_free_security_rcu(pkm_kacs_inode(&state->inode));
	kfree(state->inode_blob);
	kfree(state->sb_blob);
	state->inode_blob = NULL;
	state->sb_blob = NULL;
	return ret;
}

static void pkm_kacs_kunit_cleanup_file_mount_state(
	struct pkm_kacs_kunit_file_mount_state *state)
{
	if (!state)
		return;

	if (state->inode.i_security)
		pkm_kacs_inode_free_security_rcu(pkm_kacs_inode(&state->inode));
	kfree(state->inode_blob);
	kfree(state->sb_blob);
	memset(state, 0, sizeof(*state));
}

u32 pkm_kacs_kunit_mount_policy_for_magic(u64 magic)
{
	struct pkm_kacs_kunit_file_mount_state state;
	u32 policy;

	if (pkm_kacs_kunit_init_file_mount_state(&state, magic, NULL) != 0)
		return 0;

	policy = pkm_kacs_superblock_mount_policy(&state.sb);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return policy;
}

long pkm_kacs_kunit_missing_file_sd_result_for_magic(u64 magic)
{
	struct pkm_kacs_kunit_file_mount_state state;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	long ret;

	ret = pkm_kacs_kunit_init_file_mount_state(&state, magic, NULL);
	if (ret)
		return ret;

	ret = pkm_kacs_missing_file_sd_policy_result(&state.sb, &cache);
	if (!ret && cache) {
		ret = cache->state;
		pkm_kacs_inode_sd_cache_free(cache);
	}

	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

long pkm_kacs_kunit_get_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_get_args *args, u64 magic,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	struct pkm_kacs_kunit_file_mount_state state;
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

	ret = pkm_kacs_kunit_init_file_mount_state(&state, magic, cache);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		return ret;
	}

	ret = pkm_kacs_query_file_sd_core(args->subject_token, &state.file,
					  args->security_info, out_sd_ptr,
					  out_sd_len);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

long pkm_kacs_kunit_set_file_sd_on_mount_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args, u64 magic)
{
	struct pkm_kacs_kunit_file_mount_state state;
	struct pkm_kacs_inode_sd_cache *cache;
	long ret;

	if (!args || !args->input_sd_ptr || args->input_sd_len == 0)
		return -EINVAL;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_file_mount_state(&state, magic, cache);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		return ret;
	}

	ret = pkm_kacs_set_file_sd_core(args->subject_token, &state.file,
					args->security_info,
					args->input_sd_ptr,
					args->input_sd_len);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

static int pkm_kacs_kunit_inode_sd_xattr_check(u32 op, const char *name,
					       u32 ntfs)
{
	struct file_system_type fs_type = {};
	struct super_block sb = {};
	struct inode inode = {};
	struct dentry dentry = {};

	fs_type.name = ntfs ? "ntfs3" : "tmpfs";
	sb.s_type = &fs_type;
	inode.i_sb = &sb;
	dentry.d_inode = &inode;

	switch (op) {
	case 1:
		return pkm_kacs_inode_getxattr(&dentry, name);
	case 2:
		return pkm_kacs_inode_setxattr(NULL, &dentry, name, NULL, 0, 0);
	case 3:
		return pkm_kacs_inode_removexattr(NULL, &dentry, name);
	default:
		return -EINVAL;
	}
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
	struct cred new = {};
	struct linux_binprm bprm = {};

	if (!effective_out || !inheritable_out || !permitted_out ||
	    !ambient_out)
		return -EINVAL;

	new.cap_effective = pkm_kacs_u64_to_kernel_cap(effective_mask);
	new.cap_inheritable = pkm_kacs_u64_to_kernel_cap(inheritable_mask);
	new.cap_permitted = pkm_kacs_u64_to_kernel_cap(permitted_mask);
	new.cap_ambient = pkm_kacs_u64_to_kernel_cap(ambient_mask);
	new.cap_bset = current_cred()->cap_bset;
	bprm.cred = &new;

	if (pkm_kacs_bprm_creds_from_file(&bprm, NULL))
		return -EACCES;

	*effective_out = pkm_kacs_kernel_cap_to_u64(&new.cap_effective);
	*inheritable_out = pkm_kacs_kernel_cap_to_u64(&new.cap_inheritable);
	*permitted_out = pkm_kacs_kernel_cap_to_u64(&new.cap_permitted);
	*ambient_out = pkm_kacs_kernel_cap_to_u64(&new.cap_ambient);
	return 0;
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

	ret = pkm_kacs_bprm_creds_from_file_core(subject_token, new, old);
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

SYSCALL_DEFINE6(kacs_get_sd, int, dirfd, const char __user *, path,
		u32, security_info, void __user *, buf, u32, buf_len,
		u32, flags)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	const void *target_token = NULL;
	struct file *file = NULL;
	struct task_struct *task = NULL;
	const u8 *result_sd = NULL;
	size_t result_len = 0;
	bool self_target;
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

	ret = pkm_kacs_resolve_opath_file_target(dirfd, path, flags,
						 &subject_token, &file);
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
	if (ret)
		return ret;

	ret = pkm_kacs_query_process_sd_core(subject_token, caller_state,
					     target_state, self_target,
					     security_info, &result_sd,
					     &result_len);
	put_task_struct(task);
	task = NULL;
	if (ret)
		goto out;

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
	struct task_struct *task = NULL;
	u8 *input_sd = NULL;
	bool self_target;
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

	ret = pkm_kacs_resolve_opath_file_target(dirfd, path, flags,
						 &subject_token, &file);
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
	if (ret)
		goto out;

	input_sd = memdup_user(sd_buf, sd_len);
	if (IS_ERR(input_sd)) {
		ret = PTR_ERR(input_sd);
		input_sd = NULL;
		goto out;
	}

	ret = pkm_kacs_set_process_sd_core(subject_token, caller_state,
					   target_state, self_target,
					   security_info, input_sd, sd_len);

out:
	kfree(input_sd);
	if (target_token)
		kacs_rust_token_drop(target_token);
	if (file)
		fput(file);
	if (task)
		put_task_struct(task);
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
