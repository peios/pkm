// SPDX-License-Identifier: GPL-2.0-only
/*
 * KACS — Kernel-based Access Control System
 *
 * LSM implementing the Windows NT security model (tokens, SDs, AccessCheck)
 * in the Linux kernel. This C shim handles LSM registration, hook tables,
 * blob plumbing, syscalls, and wrappers for inline functions Rust can't call.
 * All security logic lives in Rust (kacs_rust.rs + kacs-core).
 */

#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/pid.h>
#include <linux/pidfd.h>
#include <net/sock.h>

/* ── Rust FFI declarations ─────────────────────────────────────────────── */

extern int kacs_rust_init(void);
extern const void *kacs_token_create_system(void);
extern const void *kacs_token_clone(const void *ptr);
extern void kacs_token_drop(const void *ptr);
extern long long kacs_token_format(const void *ptr, char *buf, size_t len);
extern int kacs_token_query(const void *ptr, u32 class, void *buf, u32 buf_len);
extern int kacs_token_adjust_privs(const void *ptr, u64 enable_mask,
				   u64 disable_mask, u64 remove_mask);
extern const void *kacs_token_deep_clone(const void *ptr,
					 int new_type, int new_level);
extern int kacs_token_get_type(const void *ptr);
extern int kacs_token_get_impersonation_level(const void *ptr);
extern int kacs_token_check_privilege(const void *ptr, u64 priv_mask);
extern int kacs_token_get_integrity(const void *ptr);
extern int kacs_token_same_user(const void *a, const void *b);
extern void kacs_token_set_impersonation_level(const void *ptr, int level);
extern const void *kacs_create_default_proc_sd(const void *token_ptr);
extern void kacs_proc_sd_drop(const void *sd_ptr);
extern int kacs_check_proc_sd(const void *token_ptr, const void *sd_ptr,
			      u32 desired);
extern int kacs_session_link_tokens(u64 session_id,
				    const void *elevated, const void *filtered);
extern const void *kacs_session_get_linked_token(const void *token_ptr);
extern const void *kacs_token_restrict(const void *ptr,
				       u64 privs_to_delete,
				       const void *data, u32 data_len,
				       u32 num_deny_indices,
				       u32 num_restrict_sids);
extern long long kacs_create_session_impl(const void *data, size_t len);
extern void kacs_init_session_table(const void *system_token);
extern long long kacs_format_sessions(char *buf, size_t len);
extern const void *kacs_token_from_spec(const void *data, size_t len);
extern long long kacs_access_check_sd(const void *token_ptr,
				      const void *sd_data, size_t sd_len,
				      u32 desired, u32 generic_read,
				      u32 generic_write, u32 generic_execute,
				      u32 generic_all);

/* ── Constants ─────────────────────────────────────────────────────────── */

/* Per-handle access rights (§15.2) */
#define KACS_TOKEN_ASSIGN_PRIMARY  0x0001
#define KACS_TOKEN_DUPLICATE       0x0002
#define KACS_TOKEN_IMPERSONATE     0x0004
#define KACS_TOKEN_QUERY           0x0008
#define KACS_TOKEN_ADJUST_PRIVS    0x0020
#define KACS_TOKEN_ADJUST_GROUPS   0x0040
#define KACS_TOKEN_ADJUST_DEFAULT  0x0080
#define KACS_TOKEN_ALL_ACCESS      0x00EF

/* kacs_open_self_token flags */
#define KACS_REAL_TOKEN 0x01

/* ioctl definitions */
#define KACS_IOC_MAGIC 'K'
#define KACS_IOC_QUERY         _IOWR(KACS_IOC_MAGIC, 0, struct kacs_query_args)
#define KACS_IOC_ADJUST_PRIVS  _IOW(KACS_IOC_MAGIC, 1, struct kacs_adjust_privs_args)
#define KACS_IOC_DUPLICATE     _IOWR(KACS_IOC_MAGIC, 2, struct kacs_duplicate_args)
#define KACS_IOC_INSTALL       _IO(KACS_IOC_MAGIC, 3)
#define KACS_IOC_RESTRICT          _IOWR(KACS_IOC_MAGIC, 4, struct kacs_restrict_args)
#define KACS_IOC_LINK_TOKENS       _IOW(KACS_IOC_MAGIC, 5, struct kacs_link_tokens_args)
#define KACS_IOC_GET_LINKED_TOKEN  _IOWR(KACS_IOC_MAGIC, 6, struct kacs_get_linked_token_args)
#define KACS_IOC_IMPERSONATE       _IO(KACS_IOC_MAGIC, 7)

/* Token query classes (§15.2) */
#define TOKEN_CLASS_USER              1
#define TOKEN_CLASS_GROUPS            2
#define TOKEN_CLASS_PRIVILEGES        3
#define TOKEN_CLASS_TYPE              4
#define TOKEN_CLASS_INTEGRITY_LEVEL   5
#define TOKEN_CLASS_OWNER             6
#define TOKEN_CLASS_PRIMARY_GROUP     7
#define TOKEN_CLASS_SESSION_ID        8
#define TOKEN_CLASS_RESTRICTED_SIDS   9
#define TOKEN_CLASS_SOURCE            10
#define TOKEN_CLASS_STATISTICS        11
#define TOKEN_CLASS_ORIGIN            12
#define TOKEN_CLASS_ELEVATION_TYPE    13
#define TOKEN_CLASS_DEVICE_GROUPS     14
#define TOKEN_CLASS_APPCONTAINER_SID  15
#define TOKEN_CLASS_CAPABILITIES      16
#define TOKEN_CLASS_MANDATORY_POLICY  17
#define TOKEN_CLASS_LOGON_TYPE        18
#define TOKEN_CLASS_LOGON_SID         19

/* ioctl argument structs */
struct kacs_query_args {
	u32 token_class;	/* TOKEN_CLASS_* */
	u32 buf_len;		/* in: buffer size, out: required size */
	u64 buf_ptr;		/* userspace pointer to output buffer */
};

struct kacs_adjust_privs_args {
	u64 enable_mask;	/* privileges to enable */
	u64 disable_mask;	/* privileges to disable */
	u64 remove_mask;	/* privileges to permanently remove */
};

struct kacs_duplicate_args {
	u32 access_mask;	/* access rights for the new handle */
	u32 token_type;		/* 1=Primary, 2=Impersonation */
	u32 impersonation_level;/* 0-3 */
	s32 result_fd;		/* out: fd for the new token */
};

/* Privilege bitmasks (must match kacs-core privilege::bits) */
#define KACS_PRIV_CREATE_TOKEN         (1ULL << 2)
#define KACS_PRIV_ASSIGN_PRIMARY_TOKEN (1ULL << 3)
#define KACS_PRIV_TCB                  (1ULL << 7)
#define KACS_PRIV_IMPERSONATE          (1ULL << 29)

/* Impersonation levels */
#define KACS_LEVEL_ANONYMOUS       0
#define KACS_LEVEL_IDENTIFICATION  1
#define KACS_LEVEL_IMPERSONATION   2
#define KACS_LEVEL_DELEGATION      3

struct kacs_restrict_args {
	u64 privs_to_delete;	/* bitmask of privileges to permanently remove */
	u32 num_deny_indices;	/* count of group indices to flip to deny-only */
	u32 num_restrict_sids;	/* count of restricting SIDs to add */
	u32 data_len;		/* total length of variable data */
	u32 _pad;
	u64 data_ptr;		/* userspace: u32[] deny indices, then binary SIDs */
	s32 result_fd;		/* out: new token fd */
};

struct kacs_link_tokens_args {
	s32 elevated_fd;	/* fd to the elevated/full token */
	s32 filtered_fd;	/* fd to the filtered/limited token */
	u64 session_id;		/* logon session to link them on */
};

struct kacs_get_linked_token_args {
	s32 result_fd;		/* out: fd to the partner token */
};

/* ── Credential blob ───────────────────────────────────────────────────── */

struct kacs_cred_security {
	const void *token;	/* opaque pointer to Rust-managed token */
};

/* ── Socket blob ──────────────────────────────────────────────────────── */

struct kacs_sock_security {
	const void *peer_token;		/* server side: peer's token snapshot */
	u32 max_impersonation;		/* client side: max level (default=Impersonation) */
};

/* ── Task blob (Process Security Block) ───────────────────────────────── */

struct kacs_task_security {
	const void *proc_sd;		/* Rust-managed process SD (opaque) */
	u32 pip_type;			/* PIP_TYPE_NONE/PROTECTED/ISOLATED */
	u32 pip_trust;			/* trust level within pip_type */
};

/* PIP type constants (§13) */
#define PIP_TYPE_NONE        0
#define PIP_TYPE_PROTECTED   512
#define PIP_TYPE_ISOLATED    1024

static struct lsm_blob_sizes kacs_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct kacs_cred_security),
	.lbs_sock = sizeof(struct kacs_sock_security),
	.lbs_task = sizeof(struct kacs_task_security),
};

static inline struct kacs_cred_security *kacs_cred(const struct cred *cred)
{
	return cred->security + kacs_blob_sizes.lbs_cred;
}

static inline struct kacs_task_security *kacs_task(struct task_struct *task)
{
	return task->security + kacs_blob_sizes.lbs_task;
}

/*
 * PIP dominance check (§13.1). Binary: caller dominates target iff
 * caller.pip_type >= target.pip_type AND caller.pip_trust >= target.pip_trust.
 * If target has pip_type == NONE, dominance is trivially true.
 */
static inline bool pip_dominates(struct kacs_task_security *caller,
				 struct kacs_task_security *target)
{
	if (target->pip_type == PIP_TYPE_NONE)
		return true;
	return caller->pip_type >= target->pip_type
	    && caller->pip_trust >= target->pip_trust;
}

static inline struct kacs_sock_security *kacs_sock(const struct sock *sk)
{
	return sk->sk_security + kacs_blob_sizes.lbs_sock;
}

/* ── C helpers for Rust ────────────────────────────────────────────────── */

const struct cred *kacs_helper_current_cred(void)
{
	return current_cred();
}

const struct cred *kacs_helper_current_real_cred(void)
{
	return current_real_cred();
}

const void *kacs_helper_cred_token(const struct cred *cred)
{
	return kacs_cred(cred)->token;
}

/* ── Token fd infrastructure ───────────────────────────────────────────── */

struct kacs_token_file {
	const void *token;	/* Rust-managed token (refcounted) */
	u32 access_mask;	/* per-handle rights */
};

static int kacs_token_release(struct inode *inode, struct file *file)
{
	struct kacs_token_file *tf = file->private_data;

	kacs_token_drop(tf->token);
	kfree(tf);
	return 0;
}

static long kacs_token_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg);

static const struct file_operations kacs_token_fops = {
	.release = kacs_token_release,
	.unlocked_ioctl = kacs_token_ioctl,
};

/*
 * Wrap a token pointer in an anon_inode fd with the given access mask.
 * On failure, drops the token reference and returns negative errno.
 */
static int kacs_token_to_fd(const void *token, u32 access_mask)
{
	struct kacs_token_file *tf;
	int fd;

	tf = kmalloc(sizeof(*tf), GFP_KERNEL);
	if (!tf) {
		kacs_token_drop(token);
		return -ENOMEM;
	}
	tf->token = token;
	tf->access_mask = access_mask;

	fd = anon_inode_getfd("kacs-token", &kacs_token_fops, tf, O_CLOEXEC);
	if (fd < 0) {
		kacs_token_drop(token);
		kfree(tf);
	}
	return fd;
}

/* ── ioctl handler ─────────────────────────────────────────────────────── */

static long kacs_token_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct kacs_token_file *tf = file->private_data;

	switch (cmd) {
	case KACS_IOC_QUERY: {
		struct kacs_query_args qa;
		void *kbuf;
		int ret;

		if (!(tf->access_mask & KACS_TOKEN_QUERY))
			return -EACCES;

		if (copy_from_user(&qa, (void __user *)arg, sizeof(qa)))
			return -EFAULT;

		/* Size query: buf_ptr == 0 or buf_len == 0 */
		if (!qa.buf_ptr || !qa.buf_len) {
			ret = kacs_token_query(tf->token, qa.token_class,
					       NULL, 0);
			if (ret < 0)
				return ret;
			qa.buf_len = ret;
			if (copy_to_user((void __user *)arg, &qa, sizeof(qa)))
				return -EFAULT;
			return 0;
		}

		if (qa.buf_len > PAGE_SIZE)
			return -EINVAL;

		kbuf = kmalloc(qa.buf_len, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		ret = kacs_token_query(tf->token, qa.token_class,
				       kbuf, qa.buf_len);
		if (ret < 0) {
			kfree(kbuf);
			return ret;
		}

		/* Buffer too small — return required size */
		if ((u32)ret > qa.buf_len) {
			kfree(kbuf);
			qa.buf_len = ret;
			if (copy_to_user((void __user *)arg, &qa, sizeof(qa)))
				return -EFAULT;
			return 0;
		}

		if (copy_to_user((void __user *)qa.buf_ptr, kbuf, ret)) {
			kfree(kbuf);
			return -EFAULT;
		}

		kfree(kbuf);
		qa.buf_len = ret;
		if (copy_to_user((void __user *)arg, &qa, sizeof(qa)))
			return -EFAULT;
		return 0;
	}
	case KACS_IOC_ADJUST_PRIVS: {
		struct kacs_adjust_privs_args pa;

		if (!(tf->access_mask & KACS_TOKEN_ADJUST_PRIVS))
			return -EACCES;

		if (copy_from_user(&pa, (void __user *)arg, sizeof(pa)))
			return -EFAULT;

		return kacs_token_adjust_privs(tf->token, pa.enable_mask,
					       pa.disable_mask,
					       pa.remove_mask);
	}
	case KACS_IOC_INSTALL: {
		/*
		 * Install this token as the calling process's primary token.
		 * The token must be a Primary token. After install, all new
		 * operations by this process use the new identity.
		 *
		 * This is how authd assigns identity to services: fork,
		 * child calls INSTALL with the service token, then exec.
		 */
		struct kacs_cred_security *sec;
		struct cred *new_cred;

		if (!(tf->access_mask & KACS_TOKEN_ASSIGN_PRIMARY))
			return -EACCES;

		/* Requires SeAssignPrimaryTokenPrivilege on caller's real token. */
		if (!kacs_token_check_privilege(
				kacs_cred(current_real_cred())->token,
				KACS_PRIV_ASSIGN_PRIMARY_TOKEN))
			return -EPERM;

		/* Only Primary tokens can be installed. */
		if (kacs_token_get_type(tf->token) != 1)
			return -EINVAL;

		new_cred = prepare_creds();
		if (!new_cred)
			return -ENOMEM;

		sec = kacs_cred(new_cred);
		kacs_token_drop(sec->token);
		sec->token = kacs_token_clone(tf->token);
		commit_creds(new_cred);
		return 0;
	}
	case KACS_IOC_DUPLICATE: {
		struct kacs_duplicate_args da;
		const void *new_token;
		int fd;

		if (!(tf->access_mask & KACS_TOKEN_DUPLICATE))
			return -EACCES;

		if (copy_from_user(&da, (void __user *)arg, sizeof(da)))
			return -EFAULT;

		if (da.token_type != 1 && da.token_type != 2)
			return -EINVAL;
		if (da.impersonation_level > 3)
			return -EINVAL;
		if (!da.access_mask)
			return -EINVAL;

		/* Impersonation → Primary requires SeTcbPrivilege (§15.2). */
		if (kacs_token_get_type(tf->token) == 2 && da.token_type == 1) {
			if (!kacs_token_check_privilege(
					kacs_cred(current_real_cred())->token,
					KACS_PRIV_TCB))
				return -EPERM;
		}

		new_token = kacs_token_deep_clone(tf->token,
						  (int)da.token_type,
						  (int)da.impersonation_level);
		if (!new_token)
			return -ENOMEM;

		fd = kacs_token_to_fd(new_token, da.access_mask);
		if (fd < 0)
			return fd;

		da.result_fd = fd;
		if (copy_to_user((void __user *)arg, &da, sizeof(da)))
			return -EFAULT;
		return 0;
	}
	case KACS_IOC_RESTRICT: {
		struct kacs_restrict_args ra;
		const void *new_token;
		void *data = NULL;
		int fd;

		if (!(tf->access_mask & KACS_TOKEN_DUPLICATE))
			return -EACCES;

		if (copy_from_user(&ra, (void __user *)arg, sizeof(ra)))
			return -EFAULT;

		if (ra.data_len > PAGE_SIZE)
			return -EINVAL;

		if (ra.data_len > 0 && ra.data_ptr) {
			data = kmalloc(ra.data_len, GFP_KERNEL);
			if (!data)
				return -ENOMEM;
			if (copy_from_user(data, (void __user *)ra.data_ptr,
					   ra.data_len)) {
				kfree(data);
				return -EFAULT;
			}
		}

		new_token = kacs_token_restrict(tf->token,
						ra.privs_to_delete,
						data, ra.data_len,
						ra.num_deny_indices,
						ra.num_restrict_sids);
		kfree(data);

		if (!new_token)
			return -EINVAL;

		fd = kacs_token_to_fd(new_token, KACS_TOKEN_ALL_ACCESS);
		if (fd < 0)
			return fd;

		ra.result_fd = fd;
		if (copy_to_user((void __user *)arg, &ra, sizeof(ra)))
			return -EFAULT;
		return 0;
	}
	case KACS_IOC_IMPERSONATE: {
		/*
		 * Impersonate this token on the calling thread.
		 * Same two-gate model as kacs_impersonate_peer.
		 */
		struct kacs_cred_security *sec;
		struct cred *new_cred;
		const void *server_token;
		int cap_to_id = 0;

		if (!(tf->access_mask & KACS_TOKEN_IMPERSONATE))
			return -EACCES;

		/* Only Impersonation tokens can be impersonated. */
		if (kacs_token_get_type(tf->token) != 2)
			return -EINVAL;

		server_token = kacs_cred(current_real_cred())->token;

		/* Gate 1: identity. */
		if (!kacs_token_check_privilege(server_token,
						KACS_PRIV_IMPERSONATE)) {
			if (!kacs_token_same_user(server_token, tf->token))
				cap_to_id = 1;
		}

		/* Gate 2: integrity ceiling. */
		if (kacs_token_get_integrity(tf->token) >
		    kacs_token_get_integrity(server_token))
			cap_to_id = 1;

		/* If already impersonating, revert first. */
		if (current_cred() != current_real_cred())
			revert_creds(current_real_cred());

		new_cred = prepare_creds();
		if (!new_cred)
			return -ENOMEM;

		sec = kacs_cred(new_cred);
		kacs_token_drop(sec->token);
		sec->token = kacs_token_clone(tf->token);

		if (cap_to_id)
			kacs_token_set_impersonation_level(sec->token,
				KACS_LEVEL_IDENTIFICATION);

		override_creds(new_cred);
		return 0;
	}
	case KACS_IOC_LINK_TOKENS: {
		struct kacs_link_tokens_args la;
		struct kacs_token_file *etf, *ftf;
		struct fd efd, ffd;
		int ret;

		if (copy_from_user(&la, (void __user *)arg, sizeof(la)))
			return -EFAULT;

		/* Requires SeTcbPrivilege. */
		if (!kacs_token_check_privilege(
				kacs_cred(current_real_cred())->token,
				KACS_PRIV_TCB))
			return -EPERM;

		efd = fdget(la.elevated_fd);
		if (!fd_file(efd))
			return -EBADF;
		if (fd_file(efd)->f_op != &kacs_token_fops) {
			fdput(efd);
			return -EINVAL;
		}
		etf = fd_file(efd)->private_data;

		ffd = fdget(la.filtered_fd);
		if (!fd_file(ffd)) {
			fdput(efd);
			return -EBADF;
		}
		if (fd_file(ffd)->f_op != &kacs_token_fops) {
			fdput(ffd);
			fdput(efd);
			return -EINVAL;
		}
		ftf = fd_file(ffd)->private_data;

		ret = kacs_session_link_tokens(la.session_id,
					       etf->token, ftf->token);
		fdput(ffd);
		fdput(efd);
		return ret;
	}
	case KACS_IOC_GET_LINKED_TOKEN: {
		struct kacs_get_linked_token_args ga;
		const void *partner;
		const void *clone;
		int fd;

		if (!(tf->access_mask & KACS_TOKEN_QUERY))
			return -EACCES;

		partner = kacs_session_get_linked_token(tf->token);
		if (!partner)
			return -ENOENT;

		/* Return a deep clone at Identification level —
		 * can inspect but not impersonate. */
		clone = kacs_token_deep_clone(partner, 2,
					      KACS_LEVEL_IDENTIFICATION);
		kacs_token_drop(partner);
		if (!clone)
			return -ENOMEM;

		fd = kacs_token_to_fd(clone, KACS_TOKEN_QUERY);
		if (fd < 0)
			return fd;

		ga.result_fd = fd;
		if (copy_to_user((void __user *)arg, &ga, sizeof(ga)))
			return -EFAULT;
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

/* ── Cred lifecycle hooks ──────────────────────────────────────────────── */

static int kacs_cred_prepare(struct cred *new, const struct cred *old,
			     gfp_t gfp)
{
	struct kacs_cred_security *new_sec = kacs_cred(new);
	const struct kacs_cred_security *old_sec;

	if (current->cred != current->real_cred)
		old_sec = kacs_cred(current->real_cred);
	else
		old_sec = kacs_cred(old);

	if (old_sec->token)
		new_sec->token = kacs_token_clone(old_sec->token);
	else
		new_sec->token = NULL;

	return 0;
}

static void kacs_cred_transfer(struct cred *new, const struct cred *old)
{
	struct kacs_cred_security *new_sec = kacs_cred(new);
	const struct kacs_cred_security *old_sec = kacs_cred(old);

	if (old_sec->token)
		new_sec->token = kacs_token_clone(old_sec->token);
	else
		new_sec->token = NULL;
}

static int kacs_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}

static void kacs_cred_free(struct cred *cred)
{
	struct kacs_cred_security *sec = kacs_cred(cred);

	if (sec->token)
		kacs_token_drop(sec->token);
}

/* ── Task hooks (Process SDs + PIP) ────────────────────────────────────── */

/*
 * task_alloc: called on fork/clone. Create a default process SD and
 * inherit PIP level from the parent.
 */
static int kacs_task_alloc(struct task_struct *task, u64 clone_flags)
{
	struct kacs_task_security *tsec = kacs_task(task);
	struct kacs_task_security *parent_tsec = kacs_task(current);
	const struct kacs_cred_security *cred_sec;

	/* Create default process SD from the creator's token. */
	cred_sec = kacs_cred(current_cred());
	tsec->proc_sd = kacs_create_default_proc_sd(cred_sec->token);

	/* Inherit PIP from parent. */
	tsec->pip_type = parent_tsec->pip_type;
	tsec->pip_trust = parent_tsec->pip_trust;

	return 0;
}

static void kacs_task_free(struct task_struct *task)
{
	struct kacs_task_security *tsec = kacs_task(task);

	if (tsec->proc_sd)
		kacs_proc_sd_drop(tsec->proc_sd);
}

/*
 * Signal delivery: AccessCheck against target's process SD, then PIP.
 *
 * Lethal signals (SIGKILL, SIGTERM, etc.) require PROCESS_TERMINATE.
 * Non-lethal signals require PROCESS_SIGNAL.
 * PIP is checked AFTER — even if the SD grants, PIP can deny.
 * SeDebugPrivilege doesn't bypass PIP (§13.2).
 */
static int kacs_task_kill(struct task_struct *target,
			  struct kernel_siginfo *info, int sig,
			  const struct cred *cred)
{
	struct kacs_task_security *caller_tsec = kacs_task(current);
	struct kacs_task_security *target_tsec = kacs_task(target);
	const struct kacs_cred_security *caller_cred;
	u32 desired;

	/* Self-signal always allowed. */
	if (target == current)
		return 0;

	/* AccessCheck against target's process SD. */
	if (target_tsec->proc_sd) {
		/* Lethal signals: PROCESS_TERMINATE (0x0001).
		 * Non-lethal: PROCESS_SIGNAL (0x0002). */
		desired = (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT
			   || sig == SIGQUIT || sig == SIGSEGV)
			? 0x0001   /* PROCESS_TERMINATE */
			: 0x0002;  /* PROCESS_SIGNAL */

		caller_cred = kacs_cred(cred ? cred : current_cred());
		if (!kacs_check_proc_sd(caller_cred->token,
					target_tsec->proc_sd, desired))
			return -EACCES;
	}

	/* PIP dominance check. */
	if (!pip_dominates(caller_tsec, target_tsec))
		return -EACCES;

	return 0;
}

/*
 * ptrace: AccessCheck against target's process SD, then PIP.
 *
 * PTRACE_MODE_READ → PROCESS_VM_READ (0x0010)
 * PTRACE_MODE_ATTACH → PROCESS_VM_WRITE (0x0020)
 * SeDebugPrivilege doesn't bypass PIP (§13.2).
 */
static int kacs_ptrace_access_check(struct task_struct *child,
				    unsigned int mode)
{
	struct kacs_task_security *caller_tsec = kacs_task(current);
	struct kacs_task_security *target_tsec = kacs_task(child);
	const struct kacs_cred_security *caller_cred;
	u32 desired;

	/* Self-ptrace always allowed. */
	if (child == current)
		return 0;

	/* AccessCheck against target's process SD. */
	if (target_tsec->proc_sd) {
		desired = (mode & PTRACE_MODE_READ)
			? 0x0010   /* PROCESS_VM_READ */
			: 0x0020;  /* PROCESS_VM_WRITE */

		caller_cred = kacs_cred(current_cred());
		if (!kacs_check_proc_sd(caller_cred->token,
					target_tsec->proc_sd, desired))
			return -EACCES;
	}

	/* PIP dominance check. */
	if (!pip_dominates(caller_tsec, target_tsec))
		return -EACCES;

	return 0;
}

/* ── Socket hooks ──────────────────────────────────────────────────────── */

static int kacs_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	struct kacs_sock_security *ssec = kacs_sock(sk);

	ssec->peer_token = NULL;
	ssec->max_impersonation = KACS_LEVEL_IMPERSONATION; /* default per §12 */
	return 0;
}

static void kacs_sk_free_security(struct sock *sk)
{
	struct kacs_sock_security *ssec = kacs_sock(sk);

	if (ssec->peer_token)
		kacs_token_drop(ssec->peer_token);
}

/*
 * Capture the connecting peer's identity into the server-side socket blob.
 * The peer's effective token (or primary if not impersonating) is cloned
 * as a snapshot — subsequent token changes on the peer are not reflected.
 */
static int kacs_unix_stream_connect(struct sock *sock,
				    struct sock *other,
				    struct sock *newsk)
{
	struct kacs_sock_security *nsec = kacs_sock(newsk);
	const struct kacs_cred_security *cred_sec;

	/*
	 * If the client is impersonating and level >= Delegation,
	 * capture the impersonated identity. Otherwise capture the
	 * primary (real) identity.
	 */
	{
		struct kacs_sock_security *csec = kacs_sock(sock);
		int max_level = (int)csec->max_impersonation;

		if (current->cred != current->real_cred) {
			cred_sec = kacs_cred(current->cred);
			int level = kacs_token_get_impersonation_level(
				cred_sec->token);
			int effective = level < max_level ? level : max_level;
			if (effective >= KACS_LEVEL_IMPERSONATION)
				nsec->peer_token = kacs_token_clone(
					cred_sec->token);
			else
				nsec->peer_token = kacs_token_clone(
					kacs_cred(current->real_cred)->token);
		} else {
			cred_sec = kacs_cred(current->cred);
			nsec->peer_token = kacs_token_clone(cred_sec->token);
		}

		/* Cap the stored token's level to the connection max. */
		if (nsec->peer_token) {
			int stored = kacs_token_get_impersonation_level(
				nsec->peer_token);
			if (stored > max_level)
				kacs_token_set_impersonation_level(
					nsec->peer_token, max_level);
		}
	}

	return 0;
}

/* ── Hook table ────────────────────────────────────────────────────────── */

static struct security_hook_list kacs_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, kacs_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, kacs_cred_transfer),
	LSM_HOOK_INIT(cred_alloc_blank, kacs_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, kacs_cred_free),
	LSM_HOOK_INIT(task_alloc, kacs_task_alloc),
	LSM_HOOK_INIT(task_free, kacs_task_free),
	LSM_HOOK_INIT(task_kill, kacs_task_kill),
	LSM_HOOK_INIT(ptrace_access_check, kacs_ptrace_access_check),
	LSM_HOOK_INIT(sk_alloc_security, kacs_sk_alloc_security),
	LSM_HOOK_INIT(sk_free_security, kacs_sk_free_security),
	LSM_HOOK_INIT(unix_stream_connect, kacs_unix_stream_connect),
};

/* ── Syscall: kacs_open_self_token (1000) ──────────────────────────────── */

/*
 * Opens the calling thread's own token as a token fd.
 * flags: KACS_REAL_TOKEN to get Primary even when impersonating.
 * access_mask: bitmask of requested per-handle rights.
 */
SYSCALL_DEFINE2(kacs_open_self_token, unsigned int, flags, u32, access_mask)
{
	const struct kacs_cred_security *sec;
	const void *token;

	if (flags & ~KACS_REAL_TOKEN)
		return -EINVAL;
	if (access_mask & ~KACS_TOKEN_ALL_ACCESS)
		return -EINVAL;
	if (!access_mask)
		return -EINVAL;

	if (flags & KACS_REAL_TOKEN)
		sec = kacs_cred(current_real_cred());
	else
		sec = kacs_cred(current_cred());

	token = kacs_token_clone(sec->token);
	return kacs_token_to_fd(token, access_mask);
}

/* ── Syscall: kacs_open_process_token (1001) ────────────────────────────── */

/*
 * Open the primary token of another process via pidfd.
 * Checks PROCESS_QUERY_INFORMATION against the target's process SD
 * (via PIP dominance for now; full SD check is a TODO).
 */
SYSCALL_DEFINE2(kacs_open_process_token, int, pidfd, u32, access_mask)
{
	struct kacs_task_security *caller_tsec, *target_tsec;
	const struct kacs_cred_security *target_cred;
	struct pid *pid;
	struct task_struct *task;
	const void *token;

	if (access_mask & ~KACS_TOKEN_ALL_ACCESS)
		return -EINVAL;
	if (!access_mask)
		return -EINVAL;

	pid = pidfd_get_pid(pidfd, NULL);
	if (IS_ERR(pid))
		return PTR_ERR(pid);

	rcu_read_lock();
	task = pid_task(pid, PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		put_pid(pid);
		return -ESRCH;
	}

	/* PIP dominance check. */
	caller_tsec = kacs_task(current);
	target_tsec = kacs_task(task);
	if (!pip_dominates(caller_tsec, target_tsec)) {
		rcu_read_unlock();
		put_pid(pid);
		return -EACCES;
	}

	/* Get the target's primary token from real_cred. */
	target_cred = kacs_cred(task->real_cred);
	token = kacs_token_clone(target_cred->token);
	rcu_read_unlock();
	put_pid(pid);

	return kacs_token_to_fd(token, access_mask);
}

/* ── Syscall: kacs_create_token (1002) ──────────────────────────────────── */

/*
 * Parse a binary token spec from userspace and return a token fd.
 * The caller gets a handle with full access.
 */
SYSCALL_DEFINE2(kacs_create_token, const void __user *, spec, size_t, len)
{
	const struct kacs_cred_security *caller;
	const void *new_token;
	void *kbuf;

	/* Requires SeCreateTokenPrivilege — only TCB components (authd). */
	caller = kacs_cred(current_real_cred());
	if (!kacs_token_check_privilege(caller->token,
					KACS_PRIV_CREATE_TOKEN))
		return -EPERM;

	/* Size bounds: min header (56), max PAGE_SIZE. */
	if (len < 64 || len > PAGE_SIZE)
		return -EINVAL;

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, spec, len)) {
		kfree(kbuf);
		return -EFAULT;
	}

	new_token = kacs_token_from_spec(kbuf, len);
	kfree(kbuf);

	if (!new_token)
		return -EINVAL;

	return kacs_token_to_fd(new_token, KACS_TOKEN_ALL_ACCESS);
}

/* ── Syscall: kacs_create_session (1003) ────────────────────────────────── */

/*
 * Create a new logon session. Returns the session ID (u64).
 * The logon SID is S-1-5-5-{id>>32}-{id&0xFFFFFFFF}.
 * Requires SeTcbPrivilege — only authd creates sessions.
 */
SYSCALL_DEFINE2(kacs_create_session,
		const void __user *, spec, size_t, len)
{
	const struct kacs_cred_security *caller;
	void *kspec;
	long long ret;

	caller = kacs_cred(current_real_cred());
	if (!kacs_token_check_privilege(caller->token, KACS_PRIV_TCB))
		return -EPERM;

	if (len < 5 || len > 4096)
		return -EINVAL;

	kspec = kmalloc(len, GFP_KERNEL);
	if (!kspec)
		return -ENOMEM;

	if (copy_from_user(kspec, spec, len)) {
		kfree(kspec);
		return -EFAULT;
	}

	ret = kacs_create_session_impl(kspec, len);
	kfree(kspec);
	return ret;
}

/* ── Syscall: kacs_open_peer_token (1010) ───────────────────────────────── */

/*
 * Extract the peer's identity from a connected Unix stream socket.
 * Returns a token fd. Does not impersonate — just gives a handle.
 */
SYSCALL_DEFINE1(kacs_open_peer_token, int, conn_fd)
{
	struct kacs_sock_security *ssec;
	struct socket *sock;
	const void *token;
	int err;

	sock = sockfd_lookup(conn_fd, &err);
	if (!sock)
		return err;

	ssec = kacs_sock(sock->sk);
	if (!ssec->peer_token) {
		sockfd_put(sock);
		return -EINVAL;
	}

	token = kacs_token_clone(ssec->peer_token);
	sockfd_put(sock);
	return kacs_token_to_fd(token, KACS_TOKEN_ALL_ACCESS);
}

/* ── Syscall: kacs_impersonate_peer (1011) ─────────────────────────────── */

/*
 * Impersonate the peer identity from a connected Unix stream socket.
 *
 * Two-gate model (§12.2):
 *   Gate 1 (identity): SeImpersonatePrivilege on server's real token,
 *     OR same user SID between server and peer.
 *   Gate 2 (integrity ceiling): peer integrity <= server integrity.
 *
 * If either gate fails, the token is capped to Identification level
 * (not rejected). The server enters an impersonated state but
 * AccessCheck step 0 denies all resource access.
 */
SYSCALL_DEFINE1(kacs_impersonate_peer, int, conn_fd)
{
	struct kacs_cred_security *sec;
	struct kacs_sock_security *ssec;
	struct socket *sock;
	struct cred *new_cred;
	const void *server_token;
	const void *peer_token;
	int err;
	int cap_to_identification = 0;

	sock = sockfd_lookup(conn_fd, &err);
	if (!sock)
		return err;

	ssec = kacs_sock(sock->sk);
	if (!ssec->peer_token) {
		sockfd_put(sock);
		return -EINVAL;
	}

	peer_token = ssec->peer_token;
	server_token = kacs_cred(current_real_cred())->token;

	/* Gate 1: identity gate.
	 * SeImpersonatePrivilege OR same user SID. */
	if (!kacs_token_check_privilege(server_token, KACS_PRIV_IMPERSONATE)) {
		if (!kacs_token_same_user(server_token, peer_token))
			cap_to_identification = 1;
	}

	/* Gate 2: integrity ceiling.
	 * Peer integrity must be <= server integrity. */
	if (kacs_token_get_integrity(peer_token) >
	    kacs_token_get_integrity(server_token))
		cap_to_identification = 1;

	/* If already impersonating, revert first. */
	if (current_cred() != current_real_cred())
		revert_creds(current_real_cred());

	new_cred = prepare_creds();
	if (!new_cred) {
		sockfd_put(sock);
		return -ENOMEM;
	}

	sec = kacs_cred(new_cred);
	kacs_token_drop(sec->token);
	sec->token = kacs_token_clone(peer_token);

	/* Cap to Identification if either gate failed. */
	if (cap_to_identification)
		kacs_token_set_impersonation_level(sec->token,
						   KACS_LEVEL_IDENTIFICATION);

	override_creds(new_cred);

	sockfd_put(sock);
	return 0;
}

/* ── Syscall: kacs_revert (1012) ───────────────────────────────────────── */

/*
 * Revert impersonation, restoring the thread's primary token.
 * No-op if not impersonating.
 */
SYSCALL_DEFINE0(kacs_revert)
{
	if (current_cred() == current_real_cred())
		return 0;

	revert_creds(current_real_cred());
	return 0;
}

/* ── Syscall: kacs_set_impersonation_level (1013) ──────────────────────── */

/*
 * Set the max impersonation level on a socket before connect().
 * The server cannot impersonate beyond this level.
 * Default is Impersonation (matching Windows).
 */
SYSCALL_DEFINE2(kacs_set_impersonation_level, int, sock_fd, u32, level)
{
	struct kacs_sock_security *ssec;
	struct socket *sock;
	int err;

	if (level > KACS_LEVEL_DELEGATION)
		return -EINVAL;

	sock = sockfd_lookup(sock_fd, &err);
	if (!sock)
		return err;

	ssec = kacs_sock(sock->sk);
	ssec->max_impersonation = level;
	sockfd_put(sock);
	return 0;
}

/* ── Syscall: kacs_access_check (1023) ─────────────────────────────────── */

/*
 * Evaluate a Security Descriptor against the calling thread's token.
 * Used by userspace daemons (registryd, lpsd, eventd) that manage
 * their own objects and need the kernel's AccessCheck engine.
 *
 * sd_buf/sd_len: self-relative SD in Windows binary format.
 * desired: requested access mask (e.g., KEY_QUERY_VALUE | READ_CONTROL).
 * generic_*: GenericMapping for the object type (0 = no generic expansion).
 *
 * Returns the granted access mask (>= 0) or negative errno.
 * If any requested right is denied, returns 0 (no bits granted).
 */
SYSCALL_DEFINE6(kacs_access_check,
		const void __user *, sd_buf, size_t, sd_len,
		u32, desired, u32, generic_read,
		u32, generic_write, u32, generic_execute)
{
	const struct kacs_cred_security *sec;
	void *ksd;
	long long ret;

	/* SD size bounds: min 20 (header), max 64 KiB. */
	if (sd_len < 20 || sd_len > 65536)
		return -EINVAL;

	if (!desired)
		return -EINVAL;

	ksd = kmalloc(sd_len, GFP_KERNEL);
	if (!ksd)
		return -ENOMEM;

	if (copy_from_user(ksd, sd_buf, sd_len)) {
		kfree(ksd);
		return -EFAULT;
	}

	sec = kacs_cred(current_cred());
	ret = kacs_access_check_sd(sec->token, ksd, sd_len,
				   desired, generic_read, generic_write,
				   generic_execute,
				   /* generic_all = read|write|execute|standard */
				   generic_read | generic_write |
				   generic_execute | 0x001F0000);
	kfree(ksd);
	return ret;
}

/* ── /proc/<pid>/token ─────────────────────────────────────────────────── */

/*
 * Called by fs/proc/base.c via ONE("token", ...) entries.
 * Shows the target task's primary token.
 */
int kacs_proc_token_show(struct seq_file *m, struct pid_namespace *ns,
			 struct pid *pid, struct task_struct *task)
{
	const struct cred *cred;
	const struct kacs_cred_security *sec;
	char *buf;
	long long len;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cred = get_task_cred(task);
	sec = kacs_cred(cred);
	len = kacs_token_format(sec->token, buf, PAGE_SIZE);
	put_cred(cred);

	if (len < 0) {
		kfree(buf);
		return -EINVAL;
	}

	seq_write(m, buf, len);
	kfree(buf);
	return 0;
}

/* ── securityfs: /sys/kernel/security/kacs/self ────────────────────────── */

static ssize_t kacs_self_show(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	const struct kacs_cred_security *sec;
	char *kbuf;
	long long len;
	ssize_t ret;

	if (*ppos != 0)
		return 0;

	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	sec = kacs_cred(current_cred());
	len = kacs_token_format(sec->token, kbuf, PAGE_SIZE);
	if (len < 0) {
		kfree(kbuf);
		return (ssize_t)len;
	}

	ret = simple_read_from_buffer(buf, count, ppos, kbuf, len);
	kfree(kbuf);
	return ret;
}

static const struct file_operations kacs_self_fops = {
	.read = kacs_self_show,
	.llseek = generic_file_llseek,
};

static ssize_t kacs_sessions_show(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	char *kbuf;
	long long len;
	ssize_t ret;

	if (*ppos != 0)
		return 0;

	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	len = kacs_format_sessions(kbuf, PAGE_SIZE);
	if (len < 0) {
		kfree(kbuf);
		return (ssize_t)len;
	}

	ret = simple_read_from_buffer(buf, count, ppos, kbuf, len);
	kfree(kbuf);
	return ret;
}

static const struct file_operations kacs_sessions_fops = {
	.read = kacs_sessions_show,
	.llseek = generic_file_llseek,
};

static int __init kacs_securityfs_init(void)
{
	struct dentry *dir, *self_file, *sessions_file;

	dir = securityfs_create_dir("kacs", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	self_file = securityfs_create_file("self", 0444, dir, NULL,
					   &kacs_self_fops);
	if (IS_ERR(self_file)) {
		securityfs_remove(dir);
		return PTR_ERR(self_file);
	}

	sessions_file = securityfs_create_file("sessions", 0444, dir, NULL,
					       &kacs_sessions_fops);
	if (IS_ERR(sessions_file)) {
		securityfs_remove(self_file);
		securityfs_remove(dir);
		return PTR_ERR(sessions_file);
	}

	return 0;
}
late_initcall(kacs_securityfs_init);

/* ── LSM registration ──────────────────────────────────────────────────── */

static const struct lsm_id kacs_lsmid = {
	.name = "pkm",
	.id = 1000,
};

static int __init kacs_init(void)
{
	struct kacs_cred_security *sec;
	int ret;

	security_add_hooks(kacs_hooks, ARRAY_SIZE(kacs_hooks), &kacs_lsmid);

	ret = kacs_rust_init();
	if (ret) {
		pr_err("kacs: Rust init failed (%d)\n", ret);
		return ret;
	}

	sec = kacs_cred(current_cred());
	sec->token = kacs_token_create_system();

	/* Create session table + SYSTEM session (session 0). */
	kacs_init_session_table(sec->token);

	pr_info("kacs: initialized (SYSTEM token + session 0 on init)\n");
	return 0;
}

DEFINE_LSM(kacs) = {
	.id = &kacs_lsmid,
	.init = kacs_init,
	.blobs = &kacs_blob_sizes,
};
