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
#include <linux/binfmts.h>
#include <linux/net.h>
#include <linux/pid.h>
#include <linux/pidfd.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/dcache.h>
#include <linux/xattr.h>
#include <net/sock.h>

/* ── Event subsystem (from events.c) ──────────────────────────────────── */
extern int peios_event_emit_kernel(const void *body, u32 body_len);

/* ── current_fsuid() projection support (§14.1 derooting, patch 14) ──── */

#include <linux/jump_label.h>
DEFINE_STATIC_KEY_FALSE(kacs_active_key);
EXPORT_SYMBOL(kacs_active_key);

/* Blob offset for the KACS cred blob — set at init, read by
 * the patched current_fsuid()/current_fsgid() in cred.h. */
unsigned int kacs_cred_blob_offset;
EXPORT_SYMBOL(kacs_cred_blob_offset);

/* ── Rust FFI declarations ─────────────────────────────────────────────── */

extern int kacs_rust_init(void);
extern const void *kacs_token_create_system(void);
extern const void *kacs_token_create_anonymous(void);
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
extern u32 kacs_token_get_projected_uid(const void *ptr);
extern u32 kacs_token_get_projected_gid(const void *ptr);
extern int kacs_token_get_integrity(const void *ptr);
extern int kacs_token_same_user(const void *a, const void *b);
extern void kacs_token_set_impersonation_level(const void *ptr, int level);
extern int kacs_token_adjust_group(const void *ptr, u32 index, int enable);
extern int kacs_token_is_restricted(const void *ptr);
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
extern void kacs_session_addref(u64 session_id);
extern void kacs_session_release(u64 session_id);
extern const void *kacs_token_from_spec(const void *data, size_t len);
extern const void *kacs_sd_from_bytes(const void *data, size_t len);
extern int kacs_sd_to_bytes(const void *sd_ptr, void *buf, int buf_len);
extern const void *kacs_create_inherited_sd(const void *token_ptr,
					    const void *parent_sd_ptr,
					    int is_container);
extern long long kacs_file_access_check(const void *token_ptr,
					const void *sd_ptr,
					u32 desired);
extern int kacs_token_can_own(const void *token_ptr,
			      const void *sid_data, size_t sid_len);
extern int kacs_sd_get_owner_sid(const void *sd_data, size_t sd_len,
				 void *out_sid, size_t out_max);
extern int kacs_sd_get_components(const void *sd_ptr, u32 security_info,
				  void *buf, int buf_len);
extern const void *kacs_sd_merge_components(const void *existing_sd_ptr,
					    const void *new_sd_data,
					    size_t new_sd_len,
					    u32 security_info);
extern long long kacs_dir_access_check(const void *token_ptr,
				       const void *sd_ptr,
				       u32 desired);
extern long long kacs_access_check_sd(const void *token_ptr,
				      const void *sd_data, size_t sd_len,
				      u32 desired, u32 generic_read,
				      u32 generic_write, u32 generic_execute,
				      u32 generic_all,
				      const void *self_sid, u32 self_sid_len,
				      u32 privilege_intent,
				      u32 *granted_out);
extern int kacs_check_token_sd(const void *token_ptr,
			       const void *caller_token_ptr, u32 desired);

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
#define KACS_IOC_ADJUST_GROUPS _IOW(KACS_IOC_MAGIC, 7, struct kacs_adjust_groups_args)
#define KACS_IOC_IMPERSONATE   _IO(KACS_IOC_MAGIC, 8)

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

/*
 * ADJUST_PRIVS wire format: array of LUID_AND_ATTRIBUTES pairs.
 * Matches Windows AdjustTokenPrivileges for Samba compatibility.
 *
 * Each entry: [luid:u32 (bit position)][attributes:u32]
 *   SE_PRIVILEGE_ENABLED  (0x02): enable the privilege
 *   SE_PRIVILEGE_REMOVED  (0x04): permanently remove
 *   Neither flag set:             disable the privilege
 *
 * Header is fixed-size for the ioctl; entries follow in data_ptr.
 */
#define SE_PRIVILEGE_ENABLED  0x00000002
#define SE_PRIVILEGE_REMOVED  0x00000004

struct kacs_adjust_privs_args {
	u32 count;		/* number of LUID_AND_ATTRIBUTES entries */
	u32 _pad;
	u64 data_ptr;		/* userspace pointer to entries array */
};

struct kacs_priv_entry {
	u32 luid;		/* privilege bit position (0-63) */
	u32 attributes;		/* SE_PRIVILEGE_ENABLED / REMOVED / 0 (disable) */
};

struct kacs_duplicate_args {
	u32 access_mask;	/* access rights for the new handle */
	u32 token_type;		/* 1=Primary, 2=Impersonation */
	u32 impersonation_level;/* 0-3 */
	s32 result_fd;		/* out: fd for the new token */
};

/* Privilege bitmasks (must match kacs-core privilege::bits) */
/* KACS privilege bit positions (must match kacs-core privilege.rs) */
#define KACS_PRIV_CREATE_TOKEN         (1ULL << 2)
#define KACS_PRIV_ASSIGN_PRIMARY_TOKEN (1ULL << 3)
#define KACS_PRIV_LOCK_MEMORY          (1ULL << 4)
#define KACS_PRIV_INCREASE_QUOTA       (1ULL << 5)
#define KACS_PRIV_TCB                  (1ULL << 7)
#define KACS_PRIV_SECURITY             (1ULL << 8)
#define KACS_PRIV_LOAD_DRIVER          (1ULL << 10)
#define KACS_PRIV_SYSTEM_PROFILE       (1ULL << 11)
#define KACS_PRIV_SYSTEMTIME           (1ULL << 12)
#define KACS_PRIV_PROFILE_SINGLE       (1ULL << 13)
#define KACS_PRIV_INCREASE_BASE_PRIO   (1ULL << 14)
#define KACS_PRIV_SHUTDOWN             (1ULL << 19)
#define KACS_PRIV_DEBUG                (1ULL << 20)
#define KACS_PRIV_AUDIT                (1ULL << 21)
#define KACS_PRIV_IMPERSONATE          (1ULL << 29)
#define KACS_PRIV_BIND_PRIVILEGED_PORT (1ULL << 63)

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

struct kacs_adjust_groups_args {
	u32 index;		/* group index */
	u32 enable;		/* 1=enable, 0=disable */
};

struct kacs_link_tokens_args {
	s32 elevated_fd;	/* fd to the elevated/full token */
	s32 filtered_fd;	/* fd to the filtered/limited token */
	u64 session_id;		/* logon session to link them on */
};

struct kacs_get_linked_token_args {
	s32 result_fd;		/* out: fd to the partner token */
};

/* ── AccessCheck args struct (§15.1) ────────────────────────────────────── */

struct kacs_access_check_args {
	u32 size;		/* struct size (for versioning) */
	u32 desired;
	u32 generic_read;
	u32 generic_write;
	u32 generic_execute;
	u32 generic_all;
	u64 self_sid_ptr;	/* PRINCIPAL_SELF substitution (0 = none) */
	u32 self_sid_len;
	u32 privilege_intent;	/* KACS_BACKUP_INTENT | KACS_RESTORE_INTENT */
	u64 object_tree_ptr;	/* OBJECT_TYPE_LIST array (0 = none) */
	u32 object_tree_count;
	u32 _pad0;
	u64 local_claims_ptr;	/* conditional ACE claims (0 = none) */
	u32 local_claims_len;
	u32 _pad1;
	u64 granted_out_ptr;	/* output: granted mask (always populated) */
};

/* Minimum struct size: the first versioned minimum includes through
 * generic_all (6 × u32 = 24 bytes). */
#define KACS_ACCESS_CHECK_ARGS_V1_SIZE	24

/* Privilege intent flags (§11 stage 2) */
#define KACS_BACKUP_INTENT	0x01
#define KACS_RESTORE_INTENT	0x02

/* ── Credential blob ───────────────────────────────────────────────────── */

struct kacs_cred_security {
	const void *token;	/* opaque pointer to Rust-managed token */
	u32 projected_uid;	/* filesystem identity — used by current_fsuid() patch */
	u32 projected_gid;	/* filesystem identity — used by current_fsgid() patch */
};

/* ── Socket blob ──────────────────────────────────────────────────────── */

struct kacs_sock_security {
	const void *peer_token;		/* server side: peer's token snapshot */
	u32 max_impersonation;		/* client side: max level (default=Impersonation) */
};

/* ── File blob (granted mask from open-time AccessCheck) ──────────────── */

struct kacs_file_security {
	u32 granted;			/* immutable after open */
	u32 continuous_audit_mask;	/* from SACL alarm ACEs at open time */
	u8  flags;			/* KACS_FILE_* flags */
};

#define KACS_FILE_IOCTL_ONLY	0x01	/* mode-3 ioctl-only open on device */
#define KACS_FILE_FACS_MANAGED	0x02	/* set if open went through FACS */

/* ── Inode blob (cached SD from xattr) ────────────────────────────────── */

struct kacs_inode_security {
	const void __rcu *sd_cache;	/* Rust-managed parsed SD, RCU-protected */
};

/* ── Task blob (Process Security Block) ───────────────────────────────── */

/*
 * kacs_file_decision: coordination marker between file-based and
 * dentry-based hooks (§14.3). Set by file-based hook (patches 7,9-11),
 * consumed by dentry-based hook on the same inode + op_class.
 */
#define KACS_OP_NONE		0
#define KACS_OP_SETATTR		1
#define KACS_OP_GETATTR		2
#define KACS_OP_SETXATTR	3
#define KACS_OP_GETXATTR	4

struct kacs_task_security {
	const void *proc_sd;		/* Rust-managed process SD (opaque) */
	u32 pip_type;			/* PIP_TYPE_NONE/PROTECTED/ISOLATED */
	u32 pip_trust;			/* trust level within pip_type */
	/* File/dentry hook coordination (§14.3) */
	struct inode *file_decision_inode;
	u8 file_decision_op;
};

/* PIP type constants (§13) */
#define PIP_TYPE_NONE        0
#define PIP_TYPE_PROTECTED   512
#define PIP_TYPE_ISOLATED    1024

static struct lsm_blob_sizes kacs_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct kacs_cred_security),
	.lbs_file = sizeof(struct kacs_file_security),
	.lbs_inode = sizeof(struct kacs_inode_security),
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

static inline struct kacs_file_security *kacs_file(const struct file *file)
{
	return file->f_security + kacs_blob_sizes.lbs_file;
}

static inline struct kacs_inode_security *kacs_inode(const struct inode *inode)
{
	return inode->i_security + kacs_blob_sizes.lbs_inode;
}

static inline struct kacs_sock_security *kacs_sock(const struct sock *sk)
{
	return sk->sk_security + kacs_blob_sizes.lbs_sock;
}

/*
 * Stamp projected UID/GID on the cred blob from the token.
 * Called whenever a token is set on a credential.
 */
static void stamp_projected_ids(struct kacs_cred_security *sec)
{
	if (sec->token) {
		sec->projected_uid = kacs_token_get_projected_uid(sec->token);
		sec->projected_gid = kacs_token_get_projected_gid(sec->token);
	} else {
		sec->projected_uid = 65534; /* nobody */
		sec->projected_gid = 65534;
	}
}

/* ── C helpers for Rust (called from kacs_rust.rs via FFI) ─────────────── */
/* Forward declarations suppress -Wmissing-prototypes. */
const struct cred *kacs_helper_current_cred(void);
const struct cred *kacs_helper_current_real_cred(void);
const void *kacs_helper_cred_token(const struct cred *cred);
int kacs_proc_token_show(struct seq_file *, struct pid_namespace *,
			 struct pid *, struct task_struct *);

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
		struct kacs_priv_entry *entries;
		u64 enable_mask = 0, disable_mask = 0, remove_mask = 0;
		u32 i;

		if (!(tf->access_mask & KACS_TOKEN_ADJUST_PRIVS))
			return -EACCES;

		if (copy_from_user(&pa, (void __user *)arg, sizeof(pa)))
			return -EFAULT;

		if (pa.count == 0)
			return 0; /* no-op */
		if (pa.count > 64)
			return -EINVAL;

		entries = kmalloc_array(pa.count, sizeof(*entries),
					GFP_KERNEL);
		if (!entries)
			return -ENOMEM;

		if (copy_from_user(entries, (void __user *)pa.data_ptr,
				   pa.count * sizeof(*entries))) {
			kfree(entries);
			return -EFAULT;
		}

		/* Convert LUID_AND_ATTRIBUTES to bitmasks */
		for (i = 0; i < pa.count; i++) {
			u32 luid = entries[i].luid;
			u32 attr = entries[i].attributes;

			if (luid > 63) {
				kfree(entries);
				return -EINVAL;
			}

			if (attr & SE_PRIVILEGE_REMOVED)
				remove_mask |= (1ULL << luid);
			else if (attr & SE_PRIVILEGE_ENABLED)
				enable_mask |= (1ULL << luid);
			else
				disable_mask |= (1ULL << luid);
		}

		kfree(entries);
		return kacs_token_adjust_privs(tf->token, enable_mask,
					       disable_mask,
					       remove_mask);
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
		stamp_projected_ids(sec);
		commit_creds(new_cred);

		/* Regenerate process SD if user SID changed (§15.2). */
		{
			struct kacs_task_security *tsec = kacs_task(current);
			if (tsec->proc_sd)
				kacs_proc_sd_drop(tsec->proc_sd);
			tsec->proc_sd = kacs_create_default_proc_sd(
				kacs_cred(current_cred())->token);
		}
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
		if (!da.access_mask || (da.access_mask & ~KACS_TOKEN_ALL_ACCESS))
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

		fd = kacs_token_to_fd(new_token, tf->access_mask);
		if (fd < 0) {
			kacs_token_drop(new_token);
			return fd;
		}

		ra.result_fd = fd;
		if (copy_to_user((void __user *)arg, &ra, sizeof(ra)))
			return -EFAULT;
		return 0;
	}
	case KACS_IOC_ADJUST_GROUPS: {
		struct kacs_adjust_groups_args ga;

		if (!(tf->access_mask & KACS_TOKEN_ADJUST_GROUPS))
			return -EACCES;

		if (copy_from_user(&ga, (void __user *)arg, sizeof(ga)))
			return -EFAULT;

		return kacs_token_adjust_group(tf->token, ga.index, ga.enable);
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

		/* Gate 1: identity (§12.2). */
		if (!kacs_token_check_privilege(server_token,
						KACS_PRIV_IMPERSONATE)) {
			if (!kacs_token_same_user(server_token, tf->token))
				cap_to_id = 1;
			else if (kacs_token_is_restricted(server_token) !=
				 kacs_token_is_restricted(tf->token))
				/* Sandbox escape: restricted cannot
				 * impersonate unrestricted of same user
				 * (§12.2). Hard deny, not cap. */
				return -EPERM;
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
		stamp_projected_ids(sec);

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
	stamp_projected_ids(new_sec);

	/* Compute capabilities from the token's privileges (§5.2.1). */
	{
		kernel_cap_t caps;
		compute_caps_from_token(new_sec->token, &caps);
		new->cap_effective = caps;
		new->cap_permitted = caps;
		new->cap_inheritable = caps;
		cap_clear(new->cap_ambient);
	}

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
	stamp_projected_ids(new_sec);
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
 * NOTE: /proc metadata hiding via security_inode_permission is deferred.
 *
 * A security_inode_permission hook could hide /proc/<pid>/* entries from
 * processes that don't dominate the target's PIP level. However, extracting
 * the target task from a procfs inode is non-trivial: it requires checking
 * if the inode's superblock is procfs (sb->s_magic == PROC_SUPER_MAGIC),
 * then extracting the PID via PROC_I(inode)->pid — which depends on
 * internal procfs structures not exported to LSMs.
 *
 * For v1, this is unnecessary: the ptrace_access_check hook gates
 * /proc/<pid>/mem and /proc/<pid>/maps, and the kacs_proc_token_show
 * handler gates /proc/<pid>/token. The remaining ungated entries
 * (cmdline, status, stat, environ) leak minimal information. Full procfs
 * hiding can be added in v2 if needed, potentially via a dedicated
 * proc_pid_permission LSM hook or by patching fs/proc/base.c directly.
 */

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

	/* AccessCheck against target's process SD.
	 * SeDebugPrivilege bypasses the SD check (§13.2) but NOT PIP.
	 * Map ptrace mode to process SD access rights:
	 * - PTRACE_MODE_GETFD (pidfd_getfd) → PROCESS_DUP_HANDLE (0x0040)
	 * - PTRACE_MODE_READ → PROCESS_VM_READ (0x0010)
	 * - PTRACE_MODE_ATTACH → PROCESS_VM_WRITE (0x0020)
	 */
	caller_cred = kacs_cred(current_cred());
	if (target_tsec->proc_sd &&
	    !kacs_token_check_privilege(caller_cred->token, KACS_PRIV_DEBUG)) {
		if (mode & 0x20) /* PTRACE_MODE_GETFD */
			desired = 0x0040;  /* PROCESS_DUP_HANDLE */
		else if (mode & PTRACE_MODE_READ)
			desired = 0x0010;  /* PROCESS_VM_READ */
		else
			desired = 0x0020;  /* PROCESS_VM_WRITE */

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
 * Process attribute modification: requires PROCESS_SET_INFORMATION
 * against the target's process SD + PIP dominance.
 */
static int kacs_check_process_set_info(struct task_struct *target)
{
	struct kacs_task_security *caller_tsec, *target_tsec;

	if (target == current)
		return 0;

	caller_tsec = kacs_task(current);
	target_tsec = kacs_task(target);

	if (target_tsec->proc_sd) {
		const struct kacs_cred_security *ccred =
			kacs_cred(current_cred());
		if (!kacs_check_proc_sd(ccred->token,
					target_tsec->proc_sd,
					0x0200)) /* PROCESS_SET_INFORMATION */
			return -EACCES;
	}

	if (!pip_dominates(caller_tsec, target_tsec))
		return -EACCES;

	return 0;
}

/*
 * bprm_creds_for_exec: ensure impersonation is reverted before exec
 * (§7.4). The new program always starts with the primary token.
 * Also reassert DAC bypass capabilities.
 */
static int kacs_bprm_creds_for_exec(struct linux_binprm *bprm)
{
	struct kacs_cred_security *sec = kacs_cred(bprm->cred);
	const struct kacs_cred_security *real_sec =
		kacs_cred(current_real_cred());

	/* If impersonating, reset to primary token. */
	if (sec->token != real_sec->token) {
		kacs_token_drop(sec->token);
		sec->token = kacs_token_clone(real_sec->token);
		stamp_projected_ids(sec);
	}

	/* Compute full capability set from the primary token's privileges
	 * (§14.1). This runs BEFORE commoncap — commoncap may modify caps
	 * (file capabilities, setuid), which bprm_creds_from_file then
	 * suppresses by recomputing from the token. */
	{
		kernel_cap_t caps;
		compute_caps_from_token(sec->token, &caps);
		bprm->cred->cap_effective = caps;
		bprm->cred->cap_permitted = caps;
		bprm->cred->cap_inheritable = caps;
		cap_clear(bprm->cred->cap_ambient);
	}

	return 0;
}

static int kacs_task_setnice(struct task_struct *p, int nice)
{
	return kacs_check_process_set_info(p);
}

static int kacs_task_setscheduler(struct task_struct *p)
{
	return kacs_check_process_set_info(p);
}

static int kacs_task_setioprio(struct task_struct *p, int ioprio)
{
	return kacs_check_process_set_info(p);
}

static int kacs_task_prlimit(const struct cred *cred,
			     const struct cred *tcred,
			     unsigned int flags)
{
	/* Kept for LSM stacking compat — real check is in
	 * kacs_task_prlimit_target which has the task_struct. */
	return 0;
}

/*
 * prlimit with target task_struct — process SD + PIP check.
 * Uses the same pattern as task_kill / ptrace_access_check.
 */
static int kacs_task_prlimit_target(struct task_struct *target,
				    unsigned int flags)
{
	struct kacs_task_security *caller_tsec = kacs_task(current);
	struct kacs_task_security *target_tsec = kacs_task(target);
	const struct kacs_cred_security *caller_cred;

	if (target == current)
		return 0;

	/* Process SD: PROCESS_SET_INFORMATION for write, PROCESS_QUERY for read. */
	if (target_tsec->proc_sd) {
		/* LSM_PRLIMIT_WRITE = 2 (include/linux/security.h) */
		u32 desired = (flags & 2)
			? 0x0200    /* PROCESS_SET_INFORMATION */
			: 0x0400;   /* PROCESS_QUERY_INFORMATION */
		caller_cred = kacs_cred(current_cred());
		if (!kacs_check_proc_sd(caller_cred->token,
					target_tsec->proc_sd, desired))
			return -EACCES;
	}

	/* PIP dominance. */
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
		int effective = max_level;

		if (current->cred != current->real_cred) {
			cred_sec = kacs_cred(current->cred);
			int level = kacs_token_get_impersonation_level(
				cred_sec->token);
			effective = level < max_level ? level : max_level;
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

		/* Anonymous level: suppress real identity entirely (§12.3).
		 * Replace with a token containing only S-1-5-7. */
		if (effective == KACS_LEVEL_ANONYMOUS) {
			if (nsec->peer_token)
				kacs_token_drop(nsec->peer_token);
			nsec->peer_token = kacs_token_create_anonymous();
		} else if (nsec->peer_token) {
			/* Cap the stored token's level to the connection max. */
			int stored = kacs_token_get_impersonation_level(
				nsec->peer_token);
			if (stored > max_level)
				kacs_token_set_impersonation_level(
					nsec->peer_token, max_level);
		}
	}

	return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * FACS — File Access Control Shim (§14)
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── File access right constants (§9.2) ────────────────────────────────── */

#define FILE_READ_DATA          0x0001
#define FILE_LIST_DIRECTORY     0x0001  /* alias for directories */
#define FILE_WRITE_DATA         0x0002
#define FILE_ADD_FILE           0x0002  /* alias for directories */
#define FILE_APPEND_DATA        0x0004
#define FILE_ADD_SUBDIRECTORY   0x0004  /* alias for directories */
#define FILE_READ_EA            0x0008
#define FILE_WRITE_EA           0x0010
#define FILE_EXECUTE            0x0020
#define FILE_TRAVERSE           0x0020  /* alias for directories */
#define FILE_DELETE_CHILD       0x0040
#define FILE_READ_ATTRIBUTES    0x0080
#define FILE_WRITE_ATTRIBUTES   0x0100

/* Standard rights */
#define STD_DELETE              0x00010000
#define STD_READ_CONTROL        0x00020000
#define STD_WRITE_DAC           0x00040000
#define STD_WRITE_OWNER         0x00080000
#define STD_SYNCHRONIZE         0x00100000

/* ── SECURITY_INFORMATION flags (§14.4) ────────────────────────────────── */

#define OWNER_SECURITY_INFORMATION	0x01
#define GROUP_SECURITY_INFORMATION	0x02
#define DACL_SECURITY_INFORMATION	0x04
#define SACL_SECURITY_INFORMATION	0x08
#define LABEL_SECURITY_INFORMATION	0x10

#define ACCESS_SYSTEM_SECURITY		0x01000000

/*
 * Compute the required access rights for a given security_info mask.
 * Returns the access mask that must be checked before the operation.
 */
static u32 sd_rights_for_get(u32 security_info)
{
	u32 rights = 0;
	if (security_info & (OWNER_SECURITY_INFORMATION |
			     GROUP_SECURITY_INFORMATION |
			     DACL_SECURITY_INFORMATION |
			     LABEL_SECURITY_INFORMATION))
		rights |= STD_READ_CONTROL;
	if (security_info & SACL_SECURITY_INFORMATION)
		rights |= ACCESS_SYSTEM_SECURITY;
	return rights;
}

static u32 sd_rights_for_set(u32 security_info)
{
	u32 rights = 0;
	if (security_info & (OWNER_SECURITY_INFORMATION |
			     GROUP_SECURITY_INFORMATION |
			     LABEL_SECURITY_INFORMATION))
		rights |= STD_WRITE_OWNER;
	if (security_info & DACL_SECURITY_INFORMATION)
		rights |= STD_WRITE_DAC;
	if (security_info & SACL_SECURITY_INFORMATION)
		rights |= ACCESS_SYSTEM_SECURITY;
	return rights;
}

/* ── SD xattr names ───────────────────────────────────────────────────── */

#define KACS_SD_XATTR		"security.peios.sd"
#define KACS_SD_XATTR_NTFS	"system.ntfs_security"

static inline bool is_sd_xattr(const char *name)
{
	return !strcmp(name, KACS_SD_XATTR)
	    || !strcmp(name, KACS_SD_XATTR_NTFS);
}

static inline bool is_posix_acl_xattr(const char *name)
{
	return !strcmp(name, "system.posix_acl_access")
	    || !strcmp(name, "system.posix_acl_default");
}

/* ── Capability switchboard (§5.2.1) ──────────────────────────────────── */
/*
 * Classifies all 41 Linux capabilities into ALLOW, PRIVILEGE, or DENY.
 * Called from security_capable hook. Replaces blanket capability grants
 * with per-capability KACS privilege evaluation.
 *
 * ALLOW: DAC bypass caps — always granted (KACS enforces via LSM hooks)
 * PRIVILEGE: mapped to a KACS privilege — granted iff token holds it
 * DENY: dead under KACS — always denied
 */
static int kacs_capable(const struct cred *cred,
			struct user_namespace *ns,
			int cap, unsigned int opts)
{
	const struct kacs_cred_security *sec = kacs_cred(cred);
	u64 required_priv;

	switch (cap) {
	/* ALLOW — DAC bypass, KACS enforces via other LSM hooks */
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
		return 0; /* always allow */

	/* PRIVILEGE — mapped to KACS privileges */
	case CAP_LINUX_IMMUTABLE:  required_priv = KACS_PRIV_TCB; break;
	case CAP_NET_BIND_SERVICE: required_priv = KACS_PRIV_BIND_PRIVILEGED_PORT; break;
	case CAP_NET_ADMIN:        required_priv = KACS_PRIV_TCB; break;
	case CAP_NET_RAW:          required_priv = KACS_PRIV_TCB; break;
	case CAP_IPC_LOCK:         required_priv = KACS_PRIV_LOCK_MEMORY; break;
	case CAP_SYS_MODULE:       required_priv = KACS_PRIV_LOAD_DRIVER; break;
	case CAP_SYS_RAWIO:        required_priv = KACS_PRIV_TCB; break;
	case CAP_SYS_CHROOT:       required_priv = KACS_PRIV_TCB; break;
	case CAP_SYS_PTRACE:       required_priv = KACS_PRIV_DEBUG; break;
	case CAP_SYS_PACCT:        required_priv = KACS_PRIV_TCB; break;
	case CAP_SYS_ADMIN:        required_priv = KACS_PRIV_TCB; break;
	case CAP_SYS_BOOT:         required_priv = KACS_PRIV_SHUTDOWN; break;
	case CAP_SYS_NICE:         required_priv = KACS_PRIV_INCREASE_BASE_PRIO; break;
	case CAP_SYS_RESOURCE:     required_priv = KACS_PRIV_INCREASE_QUOTA; break;
	case CAP_SYS_TIME:         required_priv = KACS_PRIV_SYSTEMTIME; break;
	case CAP_SYS_TTY_CONFIG:   required_priv = KACS_PRIV_TCB; break;
	case CAP_MKNOD:            required_priv = KACS_PRIV_TCB; break;
	case CAP_AUDIT_WRITE:      required_priv = KACS_PRIV_AUDIT; break;
	case CAP_AUDIT_CONTROL:    required_priv = KACS_PRIV_SECURITY; break;
	case CAP_MAC_ADMIN:        required_priv = KACS_PRIV_SECURITY; break;
	case CAP_SYSLOG:           required_priv = KACS_PRIV_TCB; break;
	case CAP_WAKE_ALARM:       required_priv = KACS_PRIV_TCB; break;
	case CAP_BLOCK_SUSPEND:    required_priv = KACS_PRIV_TCB; break;
	case CAP_AUDIT_READ:       required_priv = KACS_PRIV_SECURITY; break;
	case CAP_PERFMON:          required_priv = KACS_PRIV_PROFILE_SINGLE; break;
	case CAP_BPF:              required_priv = KACS_PRIV_TCB; break;
	case CAP_CHECKPOINT_RESTORE: required_priv = KACS_PRIV_TCB; break;

	/* DENY — dead or dangerous under KACS */
	case CAP_SETPCAP:
	case CAP_SETFCAP:
	case CAP_MAC_OVERRIDE:
		return -EPERM;

	/* Unknown capability — fail-closed */
	default:
		return -EPERM;
	}

	/* PRIVILEGE path: check if the token holds the required privilege. */
	if (!sec->token)
		return -EPERM;
	return kacs_token_check_privilege(sec->token, required_priv)
		? 0 : -EPERM;
}

/* ── The six implementation capabilities (§14.1) ─────────────────────── */

static void assert_impl_caps(struct cred *cred)
{
	cap_raise(cred->cap_effective, CAP_DAC_OVERRIDE);
	cap_raise(cred->cap_effective, CAP_DAC_READ_SEARCH);
	cap_raise(cred->cap_effective, CAP_FOWNER);
	cap_raise(cred->cap_effective, CAP_CHOWN);
	cap_raise(cred->cap_effective, CAP_SETUID);
	cap_raise(cred->cap_effective, CAP_SETGID);
	cap_raise(cred->cap_permitted, CAP_DAC_OVERRIDE);
	cap_raise(cred->cap_permitted, CAP_DAC_READ_SEARCH);
	cap_raise(cred->cap_permitted, CAP_FOWNER);
	cap_raise(cred->cap_permitted, CAP_CHOWN);
	cap_raise(cred->cap_permitted, CAP_SETUID);
	cap_raise(cred->cap_permitted, CAP_SETGID);
}

static inline bool is_impl_cap(int cap)
{
	return cap == CAP_DAC_OVERRIDE || cap == CAP_DAC_READ_SEARCH
	    || cap == CAP_FOWNER || cap == CAP_CHOWN
	    || cap == CAP_SETUID || cap == CAP_SETGID;
}

/* ── capset: block clearing implementation caps (§14.1) ───────────────── */

static int kacs_capset(struct cred *new, const struct cred *old,
		       const kernel_cap_t *effective,
		       const kernel_cap_t *inheritable,
		       const kernel_cap_t *permitted)
{
	/* Deny if any implementation cap would be cleared. */
	if (!cap_raised(*effective, CAP_DAC_OVERRIDE) ||
	    !cap_raised(*effective, CAP_DAC_READ_SEARCH) ||
	    !cap_raised(*effective, CAP_FOWNER) ||
	    !cap_raised(*effective, CAP_CHOWN) ||
	    !cap_raised(*effective, CAP_SETUID) ||
	    !cap_raised(*effective, CAP_SETGID))
		return -EPERM;
	return 0;
}

/* ── task_prctl: block ambient raises + bounding set drops (§14.1) ────── */

static int kacs_task_prctl(int option, unsigned long arg2,
			   unsigned long arg3, unsigned long arg4,
			   unsigned long arg5)
{
	/* Deny ambient capability manipulation entirely. */
	if (option == PR_CAP_AMBIENT)
		return -EPERM;

	/* Deny bounding set drops of implementation caps. */
	if (option == PR_CAPBSET_DROP && is_impl_cap((int)arg2))
		return -EPERM;

	/* Other prctl options: pass through (return -ENOSYS → not handled). */
	return -ENOSYS;
}

/* ── bprm_creds_from_file: suppress setuid/setgid/filecaps (§14.1) ───── */

/*
 * Compute the full Linux capability set from a KACS token's privileges.
 * This is the capability switchboard materialized: ALLOW caps are always
 * set, PRIVILEGE caps are set if the token holds the mapped privilege,
 * DENY caps are never set. Called during exec (bprm_creds_from_file)
 * and credential preparation (cred_prepare).
 */
static void compute_caps_from_token(const void *token, kernel_cap_t *caps)
{
	cap_clear(*caps);

	/* ALLOW — always set (DAC bypass, KACS enforces via LSM hooks) */
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

	if (!token)
		return;

	/* PRIVILEGE — set if token holds the corresponding KACS privilege */
#define MAP_PRIV(linux_cap, kacs_priv) \
	if (kacs_token_check_privilege(token, (kacs_priv))) \
		cap_raise(*caps, (linux_cap))

	MAP_PRIV(CAP_LINUX_IMMUTABLE,  KACS_PRIV_TCB);
	MAP_PRIV(CAP_NET_BIND_SERVICE, KACS_PRIV_BIND_PRIVILEGED_PORT);
	MAP_PRIV(CAP_NET_ADMIN,        KACS_PRIV_TCB);
	MAP_PRIV(CAP_NET_RAW,          KACS_PRIV_TCB);
	MAP_PRIV(CAP_IPC_LOCK,         KACS_PRIV_LOCK_MEMORY);
	MAP_PRIV(CAP_SYS_MODULE,       KACS_PRIV_LOAD_DRIVER);
	MAP_PRIV(CAP_SYS_RAWIO,        KACS_PRIV_TCB);
	MAP_PRIV(CAP_SYS_CHROOT,       KACS_PRIV_TCB);
	MAP_PRIV(CAP_SYS_PTRACE,       KACS_PRIV_DEBUG);
	MAP_PRIV(CAP_SYS_PACCT,        KACS_PRIV_TCB);
	MAP_PRIV(CAP_SYS_ADMIN,        KACS_PRIV_TCB);
	MAP_PRIV(CAP_SYS_BOOT,         KACS_PRIV_SHUTDOWN);
	MAP_PRIV(CAP_SYS_NICE,         KACS_PRIV_INCREASE_BASE_PRIO);
	MAP_PRIV(CAP_SYS_RESOURCE,     KACS_PRIV_INCREASE_QUOTA);
	MAP_PRIV(CAP_SYS_TIME,         KACS_PRIV_SYSTEMTIME);
	MAP_PRIV(CAP_SYS_TTY_CONFIG,   KACS_PRIV_TCB);
	MAP_PRIV(CAP_MKNOD,            KACS_PRIV_TCB);
	MAP_PRIV(CAP_AUDIT_WRITE,      KACS_PRIV_AUDIT);
	MAP_PRIV(CAP_AUDIT_CONTROL,    KACS_PRIV_SECURITY);
	MAP_PRIV(CAP_MAC_ADMIN,        KACS_PRIV_SECURITY);
	MAP_PRIV(CAP_SYSLOG,           KACS_PRIV_TCB);
	MAP_PRIV(CAP_WAKE_ALARM,       KACS_PRIV_TCB);
	MAP_PRIV(CAP_BLOCK_SUSPEND,    KACS_PRIV_TCB);
	MAP_PRIV(CAP_AUDIT_READ,       KACS_PRIV_SECURITY);
	MAP_PRIV(CAP_PERFMON,          KACS_PRIV_PROFILE_SINGLE);
	MAP_PRIV(CAP_BPF,              KACS_PRIV_TCB);
	MAP_PRIV(CAP_CHECKPOINT_RESTORE, KACS_PRIV_TCB);

#undef MAP_PRIV

	/* DENY — CAP_SETPCAP, CAP_SETFCAP, CAP_MAC_OVERRIDE: never set */
}

static int kacs_bprm_creds_from_file(struct linux_binprm *bprm,
				     const struct file *file)
{
	/*
	 * Runs AFTER commoncap in the LSM hook chain. commoncap may have:
	 * 1. Applied file capabilities (security.capability xattr)
	 * 2. Elevated creds for setuid/setgid binaries
	 * 3. Modified the capability bounding/ambient sets
	 *
	 * KACS suppresses all three and recomputes the capability set from
	 * scratch based on the token's KACS privileges via the switchboard.
	 */
	struct cred *cred = bprm->cred;
	const struct kacs_cred_security *sec = kacs_cred(cred);
	kernel_cap_t intended;

	/* Suppress setuid/setgid elevation. */
	cred->euid = cred->uid;
	cred->egid = cred->gid;
	cred->suid = cred->uid;
	cred->sgid = cred->gid;
	cred->fsuid = cred->uid;
	cred->fsgid = cred->gid;

	/* Recompute the entire cap set from the token's privileges.
	 * This replaces whatever commoncap set (file caps, setuid, etc.). */
	compute_caps_from_token(sec->token, &intended);
	cred->cap_effective = intended;
	cred->cap_permitted = intended;
	cred->cap_inheritable = intended;

	/* Clear ambient set entirely — KACS owns the capability set. */
	cap_clear(cred->cap_ambient);

	return 0;
}

/* Sentinel value for corrupt SD in inode cache. Not a valid pointer —
 * distinguishes "corrupt SD cached" from "not yet populated" (NULL). */
#define KACS_SD_CORRUPT	((const void *)1UL)

/* ── SD cache population (§14.2) ──────────────────────────────────────── */

/*
 * Lazily populate the inode's SD cache from the xattr. Uses the
 * internal __vfs_getxattr path (bypasses security_inode_getxattr — we
 * cannot gate our own cache population behind READ_CONTROL).
 *
 * Returns the cached SD (RCU-protected, caller must hold rcu_read_lock).
 * Returns NULL if the file has no SD (missing or corrupt).
 */
static const void *kacs_inode_get_sd(struct inode *inode)
{
	struct kacs_inode_security *isec = kacs_inode(inode);
	const void *sd;
	void *buf;
	ssize_t len;
	const void *new_sd;
	const void *old;

	/* Fast path: cache already populated. */
	sd = rcu_dereference(isec->sd_cache);
	if (sd == KACS_SD_CORRUPT)
		return NULL; /* corrupt SD — cached sentinel, fail-closed */
	if (sd)
		return sd;

	/* Slow path: read xattr and parse. */
	{
		struct dentry *alias = d_find_any_alias(inode);
		if (!alias)
			return NULL;

		buf = kmalloc(65536, GFP_KERNEL);
		if (!buf) {
			dput(alias);
			return NULL;
		}

		/* First try the standard KACS xattr, then NTFS. */
		len = __vfs_getxattr(alias, inode,
				     KACS_SD_XATTR, buf, 65536);
		if (len <= 0)
			len = __vfs_getxattr(alias, inode,
					     KACS_SD_XATTR_NTFS, buf, 65536);

		dput(alias);

		if (len <= 0) {
			kfree(buf);
			return NULL; /* no SD on this file */
		}

		/* Parse the binary SD via Rust. */
		new_sd = kacs_sd_from_bytes(buf, (size_t)len);
		kfree(buf);

		if (!new_sd) {
			/* Corrupt SD — cache a sentinel (KACS_SD_CORRUPT)
			 * to avoid re-reading and re-parsing on every
			 * access (§14.2 corrupt SD handling). */
			old = cmpxchg(&isec->sd_cache, NULL,
				      KACS_SD_CORRUPT);

			/* Emit corrupt SD audit event (§14.2).
			 * TODO: refine payload format when eventd is designed.
			 * Current format: simple kernel event with inode
			 * number and xattr size. Will need structured
			 * msgpack payload with parse failure reason, mount
			 * path, and file path when eventd consumes these. */
			{
				struct {
					u64 inode_num;
					u32 xattr_size;
				} __packed evt = {
					.inode_num = inode->i_ino,
					.xattr_size = (u32)len,
				};
				peios_event_emit_kernel(&evt, sizeof(evt));
			}

			return NULL;
		}
	}

	/* Race-safe install: first writer wins. */
	old = cmpxchg(&isec->sd_cache, NULL, new_sd);
	if (old) {
		/* Another thread won the race — use theirs, free ours. */
		kacs_proc_sd_drop(new_sd);
		if (old == KACS_SD_CORRUPT)
			return NULL;
		return old;
	}

	return new_sd;
}

/* ── Dentry-based hook coordination (§14.3) ───────────────────────────── */

/*
 * Check if the task-local coordination marker matches this inode
 * and operation class. If so, the file-based hook already decided —
 * consume the marker and return true (skip re-evaluation).
 */
static inline bool kacs_consume_file_decision(struct inode *inode, u8 op)
{
	struct kacs_task_security *tsec = kacs_task(current);
	if (tsec->file_decision_inode == inode &&
	    tsec->file_decision_op == op) {
		tsec->file_decision_inode = NULL;
		tsec->file_decision_op = KACS_OP_NONE;
		return true;
	}
	/* Clear unconditionally (one-shot per syscall). */
	tsec->file_decision_inode = NULL;
	tsec->file_decision_op = KACS_OP_NONE;
	return false;
}

/* security_inode_readlink — readlink on symlink's own SD (§14.3) */
static int kacs_inode_readlink(struct dentry *dentry)
{
	const void *sd;
	const struct kacs_cred_security *ccred;
	long long r;

	rcu_read_lock();
	sd = kacs_inode_get_sd(d_inode(dentry));
	if (!sd) {
		rcu_read_unlock();
		return -EACCES;
	}
	ccred = kacs_cred(current_cred());
	r = kacs_file_access_check(ccred->token, sd, FILE_READ_DATA);
	rcu_read_unlock();

	if (r < 0 || !((u32)r & FILE_READ_DATA))
		return -EACCES;
	return 0;
}

/* security_inode_setattr — path-based chmod/chown/utimensat/truncate (§14.3) */
static int kacs_inode_setattr(struct mnt_idmap *idmap,
			      struct dentry *dentry,
			      struct iattr *attr)
{
	const void *sd;
	const struct kacs_cred_security *ccred;
	u32 desired = 0;
	long long ret;

	/* If the file-based hook already decided, skip. */
	if (kacs_consume_file_decision(d_inode(dentry), KACS_OP_SETATTR))
		return 0;

	/* Path-based: run AccessCheck against the file's SD. */
	if (attr->ia_valid & ATTR_MODE)
		desired |= STD_WRITE_DAC;
	if (attr->ia_valid & (ATTR_UID | ATTR_GID))
		desired |= STD_WRITE_OWNER;
	if (attr->ia_valid & ATTR_SIZE)
		desired |= FILE_WRITE_DATA;
	if (attr->ia_valid & (ATTR_ATIME | ATTR_MTIME))
		desired |= FILE_WRITE_ATTRIBUTES;

	if (!desired)
		return 0;

	rcu_read_lock();
	sd = kacs_inode_get_sd(d_inode(dentry));
	if (!sd) {
		rcu_read_unlock();
		return -EACCES;
	}
	ccred = kacs_cred(current_cred());
	ret = kacs_file_access_check(ccred->token, sd, desired);
	rcu_read_unlock();

	if (ret < 0 || ((u32)ret & desired) != desired)
		return -EACCES;
	return 0;
}

/* security_inode_getattr — path-based stat/lstat (§14.3) */
static int kacs_inode_getattr(const struct path *path)
{
	const void *sd;
	const struct kacs_cred_security *ccred;
	long long ret;

	/* If the file-based hook already decided, skip. */
	if (kacs_consume_file_decision(d_inode(path->dentry), KACS_OP_GETATTR))
		return 0;

	/* Path-based: AccessCheck for FILE_READ_ATTRIBUTES. */
	rcu_read_lock();
	sd = kacs_inode_get_sd(d_inode(path->dentry));
	if (!sd) {
		rcu_read_unlock();
		return -EACCES;
	}
	ccred = kacs_cred(current_cred());
	ret = kacs_file_access_check(ccred->token, sd,
				     FILE_READ_ATTRIBUTES);
	rcu_read_unlock();

	if (ret < 0 || !((u32)ret & FILE_READ_ATTRIBUTES))
		return -EACCES;
	return 0;
}

/* ── inode_xattr_skipcap: skip kernel cap check for SD xattrs ─────────── */

static int kacs_inode_xattr_skipcap(const char *name)
{
	/* Tell the kernel to skip CAP_SYS_ADMIN check for our xattrs.
	 * KACS policy (inode_setxattr/getxattr) handles authorization. */
	if (is_sd_xattr(name))
		return 1;
	return 0;
}

/* ── SD xattr protection (§14.2) ─────────────────────────────────────── */

static int kacs_inode_setxattr(struct mnt_idmap *idmap,
			       struct dentry *dentry,
			       const char *name, const void *value,
			       size_t size, int flags)
{
	const void *sd;
	const struct kacs_cred_security *ccred;
	long long r;

	/* Block raw writes to SD xattrs — must use kacs_set_sd. */
	if (is_sd_xattr(name))
		return -EACCES;

	/* Block POSIX ACL writes — FACS replaces POSIX ACLs. */
	if (is_posix_acl_xattr(name))
		return -EACCES;

	/* If the file-based hook (patch 11) already decided, skip. */
	if (kacs_consume_file_decision(d_inode(dentry), KACS_OP_SETXATTR))
		return 0;

	/* Path-based: AccessCheck for FILE_WRITE_EA. */
	rcu_read_lock();
	sd = kacs_inode_get_sd(d_inode(dentry));
	if (sd) {
		ccred = kacs_cred(current_cred());
		r = kacs_file_access_check(ccred->token, sd, FILE_WRITE_EA);
		if (r < 0 || !((u32)r & FILE_WRITE_EA)) {
			rcu_read_unlock();
			return -EACCES;
		}
	}
	rcu_read_unlock();
	return 0;
}

static int kacs_inode_getxattr(struct dentry *dentry, const char *name)
{
	const void *sd;
	const struct kacs_cred_security *ccred;
	long long r;

	/* Block raw reads of SD xattrs — must use kacs_get_sd. */
	if (is_sd_xattr(name))
		return -EACCES;

	/* If the file-based hook (patch 10) already decided, skip. */
	if (kacs_consume_file_decision(d_inode(dentry), KACS_OP_GETXATTR))
		return 0;

	/* Path-based: AccessCheck for FILE_READ_EA. */
	rcu_read_lock();
	sd = kacs_inode_get_sd(d_inode(dentry));
	if (sd) {
		ccred = kacs_cred(current_cred());
		r = kacs_file_access_check(ccred->token, sd, FILE_READ_EA);
		if (r < 0 || !((u32)r & FILE_READ_EA)) {
			rcu_read_unlock();
			return -EACCES;
		}
	}
	rcu_read_unlock();
	return 0;
}

static int kacs_inode_removexattr(struct mnt_idmap *idmap,
				  struct dentry *dentry,
				  const char *name)
{
	const void *sd;
	const struct kacs_cred_security *ccred;

	/* SD xattrs cannot be removed — only replaced via kacs_set_sd. */
	if (is_sd_xattr(name))
		return -EACCES;

	/* POSIX ACLs: also deny removal. */
	if (is_posix_acl_xattr(name))
		return -EACCES;

	/* If the file-based hook (patch 11) already decided, skip. */
	if (kacs_consume_file_decision(d_inode(dentry), KACS_OP_SETXATTR))
		return 0;

	/* Path-based: AccessCheck for FILE_WRITE_EA. */
	{
		const void *sd;
		const struct kacs_cred_security *ccred;
		long long r;
		rcu_read_lock();
		sd = kacs_inode_get_sd(d_inode(dentry));
		if (sd) {
			ccred = kacs_cred(current_cred());
			r = kacs_file_access_check(ccred->token, sd,
						   FILE_WRITE_EA);
			if (r < 0 || !((u32)r & FILE_WRITE_EA)) {
				rcu_read_unlock();
				return -EACCES;
			}
		}
		rcu_read_unlock();
	}
	return 0;
}

static int kacs_inode_set_acl(struct mnt_idmap *idmap,
			      struct dentry *dentry,
			      const char *acl_name,
			      struct posix_acl *kacl)
{
	/* POSIX ACLs are inert under FACS. Deny all writes. */
	return -EACCES;
}

/* ── SD cache: inode cleanup ──────────────────────────────────────────── */

/*
 * Free the cached SD after RCU grace period. Uses inode_free_security_rcu
 * (not inode_free_security) because inode_permission() may still fire
 * during or after inode_free_security.
 */
static void kacs_inode_free_security_rcu(void *inode_security)
{
	struct kacs_inode_security *isec;

	if (!inode_security)
		return;

	isec = inode_security + kacs_blob_sizes.lbs_inode;
	if (isec->sd_cache && isec->sd_cache != KACS_SD_CORRUPT) {
		/* sd_cache is a Rust-managed object — call Rust free.
		 * RCU grace period has elapsed, safe to free. */
		kacs_proc_sd_drop((void *)isec->sd_cache);
	}
}

/* ── File lifecycle ───────────────────────────────────────────────────── */

static void kacs_file_free_security(struct file *file)
{
	/* No dynamic allocation — blob is zeroed by LSM framework. */
}

/* ── Legacy open compatibility mapping (§14) ──────────────────────────── */

/*
 * Compute core and compat rights for a legacy open() from its flags.
 * Returns 0 on success with *core and *compat populated.
 * Returns negative errno on invalid flag combinations.
 */
static int legacy_open_rights(struct file *file, u32 *core, u32 *compat)
{
	unsigned int flags = file->f_flags;
	int mode = flags & O_ACCMODE;
	bool is_dir = S_ISDIR(file_inode(file)->i_mode);
	bool is_special = S_ISCHR(file_inode(file)->i_mode)
			|| S_ISBLK(file_inode(file)->i_mode)
			|| S_ISFIFO(file_inode(file)->i_mode)
			|| S_ISSOCK(file_inode(file)->i_mode);

	*core = FILE_READ_ATTRIBUTES; /* always core */
	*compat = 0;

	if (is_dir) {
		/* Linux rejects opening directories for writing (EISDIR).
		 * Only O_RDONLY is valid for legacy directory opens.
		 * The VFS already enforces this, but we check for safety. */
		if (mode != O_RDONLY)
			return -EISDIR;
		if (flags & (O_APPEND | O_TRUNC))
			return -EISDIR;

		*core |= FILE_TRAVERSE;

		/* Directory compat */
		*compat = FILE_LIST_DIRECTORY /* readdir */
			| FILE_READ_EA
			| STD_READ_CONTROL
			| FILE_WRITE_ATTRIBUTES
			| FILE_WRITE_EA
			| STD_WRITE_DAC
			| STD_WRITE_OWNER
			| STD_SYNCHRONIZE;

		return 0;
	}

	/* Regular files, devices, FIFOs, sockets */
	if (mode == O_RDONLY) {
		*core |= FILE_READ_DATA;
	} else if (mode == O_WRONLY) {
		*core |= FILE_WRITE_DATA;
	} else if (mode == O_RDWR) {
		*core |= FILE_READ_DATA | FILE_WRITE_DATA;
	} else if (mode == 3) {
		/* ioctl-only mode (nonstandard) — only valid on special files */
		if (!is_special)
			return -EINVAL;
		/* No data rights in core — set IOCTL_ONLY flag later */
		*core = FILE_READ_ATTRIBUTES;
		*compat = STD_READ_CONTROL | STD_SYNCHRONIZE;
		return 0;
	}

	/* O_APPEND modifier */
	if (flags & O_APPEND) {
		*core &= ~FILE_WRITE_DATA;
		*core |= FILE_APPEND_DATA;
	}

	/* O_TRUNC modifier — truncation is overwrite */
	if (flags & O_TRUNC)
		*core |= FILE_WRITE_DATA;

	/* Non-directory compat */
	*compat = FILE_READ_EA
		| STD_READ_CONTROL
		| FILE_WRITE_ATTRIBUTES
		| FILE_WRITE_EA
		| STD_WRITE_DAC
		| STD_WRITE_OWNER
		| STD_SYNCHRONIZE;

	/* O_APPEND compat: include FILE_WRITE_DATA so ftruncate() works
	 * if the SD grants it (§14 O_APPEND and ftruncate note). */
	if (flags & O_APPEND)
		*compat |= FILE_WRITE_DATA;

	/* FILE_EXECUTE in compat for regular files — enables fexecve()
	 * (patch 15 checks this in granted mask). */
	if (S_ISREG(file_inode(file)->i_mode))
		*compat |= FILE_EXECUTE;

	return 0;
}

/* ── security_file_open — open-time AccessCheck (§14.3) ───────────────── */

static int kacs_file_open(struct file *file)
{
	struct kacs_file_security *fsec = kacs_file(file);
	struct kacs_inode_security *isec = kacs_inode(file_inode(file));
	const struct kacs_cred_security *ccred;
	const void *sd;
	u32 core, compat, requested, granted;
	int ret;
	long long ac_ret;

	/* O_PATH fds: VFS handles them before this hook fires — we never
	 * see them here. But guard defensively. */
	if (file->f_flags & O_PATH)
		return 0;

	/* Get the inode's SD from cache. */
	rcu_read_lock();
	sd = kacs_inode_get_sd(file_inode(file));
	if (!sd) {
		rcu_read_unlock();
		/* No SD — deny mode: deny access.
		 * TODO: synthesize mode for foreign mounts (Phase G). */
		return -EACCES;
	}

	/* Compute core + compat from open flags. */
	ret = legacy_open_rights(file, &core, &compat);
	if (ret) {
		rcu_read_unlock();
		return ret;
	}

	/* Construct the full requested mask. */
	requested = core | compat;

	/* Run AccessCheck against the cached SD. Returns the granted mask
	 * (subset of requested that the SD allows). Uses MAXIMUM_ALLOWED
	 * internally to get the full grantable set. */
	ccred = kacs_cred(current_cred());
	ac_ret = kacs_file_access_check(ccred->token, sd, requested);
	rcu_read_unlock();

	if (ac_ret < 0)
		return -EACCES;

	granted = (u32)ac_ret;

	/* Subset mode: core must be fully present. */
	if ((granted & core) != core)
		return -EACCES;

	/* O_NOATIME requires FILE_WRITE_ATTRIBUTES (§14.3). */
	if ((file->f_flags & O_NOATIME) &&
	    !(granted & FILE_WRITE_ATTRIBUTES))
		return -EACCES;

	/* Stamp the granted mask on the file blob. */
	fsec->granted = granted;
	fsec->flags = KACS_FILE_FACS_MANAGED;

	/* Access mode 3 on special files: set ioctl-only flag. */
	if ((file->f_flags & O_ACCMODE) == 3)
		fsec->flags |= KACS_FILE_IOCTL_ONLY;

	return 0;
}

/* ── Use-time enforcement — granted mask checks (§14.3) ───────────────── */

/*
 * Helper: check that a FACS-managed fd has a required right.
 * Returns 0 on success, -EACCES if the right is missing.
 * Returns 0 for non-FACS-managed fds (allow through).
 */
static inline int facs_check_granted(struct file *file, u32 right)
{
	struct kacs_file_security *fsec = kacs_file(file);
	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;
	return (fsec->granted & right) == right ? 0 : -EACCES;
}

/* security_file_permission — read/write/readdir (§14.3) */
static int kacs_file_permission(struct file *file, int mask)
{
	struct kacs_file_security *fsec = kacs_file(file);
	bool facs_managed = !!(fsec->flags & KACS_FILE_FACS_MANAGED);

	/* For non-FACS-managed fds, skip data checks but still handle
	 * O_PATH fchdir (MAY_EXEC on directory — see below). */
	if (!facs_managed && !(mask & MAY_EXEC))
		return 0;

	if (facs_managed && (mask & MAY_READ)) {
		/* FILE_READ_DATA for files, FILE_LIST_DIRECTORY for dirs.
		 * Both are bit 0x0001 (aliased). */
		if (!(fsec->granted & FILE_READ_DATA))
			return -EACCES;
	}

	if (facs_managed && (mask & MAY_WRITE)) {
		/* Write: need FILE_WRITE_DATA or FILE_APPEND_DATA. */
		if (!(fsec->granted &
		      (FILE_WRITE_DATA | FILE_APPEND_DATA)))
			return -EACCES;
	}

	if (mask & MAY_EXEC) {
		/* fchdir on directory fds: requires FILE_TRAVERSE (§14.3
		 * patch 16). NOT bypassed by SeChangeNotifyPrivilege —
		 * this is a handle-model check, not a traversal check.
		 * FILE_TRAVERSE = FILE_EXECUTE (0x0020, aliased). */
		if (S_ISDIR(file_inode(file)->i_mode)) {
			if (fsec->flags & KACS_FILE_FACS_MANAGED) {
				/* Normal fd: check granted mask. */
				if (!(fsec->granted & FILE_TRAVERSE))
					return -EACCES;
			} else if (file->f_flags & O_PATH) {
				/* O_PATH fd: live AccessCheck (§14.3). */
				const void *sd;
				const struct kacs_cred_security *ccred;
				long long r;

				rcu_read_lock();
				sd = kacs_inode_get_sd(file_inode(file));
				if (!sd) {
					rcu_read_unlock();
					return -EACCES;
				}
				ccred = kacs_cred(current_cred());
				r = kacs_dir_access_check(ccred->token,
							  sd, FILE_TRAVERSE);
				rcu_read_unlock();
				if (r < 0 || !((u32)r & FILE_TRAVERSE))
					return -EACCES;
			}
		}
	}

	return 0;
}

/* security_file_truncate — ftruncate (§14.3) */
static int kacs_file_truncate(struct file *file)
{
	/* Truncation mutates existing byte positions — needs
	 * FILE_WRITE_DATA, not just FILE_APPEND_DATA. */
	return facs_check_granted(file, FILE_WRITE_DATA);
}

/* security_mmap_file — mmap (§14.3) */
static int kacs_mmap_file(struct file *file, unsigned long reqprot,
			  unsigned long prot, unsigned long flags)
{
	struct kacs_file_security *fsec;

	if (!file)
		return 0; /* anonymous mapping */

	fsec = kacs_file(file);
	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;

	if (prot & PROT_READ) {
		if (!(fsec->granted & FILE_READ_DATA))
			return -EACCES;
	}

	if ((prot & PROT_WRITE) && (flags & MAP_SHARED)) {
		/* Shared writable mapping allows arbitrary byte-position
		 * writes — needs FILE_WRITE_DATA, not FILE_APPEND_DATA. */
		if (!(fsec->granted & FILE_WRITE_DATA))
			return -EACCES;
	}

	if ((prot & PROT_WRITE) && !(flags & MAP_SHARED)) {
		/* Private writable mapping (copy-on-write) — no write to
		 * file, but needs read access to populate the pages. */
		if (!(fsec->granted & FILE_READ_DATA))
			return -EACCES;
	}

	if (prot & PROT_EXEC) {
		if (!(fsec->granted & FILE_EXECUTE))
			return -EACCES;
	}

	/* Continuous audit mask bit 25: per-SID no-mmap flag.
	 * Set when an alarm ACE matching the opener's SID has bit 25.
	 * Denies mmap regardless of granted rights (§14.3). */
#define KACS_AUDIT_NO_MMAP	0x02000000
	if (fsec->continuous_audit_mask & KACS_AUDIT_NO_MMAP)
		return -EACCES;

	return 0;
}

/* security_file_mprotect — mprotect (§14.3) */
static int kacs_file_mprotect(struct vm_area_struct *vma,
			      unsigned long reqprot, unsigned long prot)
{
	struct file *file = vma->vm_file;
	struct kacs_file_security *fsec;

	if (!file)
		return 0; /* anonymous mapping */

	fsec = kacs_file(file);
	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;

	/* Same checks as mmap_file for the new protection flags.
	 * Prevents escalation: PROT_NONE → PROT_READ/WRITE/EXEC
	 * still requires the corresponding right in the granted mask. */
	if (prot & PROT_READ) {
		if (!(fsec->granted & FILE_READ_DATA))
			return -EACCES;
	}

	if (prot & PROT_WRITE) {
		if (vma->vm_flags & VM_SHARED) {
			/* Shared writable — arbitrary byte writes. */
			if (!(fsec->granted & FILE_WRITE_DATA))
				return -EACCES;
		} else {
			/* Private writable (COW) — needs read access. */
			if (!(fsec->granted & FILE_READ_DATA))
				return -EACCES;
		}
	}

	if (prot & PROT_EXEC) {
		if (!(fsec->granted & FILE_EXECUTE))
			return -EACCES;
	}

	return 0;
}

/* security_file_lock — flock/fcntl locking (§14.3) */
static int kacs_file_lock(struct file *file, unsigned int cmd)
{
	struct kacs_file_security *fsec = kacs_file(file);

	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;

	/* cmd is LOCK_SH(1)/LOCK_EX(2) from flock, or
	 * F_RDLCK(0)/F_WRLCK(1) from fcntl locking. */
	if (cmd == LOCK_SH || cmd == F_RDLCK) {
		if (!(fsec->granted & FILE_READ_DATA))
			return -EACCES;
	} else if (cmd == LOCK_EX || cmd == F_WRLCK) {
		if (!(fsec->granted &
		      (FILE_WRITE_DATA | FILE_APPEND_DATA)))
			return -EACCES;
	}

	return 0;
}

/* security_file_fcntl — F_SETFL enforcement (§14.3) */
static int kacs_file_fcntl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct kacs_file_security *fsec = kacs_file(file);

	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;

	if (cmd == F_SETFL) {
		unsigned long changed = arg ^ file->f_flags;

		/* Adding O_NOATIME: requires FILE_WRITE_ATTRIBUTES. */
		if ((changed & O_NOATIME) && (arg & O_NOATIME)) {
			if (!(fsec->granted & FILE_WRITE_ATTRIBUTES))
				return -EACCES;
		}

		/* Clearing O_APPEND: denied if fd has FILE_APPEND_DATA
		 * but not FILE_WRITE_DATA. Removing append-only mode
		 * would allow arbitrary overwrites through an fd that
		 * was only granted append rights. */
		if ((changed & O_APPEND) && !(arg & O_APPEND)) {
			if ((fsec->granted & FILE_APPEND_DATA) &&
			    !(fsec->granted & FILE_WRITE_DATA))
				return -EPERM;
		}

		/* Setting O_APPEND: always allowed (privilege reduction). */
	}

	return 0;
}

/* security_file_ioctl — classified allowlist for regular files (§14.3) */
static int kacs_file_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct kacs_file_security *fsec = kacs_file(file);
	struct inode *inode = file_inode(file);

	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;

	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)) {
		/* Regular files and directories: classified allowlist.
		 * Known ioctls mapped to specific rights; unknown denied. */
		switch (cmd) {
		case FS_IOC_GETFLAGS:
		case FS_IOC_FSGETXATTR:
			return facs_check_granted(file, FILE_READ_ATTRIBUTES);

		case FS_IOC_SETFLAGS:
		case FS_IOC_FSSETXATTR:
			return facs_check_granted(file, FILE_WRITE_ATTRIBUTES);

		case FICLONE:
		case FICLONERANGE:
			return facs_check_granted(file, FILE_WRITE_DATA);

		case FS_IOC_FIEMAP:
			return facs_check_granted(file, FILE_READ_DATA);

		case FITRIM:
			return facs_check_granted(file, FILE_WRITE_DATA);

		default:
			/* Unclassified ioctl on regular file/dir — deny.
			 * The set of filesystem ioctls is small and
			 * enumerable; unknown ioctls represent an
			 * unaudited mutation surface. */
			return -EACCES;
		}
	}

	/* Device nodes, pipes, sockets, other special files:
	 * device ioctl authority is primarily gated at open time
	 * by the device node's SD. Ioctls are allowed if the fd
	 * has at least one data right OR the IOCTL_ONLY flag. */
	if (fsec->flags & KACS_FILE_IOCTL_ONLY)
		return 0;
	if (fsec->granted & (FILE_READ_DATA | FILE_WRITE_DATA
			     | FILE_APPEND_DATA | FILE_EXECUTE))
		return 0;

	return -EACCES;
}

/* security_file_ioctl_compat — same policy, but handle 32-bit ioctl numbers */
static int kacs_file_ioctl_compat(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	/* Map compat ioctl numbers to their native equivalents. */
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	}
	return kacs_file_ioctl(file, cmd, arg);
}

/* security_file_getattr — fd-based fstat/statx (§14.3 patch 9) */
static int kacs_file_getattr(struct file *file)
{
	struct kacs_file_security *fsec = kacs_file(file);
	struct kacs_task_security *tsec;

	/* O_PATH fds: unconditionally allowed (§14.3). */
	if (file->f_flags & O_PATH)
		return 0;

	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;

	if (!(fsec->granted & FILE_READ_ATTRIBUTES))
		return -EACCES;

	/* Set coordination marker for inode_getattr no-op. */
	tsec = kacs_task(current);
	tsec->file_decision_inode = file_inode(file);
	tsec->file_decision_op = KACS_OP_GETATTR;
	return 0;
}

/* security_file_getxattr — fd-based fgetxattr (§14.3 patch 10) */
static int kacs_file_getxattr(struct file *file, const char *name)
{
	struct kacs_file_security *fsec = kacs_file(file);
	struct kacs_task_security *tsec;

	/* SD xattrs: unconditional deny (use kacs_get_sd). */
	if (is_sd_xattr(name))
		return -EACCES;

	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;

	/* Other xattrs: FILE_READ_EA in granted mask. */
	if (!(fsec->granted & FILE_READ_EA))
		return -EACCES;

	/* Set coordination marker for inode_getxattr no-op. */
	tsec = kacs_task(current);
	tsec->file_decision_inode = file_inode(file);
	tsec->file_decision_op = KACS_OP_GETXATTR;
	return 0;
}

/* security_file_setxattr — fd-based fsetxattr/fremovexattr (§14.3 patch 11) */
static int kacs_file_setxattr_hook(struct file *file, const char *name)
{
	struct kacs_file_security *fsec = kacs_file(file);
	struct kacs_task_security *tsec;

	/* SD xattrs: unconditional deny. */
	if (is_sd_xattr(name))
		return -EACCES;

	/* POSIX ACLs: unconditional deny. */
	if (is_posix_acl_xattr(name))
		return -EACCES;

	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;

	/* Other xattrs: FILE_WRITE_EA in granted mask. */
	if (!(fsec->granted & FILE_WRITE_EA))
		return -EACCES;

	/* Set coordination marker for inode_setxattr no-op. */
	tsec = kacs_task(current);
	tsec->file_decision_inode = file_inode(file);
	tsec->file_decision_op = KACS_OP_SETXATTR;
	return 0;
}

/* security_file_setattr — fd-based metadata ops (§14.3 patch 7) */
static int kacs_file_setattr(struct file *file, struct iattr *attr)
{
	struct kacs_file_security *fsec = kacs_file(file);
	struct kacs_task_security *tsec = kacs_task(current);

	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;

	/* Map the iattr flags to KACS rights. */
	if (attr->ia_valid & ATTR_MODE) {
		/* fchmod → WRITE_DAC */
		if (!(fsec->granted & STD_WRITE_DAC))
			return -EACCES;
	}
	if (attr->ia_valid & (ATTR_UID | ATTR_GID)) {
		/* fchown → WRITE_OWNER */
		if (!(fsec->granted & STD_WRITE_OWNER))
			return -EACCES;
	}
	if (attr->ia_valid & (ATTR_ATIME | ATTR_MTIME)) {
		/* futimens → FILE_WRITE_ATTRIBUTES */
		if (!(fsec->granted & FILE_WRITE_ATTRIBUTES))
			return -EACCES;
	}

	/* Set the coordination marker so the subsequent
	 * security_inode_setattr is a no-op for this inode. */
	tsec->file_decision_inode = file_inode(file);
	tsec->file_decision_op = KACS_OP_SETATTR;

	return 0;
}

/* security_file_handle_open — gate open_by_handle_at (§14.3 patch 6) */
static int kacs_file_handle_open(void)
{
	/* Require SeChangeNotifyPrivilege. A caller without traverse-bypass
	 * privilege must be checked on every directory; handle-based opens
	 * skip ALL directories, which would violate that invariant. */
	const struct kacs_cred_security *sec =
		kacs_cred(current_cred());
	if (!sec->token)
		return -EPERM;
#define KACS_PRIV_CHANGE_NOTIFY (1ULL << 23)
	if (!kacs_token_check_privilege(sec->token,
					KACS_PRIV_CHANGE_NOTIFY))
		return -EPERM;
	return 0;
}

/* security_access_use_effective — skip credential swap in access() (§14.3 patch 5) */
static int kacs_access_use_effective(void)
{
	/* KACS: always use effective token. Setuid does not exist on Peios.
	 * access() answers "can the current effective identity access this?"
	 * not "can the real identity access this?" */
	return 1;
}

/* security_file_deny_pwrite — append-only enforcement (§14.3 patches 1-4) */
static int kacs_file_deny_pwrite(struct file *file)
{
	struct kacs_file_security *fsec = kacs_file(file);
	if (!(fsec->flags & KACS_FILE_FACS_MANAGED))
		return 0;
	/* Deny if fd has FILE_APPEND_DATA but not FILE_WRITE_DATA.
	 * This fd can only append, not overwrite at arbitrary positions. */
	if ((fsec->granted & FILE_APPEND_DATA) &&
	    !(fsec->granted & FILE_WRITE_DATA))
		return -EPERM;
	return 0;
}

/* security_file_receive — fd transfer (§14.3) */
static int kacs_file_receive(struct file *file)
{
	/* Unconditional allow. The fd is a capability token —
	 * possession is authorization. The granted mask was decided
	 * at open time against the opener's identity. Controlling
	 * who may pass fds is an IPC concern, not a file concern. */
	return 0;
}

/* ── Inode creation hooks — parent directory rights (§14.3) ───────────── */

/*
 * Check an access right against a parent directory's SD.
 * Used by inode_create, inode_mkdir, inode_mknod, inode_symlink.
 */
/*
 * Check an access right against a directory's SD using the
 * DIRECTORY_GENERIC_MAPPING. Returns 0 on success, -EACCES on deny.
 */
static int check_parent_sd(struct inode *dir, u32 right)
{
	const void *sd;
	const struct kacs_cred_security *ccred;
	long long ret;

	rcu_read_lock();
	sd = kacs_inode_get_sd(dir);
	if (!sd) {
		rcu_read_unlock();
		return -EACCES; /* deny mode: no SD on parent */
	}
	ccred = kacs_cred(current_cred());
	ret = kacs_dir_access_check(ccred->token, sd, right);
	rcu_read_unlock();

	if (ret < 0)
		return -EACCES;
	if (((u32)ret & right) != right)
		return -EACCES;
	return 0;
}

static int kacs_inode_create(struct inode *dir, struct dentry *dentry,
			     umode_t mode)
{
	return check_parent_sd(dir, FILE_ADD_FILE);
}

static int kacs_inode_mkdir(struct inode *dir, struct dentry *dentry,
			    umode_t mode)
{
	return check_parent_sd(dir, FILE_ADD_SUBDIRECTORY);
}

static int kacs_inode_mknod(struct inode *dir, struct dentry *dentry,
			    umode_t mode, dev_t dev)
{
	return check_parent_sd(dir, FILE_ADD_FILE);
}

static int kacs_inode_symlink(struct inode *dir, struct dentry *dentry,
			      const char *old_name)
{
	return check_parent_sd(dir, FILE_ADD_FILE);
}

/* ── SD inheritance on file creation (§9.5, §14.3) ────────────────────── */

/*
 * inode_init_security: compute inherited SD for a newly created inode.
 * Returns the SD xattr to be written atomically by the VFS.
 */
static int kacs_inode_init_security(struct inode *inode,
				    struct inode *dir,
				    const struct qstr *qstr,
				    struct xattr *xattrs,
				    int *xattr_count)
{
	const void *parent_sd;
	const struct kacs_cred_security *ccred;
	const void *inherited_sd;
	const void *sd_bytes;
	int sd_len;

	if (!xattrs) {
		/* Caller just wants count. */
		if (xattr_count)
			*xattr_count = 1;
		return 0;
	}

	/* Get parent directory's SD for inheritance. */
	rcu_read_lock();
	parent_sd = kacs_inode_get_sd(dir);
	rcu_read_unlock();

	/* Compute inherited SD via Rust (§9.5 algorithm).
	 * Uses parent SD + creator's token. */
	ccred = kacs_cred(current_cred());
	inherited_sd = kacs_create_inherited_sd(ccred->token, parent_sd,
						S_ISDIR(inode->i_mode));

	if (!inherited_sd) {
		/* Inheritance failed — no SD for this file.
		 * In deny mode, this file will be inaccessible. */
		if (xattr_count)
			*xattr_count = 0;
		return -ENOMEM;
	}

	/* Serialize the inherited SD to binary for the xattr. */
	sd_len = kacs_sd_to_bytes(inherited_sd, NULL, 0);
	if (sd_len <= 0) {
		kacs_proc_sd_drop(inherited_sd);
		if (xattr_count)
			*xattr_count = 0;
		return -ENOMEM;
	}

	xattrs[0].value = kmalloc(sd_len, GFP_KERNEL);
	if (!xattrs[0].value) {
		kacs_proc_sd_drop(inherited_sd);
		if (xattr_count)
			*xattr_count = 0;
		return -ENOMEM;
	}

	kacs_sd_to_bytes(inherited_sd, xattrs[0].value, sd_len);
	xattrs[0].name = KACS_SD_XATTR;
	xattrs[0].value_len = sd_len;

	/* Also install the parsed SD in the inode cache immediately. */
	{
		struct kacs_inode_security *isec = kacs_inode(inode);
		rcu_assign_pointer(isec->sd_cache, inherited_sd);
		/* inherited_sd is now owned by the cache — don't free. */
	}

	if (xattr_count)
		*xattr_count = 1;
	return 0;
}

/* ── Exec enforcement — bprm_check_security (§14.3) ──────────────────── */

static int kacs_bprm_check_security(struct linux_binprm *bprm)
{
	struct kacs_file_security *fsec;
	const void *sd;
	const struct kacs_cred_security *ccred;
	long long r;

	if (!bprm->file)
		return 0;

	fsec = kacs_file(bprm->file);

	/* If the file has a FACS granted mask, use the handle model:
	 * check FILE_EXECUTE in the granted mask. */
	if (fsec->flags & KACS_FILE_FACS_MANAGED) {
		if (!(fsec->granted & FILE_EXECUTE))
			return -EACCES;
		return 0;
	}

	/* No granted mask (O_PATH fd, non-FACS-managed, or interpreter
	 * opened by the kernel during binfmt chain). Fall back to live
	 * AccessCheck for FILE_EXECUTE on the file's SD. */
	rcu_read_lock();
	sd = kacs_inode_get_sd(file_inode(bprm->file));
	if (!sd) {
		rcu_read_unlock();
		return -EACCES; /* no SD — deny */
	}
	ccred = kacs_cred(current_cred());
	r = kacs_file_access_check(ccred->token, sd, FILE_EXECUTE);
	rcu_read_unlock();

	if (r < 0 || !((u32)r & FILE_EXECUTE))
		return -EACCES;

	return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * FACS Phase E — Directory traversal + link operations (§14.3)
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * Helper: check DELETE on inode OR FILE_DELETE_CHILD on parent dir.
 * Either right is sufficient (§14.3 unlink/rmdir/rename semantics).
 */
static int check_delete_or_parent(struct inode *target,
				  struct inode *parent_dir)
{
	const void *sd;
	const struct kacs_cred_security *ccred;
	long long r;

	ccred = kacs_cred(current_cred());

	/* Try DELETE on the target itself. */
	rcu_read_lock();
	sd = kacs_inode_get_sd(target);
	if (sd) {
		r = kacs_file_access_check(ccred->token, sd, STD_DELETE);
		if (r >= 0 && ((u32)r & STD_DELETE)) {
			rcu_read_unlock();
			return 0; /* DELETE on target granted */
		}
	}
	rcu_read_unlock();

	/* Try FILE_DELETE_CHILD on parent directory. */
	rcu_read_lock();
	sd = kacs_inode_get_sd(parent_dir);
	if (sd) {
		r = kacs_dir_access_check(ccred->token, sd,
					  FILE_DELETE_CHILD);
		if (r >= 0 && ((u32)r & FILE_DELETE_CHILD)) {
			rcu_read_unlock();
			return 0; /* DELETE_CHILD on parent granted */
		}
	}
	rcu_read_unlock();

	return -EACCES; /* neither right granted */
}

/* security_inode_permission — traverse + deferred open (§14.3) */
static int kacs_inode_permission(struct inode *inode, int mask)
{
	const void *sd;
	const struct kacs_cred_security *ccred;
	long long r;

	/* Non-directory: defer to security_file_open. KACS returns 0
	 * to avoid double-authorization (§14.3). */
	if (!S_ISDIR(inode->i_mode))
		return 0;

	/* Directory with MAY_EXEC: traverse check.
	 * Bypassed by SeChangeNotifyPrivilege (granted to all by default). */
	if (mask & MAY_EXEC) {
		ccred = kacs_cred(current_cred());
		if (ccred->token &&
		    kacs_token_check_privilege(ccred->token,
					      KACS_PRIV_CHANGE_NOTIFY))
			return 0; /* traverse bypass */

		/* No privilege: check FILE_TRAVERSE on directory SD. */
		rcu_read_lock();
		sd = kacs_inode_get_sd(inode);
		if (!sd) {
			rcu_read_unlock();
			/* No SD on directory — in deny mode, but
			 * SeChangeNotifyPrivilege (if held) bypasses
			 * traverse on missing-SD dirs too. Since we already
			 * checked the privilege above and it wasn't held,
			 * this is a genuine missing-SD deny. */
			return -EACCES;
		}
		r = kacs_dir_access_check(ccred->token, sd, FILE_TRAVERSE);
		rcu_read_unlock();
		if (r < 0 || !((u32)r & FILE_TRAVERSE))
			return -EACCES;
	}

	return 0;
}

/* security_inode_link — hardlink creation (§14.3) */
static int kacs_inode_link(struct dentry *old_dentry, struct inode *dir,
			   struct dentry *new_dentry)
{
	int ret;

	/* FILE_ADD_FILE on destination directory. */
	ret = check_parent_sd(dir, FILE_ADD_FILE);
	if (ret)
		return ret;

	/* FILE_WRITE_ATTRIBUTES on source inode. */
	{
		const void *sd;
		const struct kacs_cred_security *ccred;
		long long r;

		rcu_read_lock();
		sd = kacs_inode_get_sd(d_inode(old_dentry));
		if (sd) {
			ccred = kacs_cred(current_cred());
			r = kacs_file_access_check(ccred->token, sd,
						   FILE_WRITE_ATTRIBUTES);
			if (r < 0 || !((u32)r & FILE_WRITE_ATTRIBUTES)) {
				rcu_read_unlock();
				return -EACCES;
			}
		}
		rcu_read_unlock();
	}

	return 0;
}

/* security_inode_unlink — file deletion (§14.3) */
static int kacs_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return check_delete_or_parent(d_inode(dentry), dir);
}

/* security_inode_rmdir — directory deletion (§14.3) */
static int kacs_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return check_delete_or_parent(d_inode(dentry), dir);
}

/* security_inode_rename — rename/move (§14.3) */
static int kacs_inode_rename(struct inode *old_dir,
			     struct dentry *old_dentry,
			     struct inode *new_dir,
			     struct dentry *new_dentry)
{
	int ret;

	/* Source side: DELETE on source OR FILE_DELETE_CHILD on old parent. */
	ret = check_delete_or_parent(d_inode(old_dentry), old_dir);
	if (ret)
		return ret;

	/* Destination side: FILE_ADD_FILE on new parent (or
	 * FILE_ADD_SUBDIRECTORY if source is a directory). */
	if (S_ISDIR(d_inode(old_dentry)->i_mode))
		ret = check_parent_sd(new_dir, FILE_ADD_SUBDIRECTORY);
	else
		ret = check_parent_sd(new_dir, FILE_ADD_FILE);
	if (ret)
		return ret;

	/* Overwrite: if dest exists, need DELETE on existing dest
	 * OR FILE_DELETE_CHILD on dest parent.
	 * Note: for RENAME_EXCHANGE, the kernel calls this hook twice
	 * (swapping source/dest), so both sides get this check.
	 *
	 * RENAME_WHITEOUT: spec requires FILE_ADD_FILE on source parent
	 * for the whiteout creation, but the LSM hook does not receive
	 * rename flags. This would need a kernel patch to pass flags
	 * to the hook. Since RENAME_WHITEOUT is overlayfs-specific and
	 * the whiteout is created by the kernel (not userspace), this
	 * gap is accepted for v1. */
	if (d_is_positive(new_dentry)) {
		ret = check_delete_or_parent(d_inode(new_dentry), new_dir);
		if (ret)
			return ret;
	}

	return 0;
}

/* security_inode_follow_link — unconditional allow (§14.3) */
static int kacs_inode_follow_link(struct dentry *dentry,
				  struct inode *inode, bool rcu)
{
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
	LSM_HOOK_INIT(bprm_creds_for_exec, kacs_bprm_creds_for_exec),
	LSM_HOOK_INIT(task_setnice, kacs_task_setnice),
	LSM_HOOK_INIT(task_setscheduler, kacs_task_setscheduler),
	LSM_HOOK_INIT(task_setioprio, kacs_task_setioprio),
	LSM_HOOK_INIT(task_prlimit, kacs_task_prlimit),
	LSM_HOOK_INIT(task_prlimit_target, kacs_task_prlimit_target),
	LSM_HOOK_INIT(sk_alloc_security, kacs_sk_alloc_security),
	LSM_HOOK_INIT(sk_free_security, kacs_sk_free_security),
	LSM_HOOK_INIT(unix_stream_connect, kacs_unix_stream_connect),
	/* FACS — File Access Control Shim (§14) */
	LSM_HOOK_INIT(capable, kacs_capable),
	LSM_HOOK_INIT(capset, kacs_capset),
	LSM_HOOK_INIT(task_prctl, kacs_task_prctl),
	LSM_HOOK_INIT(bprm_check_security, kacs_bprm_check_security),
	LSM_HOOK_INIT(bprm_creds_from_file, kacs_bprm_creds_from_file),
	LSM_HOOK_INIT(inode_permission, kacs_inode_permission),
	LSM_HOOK_INIT(inode_link, kacs_inode_link),
	LSM_HOOK_INIT(inode_unlink, kacs_inode_unlink),
	LSM_HOOK_INIT(inode_rmdir, kacs_inode_rmdir),
	LSM_HOOK_INIT(inode_rename, kacs_inode_rename),
	LSM_HOOK_INIT(inode_readlink, kacs_inode_readlink),
	LSM_HOOK_INIT(inode_follow_link, kacs_inode_follow_link),
	LSM_HOOK_INIT(inode_setattr, kacs_inode_setattr),
	LSM_HOOK_INIT(inode_getattr, kacs_inode_getattr),
	LSM_HOOK_INIT(inode_xattr_skipcap, kacs_inode_xattr_skipcap),
	LSM_HOOK_INIT(inode_setxattr, kacs_inode_setxattr),
	LSM_HOOK_INIT(inode_getxattr, kacs_inode_getxattr),
	LSM_HOOK_INIT(inode_removexattr, kacs_inode_removexattr),
	LSM_HOOK_INIT(inode_set_acl, kacs_inode_set_acl),
	LSM_HOOK_INIT(file_setattr, kacs_file_setattr),
	LSM_HOOK_INIT(file_getattr, kacs_file_getattr),
	LSM_HOOK_INIT(file_getxattr, kacs_file_getxattr),
	LSM_HOOK_INIT(file_setxattr, kacs_file_setxattr_hook),
	LSM_HOOK_INIT(inode_free_security_rcu, kacs_inode_free_security_rcu),
	LSM_HOOK_INIT(inode_create, kacs_inode_create),
	LSM_HOOK_INIT(inode_mkdir, kacs_inode_mkdir),
	LSM_HOOK_INIT(inode_mknod, kacs_inode_mknod),
	LSM_HOOK_INIT(inode_symlink, kacs_inode_symlink),
	LSM_HOOK_INIT(inode_init_security, kacs_inode_init_security),
	LSM_HOOK_INIT(file_open, kacs_file_open),
	LSM_HOOK_INIT(file_permission, kacs_file_permission),
	LSM_HOOK_INIT(file_truncate, kacs_file_truncate),
	LSM_HOOK_INIT(mmap_file, kacs_mmap_file),
	LSM_HOOK_INIT(file_mprotect, kacs_file_mprotect),
	LSM_HOOK_INIT(file_lock, kacs_file_lock),
	LSM_HOOK_INIT(file_fcntl, kacs_file_fcntl),
	LSM_HOOK_INIT(file_ioctl, kacs_file_ioctl),
	LSM_HOOK_INIT(file_ioctl_compat, kacs_file_ioctl_compat),
	LSM_HOOK_INIT(file_handle_open, kacs_file_handle_open),
	LSM_HOOK_INIT(access_use_effective, kacs_access_use_effective),
	LSM_HOOK_INIT(file_deny_pwrite, kacs_file_deny_pwrite),
	LSM_HOOK_INIT(file_receive, kacs_file_receive),
	LSM_HOOK_INIT(file_free_security, kacs_file_free_security),
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

	/* Check token SD — self-access: caller is both caller and target.
	 * Owner always gets full access so this should always pass. */
	if (!kacs_check_token_sd(sec->token, sec->token, access_mask))
		return -EACCES;

	token = kacs_token_clone(sec->token);
	return kacs_token_to_fd(token, access_mask);
}

/* ── Syscall: kacs_open_process_token (1001) ────────────────────────────── */

/*
 * Open the primary token of another process via pidfd.
 * Checks PROCESS_QUERY_INFORMATION against the target's process SD
 * and PIP dominance.
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

	caller_tsec = kacs_task(current);
	target_tsec = kacs_task(task);

	/* AccessCheck for PROCESS_QUERY_INFORMATION on target's SD. */
	if (target_tsec->proc_sd) {
		const struct kacs_cred_security *ccred =
			kacs_cred(current_cred());
		if (!kacs_check_proc_sd(ccred->token,
					target_tsec->proc_sd, 0x0400)) {
			rcu_read_unlock();
			put_pid(pid);
			return -EACCES;
		}
	}

	/* PIP dominance check. */
	if (!pip_dominates(caller_tsec, target_tsec)) {
		rcu_read_unlock();
		put_pid(pid);
		return -EACCES;
	}

	/* Get the target's primary token from real_cred. */
	target_cred = kacs_cred(task->real_cred);

	/* Check the token's own SD against the caller's token. */
	{
		const struct kacs_cred_security *ccred =
			kacs_cred(current_cred());
		if (!kacs_check_token_sd(target_cred->token,
					 ccred->token, access_mask)) {
			rcu_read_unlock();
			put_pid(pid);
			return -EACCES;
		}
	}

	token = kacs_token_clone(target_cred->token);
	rcu_read_unlock();
	put_pid(pid);

	return kacs_token_to_fd(token, access_mask);
}

/* ── Syscall: kacs_set_psb (1004) ───────────────────────────────────────── */

/*
 * Set the PIP type and trust level on a process via pidfd.
 * Requires SeTcbPrivilege — only peinit sets PIP on services.
 * No self-targeting for now.
 */
SYSCALL_DEFINE3(kacs_set_psb, int, pidfd, u32, pip_type, u32, pip_trust)
{
	const struct kacs_cred_security *caller;
	struct kacs_task_security *target_tsec;
	struct pid *pid;
	struct task_struct *task;

	/* Requires SeTcbPrivilege. */
	caller = kacs_cred(current_real_cred());
	if (!kacs_token_check_privilege(caller->token, KACS_PRIV_TCB))
		return -EPERM;

	/* Validate PIP values. */
	if (pip_type != PIP_TYPE_NONE &&
	    pip_type != PIP_TYPE_PROTECTED &&
	    pip_type != PIP_TYPE_ISOLATED)
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

	target_tsec = kacs_task(task);
	target_tsec->pip_type = pip_type;
	target_tsec->pip_trust = pip_trust;

	rcu_read_unlock();
	put_pid(pid);
	return 0;
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
	/* Max 64 KB — matches SD size limit. Supports 2000+ groups. */
	if (len < 64 || len > 65536)
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

	/* Check the peer token's own SD against the caller's token. */
	{
		const struct kacs_cred_security *ccred =
			kacs_cred(current_cred());
		if (!kacs_check_token_sd(ssec->peer_token,
					 ccred->token,
					 KACS_TOKEN_ALL_ACCESS)) {
			sockfd_put(sock);
			return -EACCES;
		}
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

	/* Gate 1: identity gate (§12.2).
	 * SeImpersonatePrivilege OR (same user AND same restriction status).
	 * A restricted token cannot impersonate an unrestricted token of
	 * the same user — that would be a sandbox escape. */
	if (!kacs_token_check_privilege(server_token, KACS_PRIV_IMPERSONATE)) {
		if (!kacs_token_same_user(server_token, peer_token))
			cap_to_identification = 1;
		else if (kacs_token_is_restricted(server_token) !=
			 kacs_token_is_restricted(peer_token)) {
			/* Sandbox escape: a restricted token cannot
			 * impersonate an unrestricted token of the same
			 * user (§12.2). Hard deny, not cap. */
			sockfd_put(sock);
			return -EPERM;
		}
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
	stamp_projected_ids(sec);

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
 * args/args_len: pointer and size of struct kacs_access_check_args.
 *
 * The args struct is versioned via its `size` field — old callers with
 * smaller structs still work. Fields beyond what the caller provides
 * are zero-initialized.
 *
 * Returns the granted access mask (>= 0) or negative errno.
 * If any requested right is denied, returns 0 (no bits granted).
 * If granted_out_ptr is set, the granted mask is also written there
 * (even on denial, where it will be 0).
 */
SYSCALL_DEFINE4(kacs_access_check,
		const void __user *, sd_buf, size_t, sd_len,
		const void __user *, uargs, size_t, args_len)
{
	struct kacs_access_check_args args;
	const struct kacs_cred_security *sec;
	void *ksd = NULL;
	void *self_sid = NULL;
	u32 copy_len;
	u32 granted;
	long long ret;

	/* args_len must cover at least the minimum V1 fields. */
	if (args_len < KACS_ACCESS_CHECK_ARGS_V1_SIZE)
		return -EINVAL;

	/* SD size bounds: min 20 (header), max 64 KiB. */
	if (sd_len < 20 || sd_len > 65536)
		return -EINVAL;

	/* Zero-initialize, then copy what the caller provided. */
	memset(&args, 0, sizeof(args));
	copy_len = args_len < sizeof(args) ? args_len : sizeof(args);
	if (copy_from_user(&args, uargs, copy_len))
		return -EFAULT;

	/* Validate the struct's own size field for forward compat. */
	if (args.size < KACS_ACCESS_CHECK_ARGS_V1_SIZE)
		return -EINVAL;

	if (!args.desired)
		return -EINVAL;

	/* Copy the SD from userspace. */
	ksd = kmalloc(sd_len, GFP_KERNEL);
	if (!ksd)
		return -ENOMEM;

	if (copy_from_user(ksd, sd_buf, sd_len)) {
		ret = -EFAULT;
		goto out;
	}

	/* Copy the self SID if provided (for PRINCIPAL_SELF substitution). */
	if (args.self_sid_ptr && args.self_sid_len > 0) {
		if (args.self_sid_len > 1024) {
			ret = -EINVAL;
			goto out;
		}
		self_sid = kmalloc(args.self_sid_len, GFP_KERNEL);
		if (!self_sid) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(self_sid,
				   (void __user *)args.self_sid_ptr,
				   args.self_sid_len)) {
			ret = -EFAULT;
			goto out;
		}
	}

	sec = kacs_cred(current_cred());
	ret = kacs_access_check_sd(sec->token, ksd, sd_len,
				   args.desired,
				   args.generic_read,
				   args.generic_write,
				   args.generic_execute,
				   args.generic_all,
				   self_sid, args.self_sid_len,
				   args.privilege_intent,
				   &granted);

	/* Write the granted mask back to userspace if requested. */
	if (args.granted_out_ptr) {
		if (ret >= 0)
			granted = (u32)ret;
		else
			granted = 0;
		if (put_user(granted,
			     (u32 __user *)args.granted_out_ptr)) {
			ret = -EFAULT;
			goto out;
		}
	}

out:
	kfree(self_sid);
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

	/* Access gating: self always allowed, others need PIP + SD check. */
	if (task != current) {
		struct kacs_task_security *caller_tsec = kacs_task(current);
		struct kacs_task_security *target_tsec = kacs_task(task);

		if (target_tsec->proc_sd) {
			const struct kacs_cred_security *ccred =
				kacs_cred(current_cred());
			if (!kacs_check_proc_sd(ccred->token,
						target_tsec->proc_sd,
						0x0400)) /* PROCESS_QUERY_INFORMATION */
				return -EACCES;
		}
		if (!pip_dominates(caller_tsec, target_tsec))
			return -EACCES;
	}

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

/* ══════════════════════════════════════════════════════════════════════════
 * FACS Phase F — KACS SD syscalls (§14.4)
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * Resolve a (dirfd, path, flags) to an inode. Handles AT_EMPTY_PATH.
 * Caller must path_put() the result on success.
 * Returns 0 on success, negative errno on failure.
 */
static int resolve_target(int dirfd, const char __user *pathname,
			  u32 flags, struct path *target)
{
	unsigned int lookup_flags = LOOKUP_FOLLOW;

	if (flags & AT_SYMLINK_NOFOLLOW)
		lookup_flags &= ~LOOKUP_FOLLOW;
	if (flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

	return user_path_at(dirfd, pathname, lookup_flags, target);
}

/* ── Syscall: kacs_get_sd (1021) ──────────────────────────────────────── */

SYSCALL_DEFINE7(kacs_get_sd, int, dirfd, const char __user *, path,
		u32, security_info, void __user *, buf, u32, buf_len,
		u32 __user *, len_needed, u32, flags)
{
	struct path target;
	struct inode *inode;
	const void *sd;
	const struct kacs_cred_security *ccred;
	u32 required;
	long long ac_ret;
	void *kbuf = NULL;
	int sd_len;
	int ret;

	if (!security_info)
		return -EINVAL;

	ret = resolve_target(dirfd, path, flags, &target);
	if (ret)
		return ret;

	inode = d_inode(target.dentry);

	/* Get the SD from cache. */
	rcu_read_lock();
	sd = kacs_inode_get_sd(inode);
	if (!sd) {
		rcu_read_unlock();
		path_put(&target);
		return -EACCES; /* no SD — deny */
	}

	/* Access check: does the caller have the required rights? */
	required = sd_rights_for_get(security_info);
	ccred = kacs_cred(current_cred());
	ac_ret = kacs_file_access_check(ccred->token, sd, required);
	if (ac_ret < 0 || ((u32)ac_ret & required) != required) {
		rcu_read_unlock();
		path_put(&target);
		return -EACCES;
	}

	/* Extract the requested components. Size query first. */
	sd_len = kacs_sd_get_components(sd, security_info, NULL, 0);
	rcu_read_unlock();
	path_put(&target);

	if (sd_len <= 0)
		return -EINVAL;

	/* Return needed size. */
	if (len_needed) {
		if (put_user((u32)sd_len, len_needed))
			return -EFAULT;
	}

	if (!buf || buf_len == 0)
		return 0; /* size query only */

	if (buf_len < (u32)sd_len)
		return -ERANGE; /* buffer too small */

	/* Allocate kernel buffer and extract. */
	kbuf = kmalloc(sd_len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	/* Re-read SD (may have changed — but we already did access check).
	 * In practice the SD is cached and this is fast. */
	rcu_read_lock();
	sd = kacs_inode_get_sd(inode);
	if (!sd) {
		rcu_read_unlock();
		kfree(kbuf);
		return -EACCES;
	}
	kacs_sd_get_components(sd, security_info, kbuf, sd_len);
	rcu_read_unlock();

	if (copy_to_user(buf, kbuf, sd_len)) {
		kfree(kbuf);
		return -EFAULT;
	}

	kfree(kbuf);
	return 0;
}

/* ── Syscall: kacs_set_sd (1022) ──────────────────────────────────────── */

SYSCALL_DEFINE6(kacs_set_sd, int, dirfd, const char __user *, path,
		u32, security_info, const void __user *, sd_buf,
		u32, sd_len, u32, flags)
{
	struct path target;
	struct inode *inode;
	struct kacs_inode_security *isec;
	const void *existing_sd;
	const void *merged_sd;
	const struct kacs_cred_security *ccred;
	u32 required;
	long long ac_ret;
	void *ksd = NULL;
	void *merged_bytes = NULL;
	int merged_len;
	int ret;

	if (!security_info || !sd_buf || sd_len == 0 || sd_len > 65536)
		return -EINVAL;

	ret = resolve_target(dirfd, path, flags, &target);
	if (ret)
		return ret;

	inode = d_inode(target.dentry);

	/* Copy the new SD from userspace. */
	ksd = kmalloc(sd_len, GFP_KERNEL);
	if (!ksd) {
		path_put(&target);
		return -ENOMEM;
	}
	if (copy_from_user(ksd, sd_buf, sd_len)) {
		kfree(ksd);
		path_put(&target);
		return -EFAULT;
	}

	/* Access check against the existing SD.
	 * SeRestorePrivilege bypasses this (handled inside AccessCheck
	 * via privilege grants — WRITE_DAC/WRITE_OWNER/ASS all granted). */
	rcu_read_lock();
	existing_sd = kacs_inode_get_sd(inode);
	if (!existing_sd) {
		rcu_read_unlock();
		/* No existing SD — only SeRestorePrivilege can stamp.
		 * Check if caller has it. */
		ccred = kacs_cred(current_cred());
		if (!ccred->token ||
		    !kacs_token_check_privilege(ccred->token,
			(1ULL << 18) /* SE_RESTORE */)) {
			kfree(ksd);
			path_put(&target);
			return -EACCES;
		}
		/* Create a fresh SD from the provided buffer. */
		merged_sd = kacs_sd_from_bytes(ksd, sd_len);
		kfree(ksd);
		if (!merged_sd) {
			path_put(&target);
			return -EINVAL; /* malformed SD */
		}
	} else {
		required = sd_rights_for_set(security_info);
		ccred = kacs_cred(current_cred());
		ac_ret = kacs_file_access_check(ccred->token,
						existing_sd, required);
		if (ac_ret < 0 || ((u32)ac_ret & required) != required) {
			rcu_read_unlock();
			kfree(ksd);
			path_put(&target);
			return -EACCES;
		}

		/* Ownership constraints (§14.2): new owner must be
		 * caller's own SID or a group with SE_GROUP_OWNER.
		 * SeRestorePrivilege bypasses this constraint. */
		if (security_info & OWNER_SECURITY_INFORMATION) {
			if (!kacs_token_check_privilege(ccred->token,
					(1ULL << 18) /* SE_RESTORE */)) {
				u8 owner_buf[68]; /* max SID: 8 + 15*4 = 68 */
				int owner_len;

				owner_len = kacs_sd_get_owner_sid(
					ksd, sd_len, owner_buf, sizeof(owner_buf));
				if (owner_len > 0 &&
				    !kacs_token_can_own(ccred->token,
						       owner_buf, owner_len)) {
					rcu_read_unlock();
					kfree(ksd);
					path_put(&target);
					return -EPERM;
				}
			}
		}

		/* Merge components from new SD into existing. */
		merged_sd = kacs_sd_merge_components(
			existing_sd, ksd, sd_len, security_info);
		rcu_read_unlock();
		kfree(ksd);

		if (!merged_sd) {
			path_put(&target);
			return -EINVAL;
		}
	}

	/* Serialize the merged SD for xattr write. */
	merged_len = kacs_sd_to_bytes(merged_sd, NULL, 0);
	if (merged_len <= 0) {
		kacs_proc_sd_drop(merged_sd);
		path_put(&target);
		return -ENOMEM;
	}

	merged_bytes = kmalloc(merged_len, GFP_KERNEL);
	if (!merged_bytes) {
		kacs_proc_sd_drop(merged_sd);
		path_put(&target);
		return -ENOMEM;
	}
	kacs_sd_to_bytes(merged_sd, merged_bytes, merged_len);

	/* Write the xattr via internal path (bypasses security_inode_setxattr).
	 * The set-security syscall IS the authorized write path. */
	inode_lock(inode);
	ret = __vfs_setxattr_noperm(
		mnt_idmap(target.mnt), target.dentry,
		KACS_SD_XATTR, merged_bytes, merged_len, 0);
	if (!ret) {
		/* Update the in-memory SD cache atomically. */
		isec = kacs_inode(inode);
		{
			const void *old = rcu_dereference_protected(
				isec->sd_cache,
				lockdep_is_held(&inode->i_rwsem));
			rcu_assign_pointer(isec->sd_cache, merged_sd);
			if (old && old != KACS_SD_CORRUPT)
				kfree_rcu_mightsleep((void *)old);
		}
	} else {
		kacs_proc_sd_drop(merged_sd);
	}
	inode_unlock(inode);

	kfree(merged_bytes);
	path_put(&target);
	return ret;
}

/* ── Syscall: kacs_open (1020) ─────────────────────────────────────────── */

/* Create dispositions (§14.4 kacs_open) */
#define KACS_FILE_SUPERSEDE	0
#define KACS_FILE_OPEN		1
#define KACS_FILE_CREATE	2
#define KACS_FILE_OPEN_IF	3
#define KACS_FILE_OVERWRITE	4
#define KACS_FILE_OVERWRITE_IF	5

/*
 * Map create disposition to Linux open flags.
 * Returns open flags, or negative errno.
 * *status_out is set to 1 (created) or 0 (opened existing).
 */
static int disposition_to_flags(u32 disposition, u32 desired,
				bool file_exists, int *o_flags)
{
	switch (disposition) {
	case KACS_FILE_OPEN:
		/* Open existing, fail if not found. */
		*o_flags = 0;
		return file_exists ? 0 : -ENOENT;
	case KACS_FILE_CREATE:
		/* Create new, fail if exists. */
		*o_flags = O_CREAT | O_EXCL;
		return file_exists ? -EEXIST : 0;
	case KACS_FILE_OPEN_IF:
		/* Open if exists, create if not. */
		*o_flags = O_CREAT;
		return 0;
	case KACS_FILE_OVERWRITE:
		/* Truncate existing, fail if not found. */
		*o_flags = O_TRUNC;
		return file_exists ? 0 : -ENOENT;
	case KACS_FILE_OVERWRITE_IF:
		/* Truncate if exists, create if not. */
		*o_flags = O_CREAT | O_TRUNC;
		return 0;
	case KACS_FILE_SUPERSEDE:
		/* Delete existing + create new. Complex — requires DELETE
		 * on existing + FILE_ADD_FILE on parent. Handled specially. */
		*o_flags = O_CREAT;
		return 0;
	default:
		return -EINVAL;
	}
}

SYSCALL_DEFINE9(kacs_open, int, dirfd, const char __user *, path,
		u32, desired_access, u32, create_disposition,
		u32, create_options, const void __user *, sd_buf,
		u32, sd_len, u32 __user *, status_out, u32, flags)
{
	struct open_how how = {};
	int o_flags = 0;
	int ret;
	long fd;
	fmode_t f_mode = 0;

	if (!desired_access)
		return -EINVAL;

	/* The desired_access must include at least one data right or
	 * FILE_EXECUTE for a valid f_mode (§14 KACS-native open). */
	if (!(desired_access & (FILE_READ_DATA | FILE_WRITE_DATA
				| FILE_APPEND_DATA | FILE_EXECUTE)))
		return -EINVAL;

	if (create_disposition > KACS_FILE_OVERWRITE_IF)
		return -EINVAL;

	/* Map desired access to f_mode. */
	if (desired_access & FILE_READ_DATA)
		f_mode |= FMODE_READ;
	if (desired_access & (FILE_WRITE_DATA | FILE_APPEND_DATA))
		f_mode |= FMODE_WRITE;

	/* Compute open flags from disposition. */
	/* FILE_SUPERSEDE is handled specially — for now, map to create. */
	ret = disposition_to_flags(create_disposition, desired_access,
				   true /* pessimistic */, &o_flags);
	/* Ignore the exists/not-exists error here — VFS handles it. */
	if (ret == -EINVAL)
		return ret;

	/* Build the open_how. */
	how.flags = o_flags;
	if (f_mode & FMODE_READ)
		how.flags |= (f_mode & FMODE_WRITE) ? O_RDWR : O_RDONLY;
	else if (f_mode & FMODE_WRITE)
		how.flags |= O_WRONLY;

	if (flags & AT_SYMLINK_NOFOLLOW)
		how.flags |= O_NOFOLLOW;

	/* Use do_sys_openat2 which handles all the VFS path resolution. */
	how.mode = 0666; /* for O_CREAT — umask will apply */
	fd = do_sys_openat2(dirfd, path, &how);
	if (fd < 0)
		return fd;

	/* The security_file_open hook already fired during do_sys_openat2.
	 * It evaluated the LEGACY core+compat mapping. For kacs_open,
	 * we need STRICT mode: the granted mask must include ALL bits
	 * from desired_access, not just core.
	 *
	 * Re-check: verify the granted mask covers the full desired_access.
	 * If not, close the fd and return -EACCES. */
	{
		CLASS(fd, f)((unsigned int)fd);
		struct kacs_file_security *fsec;

		if (fd_empty(f))
			return -EBADF;

		fsec = kacs_file(fd_file(f));
		if ((fsec->granted & desired_access) != desired_access) {
			/* Close and fail. */
			ksys_close((unsigned int)fd);
			return -EACCES;
		}
	}

	/* Set creation status for caller. */
	if (status_out) {
		u32 status = (how.flags & O_CREAT) ? 1 : 0;
		if (put_user(status, status_out)) {
			ksys_close((unsigned int)fd);
			return -EFAULT;
		}
	}

	return fd;
}

/* ── LSM registration ──────────────────────────────────────────────────── */

static const struct lsm_id kacs_lsmid = {
	.name = "pkm",
	.id = 1000,
};

static int __init kacs_init(void)
{
	struct kacs_cred_security *sec;
	int ret;

	/*
	 * LSM stack verification (§15.7 step 1).
	 *
	 * KACS must be the sole MAC LSM. Conflicting LSMs (SELinux,
	 * AppArmor, SMACK, TOMOYO) are excluded at build time via the
	 * kernel Kconfig: CONFIG_SECURITY_SELINUX, CONFIG_SECURITY_APPARMOR,
	 * CONFIG_SECURITY_SMACK, and CONFIG_SECURITY_TOMOYO are all
	 * forced off in the PKM kernel Dockerfile. Runtime detection from
	 * within an LSM init function is not practical — there is no
	 * exported API to enumerate loaded LSMs at this point. The Kconfig
	 * enforcement is the authoritative gate; if someone modifies the
	 * defconfig to enable a conflicting LSM, the build will include it
	 * and KACS hook ordering becomes unpredictable. A build-time
	 * static_assert or Kconfig dependency (depends on !SECURITY_SELINUX)
	 * could be added to the PKM Kconfig for defense in depth.
	 */
	security_add_hooks(kacs_hooks, ARRAY_SIZE(kacs_hooks), &kacs_lsmid);

	ret = kacs_rust_init();
	if (ret) {
		pr_err("kacs: Rust init failed (%d)\n", ret);
		return ret;
	}

	sec = kacs_cred(current_cred());
	sec->token = kacs_token_create_system();
	stamp_projected_ids(sec);

	/* Create session table + SYSTEM session (session 0). */
	kacs_init_session_table(sec->token);

	/* Compute capabilities from SYSTEM token's privileges via the
	 * switchboard (§5.2.1). SYSTEM has all privileges, so all ALLOW
	 * and PRIVILEGE caps are set. */
	{
		struct cred *init = (struct cred *)current_cred();
		kernel_cap_t caps;
		compute_caps_from_token(sec->token, &caps);
		init->cap_effective = caps;
		init->cap_permitted = caps;
		init->cap_inheritable = caps;
		cap_clear(init->cap_ambient);
	}

	/* Enable the current_fsuid() projection (patch 14). */
	kacs_cred_blob_offset = kacs_blob_sizes.lbs_cred;
	static_branch_enable(&kacs_active_key);

	pr_info("pkm: initialized (SYSTEM token + session 0 + DAC bypass + fsuid projection)\n");
	return 0;
}

DEFINE_LSM(kacs) = {
	.id = &kacs_lsmid,
	.init = kacs_init,
	.blobs = &kacs_blob_sizes,
};
