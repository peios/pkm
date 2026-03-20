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

/* ── Rust FFI declarations ─────────────────────────────────────────────── */

extern int kacs_rust_init(void);
extern const void *kacs_token_create_system(void);
extern const void *kacs_token_clone(const void *ptr);
extern void kacs_token_drop(const void *ptr);
extern long long kacs_token_format(const void *ptr, char *buf, size_t len);
extern int kacs_token_query(const void *ptr, u32 class, void *buf, u32 buf_len);
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
#define KACS_IOC_QUERY _IOWR(KACS_IOC_MAGIC, 0, struct kacs_query_args)

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

/* ── Credential blob ───────────────────────────────────────────────────── */

struct kacs_cred_security {
	const void *token;	/* opaque pointer to Rust-managed token */
};

static struct lsm_blob_sizes kacs_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct kacs_cred_security),
};

static inline struct kacs_cred_security *kacs_cred(const struct cred *cred)
{
	return cred->security + kacs_blob_sizes.lbs_cred;
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

/* ── Hook table ────────────────────────────────────────────────────────── */

static struct security_hook_list kacs_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, kacs_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, kacs_cred_transfer),
	LSM_HOOK_INIT(cred_alloc_blank, kacs_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, kacs_cred_free),
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

static int __init kacs_securityfs_init(void)
{
	struct dentry *dir, *self_file;

	dir = securityfs_create_dir("kacs", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	self_file = securityfs_create_file("self", 0444, dir, NULL,
					   &kacs_self_fops);
	if (IS_ERR(self_file)) {
		securityfs_remove(dir);
		return PTR_ERR(self_file);
	}

	return 0;
}
late_initcall(kacs_securityfs_init);

/* ── LSM registration ──────────────────────────────────────────────────── */

static const struct lsm_id kacs_lsmid = {
	.name = "kacs",
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

	pr_info("kacs: initialized (SYSTEM token on init)\n");
	return 0;
}

DEFINE_LSM(kacs) = {
	.id = &kacs_lsmid,
	.init = kacs_init,
	.blobs = &kacs_blob_sizes,
};
