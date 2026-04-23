// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM token-fd and self-open surface.
 *
 * Slices 30 through 33 add token query and the first narrow mutation ioctl on
 * top of the earlier token-fd handle object and kacs_open_self_token syscall.
 */

#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include "token_fd.h"
#include "token_runtime.h"

#define PKM_KACS_TOKEN_OPEN_ALLOWED_MASK \
	(KACS_TOKEN_ALL_ACCESS | KACS_ACCESS_ACCESS_SYSTEM_SECURITY | \
	 KACS_ACCESS_MAXIMUM_ALLOWED | KACS_ACCESS_GENERIC_READ | \
	 KACS_ACCESS_GENERIC_WRITE | KACS_ACCESS_GENERIC_EXECUTE | \
	 KACS_ACCESS_GENERIC_ALL)
#define PKM_KACS_PRIVILEGE_SE_TCB (1ULL << 7)

struct pkm_kacs_token_file {
	const void *token;
	u32 access_mask;
};

static bool pkm_kacs_ranges_overlap(u64 lhs_start, size_t lhs_len,
				    u64 rhs_start, size_t rhs_len)
{
	u64 lhs_end;
	u64 rhs_end;

	if (!lhs_len || !rhs_len)
		return false;
	if (check_add_overflow(lhs_start, (u64)lhs_len, &lhs_end))
		return true;
	if (check_add_overflow(rhs_start, (u64)rhs_len, &rhs_end))
		return true;

	return lhs_start < rhs_end && rhs_start < lhs_end;
}

static int pkm_kacs_token_release(struct inode *inode, struct file *file)
{
	struct pkm_kacs_token_file *tf = file->private_data;

	if (tf) {
		if (tf->token)
			kacs_rust_token_drop(tf->token);
		kfree(tf);
	}

	return 0;
}

static long pkm_kacs_token_query_prepare(struct pkm_kacs_token_file *tf,
					 struct kacs_query_args *args,
					 size_t *required_out,
					 bool *write_payload_out)
{
	size_t required = 0;
	u32 input_len;
	int ret;

	if (!tf || !tf->token || !args || !required_out || !write_payload_out)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_QUERY) != KACS_TOKEN_QUERY)
		return -EACCES;

	input_len = args->buf_len;
	*required_out = 0;
	*write_payload_out = false;

	ret = kacs_rust_token_query(tf->token, args->token_class, NULL, 0,
				    &required);
	if (ret)
		return ret;
	if (required > (size_t)~0U)
		return -EOVERFLOW;

	args->buf_len = (u32)required;
	*required_out = required;

	if (!args->buf_ptr || !input_len)
		return 0;
	if ((size_t)input_len < required)
		return -ERANGE;

	*write_payload_out = required > 0;
	return 0;
}

static long pkm_kacs_token_query_fill(struct pkm_kacs_token_file *tf,
				      const struct kacs_query_args *args,
				      void *out_buf, size_t required)
{
	size_t written = 0;
	int ret;

	if (!required)
		return 0;
	if (!out_buf)
		return -EFAULT;

	ret = kacs_rust_token_query(tf->token, args->token_class, out_buf,
				    required, &written);
	if (ret)
		return ret;
	if (written != required)
		return -EINVAL;

	return 0;
}

static long pkm_kacs_token_query_core(struct pkm_kacs_token_file *tf,
				      struct kacs_query_args *args,
				      void *out_buf)
{
	size_t required;
	bool write_payload;
	long ret;

	ret = pkm_kacs_token_query_prepare(tf, args, &required, &write_payload);
	if (ret)
		return ret;
	if (!write_payload)
		return 0;

	return pkm_kacs_token_query_fill(tf, args, out_buf, required);
}

static long pkm_kacs_require_tcb_for_token(const void *caller_token)
{
	if (!caller_token)
		return -EACCES;
	if (!kacs_rust_token_has_enabled_privilege(caller_token,
						   PKM_KACS_PRIVILEGE_SE_TCB))
		return -EACCES;
	if (!kacs_rust_token_mark_privileges_used(caller_token,
						  PKM_KACS_PRIVILEGE_SE_TCB))
		return -EACCES;

	return 0;
}

static long pkm_kacs_token_adjust_session_core(
	struct pkm_kacs_token_file *tf,
	const void *caller_token,
	u32 session_id)
{
	long ret;

	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ADJUST_SESSIONID) !=
	    KACS_TOKEN_ADJUST_SESSIONID)
		return -EACCES;

	ret = pkm_kacs_require_tcb_for_token(caller_token);
	if (ret)
		return ret;

	return kacs_rust_token_adjust_session_id(tf->token, session_id);
}

static long pkm_kacs_token_adjust_session_after_gate(
	struct pkm_kacs_token_file *tf,
	u32 session_id)
{
	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ADJUST_SESSIONID) !=
	    KACS_TOKEN_ADJUST_SESSIONID)
		return -EACCES;

	return kacs_rust_token_adjust_session_id(tf->token, session_id);
}

static long pkm_kacs_token_query_user(struct pkm_kacs_token_file *tf,
				      struct kacs_query_args __user *uargs)
{
	struct kacs_query_args args;
	size_t required;
	bool write_payload;
	u8 *payload = NULL;
	long ret;

	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_QUERY) != KACS_TOKEN_QUERY)
		return -EACCES;
	if (!uargs)
		return -EFAULT;
	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;

	ret = pkm_kacs_token_query_prepare(tf, &args, &required, &write_payload);
	if (!ret && write_payload) {
		if (pkm_kacs_ranges_overlap((u64)(unsigned long)uargs,
					    sizeof(*uargs), args.buf_ptr,
					    required)) {
			ret = -EINVAL;
			goto out;
		}

		payload = kmalloc(required, GFP_KERNEL);
		if (!payload) {
			ret = -ENOMEM;
		} else {
			ret = pkm_kacs_token_query_fill(tf, &args, payload,
							required);
			if (!ret &&
			    copy_to_user((void __user *)(unsigned long)args.buf_ptr,
					 payload, required))
				ret = -EFAULT;
		}
	}

	if (!ret || ret == -ERANGE || ret == -ENOMEM || ret == -EFAULT) {
		if (copy_to_user(uargs, &args, sizeof(args)))
			ret = -EFAULT;
	}
out:
	kfree(payload);
	return ret;
}

static long pkm_kacs_token_adjust_session_user(struct pkm_kacs_token_file *tf,
					       u32 __user *session_id_ptr)
{
	u32 session_id;
	long ret;

	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ADJUST_SESSIONID) !=
	    KACS_TOKEN_ADJUST_SESSIONID)
		return -EACCES;
	ret = pkm_kacs_require_tcb_for_token(pkm_kacs_current_primary_token_ptr());
	if (ret)
		return ret;
	if (!session_id_ptr)
		return -EFAULT;
	if (copy_from_user(&session_id, session_id_ptr, sizeof(session_id)))
		return -EFAULT;

	return pkm_kacs_token_adjust_session_after_gate(tf, session_id);
}

static long pkm_kacs_token_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct pkm_kacs_token_file *tf = file->private_data;

	if (!tf)
		return -EINVAL;

	switch (cmd) {
	case KACS_IOC_QUERY:
		return pkm_kacs_token_query_user(
			tf, (struct kacs_query_args __user *)arg);
	case KACS_IOC_ADJUST_SESSIONID:
		return pkm_kacs_token_adjust_session_user(
			tf, (u32 __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations pkm_kacs_token_fops = {
	.unlocked_ioctl = pkm_kacs_token_ioctl,
	.release = pkm_kacs_token_release,
};

static int pkm_kacs_token_to_fd(const void *token, u32 granted_access)
{
	struct pkm_kacs_token_file *tf;
	int fd;

	tf = kmalloc(sizeof(*tf), GFP_KERNEL);
	if (!tf) {
		kacs_rust_token_drop(token);
		return -ENOMEM;
	}

	tf->token = token;
	tf->access_mask = granted_access;

	fd = anon_inode_getfd("kacs-token", &pkm_kacs_token_fops, tf, O_CLOEXEC);
	if (fd < 0) {
		kacs_rust_token_drop(token);
		kfree(tf);
	}

	return fd;
}

static long pkm_kacs_open_token_fd_for_subject(const void *subject_token,
					       const void *target_token,
					       u32 access_mask)
{
	const void *token_ref;
	u32 granted = 0;
	int ret;

	ret = kacs_rust_token_open_check(subject_token, target_token, access_mask,
					 &granted);
	if (ret)
		return ret;

	token_ref = kacs_rust_token_clone(target_token);
	if (!token_ref)
		return -EACCES;

	return pkm_kacs_token_to_fd(token_ref, granted);
}

long pkm_kacs_kunit_open_token_fd_for_subject(const void *subject_token,
					      const void *target_token,
					      u32 access_mask)
{
	if (!access_mask)
		return -EINVAL;
	if (access_mask & ~PKM_KACS_TOKEN_OPEN_ALLOWED_MASK)
		return -EINVAL;

	return pkm_kacs_open_token_fd_for_subject(subject_token, target_token,
						  access_mask);
}

long pkm_kacs_open_self_token_internal(unsigned int flags, u32 access_mask)
{
	const void *subject_token;
	const void *target_token;

	if (flags & ~KACS_REAL_TOKEN)
		return -EINVAL;
	if (!access_mask)
		return -EINVAL;
	if (access_mask & ~PKM_KACS_TOKEN_OPEN_ALLOWED_MASK)
		return -EINVAL;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (flags & KACS_REAL_TOKEN)
		target_token = pkm_kacs_current_primary_token_ptr();
	else
		target_token = subject_token;

	if (!subject_token || !target_token)
		return -EACCES;

	return pkm_kacs_open_token_fd_for_subject(subject_token, target_token,
						  access_mask);
}

SYSCALL_DEFINE2(kacs_open_self_token, unsigned int, flags, u32, access_mask)
{
	return pkm_kacs_open_self_token_internal(flags, access_mask);
}

int pkm_kacs_token_fd_clone_token(int fd, const void **token_out,
				  u32 *access_mask_out)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	const void *token_ref;

	if (!token_out)
		return -EINVAL;

	*token_out = NULL;
	if (access_mask_out)
		*access_mask_out = 0;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	if (!tf || !tf->token) {
		fdput(f);
		return -EINVAL;
	}

	token_ref = kacs_rust_token_clone(tf->token);
	if (!token_ref) {
		fdput(f);
		return -EACCES;
	}

	*token_out = token_ref;
	if (access_mask_out)
		*access_mask_out = tf->access_mask;
	fdput(f);
	return 0;
}

int pkm_kacs_kunit_token_fd_snapshot(int fd, struct pkm_kacs_token_fd_view *out)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;

	if (!out)
		return -EINVAL;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	if (!tf) {
		fdput(f);
		return -EINVAL;
	}

	out->token = tf->token;
	out->access_mask = tf->access_mask;
	fdput(f);
	return 0;
}

long pkm_kacs_kunit_token_fd_query(int fd, struct kacs_query_args *args,
				   void *out_buf)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	long ret;

	if (!args)
		return -EINVAL;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	ret = pkm_kacs_token_query_core(tf, args, out_buf);
	fdput(f);
	return ret;
}

long pkm_kacs_kunit_token_fd_adjust_session_for_token(int fd,
						      const void *caller_token,
						      u32 session_id)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	long ret;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	ret = pkm_kacs_token_adjust_session_core(tf, caller_token, session_id);
	fdput(f);
	return ret;
}
