// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM token-fd and self-open surface.
 *
 * Slices 30 through 36 add token query and the first narrow mutation ioctls on
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
#define PKM_KACS_MAX_PRIVILEGE_ADJUST_ENTRIES 64U
#define PKM_KACS_ADJUST_GROUPS_RESET_INDEX 0xFFFFFFFFU
#define PKM_KACS_DEFAULT_INDEX_NO_CHANGE 0xFFFFFFFFU
#define PKM_KACS_MAX_DEFAULT_DACL_BYTES 65536U
#define PKM_KACS_MAX_RESTRICT_PAYLOAD_BYTES 65536U

struct pkm_kacs_token_file {
	const void *token;
	u32 access_mask;
};

static const struct file_operations pkm_kacs_token_fops;
static int pkm_kacs_token_to_fd(const void *token, u32 granted_access);
static long pkm_kacs_token_file_get(int fd, struct fd *held,
				    struct pkm_kacs_token_file **out);
static int pkm_kacs_bind_token_file_with_fixed_access(
	struct file *file, const void *target_token, u32 granted_access);

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

static long pkm_kacs_token_file_get(int fd, struct fd *held,
				    struct pkm_kacs_token_file **out)
{
	if (!held)
		return -EINVAL;

	if (out)
		*out = NULL;
	*held = fdget(fd);
	if (!fd_file(*held))
		return -EBADF;
	if (fd_file(*held)->f_op != &pkm_kacs_token_fops) {
		fdput(*held);
		return -EINVAL;
	}

	if (out)
		*out = fd_file(*held)->private_data;
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
						   KACS_SE_TCB_PRIVILEGE))
		return -EACCES;
	if (!kacs_rust_token_mark_privileges_used(caller_token,
						  KACS_SE_TCB_PRIVILEGE))
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

static long pkm_kacs_token_duplicate_core(
	struct pkm_kacs_token_file *tf,
	const void *subject_token,
	const void *creator_token,
	struct kacs_duplicate_args *args)
{
	const void *new_token = NULL;
	long fd;
	int ret;

	if (!tf || !tf->token || !args)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_DUPLICATE) != KACS_TOKEN_DUPLICATE)
		return -EACCES;
	if (!subject_token || !creator_token)
		return -EACCES;

	ret = kacs_rust_token_duplicate(tf->token, creator_token,
					 args->token_type,
					 args->impersonation_level,
					 &new_token);
	if (ret)
		return ret;
	if (!new_token)
		return -EACCES;

	fd = pkm_kacs_open_token_fd_for_subject_checked(subject_token, new_token,
							  args->access_mask);
	kacs_rust_token_drop(new_token);
	if (fd < 0)
		return fd;

	args->result_fd = (s32)fd;
	return 0;
}

static long pkm_kacs_token_link_core(const void *caller_token,
				     struct kacs_link_tokens_args *args)
{
	struct fd elevated_f = { 0 };
	struct fd filtered_f = { 0 };
	struct pkm_kacs_token_file *elevated_tf;
	struct pkm_kacs_token_file *filtered_tf;
	long ret;

	if (!caller_token || !args)
		return -EINVAL;

	ret = pkm_kacs_require_tcb_for_token(caller_token);
	if (ret)
		return ret;

	ret = pkm_kacs_token_file_get(args->elevated_fd, &elevated_f,
				      &elevated_tf);
	if (ret)
		return ret;

	ret = pkm_kacs_token_file_get(args->filtered_fd, &filtered_f,
				      &filtered_tf);
	if (ret) {
		fdput(elevated_f);
		return ret;
	}

	if (!elevated_tf || !filtered_tf || !elevated_tf->token ||
	    !filtered_tf->token) {
		ret = -EINVAL;
		goto out;
	}
	if ((elevated_tf->access_mask & KACS_TOKEN_DUPLICATE) !=
	    KACS_TOKEN_DUPLICATE ||
	    (filtered_tf->access_mask & KACS_TOKEN_DUPLICATE) !=
	    KACS_TOKEN_DUPLICATE) {
		ret = -EACCES;
		goto out;
	}

	ret = kacs_rust_token_link_tokens(elevated_tf->token, filtered_tf->token,
					  args->session_id);
out:
	fdput(filtered_f);
	fdput(elevated_f);
	return ret;
}

static long pkm_kacs_token_get_linked_core(
	struct pkm_kacs_token_file *tf,
	const void *caller_token,
	struct kacs_get_linked_token_args *args)
{
	const void *linked_token = NULL;
	long fd;
	int ret;
	bool privileged = false;

	if (!tf || !tf->token || !args)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_QUERY) != KACS_TOKEN_QUERY)
		return -EACCES;

	if (caller_token &&
	    kacs_rust_token_has_enabled_privilege(caller_token,
						  KACS_SE_TCB_PRIVILEGE)) {
		if (!kacs_rust_token_mark_privileges_used(
			    caller_token, KACS_SE_TCB_PRIVILEGE))
			return -EACCES;

		ret = kacs_rust_token_get_linked_actual(tf->token, &linked_token);
		privileged = true;
	} else {
		ret = kacs_rust_token_get_linked_query_copy(tf->token,
							    &linked_token);
	}
	if (ret)
		return ret;
	if (!linked_token)
		return -EACCES;

	fd = pkm_kacs_token_to_fd(linked_token,
				  privileged ? KACS_TOKEN_ALL_ACCESS :
					       KACS_TOKEN_QUERY);
	if (fd < 0)
		return fd;

	args->result_fd = (s32)fd;
	return 0;
}

static long pkm_kacs_token_install_core(
	struct pkm_kacs_token_file *tf,
	const void *caller_primary_token)
{
	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ASSIGN_PRIMARY) !=
	    KACS_TOKEN_ASSIGN_PRIMARY)
		return -EACCES;
	if (!caller_primary_token)
		return -EACCES;
	if (!kacs_rust_token_is_primary(tf->token))
		return -EINVAL;
	if (!kacs_rust_token_has_enabled_privilege(
		    caller_primary_token,
		    KACS_SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE))
		return -EACCES;
	if (!kacs_rust_token_mark_privileges_used(
		    caller_primary_token,
		    KACS_SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE))
		return -EACCES;

	return pkm_kacs_install_current_primary_token(tf->token);
}

static long pkm_kacs_impersonate_token_core(const void *client_token,
					    const void *server_primary_token);

static long pkm_kacs_token_impersonate_core(
	struct pkm_kacs_token_file *tf,
	const void *server_primary_token)
{
	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_IMPERSONATE) != KACS_TOKEN_IMPERSONATE)
		return -EACCES;

	return pkm_kacs_impersonate_token_core(tf->token,
					       server_primary_token);
}

static long pkm_kacs_impersonate_token_core(const void *client_token,
					    const void *server_primary_token)
{
	const void *effective_token = NULL;
	u32 effective_level = 0;
	u32 used_impersonate_privilege = 0;
	long ret;

	if (!client_token || !server_primary_token)
		return -EACCES;

	ret = kacs_rust_token_impersonation_gate(server_primary_token, client_token,
						 &effective_level,
						 &used_impersonate_privilege);
	if (ret)
		return ret;

	if (used_impersonate_privilege &&
	    !kacs_rust_token_mark_privileges_used(
		    server_primary_token, KACS_SE_IMPERSONATE_PRIVILEGE))
		return -EACCES;

	ret = kacs_rust_token_clone_with_impersonation_level(
		client_token, effective_level, &effective_token);
	if (ret)
		return ret;
	if (!effective_token)
		return -EACCES;

	ret = pkm_kacs_install_impersonation_token(effective_token);
	if (ret)
		kacs_rust_token_drop(effective_token);
	return ret;
}

static long pkm_kacs_token_adjust_privs_core(
	struct pkm_kacs_token_file *tf,
	struct kacs_adjust_privs_args *args,
	const struct kacs_priv_entry *entries)
{
	u64 previous_enabled = 0;
	int ret;

	if (!tf || !tf->token || !args)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ADJUST_PRIVS) !=
	    KACS_TOKEN_ADJUST_PRIVS)
		return -EACCES;
	if (args->_pad != 0)
		return -EINVAL;
	if (args->count == 0 ||
	    args->count > PKM_KACS_MAX_PRIVILEGE_ADJUST_ENTRIES)
		return -EINVAL;
	if (!entries)
		return -EINVAL;

	ret = kacs_rust_token_adjust_privs(
		tf->token,
		(const struct pkm_kacs_priv_adjust_entry *)entries,
		args->count, &previous_enabled);
	if (ret)
		return ret;

	args->previous_enabled = previous_enabled;
	return 0;
}

static long pkm_kacs_token_adjust_groups_core(
	struct pkm_kacs_token_file *tf,
	struct kacs_adjust_groups_args *args,
	const struct kacs_group_entry *entries)
{
	u64 previous_state[KACS_TOKEN_GROUP_MASK_WORDS] = {0};
	int ret;

	if (!tf || !tf->token || !args)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ADJUST_GROUPS) !=
	    KACS_TOKEN_ADJUST_GROUPS)
		return -EACCES;
	if (args->_pad != 0)
		return -EINVAL;
	if (args->count == 0 || args->count > KACS_TOKEN_MAX_GROUPS)
		return -EINVAL;
	if (!entries)
		return -EINVAL;

	ret = kacs_rust_token_adjust_groups(
		tf->token,
		(const struct pkm_kacs_group_adjust_entry *)entries,
		args->count, previous_state);
	if (ret)
		return ret;

	memcpy(args->previous_state, previous_state, sizeof(previous_state));
	return 0;
}

static long pkm_kacs_token_restrict_core(
	struct pkm_kacs_token_file *tf,
	const void *subject_token,
	const void *creator_token,
	struct kacs_restrict_args *args,
	const void *payload)
{
	const void *new_token = NULL;
	long fd;
	int ret;

	if (!tf || !tf->token || !creator_token || !args)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_DUPLICATE) != KACS_TOKEN_DUPLICATE)
		return -EACCES;
	if ((args->flags & ~KACS_TOKEN_RESTRICT_WRITE_RESTRICTED) != 0)
		return -EINVAL;
	if (args->data_len && !payload)
		return -EINVAL;
	(void)subject_token;

	ret = kacs_rust_token_restrict(tf->token, creator_token,
					 args->privs_to_delete, args->flags,
					 payload, args->data_len,
					 args->num_deny_indices,
					 args->num_restrict_sids,
					 &new_token);
	if (ret)
		return ret;
	if (!new_token)
		return -EACCES;

	fd = pkm_kacs_token_to_fd(new_token, tf->access_mask);
	if (fd < 0)
		return fd;

	args->result_fd = (s32)fd;
	return 0;
}

static long pkm_kacs_token_adjust_default_core(
	struct pkm_kacs_token_file *tf,
	const struct kacs_adjust_default_args *args,
	const void *dacl_bytes)
{
	u32 owner_index;
	u32 group_index;
	u32 change_dacl;

	if (!tf || !tf->token || !args)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ADJUST_DEFAULT) !=
	    KACS_TOKEN_ADJUST_DEFAULT)
		return -EACCES;
	if (!args->dacl_ptr && args->dacl_len)
		return -EINVAL;
	if (args->dacl_len > PKM_KACS_MAX_DEFAULT_DACL_BYTES)
		return -EINVAL;
	if (args->dacl_ptr && args->dacl_len && !dacl_bytes)
		return -EINVAL;

	owner_index = args->owner_index == 0xFFFFU ?
		PKM_KACS_DEFAULT_INDEX_NO_CHANGE : (u32)args->owner_index;
	group_index = args->group_index == 0xFFFFU ?
		PKM_KACS_DEFAULT_INDEX_NO_CHANGE : (u32)args->group_index;
	change_dacl = args->dacl_ptr ? 1U : 0U;

	return kacs_rust_token_adjust_default(tf->token, owner_index,
					      group_index, dacl_bytes,
					      args->dacl_len, change_dacl);
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

static long pkm_kacs_token_duplicate_user(
	struct pkm_kacs_token_file *tf,
	struct kacs_duplicate_args __user *uargs)
{
	struct kacs_duplicate_args args;
	long ret;

	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_DUPLICATE) != KACS_TOKEN_DUPLICATE)
		return -EACCES;
	if (!uargs)
		return -EFAULT;
	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;

	ret = pkm_kacs_token_duplicate_core(
		tf, pkm_kacs_current_effective_token_ptr(),
		pkm_kacs_current_primary_token_ptr(), &args);
	if (!ret && copy_to_user(uargs, &args, sizeof(args))) {
		/*
		 * The core already installed result_fd into the caller's fd
		 * table; revoke it rather than leak an anon-inode + token ref
		 * on the writeback fault.
		 */
		if (args.result_fd >= 0)
			close_fd((unsigned int)args.result_fd);
		return -EFAULT;
	}
	return ret;
}

static long pkm_kacs_token_link_user(struct pkm_kacs_token_file *tf,
				     struct kacs_link_tokens_args __user *uargs)
{
	struct kacs_link_tokens_args args;

	if (!tf)
		return -EINVAL;
	if (!uargs)
		return -EFAULT;
	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;

	return pkm_kacs_token_link_core(pkm_kacs_current_primary_token_ptr(),
					&args);
}

static long pkm_kacs_token_get_linked_user(
	struct pkm_kacs_token_file *tf,
	struct kacs_get_linked_token_args __user *uargs)
{
	struct kacs_get_linked_token_args args;
	long ret;

	if (!tf)
		return -EINVAL;
	if (!uargs)
		return -EFAULT;
	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;

	ret = pkm_kacs_token_get_linked_core(tf,
					     pkm_kacs_current_primary_token_ptr(),
					     &args);
	if (!ret && copy_to_user(uargs, &args, sizeof(args))) {
		/* Revoke the installed fd; see duplicate_user above. */
		if (args.result_fd >= 0)
			close_fd((unsigned int)args.result_fd);
		return -EFAULT;
	}
	return ret;
}

static long pkm_kacs_token_impersonate_user(struct pkm_kacs_token_file *tf)
{
	return pkm_kacs_token_impersonate_core(
		tf, pkm_kacs_current_primary_token_ptr());
}

static long pkm_kacs_token_install_user(struct pkm_kacs_token_file *tf)
{
	return pkm_kacs_token_install_core(tf,
					   pkm_kacs_current_primary_token_ptr());
}

static long pkm_kacs_token_adjust_privs_user(
	struct pkm_kacs_token_file *tf,
	struct kacs_adjust_privs_args __user *uargs)
{
	struct kacs_adjust_privs_args args;
	struct kacs_priv_entry *entries;
	size_t entries_size;
	long ret;

	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ADJUST_PRIVS) !=
	    KACS_TOKEN_ADJUST_PRIVS)
		return -EACCES;
	if (!uargs)
		return -EFAULT;
	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;
	if (args._pad != 0 || args.count == 0 ||
	    args.count > PKM_KACS_MAX_PRIVILEGE_ADJUST_ENTRIES)
		return -EINVAL;

	entries_size = args.count * sizeof(*entries);
	entries = kmalloc(entries_size, GFP_KERNEL);
	if (!entries)
		return -ENOMEM;
	if (copy_from_user(entries, (void __user *)(unsigned long)args.data_ptr,
			   entries_size)) {
		kfree(entries);
		return -EFAULT;
	}

	ret = pkm_kacs_token_adjust_privs_core(tf, &args, entries);
	kfree(entries);
	if (!ret && copy_to_user(uargs, &args, sizeof(args)))
		return -EFAULT;
	return ret;
}

static long pkm_kacs_token_adjust_groups_user(
	struct pkm_kacs_token_file *tf,
	struct kacs_adjust_groups_args __user *uargs)
{
	struct kacs_adjust_groups_args args;
	struct kacs_group_entry *entries;
	size_t entries_size;
	long ret;

	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ADJUST_GROUPS) !=
	    KACS_TOKEN_ADJUST_GROUPS)
		return -EACCES;
	if (!uargs)
		return -EFAULT;
	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;
	if (args._pad != 0 || args.count == 0 ||
	    args.count > KACS_TOKEN_MAX_GROUPS)
		return -EINVAL;

	entries_size = args.count * sizeof(*entries);
	entries = kmalloc(entries_size, GFP_KERNEL);
	if (!entries)
		return -ENOMEM;
	if (copy_from_user(entries, (void __user *)(unsigned long)args.data_ptr,
			   entries_size)) {
		kfree(entries);
		return -EFAULT;
	}

	ret = pkm_kacs_token_adjust_groups_core(tf, &args, entries);
	kfree(entries);
	if (!ret && copy_to_user(uargs, &args, sizeof(args)))
		return -EFAULT;
	return ret;
}

static long pkm_kacs_token_adjust_default_user(
	struct pkm_kacs_token_file *tf,
	struct kacs_adjust_default_args __user *uargs)
{
	struct kacs_adjust_default_args args;
	void *dacl = NULL;
	long ret;

	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_ADJUST_DEFAULT) !=
	    KACS_TOKEN_ADJUST_DEFAULT)
		return -EACCES;
	if (!uargs)
		return -EFAULT;
	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;
	if (!args.dacl_ptr && args.dacl_len)
		return -EINVAL;
	if (args.dacl_len > PKM_KACS_MAX_DEFAULT_DACL_BYTES)
		return -EINVAL;

	if (args.dacl_ptr && args.dacl_len) {
		dacl = kmalloc(args.dacl_len, GFP_KERNEL);
		if (!dacl)
			return -ENOMEM;
		if (copy_from_user(dacl,
				   (void __user *)(unsigned long)args.dacl_ptr,
				   args.dacl_len)) {
			kfree(dacl);
			return -EFAULT;
		}
	}

	ret = pkm_kacs_token_adjust_default_core(tf, &args, dacl);
	kfree(dacl);
	return ret;
}

static long pkm_kacs_token_restrict_user(
	struct pkm_kacs_token_file *tf,
	struct kacs_restrict_args __user *uargs)
{
	struct kacs_restrict_args args;
	void *payload = NULL;
	long ret;

	if (!tf || !tf->token)
		return -EINVAL;
	if ((tf->access_mask & KACS_TOKEN_DUPLICATE) != KACS_TOKEN_DUPLICATE)
		return -EACCES;
	if (!uargs)
		return -EFAULT;
	if (copy_from_user(&args, uargs, sizeof(args)))
		return -EFAULT;
	if ((args.flags & ~KACS_TOKEN_RESTRICT_WRITE_RESTRICTED) != 0)
		return -EINVAL;
	if (args.data_len > PKM_KACS_MAX_RESTRICT_PAYLOAD_BYTES)
		return -EINVAL;

	if (args.data_len) {
		payload = kmalloc(args.data_len, GFP_KERNEL);
		if (!payload)
			return -ENOMEM;
		if (copy_from_user(payload,
				   (void __user *)(unsigned long)args.data_ptr,
				   args.data_len)) {
			kfree(payload);
			return -EFAULT;
		}
	}

	ret = pkm_kacs_token_restrict_core(
		tf, pkm_kacs_current_effective_token_ptr(),
		pkm_kacs_current_effective_token_ptr(), &args, payload);
	kfree(payload);
	if (!ret && copy_to_user(uargs, &args, sizeof(args))) {
		/* Revoke the installed fd; see duplicate_user above. */
		if (args.result_fd >= 0)
			close_fd((unsigned int)args.result_fd);
		return -EFAULT;
	}
	return ret;
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
	case KACS_IOC_ADJUST_PRIVS:
		return pkm_kacs_token_adjust_privs_user(
			tf, (struct kacs_adjust_privs_args __user *)arg);
	case KACS_IOC_ADJUST_GROUPS:
		return pkm_kacs_token_adjust_groups_user(
			tf, (struct kacs_adjust_groups_args __user *)arg);
	case KACS_IOC_DUPLICATE:
		return pkm_kacs_token_duplicate_user(
			tf, (struct kacs_duplicate_args __user *)arg);
	case KACS_IOC_INSTALL:
		return pkm_kacs_token_install_user(tf);
	case KACS_IOC_RESTRICT:
		return pkm_kacs_token_restrict_user(
			tf, (struct kacs_restrict_args __user *)arg);
	case KACS_IOC_LINK_TOKENS:
		return pkm_kacs_token_link_user(
			tf, (struct kacs_link_tokens_args __user *)arg);
	case KACS_IOC_GET_LINKED_TOKEN:
		return pkm_kacs_token_get_linked_user(
			tf, (struct kacs_get_linked_token_args __user *)arg);
	case KACS_IOC_IMPERSONATE:
		return pkm_kacs_token_impersonate_user(tf);
	case KACS_IOC_ADJUST_DEFAULT:
		return pkm_kacs_token_adjust_default_user(
			tf, (struct kacs_adjust_default_args __user *)arg);
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

static int pkm_kacs_bind_token_file_with_fixed_access(
	struct file *file, const void *target_token, u32 granted_access)
{
	struct pkm_kacs_token_file *tf;
	const void *token_ref;

	if (!file || !target_token || !granted_access)
		return -EACCES;

	token_ref = kacs_rust_token_clone(target_token);
	if (!token_ref)
		return -EACCES;

	tf = kmalloc(sizeof(*tf), GFP_KERNEL);
	if (!tf) {
		kacs_rust_token_drop(token_ref);
		return -ENOMEM;
	}

	tf->token = token_ref;
	tf->access_mask = granted_access;

	replace_fops(file, &pkm_kacs_token_fops);
	file->private_data = tf;
	return 0;
}

long pkm_kacs_open_token_fd_with_fixed_access(const void *target_token,
					      u32 granted_access)
{
	const void *token_ref;

	if (!target_token || !granted_access)
		return -EACCES;

	token_ref = kacs_rust_token_clone(target_token);
	if (!token_ref)
		return -EACCES;

	return pkm_kacs_token_to_fd(token_ref, granted_access);
}

int pkm_kacs_bind_query_token_file(struct file *file, const void *target_token)
{
	return pkm_kacs_bind_token_file_with_fixed_access(
		file, target_token, KACS_TOKEN_QUERY);
}

int pkm_kacs_validate_token_open_access_mask(u32 access_mask)
{
	if (!access_mask)
		return -EINVAL;
	if (access_mask & ~PKM_KACS_TOKEN_OPEN_ALLOWED_MASK)
		return -EINVAL;

	return 0;
}

static long pkm_kacs_open_token_fd_for_subject(const void *subject_token,
					       const void *target_token,
					       u32 access_mask)
{
	u32 pip_type = 0;
	u32 pip_trust = 0;
	int ret;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	return pkm_kacs_open_token_fd_for_subject_checked_with_pip(
		subject_token, target_token, access_mask, pip_type, pip_trust);
}

long pkm_kacs_open_token_fd_for_subject_checked_with_pip(
	const void *subject_token, const void *target_token, u32 access_mask,
	u32 pip_type, u32 pip_trust)
{
	const void *token_ref;
	u32 granted = 0;
	int ret;

	ret = pkm_kacs_validate_token_open_access_mask(access_mask);
	if (ret)
		return ret;

	ret = kacs_rust_token_open_check(subject_token, target_token, access_mask,
					 pip_type, pip_trust, &granted);
	if (ret)
		return ret;

	token_ref = kacs_rust_token_clone(target_token);
	if (!token_ref)
		return -EACCES;

	return pkm_kacs_token_to_fd(token_ref, granted);
}

long pkm_kacs_open_token_fd_for_subject_checked(const void *subject_token,
						const void *target_token,
						u32 access_mask)
{
	int ret;

	ret = pkm_kacs_validate_token_open_access_mask(access_mask);
	if (ret)
		return ret;

	return pkm_kacs_open_token_fd_for_subject(subject_token, target_token,
						  access_mask);
}

long pkm_kacs_impersonate_token_for_current(const void *client_token)
{
	return pkm_kacs_impersonate_token_core(client_token,
					       pkm_kacs_current_primary_token_ptr());
}

long pkm_kacs_kunit_open_token_fd_for_subject(const void *subject_token,
					      const void *target_token,
					      u32 access_mask)
{
	return pkm_kacs_open_token_fd_for_subject_checked(subject_token,
							  target_token,
							  access_mask);
}

long pkm_kacs_open_self_token_internal(unsigned int flags, u32 access_mask)
{
	const void *subject_token;
	const void *target_token;
	int ret;

	if (flags & ~KACS_TOKEN_OPEN_REAL)
		return -EINVAL;
	ret = pkm_kacs_validate_token_open_access_mask(access_mask);
	if (ret)
		return ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (flags & KACS_TOKEN_OPEN_REAL)
		target_token = pkm_kacs_current_primary_token_ptr();
	else
		target_token = subject_token;

	if (!subject_token || !target_token)
		return -EACCES;

	return pkm_kacs_open_token_fd_for_subject_checked(subject_token,
							  target_token,
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

long pkm_kacs_kunit_token_fd_adjust_privs(
	int fd,
	struct kacs_adjust_privs_args *args,
	const struct kacs_priv_entry *entries)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	long ret;

	if (!args || !entries)
		return -EINVAL;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	ret = pkm_kacs_token_adjust_privs_core(tf, args, entries);
	fdput(f);
	return ret;
}

long pkm_kacs_kunit_token_fd_duplicate(
	int fd,
	const void *subject_token,
	const void *creator_token,
	struct kacs_duplicate_args *args)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	long ret;

	if (!args || !subject_token || !creator_token)
		return -EINVAL;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	ret = pkm_kacs_token_duplicate_core(tf, subject_token, creator_token,
					    args);
	fdput(f);
	return ret;
}

long pkm_kacs_kunit_token_fd_link(int fd, const void *caller_token,
				  struct kacs_link_tokens_args *args)
{
	struct fd f;
	long ret;

	if (!args || !caller_token)
		return -EINVAL;

	ret = pkm_kacs_token_file_get(fd, &f, NULL);
	if (ret)
		return ret;

	ret = pkm_kacs_token_link_core(caller_token, args);
	fdput(f);
	return ret;
}

long pkm_kacs_kunit_token_fd_get_linked(
	int fd, const void *caller_token,
	struct kacs_get_linked_token_args *args)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	long ret;

	if (!args)
		return -EINVAL;

	ret = pkm_kacs_token_file_get(fd, &f, &tf);
	if (ret)
		return ret;

	ret = pkm_kacs_token_get_linked_core(tf, caller_token, args);
	fdput(f);
	return ret;
}

long pkm_kacs_kunit_token_fd_impersonate(int fd, const void *server_token)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	long ret;

	if (!server_token)
		return -EINVAL;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	ret = pkm_kacs_token_impersonate_core(tf, server_token);
	fdput(f);
	return ret;
}

long pkm_kacs_kunit_token_fd_install(int fd, const void *caller_primary_token)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	long ret;

	if (!caller_primary_token)
		return -EINVAL;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	ret = pkm_kacs_token_install_core(tf, caller_primary_token);
	fdput(f);
	return ret;
}

long pkm_kacs_kunit_token_fd_restrict(
	int fd,
	const void *subject_token,
	const void *creator_token,
	struct kacs_restrict_args *args,
	const void *payload)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	long ret;

	if (!subject_token || !creator_token || !args)
		return -EINVAL;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	ret = pkm_kacs_token_restrict_core(tf, subject_token, creator_token,
					   args, payload);
	fdput(f);
	return ret;
}

long pkm_kacs_kunit_token_fd_adjust_groups(
	int fd,
	struct kacs_adjust_groups_args *args,
	const struct kacs_group_entry *entries)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;
	long ret;

	if (!args || !entries)
		return -EINVAL;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	ret = pkm_kacs_token_adjust_groups_core(tf, args, entries);
	fdput(f);
	return ret;
}

long pkm_kacs_kunit_token_fd_adjust_default(
	int fd,
	const struct kacs_adjust_default_args *args,
	const void *dacl_bytes)
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
	ret = pkm_kacs_token_adjust_default_core(tf, args, dacl_bytes);
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

long pkm_kacs_kunit_token_fd_ioctl(int fd, unsigned int cmd, unsigned long arg)
{
	struct fd f;
	long ret;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	ret = fd_file(f)->f_op->unlocked_ioctl(fd_file(f), cmd, arg);
	fdput(f);
	return ret;
}
