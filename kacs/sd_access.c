// SPDX-License-Identifier: GPL-2.0-only

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/pidfd.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <pkm/ipc.h>
#include <pkm/sd.h>
#include <pkm/token.h>

#include "caap_cache.h"
#include "file_access.h"
#include "file_sd_cache.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "process_access.h"
#include "process_state.h"
#include "ipc.h"
#include "sd_access.h"
#include "token_fd.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

#define PKM_KACS_SD_SUPPORTED_INFO                                            \
	(KACS_SECINFO_OWNER | KACS_SECINFO_GROUP | KACS_SECINFO_DACL |      \
	 KACS_SECINFO_SACL | KACS_SECINFO_LABEL)
#define PKM_KACS_SD_ALLOWED_AT_FLAGS (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)

long pkm_kacs_validate_sd_security_info(u32 security_info)
{
	if (security_info == 0 ||
	    (security_info & ~PKM_KACS_SD_SUPPORTED_INFO) != 0)
		return -EINVAL;
	if ((security_info & KACS_SECINFO_SACL) != 0 &&
	    (security_info & KACS_SECINFO_LABEL) != 0)
		return -EINVAL;

	return 0;
}

long pkm_kacs_get_sd_required_access(u32 security_info,
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
	     (KACS_SECINFO_OWNER | KACS_SECINFO_GROUP |
	      KACS_SECINFO_DACL | KACS_SECINFO_LABEL)) != 0)
		desired_access |= KACS_ACCESS_READ_CONTROL;
	if ((security_info & KACS_SECINFO_SACL) != 0)
		desired_access |= KACS_ACCESS_ACCESS_SYSTEM_SECURITY;

	*desired_access_out = desired_access;
	return 0;
}

long pkm_kacs_set_sd_required_access(u32 security_info,
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
	     (KACS_SECINFO_OWNER | KACS_SECINFO_GROUP |
	      KACS_SECINFO_LABEL)) != 0)
		desired_access |= KACS_ACCESS_WRITE_OWNER;
	if ((security_info & KACS_SECINFO_DACL) != 0)
		desired_access |= KACS_ACCESS_WRITE_DAC;
	if ((security_info & KACS_SECINFO_SACL) != 0)
		desired_access |= KACS_ACCESS_ACCESS_SYSTEM_SECURITY;

	*desired_access_out = desired_access;
	return 0;
}

long pkm_kacs_query_file_sd_bytes_core(
	const void *subject_token, const struct pkm_kacs_inode_sd_cache *cache,
	u32 security_info, const void *caap_cache, const u8 **out_sd_ptr,
	size_t *out_sd_len)
{
	u32 desired_access;
	u32 granted = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
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

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	/*
	 * The live policy set, not an empty one.
	 *
	 * With EMPTY_POLICIES an object whose SACL carries a scoped-policy ACE
	 * found no matching policy, and CAAP treats referenced-but-absent as a
	 * failure: it falls back to the recovery policy, which grants
	 * Administrators, SYSTEM and OWNER RIGHTS GENERIC_ALL. So a central
	 * access policy written to *restrict* administrators was replaced, on
	 * this path, by one granting them everything.
	 */
	ret = kacs_rust_check_cached_file_sd_with_intent_audit_caap(
		subject_token, cache->bytes, cache->len, &cache->layout,
		desired_access, 0, pip_type, pip_trust, caap_cache, &granted,
		NULL);
	if (ret)
		return ret;

	return kacs_rust_query_cached_file_sd_subset(
		cache->bytes, cache->len, &cache->layout, security_info,
		out_sd_ptr, out_sd_len);
}

long pkm_kacs_prepare_new_file_sd_core(
	const void *subject_token, const struct pkm_kacs_inode_sd_cache *cache,
	u32 security_info, const u8 *input_sd_ptr, size_t input_sd_len,
	bool authorize_live, const void *caap_cache, const u8 **new_sd_ptr,
	size_t *new_sd_len)
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
			u32 pip_type = 0;
			u32 pip_trust = 0;

			ret = pkm_kacs_set_sd_required_access(security_info,
							      &desired_access);
			if (ret)
				return ret;
			ret = pkm_kacs_current_pip_context(&pip_type,
							   &pip_trust);
			if (ret)
				return ret;
			/* See the note in the query path above. This is the
			 * more serious of the two: it is the path by which a
			 * descriptor is rewritten, so an administrator the
			 * policy meant to exclude reached WRITE_DAC and could
			 * rewrite the DACL -- after which the policy is moot
			 * everywhere else too. */
			ret = kacs_rust_check_cached_file_sd_with_intent_audit_caap(
				subject_token, cache->bytes, cache->len,
				&cache->layout, desired_access,
				KACS_RESTORE_INTENT, pip_type, pip_trust,
				caap_cache, &granted, NULL);
			if (ret)
				return ret;
		}

		return kacs_rust_merge_cached_file_sd(
			subject_token, cache->bytes, cache->len, &cache->layout,
			security_info, input_sd_ptr, input_sd_len,
			authorize_live ? 1U : 0U, new_sd_ptr, new_sd_len);
	}

	if (!kacs_rust_token_has_enabled_privilege(subject_token,
						   KACS_SE_RESTORE_PRIVILEGE))
		return -EACCES;

	return kacs_rust_build_replacement_file_sd(subject_token, security_info,
						   input_sd_ptr, input_sd_len,
						   new_sd_ptr, new_sd_len);
}

static long pkm_kacs_validate_empty_path_flags(u32 flags)
{
	if ((flags & ~PKM_KACS_SD_ALLOWED_AT_FLAGS) != 0)
		return -EINVAL;
	if ((flags & AT_EMPTY_PATH) == 0)
		return -EOPNOTSUPP;

	return 0;
}

static long pkm_kacs_validate_empty_path_first_char(bool path_present,
						    char first_ch, u32 flags)
{
	long ret;

	ret = pkm_kacs_validate_empty_path_flags(flags);
	if (ret)
		return ret;
	if (!path_present)
		return -EFAULT;
	if (first_ch != '\0')
		return -EOPNOTSUPP;

	return 0;
}

static long pkm_kacs_validate_empty_path_target(const char __user *path,
						u32 flags)
{
	char ch = '\0';
	long ret;

	ret = pkm_kacs_validate_empty_path_flags(flags);
	if (ret)
		return ret;
	if (!path)
		return -EFAULT;
	if (copy_from_user(&ch, path, sizeof(ch)))
		return -EFAULT;

	return pkm_kacs_validate_empty_path_first_char(true, ch, flags);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static long pkm_kacs_validate_empty_path_target_kernel(const char *path,
						       u32 flags)
{
	return pkm_kacs_validate_empty_path_first_char(path != NULL,
						      path ? path[0] : '\0',
						      flags);
}
#endif


long pkm_kacs_path_sd_lookup_flags(u32 flags, unsigned int *lookup_flags_out)
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

static long pkm_kacs_resolve_pidfd_process_target_checked(
	int dirfd,
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

	if (!subject_token_out || !caller_state_out || !task_out ||
	    !target_state_out || !self_target_out)
		return -EINVAL;

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

static long pkm_kacs_resolve_pidfd_process_target(
	int dirfd, const char __user *path, u32 flags,
	const void **subject_token_out,
	struct pkm_kacs_process_state **caller_state_out,
	struct task_struct **task_out,
	struct pkm_kacs_process_state **target_state_out, bool *self_target_out)
{
	long ret;

	ret = pkm_kacs_validate_empty_path_target(path, flags);
	if (ret)
		return ret;

	return pkm_kacs_resolve_pidfd_process_target_checked(
		dirfd, subject_token_out, caller_state_out, task_out,
		target_state_out, self_target_out);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_resolve_process_sd_pidfd_target(int dirfd,
						    const char *path,
						    u32 flags,
						    bool *self_target_out)
{
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	struct task_struct *task;
	bool self_target;
	long ret;

	if (!self_target_out)
		return -EINVAL;

	*self_target_out = false;
	ret = pkm_kacs_validate_empty_path_first_char(path != NULL,
						     path ? path[0] : '\0',
						     flags);
	if (ret)
		return ret;

	ret = pkm_kacs_resolve_pidfd_process_target_checked(
		dirfd, &subject_token, &caller_state, &task, &target_state,
		&self_target);
	if (ret)
		return ret;

	*self_target_out = self_target;
	put_task_struct(task);
	return 0;
}
#endif

static bool pkm_kacs_file_is_pidfd(const struct file *file)
{
	struct pid *pid;

	if (!file)
		return false;

	pid = pidfd_pid((struct file *)file);
	return !IS_ERR(pid);
}

static long pkm_kacs_resolve_file_target_checked(
	int dirfd, const void **subject_token_out, struct file **file_out)
{
	const void *subject_token;
	struct file *file;

	if (!subject_token_out || !file_out)
		return -EINVAL;

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

static long pkm_kacs_resolve_file_target(
	int dirfd, const char __user *path, u32 flags,
	const void **subject_token_out, struct file **file_out)
{
	long ret;

	ret = pkm_kacs_validate_empty_path_target(path, flags);
	if (ret)
		return ret;

	return pkm_kacs_resolve_file_target_checked(
		dirfd, subject_token_out, file_out);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static long pkm_kacs_resolve_file_target_kernel(
	int dirfd, const char *path, u32 flags,
	const void **subject_token_out, struct file **file_out)
{
	long ret;

	ret = pkm_kacs_validate_empty_path_target_kernel(path, flags);
	if (ret)
		return ret;

	return pkm_kacs_resolve_file_target_checked(
		dirfd, subject_token_out, file_out);
}
#endif

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

static long pkm_kacs_resolve_tokenfd_target_checked(
	int dirfd, const void **subject_token_out, const void **target_token_out)
{
	const void *subject_token;
	const void *target_token = NULL;
	long ret;

	if (!subject_token_out || !target_token_out)
		return -EINVAL;

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

static long pkm_kacs_resolve_tokenfd_target(int dirfd,
					    const char __user *path,
					    u32 flags,
					    const void **subject_token_out,
					    const void **target_token_out)
{
	long ret;

	ret = pkm_kacs_validate_empty_path_target(path, flags);
	if (ret)
		return ret;

	return pkm_kacs_resolve_tokenfd_target_checked(
		dirfd, subject_token_out, target_token_out);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static long pkm_kacs_resolve_tokenfd_target_kernel(
	int dirfd, const char *path, u32 flags, const void **subject_token_out,
	const void **target_token_out)
{
	long ret;

	ret = pkm_kacs_validate_empty_path_target_kernel(path, flags);
	if (ret)
		return ret;

	return pkm_kacs_resolve_tokenfd_target_checked(
		dirfd, subject_token_out, target_token_out);
}
#endif

long pkm_kacs_query_token_sd_core(const void *subject_token,
				  const void *target_token,
				  u32 security_info,
				  const u8 **out_sd_ptr,
				  size_t *out_sd_len)
{
	u32 desired_access;
	u32 granted = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long ret;

	if (!subject_token || !target_token || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	ret = pkm_kacs_get_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	ret = kacs_rust_check_token_sd_with_intent(subject_token, target_token,
						   desired_access, 0,
						   pip_type, pip_trust,
						   &granted);
	if (ret) {
		trace_kacs_sd_query(security_info, desired_access, granted,
				    KACS_SDS_KIND_TOKEN, 0,
				    KACS_SDS_ACCESS_DENIED, ret);
		return ret;
	}

	ret = kacs_rust_query_token_sd_subset(target_token, security_info,
					      out_sd_ptr, out_sd_len);
	trace_kacs_sd_query(security_info, desired_access, granted,
			    KACS_SDS_KIND_TOKEN, ret ? 0 : (u32)*out_sd_len,
			    ret ? KACS_SDS_QUERY_FAIL : KACS_SDS_QUERY_OK, ret);
	return ret;
}

long pkm_kacs_set_token_sd_core(const void *subject_token,
				const void *target_token,
				u32 security_info,
				const u8 *input_sd_ptr,
				size_t input_sd_len)
{
	u32 desired_access;
	u32 granted = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long ret;

	if (!subject_token || !target_token || !input_sd_ptr || input_sd_len == 0)
		return -EINVAL;

	ret = pkm_kacs_set_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	ret = kacs_rust_check_token_sd_with_intent(subject_token, target_token,
						   desired_access,
						   KACS_RESTORE_INTENT,
						   pip_type, pip_trust,
						   &granted);
	if (ret) {
		trace_kacs_sd_set(security_info, desired_access, granted,
				  KACS_SDS_KIND_TOKEN, (u32)input_sd_len,
				  KACS_SDS_ACCESS_DENIED, ret);
		return ret;
	}

	ret = kacs_rust_set_token_sd(subject_token, target_token, security_info,
				     input_sd_ptr, input_sd_len);
	trace_kacs_sd_set(security_info, desired_access, granted,
			  KACS_SDS_KIND_TOKEN, (u32)input_sd_len,
			  ret ? KACS_SDS_ACCESS_DENIED : KACS_SDS_SET_OK, ret);
	return ret;
}

long pkm_kacs_query_process_sd_core(
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
	if (!process_sd) {
		trace_kacs_sd_query(security_info, desired_access, 0,
				    KACS_SDS_KIND_PROCESS, 0, KACS_SDS_NO_SD,
				    -EACCES);
		return -EACCES;
	}

	ret = pkm_kacs_authorize_process_sd_access_nondebug(
		subject_token, process_sd, desired_access, 0,
		READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust));
	if (!ret)
		ret = pkm_kacs_enforce_cross_process_pip(caller_state,
							 target_state,
							 self_target);
	if (!ret)
		ret = kacs_rust_query_process_sd_subset(
			process_sd->bytes, process_sd->len, security_info,
			out_sd_ptr, out_sd_len);

	trace_kacs_sd_query(security_info, desired_access, 0,
			    KACS_SDS_KIND_PROCESS, ret ? 0 : (u32)*out_sd_len,
			    ret ? KACS_SDS_ACCESS_DENIED : KACS_SDS_QUERY_OK,
			    ret);
	pkm_kacs_process_sd_put(process_sd);
	return ret;
}

long pkm_kacs_set_process_sd_core(
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
		trace_kacs_sd_set(security_info, desired_access, 0,
				  KACS_SDS_KIND_PROCESS, (u32)input_sd_len,
				  KACS_SDS_NO_SD, -EACCES);
		ret = -EACCES;
		goto out_unlock;
	}

	ret = pkm_kacs_authorize_process_sd_access_nondebug(
		subject_token, process_sd, desired_access, KACS_RESTORE_INTENT,
		READ_ONCE(caller_state->pip_type),
		READ_ONCE(caller_state->pip_trust));
	if (ret) {
		trace_kacs_sd_set(security_info, desired_access, 0,
				  KACS_SDS_KIND_PROCESS, (u32)input_sd_len,
				  KACS_SDS_ACCESS_DENIED, ret);
		goto out_process_sd;
	}
	ret = pkm_kacs_enforce_cross_process_pip(caller_state, target_state,
							 self_target);
	if (ret) {
		trace_kacs_sd_set(security_info, desired_access, 0,
				  KACS_SDS_KIND_PROCESS, (u32)input_sd_len,
				  KACS_SDS_ACCESS_DENIED, ret);
		goto out_process_sd;
	}
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
	trace_kacs_sd_set(security_info, desired_access, 0,
			  KACS_SDS_KIND_PROCESS, (u32)new_sd_len,
			  KACS_SDS_SET_OK, 0);
	ret = 0;

out_process_sd:
	pkm_kacs_process_sd_put(process_sd);
out_unlock:
	mutex_unlock(&target_state->sd_lock);
	pkm_kacs_process_sd_put(new_sd);
	return ret;
}

long pkm_kacs_query_file_sd_core(const void *subject_token,
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
	    KACS_MOUNT_POLICY_UNMANAGED) {
		trace_kacs_sd_query(security_info, 0, 0, KACS_SDS_KIND_FILE, 0,
				    KACS_SDS_UNMANAGED, -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}

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
	ret = pkm_kacs_inode_ensure_effective_cache(file, sec);
	if (!ret) {
		cache = pkm_kacs_inode_sd_cache_get_current(inode, sec);
		if (!cache)
			return -EACCES;
		if (use_live_access_check) {
			const void *caap_cache = NULL;

			ret = pkm_kacs_caap_cache_lock(&caap_cache);
			if (ret)
				return ret;
			ret = pkm_kacs_query_file_sd_bytes_core(subject_token,
								cache,
								security_info,
								caap_cache,
								out_sd_ptr,
								out_sd_len);
			pkm_kacs_caap_cache_unlock();
		} else if (cache->state != PKM_KACS_INODE_SD_VALID ||
			   !cache->bytes || cache->len == 0) {
			ret = -EACCES;
		} else {
			ret = kacs_rust_query_cached_file_sd_subset(
				cache->bytes, cache->len, &cache->layout,
				security_info, out_sd_ptr, out_sd_len);
		}
		pkm_kacs_inode_sd_cache_free(cache);
	}
	trace_kacs_sd_query(security_info, desired_access, 0,
			    KACS_SDS_KIND_FILE, ret ? 0 : (u32)*out_sd_len,
			    ret ? KACS_SDS_ACCESS_DENIED : KACS_SDS_QUERY_OK,
			    ret);
	return ret;
}


long pkm_kacs_query_path_file_sd_core(const void *subject_token,
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

/*
 * Whether the descriptor write below must hold a write reference on the
 * file's mount.  Only a KUnit fixture whose xattr store is faked (and whose
 * vfsmount is a stack stand-in) is exempt; every real path and descriptor
 * form carries a real mount.
 */
static bool pkm_kacs_set_file_sd_needs_mount_write(
	const struct file *file, const struct pkm_kacs_inode_security *sec)
{
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec->kunit_fake_xattr_enabled)
		return false;
#endif
	return file->f_path.mnt != NULL;
}

long pkm_kacs_set_file_sd_core(const void *subject_token,
			       struct file *file, u32 security_info,
			       const u8 *input_sd_ptr,
			       size_t input_sd_len)
{
	const void *caap_cache = NULL;
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct pkm_kacs_inode_sd_cache *new_cache = NULL;
	struct inode *inode;
	const u8 *new_sd_bytes = NULL;
	size_t new_sd_len = 0;
	bool used_restore_bypass = false;
	bool use_live_access_check;
	bool want_write;
	u32 desired_access = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long ret;

	if (!subject_token || !file || !input_sd_ptr || input_sd_len == 0)
		return -EINVAL;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return -EACCES;
	if (pkm_kacs_superblock_mount_policy(inode->i_sb) ==
	    KACS_MOUNT_POLICY_UNMANAGED) {
		trace_kacs_sd_set(security_info, 0, 0, KACS_SDS_KIND_FILE,
				  (u32)input_sd_len, KACS_SDS_UNMANAGED,
				  -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}

	ret = pkm_kacs_set_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;
	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
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
	ret = pkm_kacs_inode_resolve_effective_cache_locked(file, sec, &cache, 0);
	if (ret)
		goto out_unlock;

	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret)
		goto out_unlock;
	ret = pkm_kacs_prepare_new_file_sd_core(subject_token, cache,
						security_info, input_sd_ptr,
						input_sd_len,
						use_live_access_check,
						caap_cache,
						&new_sd_bytes, &new_sd_len);
	pkm_kacs_caap_cache_unlock();
	if (ret)
		goto out_unlock;
	used_restore_bypass = cache->state != PKM_KACS_INODE_SD_VALID;
	if (used_restore_bypass &&
	    !kacs_rust_token_mark_privileges_used(subject_token,
						  KACS_SE_RESTORE_PRIVILEGE)) {
		ret = -EACCES;
		goto out_bytes;
	}

	new_cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_VALID,
						  new_sd_bytes, new_sd_len);
	if (!new_cache) {
		ret = -ENOMEM;
		goto out_bytes;
	}

	/*
	 * KC-07: the SD xattr write below takes i_rwsem. Ordinary fchmod/
	 * fsetxattr acquire i_rwsem first and then sec->lock in the LSM hook, so
	 * holding sec->lock across the i_rwsem acquisition here is an ABBA
	 * inversion. Drop sec->lock, write the xattr under i_rwsem only, then
	 * re-acquire sec->lock to publish and audit. A concurrent set_sd on the
	 * same inode is last-writer-wins, as it already was.
	 */
	mutex_unlock(&sec->lock);

	/*
	 * A read-only mount withholds the write along this path whatever the
	 * descriptor grants, as it does for every other modifying operation
	 * (PEI-795).  Taken after the access check above so that an
	 * unauthorised caller still sees the denial rather than EROFS.
	 */
	want_write = pkm_kacs_set_file_sd_needs_mount_write(file, sec);
	if (want_write) {
		ret = mnt_want_write(file->f_path.mnt);
		if (ret) {
			pkm_kacs_inode_sd_cache_free(new_cache);
			return ret;
		}
	}
	ret = pkm_kacs_inode_write_sd_xattr_locked(file, new_sd_bytes,
						   new_sd_len);
	if (want_write)
		mnt_drop_write(file->f_path.mnt);
	if (ret) {
		/* new_cache owns new_sd_bytes; freeing the cache frees both. */
		pkm_kacs_inode_sd_cache_free(new_cache);
		new_cache = NULL;
		new_sd_bytes = NULL;
		return ret;
	}

	mutex_lock(&sec->lock);
	pkm_kacs_inode_replace_sd_cache_locked(sec, new_cache);
	new_cache = NULL;
	ret = kacs_rust_emit_file_set_sd_audit(subject_token, new_sd_bytes,
					       new_sd_len, desired_access,
					       pip_type, pip_trust);
	trace_kacs_sd_set(security_info, desired_access, 0, KACS_SDS_KIND_FILE,
			  (u32)new_sd_len,
			  used_restore_bypass ? KACS_SDS_RESTORE_BYPASS :
						KACS_SDS_SET_OK,
			  ret);
	new_sd_bytes = NULL;
	mutex_unlock(&sec->lock);
	return ret;

out_bytes:
	if (!new_cache && new_sd_bytes)
		pkm_kacs_free((void *)new_sd_bytes);
out_unlock:
	mutex_unlock(&sec->lock);
	pkm_kacs_inode_sd_cache_free(new_cache);
	return ret;
}

long pkm_kacs_set_path_file_sd_core(const void *subject_token,
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

static long pkm_kacs_get_sd_finish_copy(const u8 *result_sd,
					size_t result_len,
					void __user *buf, u32 buf_len,
					bool kernel_copy)
{
#ifndef CONFIG_SECURITY_PKM_KUNIT
	(void)kernel_copy;
#endif
	if (buf_len != 0 && result_len <= buf_len) {
		if (!buf)
			return -EFAULT;
#ifdef CONFIG_SECURITY_PKM_KUNIT
		if (kernel_copy)
			memcpy((void *)buf, result_sd, result_len);
		else
#endif
		if (copy_to_user(buf, result_sd, result_len))
			return -EFAULT;
	}

	return (long)result_len;
}

static long pkm_kacs_get_sd_impl(int dirfd, const char __user *path,
				 u32 security_info, void __user *buf,
				 u32 buf_len, u32 flags, bool kernel_copy)
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

#ifndef CONFIG_SECURITY_PKM_KUNIT
	(void)kernel_copy;
#endif
	/* A System V IPC object addressed by (kind, id): <pkm/ipc.h>. */
	if (flags & KACS_SD_AT_SYSV_MASK) {
		int kind = pkm_kacs_ipc_kind_from_sd_flags(flags);

		if (kind < 0 || path || (flags & ~KACS_SD_AT_SYSV_MASK))
			return -EINVAL;
		subject_token = pkm_kacs_current_effective_token_ptr();
		if (!subject_token)
			return -EACCES;
		ret = pkm_kacs_ipc_sd_query(kind, dirfd, subject_token,
					    security_info, &result_sd,
					    &result_len);
		if (ret)
			return ret;
		goto copyout;
	}
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (kernel_copy)
		ret = pkm_kacs_resolve_tokenfd_target_kernel(
			dirfd, (const char *)path, flags, &subject_token,
			&target_token);
	else
#endif
	ret = pkm_kacs_resolve_tokenfd_target(dirfd, path, flags, &subject_token,
					      &target_token);
	if (!ret) {
		ret = pkm_kacs_query_token_sd_core(subject_token, target_token,
						   security_info, &result_sd,
						   &result_len);
		if (ret)
			goto out;
		goto copyout;
	}
	if (ret != -EOPNOTSUPP)
		return ret;

#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (kernel_copy)
		ret = pkm_kacs_resolve_file_target_kernel(
			dirfd, (const char *)path, flags, &subject_token,
			&file);
	else
#endif
	ret = pkm_kacs_resolve_file_target(dirfd, path, flags, &subject_token,
					   &file);
	if (!ret) {
		ret = pkm_kacs_query_file_sd_core(subject_token, file,
						  security_info, &result_sd,
						  &result_len);
		fput(file);
		file = NULL;
		if (ret)
			goto out;
		goto copyout;
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

copyout:
	ret = pkm_kacs_get_sd_finish_copy(result_sd, result_len, buf, buf_len,
					  kernel_copy);

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

SYSCALL_DEFINE6(kacs_get_sd, int, dirfd, const char __user *, path,
		u32, security_info, void __user *, buf, u32, buf_len,
		u32, flags)
{
	return pkm_kacs_get_sd_impl(dirfd, path, security_info, buf, buf_len,
				    flags, false);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_get_sd_syscall(int dirfd, const char *path,
				   u32 security_info, u8 *buf, u32 buf_len,
				   u32 flags)
{
	return pkm_kacs_get_sd_impl(dirfd, (const char __user *)path,
				    security_info, (void __user *)buf,
				    buf_len, flags, true);
}
#endif

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

	/* A System V IPC object addressed by (kind, id): <pkm/ipc.h>. */
	if (flags & KACS_SD_AT_SYSV_MASK) {
		int kind = pkm_kacs_ipc_kind_from_sd_flags(flags);

		if (kind < 0 || path || (flags & ~KACS_SD_AT_SYSV_MASK))
			return -EINVAL;
		subject_token = pkm_kacs_current_effective_token_ptr();
		if (!subject_token)
			return -EACCES;
		input_sd = memdup_user(sd_buf, sd_len);
		if (IS_ERR(input_sd))
			return PTR_ERR(input_sd);
		ret = pkm_kacs_ipc_sd_set(kind, dirfd, subject_token,
					  security_info, input_sd, sd_len);
		kfree(input_sd);
		return ret;
	}

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
