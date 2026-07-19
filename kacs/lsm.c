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

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>

#include "capability.h"
#include "caap_cache.h"
#include "cred_lifecycle.h"
#include "cred_projection.h"
#include "../kmes/kmes.h"
#include "exec.h"
#include "file_access.h"
#include "file_metadata.h"
#include "file_sd_cache.h"
#include "kmes_rate.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "namespace.h"
#include "native_open.h"
#include "object_lifecycle.h"
#include "process_access.h"
#include "primary_token.h"
#include "process_state.h"
#include "process_token.h"
#include "psb.h"
#include "sd_access.h"
#include "signing.h"
#include "socket.h"
#include "task_lifecycle.h"
#include "tlp.h"
#include "token_fd.h"
#include "token_runtime.h"
#include "token_logon_session.h"

extern int kacs_rust_init(void);

static const struct lsm_id pkm_lsmid = {
	.name = "pkm",
	.id = 1000,
};
static const void *pkm_kacs_boot_system_token;
static const void *pkm_kacs_boot_anonymous_token;

struct lsm_blob_sizes pkm_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct pkm_kacs_cred_security),
	.lbs_task = sizeof(struct pkm_kacs_task_security),
	.lbs_sock = sizeof(struct pkm_kacs_socket_security),
	.lbs_file = sizeof(struct pkm_kacs_file_security),
	.lbs_inode = sizeof(struct pkm_kacs_inode_security),
	.lbs_superblock = sizeof(struct pkm_kacs_superblock_security),
	.lbs_xattr_count = 1,
};

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
	LSM_HOOK_INIT(inode_xattr_skipcap, pkm_kacs_inode_xattr_skipcap),
	LSM_HOOK_INIT(inode_getxattr, pkm_kacs_inode_getxattr),
	LSM_HOOK_INIT(inode_setxattr, pkm_kacs_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr, pkm_kacs_inode_removexattr),
	LSM_HOOK_INIT(inode_listxattr, pkm_kacs_inode_listxattr),
	LSM_HOOK_INIT(inode_copy_up_xattr, pkm_kacs_inode_copy_up_xattr),
	LSM_HOOK_INIT(inode_follow_link, pkm_kacs_inode_follow_link),
	LSM_HOOK_INIT(inode_set_acl, pkm_kacs_inode_set_acl),
	LSM_HOOK_INIT(inode_remove_acl, pkm_kacs_inode_remove_acl),
	LSM_HOOK_INIT(inode_getsecurity, pkm_kacs_inode_getsecurity),
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
	LSM_HOOK_INIT(file_receive, pkm_kacs_file_receive),
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
	LSM_HOOK_INIT(ptrace_traceme, pkm_kacs_ptrace_traceme),
	LSM_HOOK_INIT(task_setnice, pkm_kacs_task_setnice),
	LSM_HOOK_INIT(task_setscheduler, pkm_kacs_task_setscheduler),
	LSM_HOOK_INIT(task_setioprio, pkm_kacs_task_setioprio),
	LSM_HOOK_INIT(task_setpgid, pkm_kacs_task_setpgid),
	LSM_HOOK_INIT(task_getpgid, pkm_kacs_task_getpgid),
	LSM_HOOK_INIT(task_getsid, pkm_kacs_task_getsid),
	LSM_HOOK_INIT(task_getscheduler, pkm_kacs_task_getscheduler),
	LSM_HOOK_INIT(task_getioprio, pkm_kacs_task_getioprio),
	LSM_HOOK_INIT(task_movememory, pkm_kacs_task_movememory),
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
	LSM_HOOK_INIT(bprm_committing_creds, pkm_kacs_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, pkm_kacs_bprm_committed_creds),
};

const void *pkm_kacs_boot_system_token_ptr(void)
{
	return pkm_kacs_boot_system_token;
}

const void *pkm_kacs_boot_anonymous_token_ptr(void)
{
	return pkm_kacs_boot_anonymous_token;
}



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



static int __init pkm_init(void)
{
	const void *system_token = NULL;
	const void *anonymous_token = NULL;
	const void *real_token_ref = NULL;
	struct pkm_kacs_process_state *initial_state = NULL;
	struct pkm_kacs_cred_security *sec;
	struct pkm_kacs_task_security *task_sec;
	bool split_current_creds;
	bool caap_ready = false;
	int ret;

	if (IS_ENABLED(CONFIG_SECURITY_SELINUX) ||
	    IS_ENABLED(CONFIG_SECURITY_APPARMOR) ||
	    IS_ENABLED(CONFIG_SECURITY_SMACK) ||
	    IS_ENABLED(CONFIG_SECURITY_TOMOYO) ||
	    IS_ENABLED(CONFIG_BPF_LSM)) {
		pr_err("pkm: conflicting MAC or BPF LSM detected\n");
		return -EINVAL;
	}

	if (!IS_ENABLED(CONFIG_STRICT_DEVMEM) ||
	    !IS_ENABLED(CONFIG_MODULE_SIG_FORCE)) {
		pr_err("pkm: required PIP build hardening config missing\n");
		return -EINVAL;
	}

	ret = kacs_rust_init();
	if (ret) {
		pr_err("pkm: slow-track Rust init failed (%d)\n", ret);
		return ret;
	}

	system_token = kacs_rust_create_boot_system_token();
	if (!system_token) {
		ret = -ENOMEM;
		goto out_fail;
	}
	anonymous_token = kacs_rust_create_boot_anonymous_token();
	if (!anonymous_token) {
		ret = -ENOMEM;
		goto out_fail;
	}

	initial_state = pkm_kacs_process_state_alloc(system_token, 0, 0, 0);
	if (!initial_state) {
		ret = -ENOMEM;
		goto out_fail;
	}

	split_current_creds = current_cred() != current_real_cred();
	if (split_current_creds) {
		real_token_ref = kacs_rust_token_clone(system_token);
		if (!real_token_ref) {
			ret = -ENOMEM;
			goto out_fail;
		}
	}

	ret = pkm_kacs_caap_cache_init();
	if (ret) {
		pr_err("pkm: CAAP cache init failed (%d)\n", ret);
		goto out_fail;
	}
	caap_ready = true;

	ret = pkm_kmes_init();
	if (ret) {
		pr_err("pkm: KMES init failed (%d)\n", ret);
		goto out_fail;
	}

	security_add_hooks(pkm_hooks, ARRAY_SIZE(pkm_hooks), &pkm_lsmid);

	pkm_kacs_boot_system_token = system_token;
	pkm_kacs_boot_anonymous_token = anonymous_token;

	task_sec = pkm_kacs_task(current);
	task_sec->pending_exec_pip_type = 0;
	task_sec->pending_exec_pip_trust = 0;
	task_sec->pending_exec_pip_valid = 0;
	if (!task_sec->process_state) {
		task_sec->process_state = initial_state;
		initial_state = NULL;
	} else {
		pkm_kacs_process_state_put(initial_state);
		initial_state = NULL;
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

	if (split_current_creds) {
		struct pkm_kacs_cred_security *real_sec =
			pkm_kacs_cred(current_real_cred());

		real_sec->token = real_token_ref;
		real_token_ref = NULL;
		pkm_kacs_stamp_projected_ids(real_sec);
		pkm_kacs_reset_allow_compat_caps(
			(struct cred *)current_real_cred());
	}

	pr_info("pkm: slow-track kernel scaffold initialized\n");
	return 0;

out_fail:
	if (caap_ready)
		pkm_kacs_caap_cache_destroy();
	if (real_token_ref)
		kacs_rust_token_drop(real_token_ref);
	if (initial_state)
		pkm_kacs_process_state_put(initial_state);
	if (anonymous_token)
		kacs_rust_token_drop(anonymous_token);
	if (system_token)
		kacs_rust_token_drop(system_token);
	return ret;
}

DEFINE_LSM(pkm) = {
	.id = &pkm_lsmid,
	.init = pkm_init,
	.blobs = &pkm_blob_sizes,
};
