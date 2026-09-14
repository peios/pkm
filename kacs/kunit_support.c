// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit bridge helpers for PKM KACS.
 */

#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/falloc.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/fiemap.h>
#include <linux/file.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/init.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/limits.h>
#include <linux/math64.h>
#include <linux/lsm_hooks.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/nospec.h>
#include <linux/refcount.h>
#include <linux/pid.h>
#include <linux/pidfd.h>
#include <linux/preempt.h>
#include <linux/prctl.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/sched/mm.h>
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
#include <asm/prctl.h>
#include <asm/shstk.h>

#include <net/sock.h>

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

#include "kunit_common.h"

#ifdef CONFIG_SECURITY_PKM_KUNIT
#define PKM_KACS_KUNIT_FILE_SD_ADMIN_MASK                                     \
	(KACS_FILE_READ_DATA | KACS_FILE_WRITE_DATA |                \
	 KACS_FILE_APPEND_DATA | KACS_FILE_READ_EA |                \
	 KACS_FILE_WRITE_EA | KACS_FILE_EXECUTE |                  \
	 KACS_FILE_DELETE_CHILD | KACS_FILE_READ_ATTRIBUTES |       \
	 KACS_FILE_WRITE_ATTRIBUTES | KACS_ACCESS_DELETE |              \
	 KACS_ACCESS_READ_CONTROL | KACS_ACCESS_WRITE_DAC |                 \
	 KACS_ACCESS_WRITE_OWNER)
#endif

static __maybe_unused atomic64_t pkm_kacs_kunit_native_identity_counter = ATOMIC64_INIT(0);

#ifdef CONFIG_SECURITY_PKM_KUNIT
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

	if (tokens > pkm_kmes_runtime_max_emit_rate_per_process())
		return -EINVAL;

	state = pkm_kacs_current_process_state();
	if (!state || !state->kmes_rate_bucket)
		return -EACCES;

	return pkm_kmes_rate_bucket_kunit_set_tokens(state->kmes_rate_bucket,
						    tokens);
}

int pkm_kmes_kunit_set_current_process_rate_refill_frozen(bool frozen)
{
	struct pkm_kacs_process_state *state;

	state = pkm_kacs_current_process_state();
	if (!state || !state->kmes_rate_bucket)
		return -EACCES;

	return pkm_kmes_rate_bucket_kunit_set_refill_frozen(
		state->kmes_rate_bucket, frozen);
}

int pkm_kmes_kunit_get_current_process_rate_tokens(u32 *tokens_out)
{
	struct pkm_kacs_process_state *state;

	if (!tokens_out)
		return -EINVAL;
	state = pkm_kacs_current_process_state();
	if (!state || !state->kmes_rate_bucket)
		return -EACCES;

	return pkm_kmes_rate_bucket_kunit_get_tokens(state->kmes_rate_bucket,
						    tokens_out);
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

int pkm_kacs_kunit_token_eval_context_allowed(u32 task_context, u32 has_cred,
					      u32 has_security_blob,
					      u32 has_token)
{
	return pkm_kacs_subjective_cred_context_allowed(
		       task_context != 0, has_cred != 0,
		       has_security_blob != 0, has_token != 0) ?
		       1 :
		       0;
}

const void *pkm_kacs_kunit_current_process_state_ptr(void)
{
	return pkm_kacs_current_process_state();
}

const void *pkm_kacs_kunit_current_effective_cred_process_state_ptr(void)
{
	const struct cred *cred = current_cred();

	if (!cred || !cred->security)
		return NULL;

	return pkm_kacs_cred(cred)->process_state;
}

const void *pkm_kacs_kunit_current_real_cred_process_state_ptr(void)
{
	const struct cred *cred = current_real_cred();

	if (!cred || !cred->security)
		return NULL;

	return pkm_kacs_cred(cred)->process_state;
}

const void *pkm_kacs_kunit_inherit_current_process_state(u64 clone_flags)
{
	return pkm_kacs_inherit_process_state(clone_flags);
}

long pkm_kacs_kunit_clone_token_lifecycle_probe(
	u64 clone_flags, u32 simulate_shared_thread_cred,
	struct pkm_kacs_boot_snapshot *parent_primary_out,
	struct pkm_kacs_boot_snapshot *parent_effective_out,
	struct pkm_kacs_boot_snapshot *child_effective_out,
	u32 *child_token_is_parent_primary_out,
	u32 *child_cred_is_parent_real_out)
{
	const struct cred *child_cred;
	const struct cred *child_real_cred;
	const void *parent_primary;
	const void *parent_effective;
	const void *child_token;
	struct cred *prepared = NULL;
	long ret;

	if (!parent_primary_out || !parent_effective_out ||
	    !child_effective_out || !child_token_is_parent_primary_out ||
	    !child_cred_is_parent_real_out)
		return -EINVAL;

	memset(parent_primary_out, 0, sizeof(*parent_primary_out));
	memset(parent_effective_out, 0, sizeof(*parent_effective_out));
	memset(child_effective_out, 0, sizeof(*child_effective_out));
	*child_token_is_parent_primary_out = 0;
	*child_cred_is_parent_real_out = 0;

	parent_primary = pkm_kacs_current_primary_token_ptr();
	parent_effective = pkm_kacs_current_effective_token_ptr();
	if (!parent_primary || !parent_effective)
		return -EACCES;
	if (!kacs_rust_kunit_token_snapshot(parent_primary,
					    parent_primary_out) ||
	    !kacs_rust_kunit_token_snapshot(parent_effective,
					    parent_effective_out))
		return -EACCES;

	if (simulate_shared_thread_cred) {
		if ((clone_flags & CLONE_THREAD) == 0)
			return -EINVAL;
		child_cred = get_cred(current_cred());
		child_real_cred = get_cred(current_cred());
	} else {
		prepared = prepare_creds();
		if (!prepared)
			return -ENOMEM;
		child_cred = prepared;
		child_real_cred = prepared;
	}

	ret = pkm_kacs_apply_clone_token_lifecycle(&child_cred,
						   &child_real_cred,
						   clone_flags);
	if (ret)
		goto out;

	child_token = pkm_kacs_cred(child_cred)->token;
	if (!child_token ||
	    !kacs_rust_kunit_token_snapshot(child_token,
					    child_effective_out)) {
		ret = -EACCES;
		goto out;
	}

	*child_token_is_parent_primary_out = child_token == parent_primary;
	*child_cred_is_parent_real_out = child_cred == current_real_cred();

out:
	if (simulate_shared_thread_cred) {
		put_cred(child_cred);
		put_cred(child_real_cred);
	} else if (prepared) {
		abort_creds(prepared);
	}
	return ret;
}

static long pkm_kacs_kunit_clone_mutation_probe(
	bool deep_copy_primary, struct pkm_kacs_kunit_clone_mutation_probe *out)
{
	const struct cred *child_cred;
	const struct cred *child_real_cred;
	const void *source_token = NULL;
	const void *child_token;
	struct cred *prepared = NULL;
	u32 next_interactivity_scope;
	long ret = 0;

	if (!out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	source_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	if (!source_token)
		return -ENOMEM;

	prepared = prepare_creds();
	if (!prepared) {
		ret = -ENOMEM;
		goto out;
	}
	child_cred = prepared;
	child_real_cred = prepared;

	ret = pkm_kacs_install_primary_on_child_cred_pair(
		child_cred, child_real_cred, source_token, deep_copy_primary);
	if (ret)
		goto out;

	child_token = pkm_kacs_cred(child_real_cred)->token;
	if (!child_token) {
		ret = -EACCES;
		goto out;
	}
	out->child_token_is_source = child_token == source_token;

	if (!kacs_rust_kunit_token_snapshot(source_token, &out->source_before) ||
	    !kacs_rust_kunit_token_snapshot(child_token, &out->child_before)) {
		ret = -EACCES;
		goto out;
	}

	next_interactivity_scope = out->source_before.interactivity_scope ^ 1U;
	ret = kacs_rust_token_adjust_interactivity_scope(source_token,
						next_interactivity_scope);
	if (ret)
		goto out;

	if (!kacs_rust_kunit_token_snapshot(
		    source_token, &out->source_after_source_mutation) ||
	    !kacs_rust_kunit_token_snapshot(
		    child_token, &out->child_after_source_mutation)) {
		ret = -EACCES;
		goto out;
	}

	next_interactivity_scope =
		out->child_after_source_mutation.interactivity_scope ^ 2U;
	ret = kacs_rust_token_adjust_interactivity_scope(child_token, next_interactivity_scope);
	if (ret)
		goto out;

	if (!kacs_rust_kunit_token_snapshot(
		    source_token, &out->source_after_child_mutation) ||
	    !kacs_rust_kunit_token_snapshot(
		    child_token, &out->child_after_child_mutation))
		ret = -EACCES;

out:
	if (prepared)
		abort_creds(prepared);
	if (source_token)
		kacs_rust_token_drop(source_token);
	return ret;
}

long pkm_kacs_kunit_clone_thread_shared_token_mutation_probe(
	struct pkm_kacs_kunit_clone_mutation_probe *out)
{
	return pkm_kacs_kunit_clone_mutation_probe(false, out);
}

long pkm_kacs_kunit_clone_process_deep_copy_mutation_probe(
	struct pkm_kacs_kunit_clone_mutation_probe *out)
{
	return pkm_kacs_kunit_clone_mutation_probe(true, out);
}

long pkm_kacs_kunit_exec_committing_creds_for_current(void)
{
	pkm_kacs_bprm_committing_creds(NULL);
	return 0;
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
	memcpy(out->process_guid, state->process_guid,
	       sizeof(out->process_guid));
	out->process_sd_ptr = state->process_sd ? state->process_sd->bytes : NULL;
	out->process_sd_len = state->process_sd ? state->process_sd->len : 0;
	out->rate_bucket_ptr = state->kmes_rate_bucket;
	out->pip_type = READ_ONCE(state->pip_type);
	out->pip_trust = READ_ONCE(state->pip_trust);
	out->mitigation_bits = pkm_kacs_process_state_mitigation_bits(state);
	return 0;
}



long pkm_kacs_kunit_read_securityfs_logon_sessions_for_subject(
	const void *subject_token, u8 *buf, size_t buf_len,
	size_t *required_out)
{
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long ret;

	if (!subject_token)
		return -EACCES;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	ret = kacs_rust_check_securityfs_logon_sessions_read(subject_token, pip_type,
						       pip_trust);
	if (ret)
		return ret;

	return kacs_rust_securityfs_logon_sessions_listing(buf, buf_len,
						    required_out);
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
	struct pkm_kacs_inode_sd_cache *cache;
	const u8 *copied_bytes = NULL;

	switch (state) {
	case PKM_KACS_KUNIT_FILE_SD_VALID:
		if (!sd_ptr || sd_len == 0)
			return NULL;
		copied_bytes = kmemdup(sd_ptr, sd_len, GFP_KERNEL);
		if (!copied_bytes)
			return NULL;
		cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_VALID,
						      copied_bytes, sd_len);
		if (!cache)
			kfree(copied_bytes);
		return cache;
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
	const void *caap_cache = NULL;
	struct pkm_kacs_inode_sd_cache *cache;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len)
		return -EINVAL;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		return ret;
	}
	ret = pkm_kacs_query_file_sd_bytes_core(args->subject_token, cache,
						args->security_info, caap_cache,
						out_sd_ptr, out_sd_len);
	pkm_kacs_caap_cache_unlock();
	pkm_kacs_inode_sd_cache_free(cache);
	return ret;
}

long pkm_kacs_kunit_set_file_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len)
{
	const void *caap_cache = NULL;
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

	ret = pkm_kacs_caap_cache_lock(&caap_cache);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		return ret;
	}
	ret = pkm_kacs_prepare_new_file_sd_core(args->subject_token, cache,
						args->security_info,
						args->input_sd_ptr,
						args->input_sd_len, true,
						caap_cache,
						&result_sd,
						&result_sd_len);
	pkm_kacs_caap_cache_unlock();
	if (!ret) {
		if (args->target_file_sd_state != PKM_KACS_KUNIT_FILE_SD_VALID)
			(void)kacs_rust_token_mark_privileges_used(
				args->subject_token,
				KACS_SE_RESTORE_PRIVILEGE);
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

long pkm_kacs_kunit_open_then_change_sd_for_subject(
	const struct pkm_kacs_kunit_file_sd_set_args *args,
	u32 *cached_grant_out, long *new_open_ret_out,
	u32 *new_open_grant_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_file_security *file_sec;
	struct file reopened = {};
	void *reopen_blob = NULL;
	u64 magic;
	umode_t mode;
	long ret;

	if (!args || !cached_grant_out || !new_open_ret_out ||
	    !new_open_grant_out || !args->subject_token ||
	    !args->input_sd_ptr || args->input_sd_len == 0)
		return -EINVAL;

	*cached_grant_out = 0;
	*new_open_ret_out = -EINVAL;
	*new_open_grant_out = 0;

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
	if (ret)
		goto out_cleanup;

	file_sec = pkm_kacs_file(&state->file);
	if (!file_sec || !file_sec->managed) {
		ret = -EACCES;
		goto out_cleanup;
	}
	*cached_grant_out = file_sec->granted_access;

	ret = pkm_kacs_set_file_sd_core(args->subject_token, &state->file,
					args->security_info,
					args->input_sd_ptr,
					args->input_sd_len);
	if (ret)
		goto out_cleanup;

	ret = pkm_kacs_check_file_permission_snapshot(&state->file, MAY_READ);
	if (ret)
		goto out_cleanup;

	reopen_blob = kzalloc(pkm_blob_sizes.lbs_file +
				      sizeof(struct pkm_kacs_file_security),
			      GFP_KERNEL);
	if (!reopen_blob) {
		ret = -ENOMEM;
		goto out_cleanup;
	}

	reopened.f_inode = &state->inode;
	reopened.f_security = reopen_blob;
	reopened.f_mode = state->file.f_mode;
	reopened.f_flags = state->file.f_flags;
	*(struct path *)&reopened.f_path = (struct path){
		.mnt = &state->mnt,
		.dentry = &state->dentry,
	};
	ret = pkm_kacs_file_alloc_security(&reopened);
	if (ret)
		goto out_reopen;

	*new_open_ret_out = pkm_kacs_stamp_file_granted_access_for_subject(
		args->subject_token, &reopened);
	if (*new_open_ret_out == 0) {
		file_sec = pkm_kacs_file(&reopened);
		*new_open_grant_out = file_sec && file_sec->managed ?
					       file_sec->granted_access :
					       0;
	}
	ret = 0;

out_reopen:
	kfree(reopen_blob);
out_cleanup:
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

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

long pkm_kacs_kunit_open_opath_for_subject(
	const struct pkm_kacs_kunit_file_open_args *args, u32 *managed_out,
	u32 *granted_access_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_file_security *file_sec;
	u64 magic;
	umode_t mode;
	long ret;

	if (!args || !managed_out || !granted_access_out)
		return -EINVAL;

	*managed_out = 0;
	*granted_access_out = 0;
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

	state->file.f_mode = FMODE_PATH;
	state->file.f_flags = O_PATH;
	ret = pkm_kacs_file_open(&state->file);
	file_sec = pkm_kacs_file(&state->file);
	if (file_sec) {
		*managed_out = file_sec->managed ? 1U : 0U;
		*granted_access_out = file_sec->granted_access;
	}

	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
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
	if (args->create_disposition == KACS_DISPOSITION_CREATE)
		return -EEXIST;
	if ((args->create_disposition == KACS_DISPOSITION_OPEN_IF ||
	     args->create_disposition == KACS_DISPOSITION_OVERWRITE_IF) &&
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

	if (args->create_disposition == KACS_DISPOSITION_SUPERSEDE) {
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
	    KACS_MOUNT_POLICY_UNMANAGED) {
		ret = -EOPNOTSUPP;
		goto out_parent_cleanup;
	}
	if ((args->flags & AT_SYMLINK_NOFOLLOW) != 0 &&
	    S_ISLNK(inode->i_mode)) {
		ret = -ELOOP;
		goto out_parent_cleanup;
	}
	if (args->create_disposition == KACS_DISPOSITION_SUPERSEDE ||
	    args->create_disposition == KACS_DISPOSITION_OVERWRITE ||
	    args->create_disposition == KACS_DISPOSITION_OVERWRITE_IF) {
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
		   (prepared.desired_access & KACS_FILE_EXECUTE) != 0) {
		ret = -EACCES;
		goto out_parent_cleanup;
	}
	if ((args->create_disposition == KACS_DISPOSITION_OVERWRITE ||
	     args->create_disposition == KACS_DISPOSITION_OVERWRITE_IF) &&
	    (prepared.desired_access & KACS_FILE_WRITE_DATA) == 0) {
		ret = -EINVAL;
		goto out_parent_cleanup;
	}

	if (args->create_disposition == KACS_DISPOSITION_SUPERSEDE) {
		pkm_kacs_init_path_anchor_file(
			&parent_file,
			&(struct path){
				.mnt = &parent_state->mnt,
				.dentry = &parent_state->dentry,
			});
		ret = pkm_kacs_build_created_file_sd_for_subject(
			args->subject_token, &parent_file, args->input_sd_ptr,
			args->input_sd_len, false, prepared.desired_access,
			prepared.privilege_intent, &created_sd, &created_sd_len,
			granted_access_out);
		if (ret)
			goto out_parent_cleanup;

		delete_ret = pkm_kacs_authorize_live_file_access_core(
			args->subject_token, &state->file, KACS_ACCESS_DELETE);
		if (delete_ret == -EACCES) {
			delete_ret = pkm_kacs_authorize_live_file_access_core(
				args->subject_token, &parent_file,
				KACS_FILE_DELETE_CHILD);
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
		args->subject_token, &state->file, prepared.desired_access,
		prepared.privilege_intent);
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
	if (args->create_disposition != KACS_DISPOSITION_CREATE &&
	    args->create_disposition != KACS_DISPOSITION_OPEN_IF &&
	    args->create_disposition != KACS_DISPOSITION_OVERWRITE_IF &&
	    args->create_disposition != KACS_DISPOSITION_SUPERSEDE)
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
		prepared.desired_access, prepared.privilege_intent,
		created_sd_out, created_sd_len_out, granted_access_out);
	if (!ret && status_out)
		*status_out = KACS_STATUS_CREATED;

	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_native_create_mode_for_subject(
	const struct pkm_kacs_kunit_native_create_args *args, u32 *mode_out)
{
	const u8 *created_sd = NULL;
	size_t created_sd_len = 0;
	long ret;

	if (!args || !mode_out)
		return -EINVAL;

	*mode_out = 0;
	ret = pkm_kacs_kunit_native_create_for_subject(
		args, &created_sd, &created_sd_len, NULL, NULL);
	if (ret)
		return ret;

	*mode_out = pkm_kacs_native_create_mode(
		(args->create_options & KACS_CREATE_OPT_DIRECTORY) != 0);
	pkm_kacs_free((void *)created_sd);
	return 0;
}

long pkm_kacs_kunit_native_prepare_open_with_padding(u32 padding)
{
	struct pkm_kacs_native_open_prepared prepared = {};
	struct kacs_open_how how = {
		.desired_access = KACS_FILE_READ_DATA,
		.create_disposition = KACS_DISPOSITION_OPEN,
		.__pad = padding,
	};

	return pkm_kacs_prepare_native_open(&how, &prepared);
}

long pkm_kacs_kunit_native_missing_existing_result(u32 create_disposition)
{
	char path[64];
	struct pkm_kacs_native_open_prepared prepared = {};
	struct kacs_open_how how = {
		.desired_access = KACS_FILE_READ_DATA,
		.create_disposition = create_disposition,
	};
	struct path resolved_path = {};
	long ret;

	if (create_disposition == KACS_DISPOSITION_OVERWRITE)
		how.desired_access = KACS_FILE_WRITE_DATA;

	ret = pkm_kacs_prepare_native_open(&how, &prepared);
	if (ret)
		return ret;

	scnprintf(path, sizeof(path), "/pkm-kacs-missing-%llu",
		  (unsigned long long)pkm_kacs_next_native_supersede_tmp_id());
	ret = kern_path(path, 0, &resolved_path);
	if (!ret) {
		path_put(&resolved_path);
		return -EEXIST;
	}
	if (ret != -ENOENT)
		return ret;
	if (prepared.create_disposition == KACS_DISPOSITION_OPEN_IF ||
	    prepared.create_disposition == KACS_DISPOSITION_OVERWRITE_IF ||
	    prepared.create_disposition == KACS_DISPOSITION_SUPERSEDE)
		return 0;

	return -ENOENT;
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

	create_branch = args->create_disposition == KACS_DISPOSITION_CREATE;
	if (!create_branch &&
	    (args->create_disposition == KACS_DISPOSITION_OPEN_IF ||
	     args->create_disposition == KACS_DISPOSITION_OVERWRITE_IF ||
	     args->create_disposition == KACS_DISPOSITION_SUPERSEDE) &&
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
			prepared.privilege_intent, &created_sd, &created_sd_len,
			NULL);
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
		if ((args->create_disposition == KACS_DISPOSITION_OPEN_IF ||
		     args->create_disposition == KACS_DISPOSITION_OVERWRITE_IF) &&
		    args->input_sd_ptr && args->input_sd_len != 0)
			return -EINVAL;
		if (args->create_disposition != KACS_DISPOSITION_OPEN &&
		    args->create_disposition != KACS_DISPOSITION_OPEN_IF &&
		    args->create_disposition != KACS_DISPOSITION_OVERWRITE &&
		    args->create_disposition != KACS_DISPOSITION_OVERWRITE_IF)
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
		args->subject_token, &state->file, prepared.desired_access,
		prepared.privilege_intent);
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

static const struct file_operations pkm_kacs_kunit_delete_on_close_fops = { };

static int pkm_kacs_kunit_dup_fd_same_file(int fd)
{
	struct fd f;
	struct file *file;
	int duplicate_fd;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;

	file = get_file(fd_file(f));
	duplicate_fd = get_unused_fd_flags(O_CLOEXEC);
	if (duplicate_fd < 0) {
		fput(file);
		fdput(f);
		return duplicate_fd;
	}

	fd_install(duplicate_fd, file);
	fdput(f);
	return duplicate_fd;
}

long pkm_kacs_kunit_delete_on_close_dup_lineage_for_subject(
	const struct pkm_kacs_kunit_native_open_args *args,
	struct pkm_kacs_kunit_delete_on_close_result *out)
{
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct pkm_kacs_native_open_prepared prepared = {};
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct file *file = NULL;
	struct inode *inode;
	int fd = -1;
	int duplicate_fd = -1;
	long ret;

	if (!args || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	if ((args->create_options & KACS_CREATE_OPT_DELETE_ON_CLOSE) == 0)
		return -EINVAL;
	if (args->create_disposition != KACS_DISPOSITION_OPEN)
		return -EOPNOTSUPP;

	ret = pkm_kacs_prepare_native_open(
		&(struct kacs_open_how){
			.desired_access = args->desired_access,
			.create_disposition = args->create_disposition,
			.create_options = args->create_options,
			.flags = args->flags,
		},
		&prepared);
	if (ret)
		return ret;
	if (prepared.directory_required)
		return -EOPNOTSUPP;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(args->target_file_sd_ptr,
						   args->target_file_sd_len,
						   args->target_file_sd_state);
	if (!cache)
		return -EINVAL;

	file = anon_inode_create_getfile("pkm-kacs-delete-on-close",
					 &pkm_kacs_kunit_delete_on_close_fops,
					 NULL, prepared.open_flags | O_CLOEXEC,
					 NULL);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		file = NULL;
		goto out_cache;
	}

	inode = file_inode(file);
	if (!inode || !inode->i_security || !file->f_security) {
		ret = -EACCES;
		goto out_file;
	}
	ihold(inode);
	inode->i_mode = S_IFREG | 0600;
	file->f_flags = prepared.open_flags;
	file->f_mode |= OPEN_FMODE(prepared.open_flags);

	inode_sec = pkm_kacs_inode(inode);
	mutex_lock(&inode_sec->lock);
	RCU_INIT_POINTER(inode_sec->sd_cache, cache);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	inode_sec->kunit_fake_xattr_enabled = true;
#endif
	mutex_unlock(&inode_sec->lock);
	cache = NULL;

	ret = pkm_kacs_stamp_native_file_granted_access_for_subject(
		args->subject_token, file, prepared.desired_access,
		prepared.privilege_intent);
	if (ret)
		goto out_inode;

	ret = pkm_kacs_maybe_arm_delete_on_close_for_subject(
		args->subject_token, file, prepared.create_options);
	if (ret)
		goto out_inode;

	file_sec = pkm_kacs_file(file);
	out->granted_access = file_sec && file_sec->managed ?
				      file_sec->granted_access :
				      0;
	out->status = prepared.status;
	out->pending_before_release =
		(u32)atomic_read(&inode_sec->delete_on_close_lineages);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto out_inode;
	}
	fd_install(fd, file);
	file = NULL;

	duplicate_fd = pkm_kacs_kunit_dup_fd_same_file(fd);
	if (duplicate_fd < 0) {
		ret = duplicate_fd;
		goto out_fd;
	}

	ret = close_fd((unsigned int)duplicate_fd);
	duplicate_fd = -1;
	if (ret)
		goto out_fd;
	flush_delayed_fput();
	out->pending_after_duplicate_close =
		(u32)atomic_read(&inode_sec->delete_on_close_lineages);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	out->unlink_calls_after_duplicate_close =
		inode_sec->kunit_unlink_calls;
#endif

	ret = close_fd((unsigned int)fd);
	fd = -1;
	if (ret)
		goto out_inode;
	flush_delayed_fput();
	out->pending_after_release =
		(u32)atomic_read(&inode_sec->delete_on_close_lineages);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	out->unlink_calls = inode_sec->kunit_unlink_calls;
#endif
	ret = 0;

out_fd:
	if (duplicate_fd >= 0) {
		close_fd((unsigned int)duplicate_fd);
		flush_delayed_fput();
	}
	if (fd >= 0) {
		close_fd((unsigned int)fd);
		flush_delayed_fput();
	}
out_inode:
	iput(inode);
out_file:
	if (file)
		__fput_sync(file);
out_cache:
	if (cache)
		pkm_kacs_inode_sd_cache_free(cache);
	return ret;
}

static void pkm_kacs_kunit_native_identity_paths(char *dir_path,
						 size_t dir_path_len,
						 char *target_path,
						 size_t target_path_len,
						 char *link_path,
						 size_t link_path_len)
{
	u64 id = (u64)atomic64_inc_return(
		&pkm_kacs_kunit_native_identity_counter);

	scnprintf(dir_path, dir_path_len, "/pkm-kacs-native-%llu",
		  (unsigned long long)id);
	scnprintf(target_path, target_path_len, "%s/target", dir_path);
	scnprintf(link_path, link_path_len, "%s/link", dir_path);
}

enum pkm_kacs_kunit_native_identity_step {
	PKM_KACS_KUNIT_NATIVE_ID_STEP_NONE = 0,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_MKDIR = 1,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_INSTALL_DIR_SD = 2,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_CREATE_FILE = 3,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_INSTALL_TARGET_SD = 4,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_LINK = 5,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_QUERY_BEFORE = 6,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_RESOLVE_TARGET = 7,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_NATIVE_OPEN = 8,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_SNAPSHOT_TARGET = 9,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_SNAPSHOT_LINK = 10,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_QUERY_TARGET_AFTER = 11,
	PKM_KACS_KUNIT_NATIVE_ID_STEP_QUERY_LINK_AFTER = 12,
};

static long pkm_kacs_kunit_mkdir_path(const char *path)
{
	struct path parent_path = {};
	struct dentry *dentry;
	struct dentry *created;
	struct inode *parent_inode;
	long ret = 0;

	if (!path)
		return -EINVAL;

	dentry = start_creating_path(AT_FDCWD, path, &parent_path, 0);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	parent_inode = d_inode(parent_path.dentry);
	if (!parent_inode) {
		ret = -EACCES;
		goto out;
	}

	created = vfs_mkdir(mnt_idmap(parent_path.mnt), parent_inode, dentry,
			    0700, NULL);
	if (IS_ERR(created)) {
		ret = PTR_ERR(created);
		goto out;
	}
	dentry = created;

out:
	end_creating_path(&parent_path, dentry);
	return ret;
}

static long pkm_kacs_kunit_remove_path(const char *pathname, bool directory)
{
	struct path victim_path = {};
	struct path parent_path = {};
	struct inode *parent_inode;
	long ret;

	if (!pathname)
		return -EINVAL;

	ret = kern_path(pathname, directory ? LOOKUP_DIRECTORY : 0,
			&victim_path);
	if (ret)
		return ret;

	parent_path.mnt = mntget(victim_path.mnt);
	parent_path.dentry = dget_parent(victim_path.dentry);
	if (!parent_path.mnt || !parent_path.dentry) {
		ret = -EACCES;
		goto out_victim;
	}

	parent_inode = d_inode(parent_path.dentry);
	if (!parent_inode) {
		ret = -EACCES;
		goto out_parent;
	}

	ret = mnt_want_write(parent_path.mnt);
	if (ret)
		goto out_parent;

	inode_lock(parent_inode);
	if (directory)
		ret = vfs_rmdir(mnt_idmap(parent_path.mnt), parent_inode,
				victim_path.dentry, NULL);
	else
		ret = vfs_unlink(mnt_idmap(parent_path.mnt), parent_inode,
				 victim_path.dentry, NULL);
	inode_unlock(parent_inode);
	mnt_drop_write(parent_path.mnt);

out_parent:
	path_put(&parent_path);
out_victim:
	path_put(&victim_path);
	return ret;
}

static void pkm_kacs_kunit_cleanup_native_identity_paths(
	const char *dir_path, const char *target_path, const char *link_path)
{
	(void)pkm_kacs_kunit_remove_path(link_path, false);
	(void)pkm_kacs_kunit_remove_path(target_path, false);
	(void)pkm_kacs_kunit_remove_path(dir_path, true);
}

static long pkm_kacs_kunit_install_live_inode_sd(struct inode *inode,
						const u8 *sd_bytes,
						size_t sd_len)
{
#ifdef CONFIG_SECURITY_PKM_KUNIT
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache;
	u8 *cache_bytes;
	u8 *fake_bytes;

	if (!inode || !inode->i_security || !sd_bytes || sd_len == 0)
		return -EINVAL;
	if (kacs_rust_validate_stored_sd_bytes(sd_bytes, sd_len) != 0)
		return -EINVAL;

	cache_bytes = kmemdup(sd_bytes, sd_len, GFP_KERNEL);
	if (!cache_bytes)
		return -ENOMEM;
	fake_bytes = kmemdup(sd_bytes, sd_len, GFP_KERNEL);
	if (!fake_bytes) {
		kfree(cache_bytes);
		return -ENOMEM;
	}
	cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_VALID,
					      cache_bytes, sd_len);
	if (!cache) {
		kfree(fake_bytes);
		kfree(cache_bytes);
		return -ENOMEM;
	}

	sec = pkm_kacs_inode(inode);
	mutex_lock(&sec->lock);
	kfree(sec->kunit_fake_xattr_bytes);
	sec->kunit_fake_xattr_bytes = fake_bytes;
	sec->kunit_fake_xattr_len = sd_len;
	sec->kunit_fake_xattr_enabled = true;
	pkm_kacs_inode_replace_sd_cache_locked(sec, cache);
	mutex_unlock(&sec->lock);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static long pkm_kacs_kunit_install_live_path_sd(const char *pathname,
						const u8 *sd_bytes,
						size_t sd_len)
{
	struct path path = {};
	struct inode *inode;
	long ret;

	if (!pathname)
		return -EINVAL;

	ret = kern_path(pathname, 0, &path);
	if (ret)
		return ret;
	inode = d_inode(path.dentry);
	ret = pkm_kacs_kunit_install_live_inode_sd(inode, sd_bytes, sd_len);
	path_put(&path);
	return ret;
}

static long pkm_kacs_kunit_create_live_file(const void *subject_token,
					    const char *pathname,
					    struct file **file_out,
					    u64 *inode_out, u64 *size_out)
{
	static const char payload[] = "kacs-id";
	struct pkm_kacs_native_open_prepared prepared = {};
	struct kacs_open_how how = {
		.desired_access = KACS_FILE_READ_DATA |
				  KACS_FILE_WRITE_DATA,
		.create_disposition = KACS_DISPOSITION_CREATE,
	};
	struct path parent_path = {};
	struct path child_path = {};
	struct file parent_file = {};
	struct file *file = NULL;
	struct dentry *dentry;
	struct inode *parent_inode;
	struct inode *inode;
	const u8 *created_sd = NULL;
	size_t created_sd_len = 0;
	u32 granted_access = 0;
	loff_t pos = 0;
	ssize_t written;
	long ret;

	if (!subject_token || !pathname || !file_out)
		return -EINVAL;

	*file_out = NULL;
	ret = pkm_kacs_prepare_native_open(&how, &prepared);
	if (ret)
		return ret;

	dentry = start_creating_path(AT_FDCWD, pathname, &parent_path, 0);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	parent_inode = d_inode(parent_path.dentry);
	if (!parent_inode) {
		ret = -EACCES;
		goto out_end_create;
	}

	parent_file.f_inode = parent_inode;
	*(struct path *)&parent_file.f_path = parent_path;
	ret = pkm_kacs_build_created_file_sd_for_subject(
		subject_token, &parent_file, NULL, 0, false,
		prepared.desired_access, prepared.privilege_intent, &created_sd,
		&created_sd_len, &granted_access);
	if (ret)
		goto out_end_create;

	pkm_kacs_set_current_native_create_request(parent_inode, false,
						   created_sd, created_sd_len);
	ret = security_path_mknod(&parent_path, dentry,
				  pkm_kacs_native_create_mode(false), 0);
	if (!ret)
		ret = vfs_create(mnt_idmap(parent_path.mnt), dentry,
				 pkm_kacs_native_create_mode(false), NULL);
	pkm_kacs_clear_current_native_create_request();
	if (ret)
		goto out_end_create;

	child_path.mnt = mntget(parent_path.mnt);
	child_path.dentry = dget(dentry);
	pkm_kacs_set_current_native_open_request(&child_path,
						 prepared.desired_access,
						 prepared.create_options,
						 prepared.privilege_intent);
	file = dentry_open(&child_path, prepared.open_flags, current_cred());
	pkm_kacs_clear_current_native_open_request();
	path_put(&child_path);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		file = NULL;
		(void)vfs_unlink(mnt_idmap(parent_path.mnt), parent_inode,
				 dentry, NULL);
		goto out_end_create;
	}

	written = kernel_write(file, payload, sizeof(payload) - 1, &pos);
	if (written != sizeof(payload) - 1) {
		ret = written < 0 ? written : -EIO;
		goto out_file;
	}

	inode = file_inode(file);
	if (!inode) {
		ret = -EACCES;
		goto out_file;
	}
	if (inode_out)
		*inode_out = inode->i_ino;
	if (size_out)
		*size_out = (u64)i_size_read(inode);
	*file_out = file;
	ret = 0;
	goto out_end_create;

out_file:
	fput(file);
	flush_delayed_fput();
out_end_create:
	pkm_kacs_clear_current_native_create_request();
	end_creating_path(&parent_path, dentry);
	if (created_sd)
		pkm_kacs_free((void *)created_sd);
	return ret;
}

void pkm_kacs_kunit_cleanup_live_file_fd(
	struct pkm_kacs_kunit_live_file_fd *live)
{
	if (!live)
		return;

	if (live->fd >= 0) {
		close_fd((unsigned int)live->fd);
		flush_delayed_fput();
		live->fd = -1;
	}
	if (live->target_path[0] != '\0')
		(void)pkm_kacs_kunit_remove_path(live->target_path, false);
	if (live->dir_path[0] != '\0')
		(void)pkm_kacs_kunit_remove_path(live->dir_path, true);
}

long pkm_kacs_kunit_create_live_file_fd_for_get_sd(
	const void *subject_token, u32 security_info,
	struct pkm_kacs_kunit_live_file_fd *live_out,
	const u8 **expected_sd_out, size_t *expected_len_out)
{
	char dir_path[64];
	char target_path[96];
	char link_path[96];
	const u8 *dir_sd = NULL;
	struct pkm_kacs_file_security *file_sec;
	struct file *file = NULL;
	size_t dir_sd_len = 0;
	u32 desired_access = 0;
	int fd = -1;
	long ret;

	if (!subject_token || !live_out || !expected_sd_out ||
	    !expected_len_out)
		return -EINVAL;

	memset(live_out, 0, sizeof(*live_out));
	live_out->fd = -1;
	*expected_sd_out = NULL;
	*expected_len_out = 0;

	ret = pkm_kacs_get_sd_required_access(security_info, &desired_access);
	if (ret)
		return ret;

	pkm_kacs_kunit_native_identity_paths(dir_path, sizeof(dir_path),
					     target_path, sizeof(target_path),
					     link_path, sizeof(link_path));
	strscpy(live_out->dir_path, dir_path, sizeof(live_out->dir_path));
	strscpy(live_out->target_path, target_path,
		sizeof(live_out->target_path));
	strscpy(live_out->link_path, link_path, sizeof(live_out->link_path));

	ret = pkm_kacs_kunit_mkdir_path(dir_path);
	if (ret)
		goto out_cleanup;

	dir_sd = kacs_rust_kunit_create_file_sd(
		subject_token, PKM_KACS_KUNIT_FILE_SD_ADMIN_MASK,
		PKM_KACS_KUNIT_FILE_SD_ADMIN_MASK,
		PKM_KACS_KUNIT_FILE_SD_ADMIN_MASK, 0, &dir_sd_len);
	if (!dir_sd || dir_sd_len == 0) {
		ret = -ENOMEM;
		goto out_cleanup;
	}

	ret = pkm_kacs_kunit_install_live_path_sd(dir_path, dir_sd,
						 dir_sd_len);
	if (ret)
		goto out_cleanup;

	ret = pkm_kacs_kunit_create_live_file(subject_token, target_path,
					      &file, NULL, NULL);
	if (ret)
		goto out_cleanup;

	if (!file->f_security) {
		ret = -EACCES;
		goto out_file;
	}
	file_sec = pkm_kacs_file(file);
	if (!file_sec || !file_sec->managed) {
		ret = -EACCES;
		goto out_file;
	}
	file_sec->granted_access |= desired_access;

	ret = pkm_kacs_query_file_sd_core(subject_token, file, security_info,
					  expected_sd_out, expected_len_out);
	if (ret)
		goto out_file;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto out_file;
	}

	fd_install(fd, file);
	file = NULL;
	live_out->fd = fd;
	ret = 0;
	goto out_free_sd;

out_file:
	if (file)
		__fput_sync(file);
	if (ret && *expected_sd_out) {
		pkm_kacs_free((void *)*expected_sd_out);
		*expected_sd_out = NULL;
		*expected_len_out = 0;
	}
out_cleanup:
	pkm_kacs_kunit_cleanup_live_file_fd(live_out);
out_free_sd:
	if (dir_sd)
		pkm_kacs_free((void *)dir_sd);
	return ret;
}

static long pkm_kacs_kunit_link_path(const char *oldname,
				     const char *newname)
{
	struct path old_path = {};
	struct path new_parent_path = {};
	struct dentry *new_dentry;
	struct inode *new_parent_inode;
	long ret;

	if (!oldname || !newname)
		return -EINVAL;

	ret = kern_path(oldname, 0, &old_path);
	if (ret)
		return ret;

	new_dentry = start_creating_path(AT_FDCWD, newname, &new_parent_path,
					 0);
	if (IS_ERR(new_dentry)) {
		ret = PTR_ERR(new_dentry);
		goto out_old;
	}

	new_parent_inode = d_inode(new_parent_path.dentry);
	if (!new_parent_inode) {
		ret = -EACCES;
		goto out_new;
	}

	ret = vfs_link(old_path.dentry, mnt_idmap(new_parent_path.mnt),
		       new_parent_inode, new_dentry, NULL);

out_new:
	end_creating_path(&new_parent_path, new_dentry);
out_old:
	path_put(&old_path);
	return ret;
}

static long pkm_kacs_kunit_path_snapshot(const char *pathname, u64 *inode_out,
					 u64 *size_out)
{
	struct path path = {};
	struct inode *inode;
	long ret;

	if (!pathname)
		return -EINVAL;

	ret = kern_path(pathname, 0, &path);
	if (ret)
		return ret;
	inode = d_inode(path.dentry);
	if (!inode) {
		ret = -EACCES;
		goto out;
	}
	if (inode_out)
		*inode_out = inode->i_ino;
	if (size_out)
		*size_out = (u64)i_size_read(inode);
out:
	path_put(&path);
	return ret;
}

static long pkm_kacs_kunit_query_live_path_sd(const void *subject_token,
					      const char *pathname,
					      const u8 **sd_out,
					      size_t *sd_len_out)
{
	struct path path = {};
	long ret;

	if (!subject_token || !pathname || !sd_out || !sd_len_out)
		return -EINVAL;

	*sd_out = NULL;
	*sd_len_out = 0;
	ret = kern_path(pathname, 0, &path);
	if (ret)
		return ret;

	ret = pkm_kacs_query_path_file_sd_core(
		subject_token, &path,
		KACS_SECINFO_OWNER | KACS_SECINFO_GROUP |
			KACS_SECINFO_DACL,
		sd_out, sd_len_out);
	path_put(&path);
	return ret;
}

static bool pkm_kacs_kunit_sd_equal(const u8 *lhs, size_t lhs_len,
				    const u8 *rhs, size_t rhs_len)
{
	return lhs && rhs && lhs_len == rhs_len &&
	       memcmp(lhs, rhs, lhs_len) == 0;
}

static bool pkm_kacs_kunit_sd_different(const u8 *lhs, size_t lhs_len,
					const u8 *rhs, size_t rhs_len)
{
	if (!lhs || !rhs)
		return false;
	if (lhs_len != rhs_len)
		return true;
	return memcmp(lhs, rhs, lhs_len) != 0;
}

long pkm_kacs_kunit_native_overwrite_identity_for_subject(
	const struct pkm_kacs_kunit_native_open_args *args,
	struct pkm_kacs_kunit_native_identity_result *out)
{
	char dir_path[64];
	char target_path[96];
	char link_path[96];
	struct pkm_kacs_native_open_prepared prepared = {};
	struct file *old_file = NULL;
	struct file *opened_file = NULL;
	struct path target_resolved = {};
	const u8 *sd_before = NULL;
	const u8 *sd_after = NULL;
	size_t sd_before_len = 0;
	size_t sd_after_len = 0;
	u32 status = 0;
	long ret;

	if (!args || !out || !args->subject_token ||
	    !args->target_file_sd_ptr || args->target_file_sd_len == 0 ||
	    !args->parent_file_sd_ptr || args->parent_file_sd_len == 0)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	ret = pkm_kacs_prepare_native_open(
		&(struct kacs_open_how){
			.desired_access = args->desired_access,
			.create_disposition = args->create_disposition,
			.create_options = args->create_options,
			.flags = args->flags,
		},
		&prepared);
	if (ret)
		return ret;
	if (prepared.create_disposition != KACS_DISPOSITION_OVERWRITE &&
	    prepared.create_disposition != KACS_DISPOSITION_OVERWRITE_IF)
		return -EINVAL;

	pkm_kacs_kunit_native_identity_paths(dir_path, sizeof(dir_path),
					     target_path, sizeof(target_path),
					     link_path, sizeof(link_path));

	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_MKDIR;
	ret = pkm_kacs_kunit_mkdir_path(dir_path);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_INSTALL_DIR_SD;
	ret = pkm_kacs_kunit_install_live_path_sd(
		dir_path, args->parent_file_sd_ptr, args->parent_file_sd_len);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_CREATE_FILE;
	ret = pkm_kacs_kunit_create_live_file(args->subject_token, target_path,
					     &old_file,
					     &out->old_inode,
					     &out->size_before);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_INSTALL_TARGET_SD;
	ret = pkm_kacs_kunit_install_live_path_sd(
		target_path, args->target_file_sd_ptr,
		args->target_file_sd_len);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_LINK;
	ret = pkm_kacs_kunit_link_path(target_path, link_path);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_QUERY_BEFORE;
	ret = pkm_kacs_kunit_query_live_path_sd(args->subject_token,
						target_path, &sd_before,
						&sd_before_len);
	if (ret)
		goto out;

	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_RESOLVE_TARGET;
	ret = kern_path(target_path, 0, &target_resolved);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_NATIVE_OPEN;
	ret = pkm_kacs_do_native_overwrite_open(&target_resolved, &prepared,
						&opened_file, &status);
	path_put(&target_resolved);
	memset(&target_resolved, 0, sizeof(target_resolved));
	if (ret)
		goto out;

	out->status = status;
	out->granted_access = pkm_kacs_file(opened_file)->granted_access;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_SNAPSHOT_TARGET;
	ret = pkm_kacs_kunit_path_snapshot(target_path,
					   &out->target_inode_after,
					   &out->size_after);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_SNAPSHOT_LINK;
	ret = pkm_kacs_kunit_path_snapshot(link_path, &out->link_inode_after,
					   NULL);
	if (ret)
		goto out;
	out->old_fd_inode_after = file_inode(old_file)->i_ino;
	out->old_fd_size_after = (u64)i_size_read(file_inode(old_file));
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_QUERY_TARGET_AFTER;
	ret = pkm_kacs_kunit_query_live_path_sd(args->subject_token,
						target_path, &sd_after,
						&sd_after_len);
	if (ret)
		goto out;

	out->same_inode_after =
		out->target_inode_after == out->old_inode ? 1U : 0U;
	out->hardlink_preserved =
		out->link_inode_after == out->old_inode ? 1U : 0U;
	out->old_fd_preserved =
		out->old_fd_inode_after == out->old_inode ? 1U : 0U;
	out->sd_preserved = pkm_kacs_kunit_sd_equal(
		sd_before, sd_before_len, sd_after, sd_after_len) ? 1U : 0U;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_NONE;
	ret = 0;

out:
	if (target_resolved.dentry)
		path_put(&target_resolved);
	pkm_kacs_free((void *)sd_after);
	pkm_kacs_free((void *)sd_before);
	if (opened_file) {
		fput(opened_file);
		flush_delayed_fput();
	}
	if (old_file) {
		fput(old_file);
		flush_delayed_fput();
	}
	pkm_kacs_kunit_cleanup_native_identity_paths(dir_path, target_path,
						     link_path);
	return ret;
}

long pkm_kacs_kunit_native_supersede_identity_for_subject(
	const struct pkm_kacs_kunit_native_open_args *args,
	struct pkm_kacs_kunit_native_identity_result *out)
{
	char dir_path[64];
	char target_path[96];
	char link_path[96];
	struct pkm_kacs_native_open_prepared prepared = {};
	struct file *old_file = NULL;
	struct file *opened_file = NULL;
	struct path target_resolved = {};
	const u8 *old_sd = NULL;
	const u8 *target_sd_after = NULL;
	const u8 *link_sd_after = NULL;
	size_t old_sd_len = 0;
	size_t target_sd_after_len = 0;
	size_t link_sd_after_len = 0;
	u32 status = 0;
	long ret;

	if (!args || !out || !args->subject_token ||
	    !args->target_file_sd_ptr || args->target_file_sd_len == 0 ||
	    !args->parent_file_sd_ptr || args->parent_file_sd_len == 0)
		return -EINVAL;
	if (args->input_sd_ptr || args->input_sd_len != 0)
		return -EOPNOTSUPP;

	memset(out, 0, sizeof(*out));
	ret = pkm_kacs_prepare_native_open(
		&(struct kacs_open_how){
			.desired_access = args->desired_access,
			.create_disposition = args->create_disposition,
			.create_options = args->create_options,
			.flags = args->flags,
		},
		&prepared);
	if (ret)
		return ret;
	if (prepared.create_disposition != KACS_DISPOSITION_SUPERSEDE)
		return -EINVAL;

	pkm_kacs_kunit_native_identity_paths(dir_path, sizeof(dir_path),
					     target_path, sizeof(target_path),
					     link_path, sizeof(link_path));

	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_MKDIR;
	ret = pkm_kacs_kunit_mkdir_path(dir_path);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_INSTALL_DIR_SD;
	ret = pkm_kacs_kunit_install_live_path_sd(
		dir_path, args->parent_file_sd_ptr, args->parent_file_sd_len);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_CREATE_FILE;
	ret = pkm_kacs_kunit_create_live_file(args->subject_token, target_path,
					     &old_file,
					     &out->old_inode,
					     &out->size_before);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_INSTALL_TARGET_SD;
	ret = pkm_kacs_kunit_install_live_path_sd(
		target_path, args->target_file_sd_ptr,
		args->target_file_sd_len);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_LINK;
	ret = pkm_kacs_kunit_link_path(target_path, link_path);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_QUERY_BEFORE;
	ret = pkm_kacs_kunit_query_live_path_sd(args->subject_token,
						target_path, &old_sd,
						&old_sd_len);
	if (ret)
		goto out;

	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_RESOLVE_TARGET;
	ret = kern_path(target_path, 0, &target_resolved);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_NATIVE_OPEN;
	ret = pkm_kacs_do_native_supersede_open(
		args->subject_token, &target_resolved,
		&(struct kacs_open_how){
			.desired_access = args->desired_access,
			.create_disposition = args->create_disposition,
			.create_options = args->create_options,
			.flags = args->flags,
		},
		&prepared, &opened_file, &status);
	path_put(&target_resolved);
	memset(&target_resolved, 0, sizeof(target_resolved));
	if (ret)
		goto out;

	out->status = status;
	out->granted_access = pkm_kacs_file(opened_file)->granted_access;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_SNAPSHOT_TARGET;
	ret = pkm_kacs_kunit_path_snapshot(target_path,
					   &out->target_inode_after,
					   &out->size_after);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_SNAPSHOT_LINK;
	ret = pkm_kacs_kunit_path_snapshot(link_path, &out->link_inode_after,
					   NULL);
	if (ret)
		goto out;
	out->old_fd_inode_after = file_inode(old_file)->i_ino;
	out->old_fd_size_after = (u64)i_size_read(file_inode(old_file));
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_QUERY_TARGET_AFTER;
	ret = pkm_kacs_kunit_query_live_path_sd(args->subject_token,
						target_path, &target_sd_after,
						&target_sd_after_len);
	if (ret)
		goto out;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_QUERY_LINK_AFTER;
	ret = pkm_kacs_kunit_query_live_path_sd(args->subject_token,
						link_path, &link_sd_after,
						&link_sd_after_len);
	if (ret)
		goto out;

	out->same_inode_after =
		out->target_inode_after == out->old_inode ? 1U : 0U;
	out->hardlink_preserved =
		out->link_inode_after == out->old_inode ? 1U : 0U;
	out->old_fd_preserved =
		out->old_fd_inode_after == out->old_inode ? 1U : 0U;
	out->sd_preserved = pkm_kacs_kunit_sd_equal(
		old_sd, old_sd_len, link_sd_after, link_sd_after_len) ? 1U : 0U;
	out->sd_recomputed = pkm_kacs_kunit_sd_different(
		old_sd, old_sd_len, target_sd_after,
		target_sd_after_len) ? 1U : 0U;
	out->failure_step = PKM_KACS_KUNIT_NATIVE_ID_STEP_NONE;
	ret = 0;

out:
	if (target_resolved.dentry)
		path_put(&target_resolved);
	pkm_kacs_free((void *)link_sd_after);
	pkm_kacs_free((void *)target_sd_after);
	pkm_kacs_free((void *)old_sd);
	if (opened_file) {
		fput(opened_file);
		flush_delayed_fput();
	}
	if (old_file) {
		fput(old_file);
		flush_delayed_fput();
	}
	pkm_kacs_kunit_cleanup_native_identity_paths(dir_path, target_path,
						     link_path);
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
	long set_ret;
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
	inode_sec = pkm_kacs_inode(&state->inode);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	inode_sec->kunit_fake_xattr_fail_set = args->fail_xattr_write != 0;
#endif

	ret = pkm_kacs_set_file_sd_core(args->subject_token, &state->file,
					args->security_info,
					args->input_sd_ptr,
					args->input_sd_len);
	set_ret = ret;
	if (ret && !args->fail_xattr_write)
		goto out_cleanup;

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
	if (!ret || (args->fail_xattr_write && result_sd)) {
		*out_sd_ptr = result_sd;
		*out_sd_len = result_sd_len;
		ret = set_ret;
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
	if (kacs_rust_validate_stored_sd_bytes(sd_ptr, sd_len) != 0)
		return PKM_KACS_KUNIT_FILE_SD_CORRUPT;

	return PKM_KACS_KUNIT_FILE_SD_VALID;
}

static int pkm_kacs_kunit_init_file_mount_state_ex(
	struct pkm_kacs_kunit_file_mount_state *state, u64 magic,
	struct pkm_kacs_inode_sd_cache *cache, u32 policy_override,
	const u8 *template_sd_ptr, size_t template_sd_len, umode_t mode,
	bool fake_xattr_enabled);
static void pkm_kacs_kunit_cleanup_file_mount_state(
	struct pkm_kacs_kunit_file_mount_state *state);

int pkm_kacs_kunit_file_sd_cache_cas_loser(
	const u8 *sd_ptr, size_t sd_len, u32 *first_installed_out,
	u32 *second_installed_out, size_t *live_len_out)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_inode_sd_cache *first_cache = NULL;
	struct pkm_kacs_inode_sd_cache *second_cache = NULL;
	struct pkm_kacs_inode_sd_cache *live_cache;
	struct pkm_kacs_inode_security *sec;
	const u8 *first_bytes = NULL;
	const u8 *second_bytes = NULL;
	bool first_installed;
	bool second_installed;
	int ret;

	if (!sd_ptr || sd_len == 0 || !first_installed_out ||
	    !second_installed_out || !live_len_out)
		return -EINVAL;

	*first_installed_out = 0;
	*second_installed_out = 0;
	*live_len_out = 0;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	first_bytes = kmemdup(sd_ptr, sd_len, GFP_KERNEL);
	second_bytes = kmemdup(sd_ptr, sd_len, GFP_KERNEL);
	if (!first_bytes || !second_bytes) {
		ret = -ENOMEM;
		goto out;
	}

	first_cache = pkm_kacs_inode_sd_cache_alloc(
		PKM_KACS_INODE_SD_VALID, first_bytes, sd_len);
	if (first_cache)
		first_bytes = NULL;
	second_cache = pkm_kacs_inode_sd_cache_alloc(
		PKM_KACS_INODE_SD_VALID, second_bytes, sd_len);
	if (second_cache)
		second_bytes = NULL;
	if (!first_cache || !second_cache) {
		ret = -ENOMEM;
		goto out;
	}

	sec = pkm_kacs_inode(&state.inode);
	first_installed =
		pkm_kacs_inode_try_publish_sd_cache(sec, NULL, first_cache);
	if (first_installed)
		first_cache = NULL;
	second_installed =
		pkm_kacs_inode_try_publish_sd_cache(sec, NULL, second_cache);
	if (second_installed) {
		second_cache = NULL;
	} else {
		pkm_kacs_inode_sd_cache_free(second_cache);
		second_cache = NULL;
	}

	live_cache = rcu_dereference_protected(sec->sd_cache, 1);
	*first_installed_out = first_installed ? 1U : 0U;
	*second_installed_out = second_installed ? 1U : 0U;
	*live_len_out = live_cache ? live_cache->len : 0;
	ret = 0;

out:
	pkm_kacs_inode_sd_cache_free(second_cache);
	pkm_kacs_inode_sd_cache_free(first_cache);
	pkm_kacs_free((void *)second_bytes);
	pkm_kacs_free((void *)first_bytes);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
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
		const u8 *copied_bytes;

		if (kacs_rust_validate_stored_sd_bytes(template_sd_ptr,
						       template_sd_len) != 0) {
			ret = -EINVAL;
			goto out_err;
		}
		copied_bytes = kmemdup(template_sd_ptr, template_sd_len,
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
	state->file.f_mode = FMODE_READ;
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

long pkm_kacs_kunit_corrupt_file_sd_population_twice(
	const u8 *sd_ptr, size_t sd_len, long *first_ret_out,
	long *second_ret_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_security *sec;
	const void *subject_token;
	const u8 *subset = NULL;
	size_t subset_len = 0;
	long first_ret;
	long second_ret;
	long ret;

	if (!sd_ptr || sd_len == 0 || !first_ret_out || !second_ret_out)
		return -EINVAL;

	*first_ret_out = 0;
	*second_ret_out = 0;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, EXT4_SUPER_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		goto out_free;

	sec = pkm_kacs_inode(&state->inode);
	ret = pkm_kacs_kunit_fake_setxattr_locked(sec, sd_ptr, sd_len);
	if (ret)
		goto out_cleanup;

	state->file.f_mode = FMODE_PATH;
	first_ret = pkm_kacs_query_file_sd_core(
		subject_token, &state->file, KACS_SECINFO_DACL, &subset,
		&subset_len);
	pkm_kacs_free((void *)subset);
	subset = NULL;
	subset_len = 0;

	second_ret = pkm_kacs_query_file_sd_core(
		subject_token, &state->file, KACS_SECINFO_DACL, &subset,
		&subset_len);
	pkm_kacs_free((void *)subset);

	*first_ret_out = first_ret;
	*second_ret_out = second_ret;
	ret = 0;

out_cleanup:
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

	state->file.f_mode = FMODE_PATH;
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

	state->file.f_mode = FMODE_PATH;
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

long pkm_kacs_kunit_persistent_synthesis_second_query_uses_cache(
	const void *subject_token, long *first_ret_out, long *second_ret_out,
	u32 *xattr_written_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_security *sec;
	const u8 *subset = NULL;
	size_t subset_len = 0;
	long ret;

	if (!subject_token || !first_ret_out || !second_ret_out ||
	    !xattr_written_out)
		return -EINVAL;

	*first_ret_out = 0;
	*second_ret_out = 0;
	*xattr_written_out = 0;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, TMPFS_MAGIC, NULL,
		KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT, NULL, 0,
		S_IFREG, true);
	if (ret)
		goto out_free;

	state->file.f_mode = FMODE_PATH;
	*first_ret_out = pkm_kacs_query_file_sd_core(
		subject_token, &state->file, KACS_SECINFO_DACL, &subset,
		&subset_len);
	pkm_kacs_free((void *)subset);
	subset = NULL;
	subset_len = 0;

	sec = pkm_kacs_inode(&state->inode);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	*xattr_written_out = sec->kunit_fake_xattr_bytes &&
			     sec->kunit_fake_xattr_len != 0;
	sec->kunit_fake_xattr_fail_set = true;
#endif

	*second_ret_out = pkm_kacs_query_file_sd_core(
		subject_token, &state->file, KACS_SECINFO_DACL, &subset,
		&subset_len);
	pkm_kacs_free((void *)subset);
	ret = 0;

	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_persistent_synthesis_pending_entry_persists_on_access(
	const void *subject_token, u32 *queued_after_synthesis_out,
	u32 *queued_after_reaccess_out, u32 *source_after_persist_out,
	u32 *queued_after_persisted_reaccess_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache;
	const u8 *subset = NULL;
	size_t subset_len = 0;
	long ret;

	if (!subject_token || !queued_after_synthesis_out ||
	    !queued_after_reaccess_out || !source_after_persist_out ||
	    !queued_after_persisted_reaccess_out)
		return -EINVAL;

	*queued_after_synthesis_out = 0;
	*queued_after_reaccess_out = 0;
	*source_after_persist_out = 0;
	*queued_after_persisted_reaccess_out = 0;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, TMPFS_MAGIC, NULL,
		KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT, NULL, 0,
		S_IFREG, true);
	if (ret)
		goto out_free;
	sec = pkm_kacs_inode(&state->inode);

	/* Synthesis: a SYNTHETIC_PENDING entry, offered for write-back once. */
	state->file.f_mode = FMODE_PATH;
	ret = pkm_kacs_query_file_sd_core(subject_token, &state->file,
					  KACS_SECINFO_DACL, &subset,
					  &subset_len);
	pkm_kacs_free((void *)subset);
	if (ret)
		goto out_cleanup;
	*queued_after_synthesis_out = sec->kunit_persist_queue_calls;

	/*
	 * The entry is current, and (a kthread cannot carry task_work, and a
	 * pending ancestor is never offered at all) still pending.  A later
	 * access to the object in its own right offers it again.
	 */
	ret = pkm_kacs_inode_ensure_effective_cache(&state->file, sec);
	if (ret)
		goto out_cleanup;
	*queued_after_reaccess_out = sec->kunit_persist_queue_calls;

	/* The write-back runs: the entry becomes a stored-descriptor one. */
	pkm_kacs_inode_run_sd_persist(&state->dentry, &state->inode, sec);
	cache = pkm_kacs_inode_sd_cache_get_current(&state->inode, sec);
	if (cache) {
		*source_after_persist_out = cache->source;
		pkm_kacs_inode_sd_cache_free(cache);
	}

	/* And once stored, a further access owes nothing. */
	ret = pkm_kacs_inode_ensure_effective_cache(&state->file, sec);
	if (ret)
		goto out_cleanup;
	*queued_after_persisted_reaccess_out = sec->kunit_persist_queue_calls;
	ret = 0;

out_cleanup:
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_query_file_sd_with_getxattr_errno(
	const void *subject_token, int getxattr_errno, u32 mount_policy)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_security *sec;
	const u8 *subset = NULL;
	size_t subset_len = 0;
	long ret;

	if (!subject_token || getxattr_errno >= 0)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, TMPFS_MAGIC, NULL, mount_policy, NULL, 0, S_IFREG,
		true);
	if (ret)
		goto out_free;
	sec = pkm_kacs_inode(&state->inode);
	sec->kunit_fake_xattr_get_errno = getxattr_errno;

	state->file.f_mode = FMODE_PATH;
	ret = pkm_kacs_query_file_sd_core(subject_token, &state->file,
					  KACS_SECINFO_DACL, &subset,
					  &subset_len);
	pkm_kacs_free((void *)subset);

	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_persistent_synthesis_deferred_persist(
	const void *subject_token, u32 *inline_written_out,
	u32 *persisted_written_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_security *sec;
	const u8 *subset = NULL;
	size_t subset_len = 0;
	long ret;

	if (!subject_token || !inline_written_out || !persisted_written_out)
		return -EINVAL;

	*inline_written_out = 0;
	*persisted_written_out = 0;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, TMPFS_MAGIC, NULL,
		KACS_MOUNT_POLICY_SYNTHESIZE_PERSISTENT, NULL, 0,
		S_IFREG, true);
	if (ret)
		goto out_free;

	state->file.f_mode = FMODE_PATH;
	ret = pkm_kacs_query_file_sd_core(subject_token, &state->file,
					  KACS_SECINFO_DACL, &subset,
					  &subset_len);
	pkm_kacs_free((void *)subset);
	if (ret)
		goto out_cleanup;

	/*
	 * Synthesis on a PERSISTENT mount must defer the xattr write-back; the
	 * fake xattr stays unwritten immediately after the query.
	 */
	sec = pkm_kacs_inode(&state->inode);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	*inline_written_out = (sec->kunit_fake_xattr_bytes &&
			       sec->kunit_fake_xattr_len != 0) ?
				      1U :
				      0U;
#endif

	/* Drive the work the return-to-userspace task_work would run. */
	pkm_kacs_inode_run_sd_persist(&state->dentry, &state->inode, sec);

#ifdef CONFIG_SECURITY_PKM_KUNIT
	*persisted_written_out = (sec->kunit_fake_xattr_bytes &&
				  sec->kunit_fake_xattr_len != 0) ?
					 1U :
					 0U;
#endif
	ret = 0;

out_cleanup:
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

int pkm_kacs_kunit_cache_generation_currentness(
	const u8 *valid_sd_ptr, size_t valid_sd_len, u32 *missing_current_out,
	u32 *synthetic_current_out, u32 *xattr_current_out,
	u32 *corrupt_current_out, u32 *synthetic_pending_current_out)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_superblock_security *sb_sec;
	struct pkm_kacs_inode_sd_cache *missing_cache = NULL;
	struct pkm_kacs_inode_sd_cache *synthetic_cache = NULL;
	struct pkm_kacs_inode_sd_cache *xattr_cache = NULL;
	struct pkm_kacs_inode_sd_cache *corrupt_cache = NULL;
	struct pkm_kacs_inode_sd_cache *pending_cache = NULL;
	const u8 *synthetic_bytes = NULL;
	const u8 *xattr_bytes = NULL;
	const u8 *pending_bytes = NULL;
	int ret;

	if (!valid_sd_ptr || valid_sd_len == 0 || !missing_current_out ||
	    !synthetic_current_out || !xattr_current_out ||
	    !corrupt_current_out || !synthetic_pending_current_out)
		return -EINVAL;

	*missing_current_out = 0;
	*synthetic_current_out = 0;
	*xattr_current_out = 0;
	*corrupt_current_out = 0;
	*synthetic_pending_current_out = 0;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL,
		KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL, NULL, 0,
		S_IFREG, true);
	if (ret)
		return ret;

	sb_sec = pkm_kacs_sb(&state.sb);
	WRITE_ONCE(sb_sec->policy_generation, 2);

	missing_cache = pkm_kacs_inode_sd_cache_alloc_ex(
		PKM_KACS_INODE_SD_MISSING, NULL, 0,
		PKM_KACS_INODE_SD_SOURCE_MISSING, 1);
	synthetic_bytes = kmemdup(valid_sd_ptr, valid_sd_len, GFP_KERNEL);
	xattr_bytes = kmemdup(valid_sd_ptr, valid_sd_len, GFP_KERNEL);
	if (!synthetic_bytes || !xattr_bytes) {
		ret = -ENOMEM;
		goto out;
	}
	synthetic_cache = pkm_kacs_inode_sd_cache_alloc_ex(
		PKM_KACS_INODE_SD_VALID, synthetic_bytes, valid_sd_len,
		PKM_KACS_INODE_SD_SOURCE_SYNTHETIC, 1);
	if (synthetic_cache)
		synthetic_bytes = NULL;
	xattr_cache = pkm_kacs_inode_sd_cache_alloc_ex(
		PKM_KACS_INODE_SD_VALID, xattr_bytes, valid_sd_len,
		PKM_KACS_INODE_SD_SOURCE_XATTR, 1);
	if (xattr_cache)
		xattr_bytes = NULL;
	corrupt_cache = pkm_kacs_inode_sd_cache_alloc_ex(
		PKM_KACS_INODE_SD_CORRUPT, NULL, 0,
		PKM_KACS_INODE_SD_SOURCE_CORRUPT, 1);
	pending_bytes = kmemdup(valid_sd_ptr, valid_sd_len, GFP_KERNEL);
	if (!pending_bytes) {
		ret = -ENOMEM;
		goto out;
	}
	pending_cache = pkm_kacs_inode_sd_cache_alloc_ex(
		PKM_KACS_INODE_SD_VALID, pending_bytes, valid_sd_len,
		PKM_KACS_INODE_SD_SOURCE_SYNTHETIC_PENDING, 1);
	if (pending_cache)
		pending_bytes = NULL;
	if (!missing_cache || !synthetic_cache || !xattr_cache ||
	    !corrupt_cache || !pending_cache) {
		ret = -ENOMEM;
		goto out;
	}

	*missing_current_out = pkm_kacs_inode_sd_cache_current(
				       &state.sb, missing_cache) ?
				       1U :
				       0U;
	*synthetic_current_out = pkm_kacs_inode_sd_cache_current(
					 &state.sb, synthetic_cache) ?
					 1U :
					 0U;
	*xattr_current_out = pkm_kacs_inode_sd_cache_current(
				     &state.sb, xattr_cache) ?
				     1U :
				     0U;
	*corrupt_current_out = pkm_kacs_inode_sd_cache_current(
				       &state.sb, corrupt_cache) ?
				       1U :
				       0U;
	*synthetic_pending_current_out = pkm_kacs_inode_sd_cache_current(
						 &state.sb, pending_cache) ?
						 1U :
						 0U;
	ret = 0;

out:
	pkm_kacs_free((void *)pending_bytes);
	pkm_kacs_free((void *)xattr_bytes);
	pkm_kacs_free((void *)synthetic_bytes);
	pkm_kacs_inode_sd_cache_free(pending_cache);
	pkm_kacs_inode_sd_cache_free(corrupt_cache);
	pkm_kacs_inode_sd_cache_free(xattr_cache);
	pkm_kacs_inode_sd_cache_free(synthetic_cache);
	pkm_kacs_inode_sd_cache_free(missing_cache);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

static long pkm_kacs_kunit_copy_mount_template(
	const struct kacs_mount_policy_args *args, const u8 **template_out)
{
	const u8 *template_ptr;
	const u8 *copy;

	if (!args || !template_out)
		return -EINVAL;

	*template_out = NULL;
	if (args->template_sd_len == 0)
		return 0;
	if (args->template_sd_ptr == 0)
		return -EINVAL;

	template_ptr = (const u8 *)(unsigned long)args->template_sd_ptr;
	copy = kmemdup(template_ptr, args->template_sd_len, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	*template_out = copy;
	return 0;
}

long pkm_kacs_kunit_set_mount_policy_for_subject(
	const void *subject_token, u64 magic,
	const struct kacs_mount_policy_args *args, u32 *policy_out,
	u32 *generation_out, u32 *template_len_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct kacs_mount_policy_args snapshot = {};
	const u8 *template_bytes = NULL;
	const u8 *snapshot_template = NULL;
	long ret;

	if (!args || !policy_out || !generation_out || !template_len_out)
		return -EINVAL;

	*policy_out = 0;
	*generation_out = 0;
	*template_len_out = 0;

	ret = pkm_kacs_validate_mount_policy_args(args);
	if (ret)
		return ret;

	ret = pkm_kacs_kunit_copy_mount_template(args, &template_bytes);
	if (ret)
		return ret;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_free((void *)template_bytes);
		return -ENOMEM;
	}

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic ? magic : TMPFS_MAGIC, NULL, 0, NULL, 0,
		S_IFREG, true);
	if (ret)
		goto out_free;

	ret = pkm_kacs_set_mount_policy_core(subject_token, &state->sb, args,
					     template_bytes);
	if (ret)
		goto out_mount;
	template_bytes = NULL;

	ret = pkm_kacs_get_mount_policy_snapshot(&state->sb, &snapshot,
						 &snapshot_template);
	if (ret)
		goto out_mount;

	*policy_out = snapshot.policy;
	*generation_out = snapshot.generation;
	*template_len_out = snapshot.template_sd_len;

out_mount:
	pkm_kacs_free((void *)snapshot_template);
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	pkm_kacs_free((void *)template_bytes);
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_same_superblock_mount_policy_for_subject(
	const void *subject_token, const struct kacs_mount_policy_args *args,
	u32 *first_policy_out, u32 *second_policy_out,
	u32 *first_generation_out, u32 *second_generation_out,
	u32 *first_template_len_out, u32 *second_template_len_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct kacs_mount_policy_args first_snapshot = {};
	struct kacs_mount_policy_args second_snapshot = {};
	struct inode second_inode = {};
	const u8 *template_bytes = NULL;
	const u8 *first_template = NULL;
	const u8 *second_template = NULL;
	long ret;

	if (!args || !first_policy_out || !second_policy_out ||
	    !first_generation_out || !second_generation_out ||
	    !first_template_len_out || !second_template_len_out)
		return -EINVAL;

	*first_policy_out = 0;
	*second_policy_out = 0;
	*first_generation_out = 0;
	*second_generation_out = 0;
	*first_template_len_out = 0;
	*second_template_len_out = 0;

	ret = pkm_kacs_validate_mount_policy_args(args);
	if (ret)
		return ret;

	ret = pkm_kacs_kunit_copy_mount_template(args, &template_bytes);
	if (ret)
		return ret;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_free((void *)template_bytes);
		return -ENOMEM;
	}

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, EXT4_SUPER_MAGIC, NULL, 0, NULL, 0, S_IFREG, true);
	if (ret)
		goto out_free;

	second_inode.i_sb = state->file.f_inode->i_sb;
	ret = pkm_kacs_set_mount_policy_core(subject_token,
					     state->file.f_inode->i_sb, args,
					     template_bytes);
	if (ret)
		goto out_mount;
	template_bytes = NULL;

	ret = pkm_kacs_get_mount_policy_snapshot(state->file.f_inode->i_sb,
						 &first_snapshot,
						 &first_template);
	if (ret)
		goto out_mount;
	ret = pkm_kacs_get_mount_policy_snapshot(second_inode.i_sb,
						 &second_snapshot,
						 &second_template);
	if (ret)
		goto out_mount;

	*first_policy_out = first_snapshot.policy;
	*second_policy_out = second_snapshot.policy;
	*first_generation_out = first_snapshot.generation;
	*second_generation_out = second_snapshot.generation;
	*first_template_len_out = first_snapshot.template_sd_len;
	*second_template_len_out = second_snapshot.template_sd_len;

out_mount:
	pkm_kacs_free((void *)second_template);
	pkm_kacs_free((void *)first_template);
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	pkm_kacs_free((void *)template_bytes);
	kfree(state);
	return ret;
}

long pkm_kacs_kunit_mount_policy_failure_preserves_state(
	const void *subject_token, u64 magic,
	const struct kacs_mount_policy_args *initial_args,
	const struct kacs_mount_policy_args *failure_args,
	long *failure_ret_out, u32 *policy_out, u32 *generation_out,
	u32 *template_len_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct kacs_mount_policy_args snapshot = {};
	const u8 *initial_template = NULL;
	const u8 *failure_template = NULL;
	const u8 *snapshot_template = NULL;
	long failure_ret;
	long ret;

	if (!initial_args || !failure_args || !failure_ret_out ||
	    !policy_out || !generation_out || !template_len_out)
		return -EINVAL;

	*failure_ret_out = 0;
	*policy_out = 0;
	*generation_out = 0;
	*template_len_out = 0;

	ret = pkm_kacs_validate_mount_policy_args(initial_args);
	if (ret)
		return ret;
	ret = pkm_kacs_kunit_copy_mount_template(initial_args,
						 &initial_template);
	if (ret)
		return ret;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_free((void *)initial_template);
		return -ENOMEM;
	}

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, magic ? magic : TMPFS_MAGIC, NULL, 0, NULL, 0,
		S_IFREG, true);
	if (ret)
		goto out_free;

	ret = pkm_kacs_set_mount_policy_core(subject_token, &state->sb,
					     initial_args,
					     initial_template);
	if (ret)
		goto out_mount;
	initial_template = NULL;

	failure_ret = pkm_kacs_validate_mount_policy_args(failure_args);
	if (!failure_ret) {
		failure_ret = pkm_kacs_kunit_copy_mount_template(
			failure_args, &failure_template);
		if (!failure_ret) {
			failure_ret = pkm_kacs_set_mount_policy_core(
				subject_token, &state->sb, failure_args,
				failure_template);
			if (!failure_ret)
				failure_template = NULL;
		}
	}
	*failure_ret_out = failure_ret;

	ret = pkm_kacs_get_mount_policy_snapshot(&state->sb, &snapshot,
						 &snapshot_template);
	if (ret)
		goto out_mount;

	*policy_out = snapshot.policy;
	*generation_out = snapshot.generation;
	*template_len_out = snapshot.template_sd_len;

out_mount:
	pkm_kacs_free((void *)snapshot_template);
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	pkm_kacs_free((void *)failure_template);
	pkm_kacs_free((void *)initial_template);
	kfree(state);
	return ret;
}

static const struct file_operations pkm_kacs_kunit_mount_policy_fops = { };

long pkm_kacs_kunit_mount_policy_opath_fd_resolves_superblock(
	u32 *policy_out)
{
	struct super_block *sb = NULL;
	struct file *resolved_file = NULL;
	struct file *file;
	int fd;
	long ret;

	if (!policy_out)
		return -EINVAL;

	*policy_out = 0;
	file = anon_inode_create_getfile("pkm-kacs-mount-policy-opath",
					 &pkm_kacs_kunit_mount_policy_fops,
					 NULL, O_RDONLY | O_CLOEXEC, NULL);
	if (IS_ERR(file))
		return PTR_ERR(file);

	file->f_flags = O_PATH | O_CLOEXEC;
	/*
	 * OR in FMODE_PATH rather than overwriting: anon_inode_create_getfile()
	 * set FMODE_OPENED and the file pins path.dentry/path.mnt. Clearing
	 * FMODE_OPENED makes __fput() take the file_free() fast path and skip
	 * dput()/mntput(), leaking the dentry/mnt on every call.
	 */
	file->f_mode |= FMODE_PATH;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		return fd;
	}

	fd_install(fd, file);
	file = NULL;

	ret = pkm_kacs_mount_policy_fd_superblock(fd, &resolved_file, &sb);
	if (!ret)
		*policy_out = pkm_kacs_superblock_mount_policy(sb);

	if (resolved_file)
		fput(resolved_file);
	close_fd((unsigned int)fd);
	return ret;
}

u32 pkm_kacs_kunit_next_mount_policy_generation(u32 generation)
{
	return pkm_kacs_next_mount_policy_generation(generation);
}

long pkm_kacs_kunit_adopt_missing_mount_for_subject(
	const void *subject_token, const struct kacs_mount_policy_args *args,
	const u8 **out_sd_ptr, size_t *out_sd_len,
	u32 *xattr_written_out, long *first_query_ret_out)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_security *sec;
	const u8 *template_bytes = NULL;
	const u8 *first_sd = NULL;
	size_t first_sd_len = 0;
	long first_ret;
	long ret;

	if (!args || !out_sd_ptr || !out_sd_len || !xattr_written_out ||
	    !first_query_ret_out)
		return -EINVAL;

	*out_sd_ptr = NULL;
	*out_sd_len = 0;
	*xattr_written_out = 0;
	*first_query_ret_out = 0;

	ret = pkm_kacs_validate_mount_policy_args(args);
	if (ret)
		return ret;

	ret = pkm_kacs_kunit_copy_mount_template(args, &template_bytes);
	if (ret)
		return ret;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		pkm_kacs_free((void *)template_bytes);
		return -ENOMEM;
	}

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		state, TMPFS_MAGIC, NULL, 0, NULL, 0, S_IFREG, true);
	if (ret)
		goto out_free;

	state->file.f_mode = FMODE_PATH;
	first_ret = pkm_kacs_query_file_sd_core(
		subject_token, &state->file, KACS_SECINFO_DACL,
		&first_sd, &first_sd_len);
	pkm_kacs_free((void *)first_sd);
	*first_query_ret_out = first_ret;

	ret = pkm_kacs_set_mount_policy_core(subject_token, &state->sb, args,
					     template_bytes);
	if (ret)
		goto out_mount;
	template_bytes = NULL;

	ret = pkm_kacs_query_file_sd_core(subject_token, &state->file,
					  KACS_SECINFO_DACL,
					  out_sd_ptr, out_sd_len);
	if (!ret) {
		sec = pkm_kacs_inode(&state->inode);
#ifdef CONFIG_SECURITY_PKM_KUNIT
		*xattr_written_out = sec->kunit_fake_xattr_bytes &&
				     sec->kunit_fake_xattr_len != 0;
#endif
	}

out_mount:
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	pkm_kacs_free((void *)template_bytes);
	kfree(state);
	return ret;
}

static int pkm_kacs_kunit_inode_sd_xattr_check(u32 op, const char *name,
					       size_t set_size, u32 ntfs)
{
	struct file_system_type fs_type = {};
	struct pkm_kacs_kunit_file_mount_state state = {};
	static const u8 nonempty_value[4] = { 1, 2, 3, 4 };
	const void *value = set_size ? nonempty_value : NULL;
	int ret;

	fs_type.name = ntfs ? "ntfs3" : "tmpfs";
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_UNMANAGED,
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
					      value, set_size, 0);
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
	return pkm_kacs_kunit_inode_sd_xattr_check(1, name, 0, ntfs);
}

int pkm_kacs_kunit_inode_sd_xattr_set(const char *name, u32 ntfs)
{
	return pkm_kacs_kunit_inode_sd_xattr_check(2, name, 0, ntfs);
}

int pkm_kacs_kunit_inode_sd_xattr_set_sized(const char *name, size_t size,
					    u32 ntfs)
{
	if (size > 4)
		return -EINVAL;

	return pkm_kacs_kunit_inode_sd_xattr_check(2, name, size, ntfs);
}

int pkm_kacs_kunit_inode_sd_xattr_remove(const char *name, u32 ntfs)
{
	return pkm_kacs_kunit_inode_sd_xattr_check(3, name, 0, ntfs);
}

int pkm_kacs_kunit_inode_xattr_skipcap(const char *name)
{
	return pkm_kacs_inode_xattr_skipcap(name);
}

int pkm_kacs_kunit_check_inode_follow_link(void)
{
	return pkm_kacs_inode_follow_link(NULL, NULL, false);
}

int pkm_kacs_kunit_check_inode_set_acl(void)
{
	return pkm_kacs_inode_set_acl(&nop_mnt_idmap, NULL,
				      XATTR_NAME_POSIX_ACL_ACCESS, NULL);
}

int pkm_kacs_kunit_check_inode_remove_acl(void)
{
	return pkm_kacs_inode_remove_acl(&nop_mnt_idmap, NULL,
					 XATTR_NAME_POSIX_ACL_ACCESS);
}

int pkm_kacs_kunit_check_inode_getsecurity_sd(
	const u8 *sd_ptr, size_t sd_len, const char *name, u8 *out,
	size_t out_len, size_t *written)
{
	struct pkm_kacs_kunit_file_mount_state state = {};
	struct pkm_kacs_inode_sd_cache *cache;
	void *buffer = NULL;
	int ret;

	if (!out || !written)
		return -EINVAL;
	*written = 0;

	cache = pkm_kacs_kunit_file_sd_cache_alloc(
		sd_ptr, sd_len, PKM_KACS_KUNIT_FILE_SD_VALID);
	if (!cache)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_file_mount_state(&state, TMPFS_MAGIC, cache);
	if (ret) {
		pkm_kacs_inode_sd_cache_free(cache);
		return ret;
	}

	ret = pkm_kacs_inode_getsecurity(&nop_mnt_idmap, &state.inode, name,
					 &buffer, true);
	if (ret < 0)
		goto out;
	if ((size_t)ret > out_len) {
		ret = -ENOSPC;
		goto out;
	}

	memcpy(out, buffer, ret);
	*written = ret;
	ret = 0;

out:
	kfree(buffer);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
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



int pkm_kacs_kunit_check_mmap_snapshot(u32 managed, u32 granted_access,
				       unsigned long prot,
				       unsigned long flags)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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

int pkm_kacs_kunit_check_mmap_opath(unsigned long prot, unsigned long flags)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	state.file.f_mode = FMODE_PATH;
	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = 0;
	file_sec->granted_access = 0;

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
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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

int pkm_kacs_kunit_check_file_permission_snapshot_for_subject(
	const void *subject_token, u64 magic, u32 managed, u32 granted_access,
	int file_flags, int mask)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, magic ? magic : TMPFS_MAGIC, NULL, 0, NULL, 0,
		S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;
	file_sec->continuous_audit_mask = 0;
	state.file.f_flags = file_flags;

	ret = pkm_kacs_check_file_permission_snapshot_for_subject(
		subject_token, &state.file, mask);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

long pkm_kacs_kunit_set_file_fd_snapshot(int fd, u32 managed,
					 u32 granted_access, int file_flags)
{
	struct pkm_kacs_file_security *file_sec;
	struct fd f;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (!fd_file(f)->f_security) {
		fdput(f);
		return -EACCES;
	}

	file_sec = pkm_kacs_file(fd_file(f));
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;
	fd_file(f)->f_flags = file_flags;
	fdput(f);
	return 0;
}

long pkm_kacs_kunit_file_fd_snapshot(
	int fd, struct pkm_kacs_kunit_file_fd_view *view)
{
	struct pkm_kacs_file_security *file_sec;
	struct fd f;

	if (!view)
		return -EINVAL;

	memset(view, 0, sizeof(*view));
	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (!fd_file(f)->f_security) {
		fdput(f);
		return -EACCES;
	}

	file_sec = pkm_kacs_file(fd_file(f));
	view->file_cookie = (unsigned long)fd_file(f);
	view->managed = file_sec->managed;
	view->granted_access = file_sec->granted_access;
	fdput(f);
	return 0;
}

long pkm_kacs_kunit_check_file_permission_fd(int fd, int mask)
{
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;

	ret = pkm_kacs_check_file_permission_snapshot(fd_file(f), mask);
	fdput(f);
	return ret;
}

int pkm_kacs_kunit_check_file_write_intent_snapshot(u32 managed,
						    u32 granted_access,
						    int file_flags,
						    u32 rwf_flags,
						    bool positioned)
{
	return pkm_kacs_kunit_check_file_write_intent_snapshot_for_subject(
		pkm_kacs_current_effective_token_ptr(), TMPFS_MAGIC, managed,
		granted_access, file_flags, rwf_flags, positioned);
}

int pkm_kacs_kunit_check_file_write_intent_snapshot_for_subject(
	const void *subject_token, u64 magic, u32 managed, u32 granted_access,
	int file_flags, u32 rwf_flags, bool positioned)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, magic ? magic : TMPFS_MAGIC, NULL, 0, NULL, 0,
		S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;
	state.file.f_flags = file_flags;

	ret = pkm_kacs_check_file_write_intent_snapshot_for_subject(
		subject_token, &state.file, rwf_flags, positioned);
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
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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
		&first, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&second, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		goto out_first;

	file_sec = pkm_kacs_file(&first.file);
	file_sec->managed = 1;
	file_sec->granted_access = KACS_FILE_APPEND_DATA;
	file_sec = pkm_kacs_file(&second.file);
	file_sec->managed = 1;
	file_sec->granted_access = KACS_FILE_APPEND_DATA;

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
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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

int pkm_kacs_kunit_check_file_metadata_opath(u32 op, const char *name)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	state.file.f_mode = FMODE_PATH;
	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = 0;
	file_sec->granted_access = 0;

	ret = pkm_kacs_kunit_call_file_metadata_op(&state.file, op, name);
	pkm_kacs_file_end_metadata(&state.file);
	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_file_metadata_null(u32 op, const char *name)
{
	return pkm_kacs_kunit_call_file_metadata_op(NULL, op, name);
}

static int pkm_kacs_kunit_begin_getattr_marker(
	struct pkm_kacs_kunit_file_mount_state *state)
{
	struct pkm_kacs_file_security *file_sec;

	file_sec = pkm_kacs_file(&state->file);
	file_sec->managed = 1;
	file_sec->granted_access = KACS_FILE_READ_ATTRIBUTES;
	return pkm_kacs_file_getattr(&state->file);
}

int pkm_kacs_kunit_check_file_metadata_marker_clears(void)
{
	struct pkm_kacs_kunit_file_mount_state first = { };
	struct pkm_kacs_kunit_file_mount_state second = { };
	struct iattr attr = {
		.ia_valid = ATTR_MODE,
	};
	struct path path;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&first, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;
	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&second, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		goto out_first;

	path.mnt = &first.mnt;
	path.dentry = &first.dentry;
	ret = pkm_kacs_kunit_begin_getattr_marker(&first);
	if (ret)
		goto out;
	ret = pkm_kacs_inode_getattr(&path);
	if (ret)
		goto out;
	ret = pkm_kacs_kunit_begin_getattr_marker(&first);
	if (ret)
		goto out;
	pkm_kacs_file_end_metadata(&first.file);

	ret = pkm_kacs_kunit_begin_getattr_marker(&first);
	if (ret)
		goto out;
	(void)pkm_kacs_inode_setattr(&nop_mnt_idmap, &first.dentry,
				      &attr);
	ret = pkm_kacs_kunit_begin_getattr_marker(&first);
	if (ret)
		goto out;
	pkm_kacs_file_end_metadata(&first.file);

	ret = pkm_kacs_kunit_begin_getattr_marker(&first);
	if (ret)
		goto out;
	path.mnt = &second.mnt;
	path.dentry = &second.dentry;
	(void)pkm_kacs_inode_getattr(&path);
	ret = pkm_kacs_kunit_begin_getattr_marker(&first);
	if (!ret)
		pkm_kacs_file_end_metadata(&first.file);

out:
	pkm_kacs_file_end_metadata(&first.file);
	pkm_kacs_file_end_metadata(&second.file);
	pkm_kacs_kunit_cleanup_file_mount_state(&second);
out_first:
	pkm_kacs_kunit_cleanup_file_mount_state(&first);
	return ret;
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
		&state, TMPFS_MAGIC, cache, KACS_MOUNT_POLICY_DENY_MISSING,
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
	return pkm_kacs_kunit_check_inode_permission_live_mode(
		target_file_sd_ptr, target_file_sd_len, target_file_sd_state,
		mount_policy, subject_token, S_IFDIR, mask);
}

int pkm_kacs_kunit_check_inode_permission_live_mode(
	const u8 *target_file_sd_ptr, size_t target_file_sd_len,
	u32 target_file_sd_state, u32 mount_policy,
	const void *subject_token, u32 mode, int mask)
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
		&state, TMPFS_MAGIC, cache, mount_policy, NULL, 0, mode, true);
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
		subject_token, KACS_SE_CHANGE_NOTIFY_PRIVILEGE);
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

/*
 * Prime an inode's SD cache, fire the post-setxattr hook with @name, and
 * report whether the cache survived.
 *
 * The point is the pairing: the canonical name must drop it, anything else
 * must not. A hook that cleared unconditionally would look correct against the
 * first half alone and would throw away every cache in the system on every
 * xattr write.
 */
int pkm_kacs_kunit_post_setxattr_drops_cache(const u8 *sd_ptr, size_t sd_len,
					     const char *name,
					     bool *survived_out)
{
	struct pkm_kacs_kunit_file_mount_state state = {};
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_security *sec;
	int ret;

	if (!sd_ptr || sd_len == 0 || !name || !survived_out)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_namespace_state(
		&state, sd_ptr, sd_len, PKM_KACS_KUNIT_FILE_SD_VALID,
		TMPFS_MAGIC, KACS_MOUNT_POLICY_DENY_MISSING, S_IFREG);
	if (ret)
		return ret;

	sec = pkm_kacs_inode(&state.inode);
	cache = pkm_kacs_inode_sd_cache_get_current(&state.inode, sec);
	if (!cache) {
		pkm_kacs_kunit_cleanup_file_mount_state(&state);
		return -EACCES;
	}
	pkm_kacs_inode_sd_cache_free(cache);

	pkm_kacs_inode_post_setxattr(&state.dentry, name, sd_ptr, sd_len, 0);

	cache = pkm_kacs_inode_sd_cache_get_current(&state.inode, sec);
	*survived_out = cache != NULL;
	if (cache)
		pkm_kacs_inode_sd_cache_free(cache);

	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return 0;
}

/*
 * What inheritance yields for @subject_token from a parent carrying
 * @parent_sd_ptr -- the answer the overlay hook above has to match, since it
 * exists to reproduce it from the right inode and the right subject.
 */
long pkm_kacs_kunit_build_created_sd_for_parent(
	const void *subject_token, const u8 *parent_sd_ptr,
	size_t parent_sd_len, bool directory, const u8 **created_sd_out,
	size_t *created_sd_len_out)
{
	struct pkm_kacs_kunit_file_mount_state parent = {};
	long ret;

	if (!subject_token || !parent_sd_ptr || parent_sd_len == 0 ||
	    !created_sd_out || !created_sd_len_out)
		return -EINVAL;

	*created_sd_out = NULL;
	*created_sd_len_out = 0;

	ret = pkm_kacs_kunit_init_namespace_state(
		&parent, parent_sd_ptr, parent_sd_len,
		PKM_KACS_KUNIT_FILE_SD_VALID, TMPFS_MAGIC,
		KACS_MOUNT_POLICY_DENY_MISSING, S_IFDIR);
	if (ret)
		return ret;

	ret = pkm_kacs_build_legacy_created_file_sd_for_subject(
		subject_token, &parent.inode, &parent.dentry, directory,
		created_sd_out, created_sd_len_out);
	pkm_kacs_kunit_cleanup_file_mount_state(&parent);
	return ret;
}

/*
 * Drive pkm_kacs_dentry_create_files_as() the way overlayfs does: a negative
 * child dentry below a parent whose descriptor is primed, a cred for the
 * *calling* principal, and a separate cred for overlayfs to install.
 *
 * The subject deliberately arrives on @old only. The KUnit task has an
 * effective token of its own, and the parent descriptor callers prime here
 * grants that token nothing, so a hook that read current instead of @old
 * fails the FILE_ADD_FILE check and this returns an error rather than bytes.
 * That is the whole point of the test: on an overlay the two differ, and the
 * caller's is the right one.
 */
int pkm_kacs_kunit_overlay_create_files_as(
	const void *subject_token, const u8 *parent_sd_ptr,
	size_t parent_sd_len, bool directory, const u8 **pending_sd_out,
	size_t *pending_sd_len_out, u32 *new_uid_out, u32 *new_gid_out)
{
	struct pkm_kacs_kunit_file_mount_state parent = {};
	struct pkm_kacs_cred_security *old_sec;
	struct pkm_kacs_cred_security *new_sec;
	struct cred old_cred = {};
	struct cred new_cred = {};
	struct dentry child = {};
	struct qstr *child_name;
	void *old_blob = NULL;
	void *new_blob = NULL;
	size_t cred_blob_len;
	u8 *copy = NULL;
	umode_t mode;
	bool parent_ready = false;
	int ret;

	if (!pending_sd_out || !pending_sd_len_out || !parent_sd_ptr ||
	    parent_sd_len == 0)
		return -EINVAL;

	*pending_sd_out = NULL;
	*pending_sd_len_out = 0;

	mode = directory ? (S_IFDIR | 0700) : (S_IFREG | 0600);
	ret = pkm_kacs_kunit_init_namespace_state(
		&parent, parent_sd_ptr, parent_sd_len,
		PKM_KACS_KUNIT_FILE_SD_VALID, TMPFS_MAGIC,
		KACS_MOUNT_POLICY_DENY_MISSING, S_IFDIR);
	if (ret)
		return ret;
	parent_ready = true;

	child.d_parent = &parent.dentry;
	child.d_sb = parent.dentry.d_sb;
	child_name = (struct qstr *)&child.d_name;
	child_name->name = (const u8 *)"child";
	child_name->len = 5;

	cred_blob_len = pkm_blob_sizes.lbs_cred +
			sizeof(struct pkm_kacs_cred_security);
	old_blob = kzalloc(cred_blob_len, GFP_KERNEL);
	new_blob = kzalloc(cred_blob_len, GFP_KERNEL);
	if (!old_blob || !new_blob) {
		ret = -ENOMEM;
		goto out;
	}
	old_cred.security = old_blob;
	new_cred.security = new_blob;
	old_sec = pkm_kacs_cred(&old_cred);
	new_sec = pkm_kacs_cred(&new_cred);
	old_sec->token = subject_token;

	/*
	 * The two creds carry different projections, as they do in the kernel:
	 * @new is prepared from the overlay mounter's cred and so answers for
	 * the mounter until the hook is told whose create this really is.
	 */
	old_sec->projected_uid = PKM_KACS_KUNIT_OVERLAY_CALLER_UID;
	old_sec->projected_gid = PKM_KACS_KUNIT_OVERLAY_CALLER_GID;
	new_sec->projected_uid = PKM_KACS_KUNIT_OVERLAY_MOUNTER_UID;
	new_sec->projected_gid = PKM_KACS_KUNIT_OVERLAY_MOUNTER_GID;

	ret = pkm_kacs_dentry_create_files_as(&child, (int)mode, &child.d_name,
					      &old_cred, &new_cred);
	if (new_uid_out)
		*new_uid_out = new_sec->projected_uid;
	if (new_gid_out)
		*new_gid_out = new_sec->projected_gid;
	if (ret)
		goto out;
	if (!new_sec->pending_create_sd || new_sec->pending_create_sd_len == 0)
		goto out;

	copy = kmemdup(new_sec->pending_create_sd,
		       new_sec->pending_create_sd_len, GFP_KERNEL);
	if (!copy) {
		ret = -ENOMEM;
		goto out;
	}
	*pending_sd_out = copy;
	*pending_sd_len_out = new_sec->pending_create_sd_len;

out:
	if (new_blob) {
		new_sec = pkm_kacs_cred(&new_cred);
		kfree(new_sec->pending_create_sd);
	}
	kfree(new_blob);
	kfree(old_blob);
	if (parent_ready)
		pkm_kacs_kunit_cleanup_file_mount_state(&parent);
	return ret;
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
			 KACS_MOUNT_POLICY_DENY_MISSING;
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
			KACS_FILE_READ_DATA);
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
	struct dentry source_dentry = {};
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
			 KACS_MOUNT_POLICY_DENY_MISSING;

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

	/*
	 * Mirror the real security_inode_rename call shape: old_dentry is the
	 * source entry parented under old_dir, so RENAME_WHITEOUT authorization
	 * can resolve old_dir's own dentry (the whiteout sentinel lands at this
	 * name) and read its SD. Passing NULL would leave the access core with
	 * no dentry alias to anchor on.
	 */
	source_dentry.d_parent = &old_parent.dentry;
	ret = pkm_kacs_inode_rename_flags(&old_parent.inode, &source_dentry,
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
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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

int pkm_kacs_kunit_check_file_ioctl_opath(unsigned int cmd, bool compat)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	state.file.f_mode = FMODE_PATH;
	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = 0;
	file_sec->granted_access = 0;

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
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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

int pkm_kacs_kunit_check_file_receive(void)
{
	return pkm_kacs_file_receive(NULL);
}

int pkm_kacs_kunit_check_file_truncate_snapshot(u32 managed,
						u32 granted_access)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
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

int pkm_kacs_kunit_check_file_continuous_audit_op(
	u32 op, u32 managed, u32 granted_access, u32 continuous_audit,
	int file_flags, unsigned long arg0, unsigned long arg1)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;
	file_sec->continuous_audit_mask = continuous_audit;
	state.file.f_flags = file_flags;

	switch (op) {
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_ACCESS:
		ret = pkm_kacs_check_file_snapshot_grant(&state.file,
							 (u32)arg0);
		break;
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_MMAP:
		ret = pkm_kacs_check_mmap_snapshot(&state.file, arg0, arg1);
		break;
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_MPROTECT:
		ret = pkm_kacs_check_mprotect_snapshot(&state.file, arg0,
						       arg1);
		break;
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_PERMISSION:
		ret = pkm_kacs_check_file_permission_snapshot(&state.file,
							      (int)arg0);
		break;
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_WRITE:
		ret = pkm_kacs_check_file_write_intent_snapshot(
			&state.file, (u32)arg0, arg1 != 0);
		break;
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_IOCTL:
		ret = pkm_kacs_check_file_ioctl_snapshot(
			&state.file, (unsigned int)arg0, 0, false);
		break;
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_LOCK:
		ret = pkm_kacs_check_file_lock_snapshot(&state.file,
							(unsigned int)arg0);
		break;
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_FCNTL:
		ret = pkm_kacs_check_file_fcntl_snapshot(
			&state.file, (unsigned int)arg0, arg1);
		break;
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_TRUNCATE:
		ret = pkm_kacs_check_file_truncate_snapshot(&state.file);
		break;
	case PKM_KACS_KUNIT_CONT_AUDIT_OP_FALLOCATE:
		ret = pkm_kacs_check_file_fallocate_snapshot(&state.file,
							    (int)arg0);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}

int pkm_kacs_kunit_check_signed_exec_pin_mutation(u32 pinned, u32 managed,
						  u32 granted_access,
						  u32 operation)
{
	struct pkm_kacs_kunit_file_mount_state state = { };
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct iattr attr = { };
	int ret;

	ret = pkm_kacs_kunit_init_file_mount_state_ex(
		&state, TMPFS_MAGIC, NULL, KACS_MOUNT_POLICY_DENY_MISSING,
		NULL, 0, S_IFREG, true);
	if (ret)
		return ret;

	file_sec = pkm_kacs_file(&state.file);
	file_sec->managed = managed ? 1 : 0;
	file_sec->granted_access = granted_access;
	inode_sec = pkm_kacs_inode(&state.inode);
	atomic_set(&inode_sec->signed_exec_pinned, pinned ? 1 : 0);

	switch (operation) {
	case PKM_KACS_KUNIT_PIN_OP_WRITE_PERMISSION:
		ret = pkm_kacs_check_file_permission_snapshot(&state.file,
							      MAY_WRITE);
		break;
	case PKM_KACS_KUNIT_PIN_OP_WRITE_INTENT:
		ret = pkm_kacs_check_file_write_intent_snapshot(&state.file,
								0, true);
		break;
	case PKM_KACS_KUNIT_PIN_OP_TRUNCATE:
		ret = pkm_kacs_check_file_truncate_snapshot(&state.file);
		break;
	case PKM_KACS_KUNIT_PIN_OP_FALLOCATE_MUTATE:
		ret = pkm_kacs_check_file_fallocate_snapshot(
			&state.file, FALLOC_FL_ZERO_RANGE);
		break;
	case PKM_KACS_KUNIT_PIN_OP_FALLOCATE_ALLOCATE:
		ret = pkm_kacs_check_file_fallocate_snapshot(
			&state.file, FALLOC_FL_ALLOCATE_RANGE);
		break;
	case PKM_KACS_KUNIT_PIN_OP_IOCTL_MUTATE:
		ret = pkm_kacs_check_file_ioctl_snapshot(&state.file,
							 FS_IOC_ZERO_RANGE, 0,
							 false);
		break;
	case PKM_KACS_KUNIT_PIN_OP_IOCTL_UNKNOWN:
		ret = pkm_kacs_check_file_ioctl_snapshot(&state.file,
							 0x5a5a5a5aU, 0,
							 false);
		break;
	case PKM_KACS_KUNIT_PIN_OP_PATH_TRUNCATE:
		attr.ia_valid = ATTR_SIZE;
		ret = pkm_kacs_inode_setattr(&nop_mnt_idmap, &state.dentry,
					     &attr);
		break;
	case PKM_KACS_KUNIT_PIN_OP_SIGNING_XATTR_SET:
		ret = pkm_kacs_inode_setxattr(&nop_mnt_idmap, &state.dentry,
					      PKM_KACS_SIGNING_XATTR_NAME,
					      NULL, 0, 0);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	pkm_kacs_kunit_cleanup_file_mount_state(&state);
	return ret;
}


long pkm_kacs_kunit_check_bprm_file_execute_for_subject(
	const struct pkm_kacs_kunit_file_open_args *args)
{
	struct pkm_kacs_kunit_file_mount_state *state;
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_cred_security *cred_sec;
	struct linux_binprm bprm = {};
	const struct cred *saved;
	struct cred *cred;
	const void *token_ref;
	umode_t mode;
	u64 magic;
	long ret;

	if (!args || !args->subject_token)
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

	bprm.file = &state->file;
	cred = prepare_creds();
	if (!cred) {
		ret = -ENOMEM;
		goto out_mount;
	}

	cred_sec = pkm_kacs_cred(cred);
	if (cred_sec->token) {
		kacs_rust_token_drop(cred_sec->token);
		cred_sec->token = NULL;
	}
	token_ref = kacs_rust_token_clone(args->subject_token);
	if (!token_ref) {
		abort_creds(cred);
		ret = -ENOMEM;
		goto out_mount;
	}
	cred_sec->token = token_ref;
	pkm_kacs_stamp_projected_ids(cred_sec);

	saved = override_creds(cred);
	ret = pkm_kacs_bprm_check_security(&bprm);
	revert_creds(saved);
	abort_creds(cred);

out_mount:
	pkm_kacs_kunit_cleanup_file_mount_state(state);
out_free:
	kfree(state);
	return ret;
}

u64 pkm_kacs_kunit_allow_cap_mask(void)
{
	return pkm_kacs_allow_cap_mask_u64();
}

long pkm_kacs_kunit_capget_fixup_masks(u64 effective_mask,
					u64 inheritable_mask,
					u64 permitted_mask,
					u64 *effective_out,
					u64 *inheritable_out,
					u64 *permitted_out)
{
	kernel_cap_t effective;
	kernel_cap_t inheritable;
	kernel_cap_t permitted;

	if (!effective_out || !inheritable_out || !permitted_out)
		return -EINVAL;

	effective = pkm_kacs_u64_to_kernel_cap(effective_mask);
	inheritable = pkm_kacs_u64_to_kernel_cap(inheritable_mask);
	permitted = pkm_kacs_u64_to_kernel_cap(permitted_mask);
	pkm_kacs_capget_fixup(&effective, &inheritable, &permitted);

	*effective_out = pkm_kacs_kernel_cap_to_u64(&effective);
	*inheritable_out = pkm_kacs_kernel_cap_to_u64(&inheritable);
	*permitted_out = pkm_kacs_kernel_cap_to_u64(&permitted);
	return 0;
}

long pkm_kacs_kunit_proc_status_cap_fixup_masks(
	u64 inheritable_mask, u64 permitted_mask, u64 effective_mask,
	u64 bset_mask, u64 ambient_mask, u64 *inheritable_out,
	u64 *permitted_out, u64 *effective_out, u64 *bset_out,
	u64 *ambient_out)
{
	kernel_cap_t inheritable;
	kernel_cap_t permitted;
	kernel_cap_t effective;
	kernel_cap_t bset;
	kernel_cap_t ambient;
	long ret;

	if (!inheritable_out || !permitted_out || !effective_out || !bset_out ||
	    !ambient_out)
		return -EINVAL;

	inheritable = pkm_kacs_u64_to_kernel_cap(inheritable_mask);
	permitted = pkm_kacs_u64_to_kernel_cap(permitted_mask);
	effective = pkm_kacs_u64_to_kernel_cap(effective_mask);
	bset = pkm_kacs_u64_to_kernel_cap(bset_mask);
	ambient = pkm_kacs_u64_to_kernel_cap(ambient_mask);

	ret = pkm_kacs_proc_status_cap_fixup(&inheritable, &permitted,
					     &effective, &bset, &ambient);
	if (ret)
		return ret;

	*inheritable_out = pkm_kacs_kernel_cap_to_u64(&inheritable);
	*permitted_out = pkm_kacs_kernel_cap_to_u64(&permitted);
	*effective_out = pkm_kacs_kernel_cap_to_u64(&effective);
	*bset_out = pkm_kacs_kernel_cap_to_u64(&bset);
	*ambient_out = pkm_kacs_kernel_cap_to_u64(&ambient);
	return 0;
}

long pkm_kacs_kunit_check_capget_for_subject(
	const struct pkm_kacs_kunit_process_capget_check_args *args)
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

	return pkm_kacs_check_process_capget_core(args->subject_token,
						  &caller_state,
						  &target_state);
}

long pkm_kacs_kunit_check_capability_for_subject(const void *subject_token,
						 int cap)
{
	return pkm_kacs_check_capability_for_token(subject_token, cap);
}

bool pkm_kacs_kunit_may_manage_volumes_for_subject(const void *subject_token)
{
	return pkm_kacs_may_manage_volumes_for_token(subject_token);
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

long pkm_kacs_kunit_capset_result_masks(
	const void *subject_token, u64 effective_mask, u64 inheritable_mask,
	u64 permitted_mask, u64 bset_mask, u64 ambient_mask,
	u64 *effective_out, u64 *inheritable_out, u64 *permitted_out,
	u64 *bset_out, u64 *ambient_out)
{
	struct cred new = {};
	kernel_cap_t effective;
	kernel_cap_t inheritable;
	kernel_cap_t permitted;
	long ret;

	if (!effective_out || !inheritable_out || !permitted_out ||
	    !bset_out || !ambient_out)
		return -EINVAL;

	effective = pkm_kacs_u64_to_kernel_cap(effective_mask);
	inheritable = pkm_kacs_u64_to_kernel_cap(inheritable_mask);
	permitted = pkm_kacs_u64_to_kernel_cap(permitted_mask);
	new.cap_bset = pkm_kacs_u64_to_kernel_cap(bset_mask);
	new.cap_ambient = pkm_kacs_u64_to_kernel_cap(ambient_mask);

	ret = pkm_kacs_capset_core(subject_token, &new, &effective,
				   &inheritable, &permitted);
	if (ret)
		return ret;

	*effective_out = pkm_kacs_kernel_cap_to_u64(&new.cap_effective);
	*inheritable_out = pkm_kacs_kernel_cap_to_u64(&new.cap_inheritable);
	*permitted_out = pkm_kacs_kernel_cap_to_u64(&new.cap_permitted);
	*bset_out = pkm_kacs_kernel_cap_to_u64(&new.cap_bset);
	*ambient_out = pkm_kacs_kernel_cap_to_u64(&new.cap_ambient);
	return 0;
}

static bool pkm_kacs_kunit_cred_has_allow_caps(const struct cred *cred)
{
	return cred && pkm_kacs_allow_caps_present(&cred->cap_effective) &&
	       pkm_kacs_allow_caps_present(&cred->cap_inheritable) &&
	       pkm_kacs_allow_caps_present(&cred->cap_permitted) &&
	       pkm_kacs_allow_caps_present(&cred->cap_bset);
}

int pkm_kacs_kunit_check_cred_prepare_transfer_allow_caps(void)
{
	struct pkm_kacs_cred_security *sec;
	struct cred *new;
	int ret = 0;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (!pkm_kacs_kunit_cred_has_allow_caps(new)) {
		ret = -EBADE;
		goto out;
	}

	new->cap_effective = CAP_EMPTY_SET;
	new->cap_inheritable = CAP_EMPTY_SET;
	new->cap_permitted = CAP_EMPTY_SET;
	new->cap_bset = CAP_EMPTY_SET;
	new->cap_ambient = CAP_EMPTY_SET;

	sec = pkm_kacs_cred(new);
	if (sec->token) {
		kacs_rust_token_drop(sec->token);
		sec->token = NULL;
	}
	pkm_kacs_set_cred_process_state(new, NULL);

	pkm_kacs_cred_transfer(new, current_cred());
	if (!pkm_kacs_kunit_cred_has_allow_caps(new))
		ret = -EBADE;

out:
	abort_creds(new);
	return ret;
}

static void *pkm_kacs_kunit_alloc_poisoned_blob(size_t offset, size_t size)
{
	void *blob;

	blob = kmalloc(offset + size, GFP_KERNEL);
	if (blob)
		memset(blob, 0xaa, offset + size);
	return blob;
}

struct pkm_kacs_kunit_blob_lifecycle_state {
	struct super_block sb;
	struct inode inode;
	struct file file;
	struct cred cred;
	struct sock sk;
	struct task_struct *task;
};

int pkm_kacs_kunit_check_blob_lifecycle_defaults(void)
{
	struct pkm_kacs_kunit_blob_lifecycle_state *state;
	struct pkm_kacs_superblock_security *sb_sec;
	struct pkm_kacs_inode_sd_cache *cache = NULL;
	struct pkm_kacs_socket_security *socket_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct pkm_kacs_task_security *task_sec;
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_cred_security *cred_sec;
	const void *current_token;
	struct cred *prepared = NULL;
	void *inode_blob = NULL;
	void *socket_blob = NULL;
	void *cred_blob = NULL;
	void *file_blob = NULL;
	void *task_blob = NULL;
	void *sb_blob = NULL;
	bool socket_allocated = false;
	bool inode_allocated = false;
	bool task_allocated = false;
	bool sb_allocated = false;
	int ret = -EBADE;

	current_token = pkm_kacs_current_effective_token_ptr();
	if (!current_token || !pkm_kacs_current_process_state())
		return -EACCES;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	state->task = kzalloc(sizeof(*state->task), GFP_KERNEL);
	if (!state->task) {
		kfree(state);
		return -ENOMEM;
	}

	cred_blob = pkm_kacs_kunit_alloc_poisoned_blob(
		pkm_blob_sizes.lbs_cred, sizeof(struct pkm_kacs_cred_security));
	file_blob = pkm_kacs_kunit_alloc_poisoned_blob(
		pkm_blob_sizes.lbs_file, sizeof(struct pkm_kacs_file_security));
	inode_blob = pkm_kacs_kunit_alloc_poisoned_blob(
		pkm_blob_sizes.lbs_inode, sizeof(struct pkm_kacs_inode_security));
	sb_blob = pkm_kacs_kunit_alloc_poisoned_blob(
		pkm_blob_sizes.lbs_superblock,
		sizeof(struct pkm_kacs_superblock_security));
	socket_blob = pkm_kacs_kunit_alloc_poisoned_blob(
		pkm_blob_sizes.lbs_sock, sizeof(struct pkm_kacs_socket_security));
	task_blob = pkm_kacs_kunit_alloc_poisoned_blob(
		pkm_blob_sizes.lbs_task, sizeof(struct pkm_kacs_task_security));
	if (!cred_blob || !file_blob || !inode_blob || !sb_blob ||
	    !socket_blob || !task_blob) {
		ret = -ENOMEM;
		goto out;
	}

	state->cred.security = cred_blob;
	ret = pkm_kacs_cred_alloc_blank(&state->cred, GFP_KERNEL);
	if (ret)
		goto out;
	cred_sec = pkm_kacs_cred(&state->cred);
	if (cred_sec->token || cred_sec->process_state ||
	    cred_sec->projected_uid != PKM_KACS_UNMAPPED_ID ||
	    cred_sec->projected_gid != PKM_KACS_UNMAPPED_ID) {
		ret = -EBADE;
		goto out;
	}
	cred_sec->token = kacs_rust_token_clone(current_token);
	if (!cred_sec->token) {
		ret = -ENOMEM;
		goto out;
	}
	cred_sec->process_state =
		pkm_kacs_process_state_get(pkm_kacs_current_process_state());
	if (!cred_sec->process_state) {
		ret = -ENOMEM;
		goto out;
	}
	pkm_kacs_cred_free(&state->cred);
	cred_sec->token = NULL;
	cred_sec->process_state = NULL;

	state->file.f_security = file_blob;
	ret = pkm_kacs_file_alloc_security(&state->file);
	if (ret)
		goto out;
	file_sec = pkm_kacs_file(&state->file);
	if (file_sec->granted_access || file_sec->continuous_audit_mask ||
	    file_sec->managed || file_sec->delete_on_close) {
		ret = -EBADE;
		goto out;
	}

	state->sb.s_security = sb_blob;
	ret = pkm_kacs_sb_alloc_security(&state->sb);
	if (ret)
		goto out;
	sb_allocated = true;
	sb_sec = pkm_kacs_sb(&state->sb);
	if (sb_sec->template_sd_bytes || sb_sec->template_sd_len ||
	    sb_sec->policy_generation || sb_sec->mount_policy) {
		ret = -EBADE;
		goto out;
	}
	pkm_kacs_sb_free_security(&state->sb);
	sb_allocated = false;

	state->inode.i_security = inode_blob;
	ret = pkm_kacs_inode_alloc_security(&state->inode);
	if (ret)
		goto out;
	inode_allocated = true;
	inode_sec = pkm_kacs_inode(&state->inode);
	if (rcu_dereference_protected(inode_sec->sd_cache, 1) ||
	    atomic_read(&inode_sec->delete_on_close_lineages) ||
	    atomic_read(&inode_sec->signed_exec_pinned)) {
		ret = -EBADE;
		goto out;
	}
	cache = pkm_kacs_inode_sd_cache_alloc(PKM_KACS_INODE_SD_MISSING,
					      NULL, 0);
	if (!cache) {
		ret = -ENOMEM;
		goto out;
	}
	mutex_lock(&inode_sec->lock);
	pkm_kacs_inode_replace_sd_cache_locked(inode_sec, cache);
	mutex_unlock(&inode_sec->lock);
	cache = NULL;
	pkm_kacs_inode_free_security_rcu(state->inode.i_security);
	inode_allocated = false;
	if (rcu_dereference_protected(inode_sec->sd_cache, 1) ||
	    atomic_read(&inode_sec->delete_on_close_lineages) ||
	    atomic_read(&inode_sec->signed_exec_pinned)) {
		ret = -EBADE;
		goto out;
	}

	state->sk.sk_security = socket_blob;
	ret = pkm_kacs_sk_alloc_security(&state->sk, AF_UNIX, GFP_KERNEL);
	if (ret)
		goto out;
	socket_allocated = true;
	socket_sec = pkm_kacs_sock(&state->sk);
	if (socket_sec->peer_token || socket_sec->socket_sd ||
	    socket_sec->max_impersonation != KACS_IMLEVEL_IMPERSONATION) {
		ret = -EBADE;
		goto out;
	}
	socket_sec->peer_token = kacs_rust_token_clone(current_token);
	socket_sec->socket_sd = pkm_kacs_socket_sd_alloc(current_token);
	if (!socket_sec->peer_token || !socket_sec->socket_sd) {
		ret = -ENOMEM;
		goto out;
	}
	pkm_kacs_sk_free_security(&state->sk);
	socket_allocated = false;
	if (socket_sec->peer_token || socket_sec->socket_sd ||
	    socket_sec->max_impersonation != KACS_IMLEVEL_IMPERSONATION) {
		ret = -EBADE;
		goto out;
	}

	state->task->security = task_blob;
	prepared = prepare_creds();
	if (!prepared) {
		ret = -ENOMEM;
		goto out;
	}
	rcu_assign_pointer(state->task->cred, prepared);
	rcu_assign_pointer(state->task->real_cred, prepared);
	ret = pkm_kacs_task_alloc(state->task, CLONE_THREAD);
	if (ret)
		goto out;
	task_allocated = true;
	task_sec = pkm_kacs_task(state->task);
	if (!task_sec->process_state || task_sec->impersonation_saved_cred ||
	    task_sec->native_open.expected_dentry ||
	    task_sec->native_open.expected_mnt || task_sec->native_open.active ||
	    task_sec->native_create.expected_parent_inode ||
	    task_sec->native_create.sd_bytes || task_sec->native_create.sd_len ||
	    task_sec->native_create.directory || task_sec->native_create.active ||
	    task_sec->metadata_decision.inode ||
	    task_sec->metadata_decision.op_class != PKM_KACS_METADATA_OP_NONE ||
	    task_sec->metadata_decision.active ||
	    task_sec->stratafs_create_subject ||
	    task_sec->stratafs_create_authority ||
	    task_sec->stratafs_create_parent ||
	    task_sec->stratafs_create_dentry ||
	    task_sec->stratafs_create_link_source ||
	    task_sec->stratafs_create_link_inode ||
	    task_sec->stratafs_create_access ||
	    task_sec->stratafs_create_state ||
	    task_sec->stratafs_supersede_subject ||
	    task_sec->stratafs_supersede_target ||
	    task_sec->stratafs_supersede_target_inode ||
	    task_sec->stratafs_supersede_source ||
	    task_sec->stratafs_supersede_source_inode ||
	    task_sec->stratafs_supersede_file ||
	    task_sec->stratafs_supersede_old_parent ||
	    task_sec->stratafs_supersede_old_dentry ||
	    task_sec->stratafs_supersede_old_inode ||
	    task_sec->stratafs_supersede_new_parent ||
	    task_sec->stratafs_supersede_new_dentry ||
	    task_sec->stratafs_supersede_new_inode ||
	    task_sec->stratafs_supersede_state ||
	    task_sec->stratafs_supersede_phase ||
	    task_sec->stratafs_cleanup_parent ||
	    task_sec->stratafs_cleanup_dentry ||
	    task_sec->stratafs_cleanup_inode ||
	    task_sec->stratafs_cleanup_outer ||
	    task_sec->stratafs_cleanup_outer_inode ||
	    task_sec->stratafs_cleanup_subject ||
	    task_sec->pending_exec_pip_type ||
	    task_sec->pending_exec_pip_trust ||
	    task_sec->pending_exec_pip_valid) {
		ret = -EBADE;
		goto out;
	}
	pkm_kacs_task_free(state->task);
	task_allocated = false;
	if (task_sec->process_state || task_sec->impersonation_saved_cred ||
	    task_sec->stratafs_create_subject ||
	    task_sec->stratafs_create_authority ||
	    task_sec->stratafs_create_parent ||
	    task_sec->stratafs_create_dentry ||
	    task_sec->stratafs_create_link_source ||
	    task_sec->stratafs_create_link_inode ||
	    task_sec->stratafs_create_access ||
	    task_sec->stratafs_create_state ||
	    task_sec->stratafs_supersede_subject ||
	    task_sec->stratafs_supersede_target ||
	    task_sec->stratafs_supersede_target_inode ||
	    task_sec->stratafs_supersede_source ||
	    task_sec->stratafs_supersede_source_inode ||
	    task_sec->stratafs_supersede_file ||
	    task_sec->stratafs_supersede_old_parent ||
	    task_sec->stratafs_supersede_old_dentry ||
	    task_sec->stratafs_supersede_old_inode ||
	    task_sec->stratafs_supersede_new_parent ||
	    task_sec->stratafs_supersede_new_dentry ||
	    task_sec->stratafs_supersede_new_inode ||
	    task_sec->stratafs_supersede_state ||
	    task_sec->stratafs_supersede_phase ||
	    task_sec->stratafs_cleanup_parent ||
	    task_sec->stratafs_cleanup_dentry ||
	    task_sec->stratafs_cleanup_inode ||
	    task_sec->stratafs_cleanup_outer ||
	    task_sec->stratafs_cleanup_outer_inode ||
	    task_sec->stratafs_cleanup_subject ||
	    task_sec->pending_exec_pip_type || task_sec->pending_exec_pip_trust ||
	    task_sec->pending_exec_pip_valid) {
		ret = -EBADE;
		goto out;
	}

	ret = 0;

out:
	if (task_allocated)
		pkm_kacs_task_free(state->task);
	if (prepared) {
		rcu_assign_pointer(state->task->cred, NULL);
		rcu_assign_pointer(state->task->real_cred, NULL);
		abort_creds(prepared);
	}
	if (socket_allocated)
		pkm_kacs_sk_free_security(&state->sk);
	if (inode_allocated)
		pkm_kacs_inode_free_security_rcu(state->inode.i_security);
	if (cache)
		pkm_kacs_inode_sd_cache_free(cache);
	if (sb_allocated)
		pkm_kacs_sb_free_security(&state->sb);
	/*
	 * Guard on state->cred.security, not cred_blob: an early failure can
	 * `goto out` after cred_blob is allocated but before
	 * state->cred.security is assigned, so pkm_kacs_cred() would dereference
	 * (NULL + lbs_cred). cred_blob itself is still freed unconditionally below.
	 */
	if (state->cred.security) {
		cred_sec = pkm_kacs_cred(&state->cred);
		if (cred_sec->token)
			kacs_rust_token_drop(cred_sec->token);
		if (cred_sec->process_state)
			pkm_kacs_process_state_put(cred_sec->process_state);
	}
	kfree(state->task);
	kfree(state);
	kfree(task_blob);
	kfree(socket_blob);
	kfree(sb_blob);
	kfree(inode_blob);
	kfree(file_blob);
	kfree(cred_blob);
	return ret;
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
		    current_cred(), false, false, false, 0)) {
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
		subject_token, subject_token, NULL, new, old, false, false,
		false, 0);
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
		old, true, false, false, 0);
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

int pkm_kacs_kunit_project_peer_cred_for_subject(const void *subject_token,
						 u32 raw_euid, u32 raw_egid,
						 u32 *uid_out, u32 *gid_out)
{
	struct pkm_kacs_cred_security *sec;
	const void *token_ref = NULL;
	struct cred *new;
	kuid_t uid;
	kgid_t gid;

	if (!uid_out || !gid_out)
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	new->euid = KUIDT_INIT(raw_euid);
	new->egid = KGIDT_INIT(raw_egid);
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

	pkm_kacs_project_cred_uid_gid(new, &uid, &gid);
	*uid_out = __kuid_val(uid);
	*gid_out = __kgid_val(gid);

	abort_creds(new);
	return 0;
}

int pkm_kacs_kunit_prepare_projected_cred_for_subject(
	const void *subject_token,
	struct pkm_kacs_kunit_cred_projection_view *out)
{
	const struct cred *saved;
	struct cred *new;
	u32 i;
	long ret;

	if (!subject_token || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	ret = pkm_kacs_prepare_current_token_cred(subject_token, &new);
	if (ret)
		return (int)ret;

	out->uid = __kuid_val(new->uid);
	out->euid = __kuid_val(new->euid);
	out->suid = __kuid_val(new->suid);
	out->fsuid = __kuid_val(new->fsuid);
	out->gid = __kgid_val(new->gid);
	out->egid = __kgid_val(new->egid);
	out->sgid = __kgid_val(new->sgid);
	out->fsgid = __kgid_val(new->fsgid);
	out->group_count = new->group_info->ngroups;
	for (i = 0; i < out->group_count &&
		    i < PKM_KACS_KUNIT_CRED_PROJECTION_GROUP_MAX;
	     i++)
		out->groups[i] = __kgid_val(new->group_info->gid[i]);

	saved = override_creds(new);
	out->projected_fsuid = __kuid_val(pkm_kacs_current_fsuid_kuid());
	out->projected_fsgid = __kgid_val(pkm_kacs_current_fsgid_kgid());
	revert_creds(saved);

	abort_creds(new);
	return 0;
}
#endif

/*
 * The used-privilege recorder, interposed (see token_runtime.h).  A case can
 * make it fail to witness that every gate fails its operation on a failed
 * record, and can count how many times one operation records use.
 */
static atomic_t pkm_kacs_kunit_mark_used_fail = ATOMIC_INIT(0);
static atomic_t pkm_kacs_kunit_mark_used_calls = ATOMIC_INIT(0);

bool pkm_kacs_kunit_mark_privileges_used(const void *token, u64 used_mask)
{
	atomic_inc(&pkm_kacs_kunit_mark_used_calls);
	if (atomic_read(&pkm_kacs_kunit_mark_used_fail))
		return false;
	return (kacs_rust_token_mark_privileges_used)(token, used_mask);
}

void pkm_kacs_kunit_set_fail_mark_privileges_used(bool fail)
{
	atomic_set(&pkm_kacs_kunit_mark_used_fail, fail ? 1 : 0);
}

u32 pkm_kacs_kunit_mark_privileges_used_calls(bool reset)
{
	u32 calls = (u32)atomic_read(&pkm_kacs_kunit_mark_used_calls);

	if (reset)
		atomic_set(&pkm_kacs_kunit_mark_used_calls, 0);
	return calls;
}
