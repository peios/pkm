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
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/mman.h>
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
#include <linux/timekeeping.h>
#include <linux/un.h>

#include <asm/cpufeatures.h>

#include <net/sock.h>

#include "caap_cache.h"
#include "kmes.h"
#include "token_fd.h"
#include "token_runtime.h"

#define PKM_KACS_UNMAPPED_ID 65534U
#define PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS 10000U
#define PKM_KACS_PRIVILEGE_SE_DEBUG (1ULL << 20)
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

struct pkm_kacs_process_state {
	refcount_t refs;
	spinlock_t mitigation_lock;
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

static struct pkm_kacs_process_state *pkm_kacs_process_state_get(
	struct pkm_kacs_process_state *state);
static void pkm_kacs_process_state_put(struct pkm_kacs_process_state *state);

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
static int pkm_kacs_task_prlimit(const struct cred *cred,
				 const struct cred *tcred,
				 unsigned int flags);
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
static long pkm_kacs_check_process_setinfo_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state);

static struct pkm_kacs_process_sd *pkm_kacs_process_sd_alloc(const void *token)
{
	struct pkm_kacs_process_sd *process_sd;
	size_t len = 0;
	const u8 *bytes;

	if (!token)
		return NULL;

	bytes = kacs_rust_create_default_process_sd(token, &len);
	if (!bytes || len == 0)
		return NULL;

	process_sd = kzalloc(sizeof(*process_sd), GFP_KERNEL);
	if (!process_sd) {
		pkm_kacs_free((void *)bytes);
		return NULL;
	}

	refcount_set(&process_sd->refs, 1);
	process_sd->bytes = bytes;
	process_sd->len = len;
	return process_sd;
}

static struct pkm_kacs_process_sd *pkm_kacs_socket_sd_alloc(const void *token)
{
	struct pkm_kacs_process_sd *socket_sd;
	size_t len = 0;
	const u8 *bytes;

	if (!token)
		return NULL;

	bytes = kacs_rust_create_default_socket_sd(token, &len);
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

static void pkm_kacs_assert_boot_caps(struct cred *cred)
{
	kernel_cap_t caps = CAP_EMPTY_SET;

	cap_raise(caps, CAP_CHOWN);
	cap_raise(caps, CAP_DAC_OVERRIDE);
	cap_raise(caps, CAP_DAC_READ_SEARCH);
	cap_raise(caps, CAP_FOWNER);
	cap_raise(caps, CAP_FSETID);
	cap_raise(caps, CAP_KILL);
	cap_raise(caps, CAP_SETGID);
	cap_raise(caps, CAP_SETUID);
	cap_raise(caps, CAP_NET_BROADCAST);
	cap_raise(caps, CAP_IPC_OWNER);
	cap_raise(caps, CAP_LEASE);

	cred->cap_effective = caps;
	cred->cap_permitted = caps;
	cred->cap_inheritable = caps;
	cap_clear(cred->cap_ambient);
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
	pkm_kacs_assert_boot_caps(new);
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
	pkm_kacs_assert_boot_caps(new);
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
	LSM_HOOK_INIT(task_prlimit, pkm_kacs_task_prlimit),
	LSM_HOOK_INIT(task_prctl, pkm_kacs_task_prctl),
	LSM_HOOK_INIT(mmap_file, pkm_kacs_mmap_file),
	LSM_HOOK_INIT(file_mprotect, pkm_kacs_file_mprotect),
	LSM_HOOK_INIT(bprm_check_security, pkm_kacs_bprm_check_security),
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

static long pkm_kacs_authorize_process_access_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *target_state, u32 caller_pip_type,
	u32 caller_pip_trust, u32 desired_process_access)
{
	long ret;

	if (!subject_token || !target_state)
		return -EACCES;

	ret = pkm_kacs_authorize_process_sd_access(subject_token,
						   target_state->process_sd,
						   desired_process_access);
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
	bool is_read_mode;
	bool is_attach_mode;

	if (!desired_access)
		return -EINVAL;

	is_pidfd_open_mode = (mode & PTRACE_MODE_PIDFD_OPEN) != 0;
	is_getfd_mode = (mode & PTRACE_MODE_GETFD) != 0;
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

static int pkm_kacs_task_prctl(int option, unsigned long arg2,
			       unsigned long arg3, unsigned long arg4,
			       unsigned long arg5)
{
	struct pkm_kacs_process_state *state;

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
	pkm_kacs_assert_boot_caps(new);

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
	struct socket client_sock;
	struct socket listener_sock;
	struct socket accepted_sock;
	struct sock client_sk;
	struct sock listener_sk;
	struct sock accepted_sk;
	struct pkm_kacs_socket_security *client_sec;
	struct pkm_kacs_socket_security *listener_sec;
	struct pkm_kacs_socket_security *accepted_sec;
	void *client_blob = NULL;
	void *listener_blob = NULL;
	void *accepted_blob = NULL;
	const void *bind_token;
	long ret;

	if (captured_token_out)
		*captured_token_out = NULL;
	if (!client_token)
		return -EINVAL;

	ret = pkm_kacs_kunit_init_socket(&client_sock, &client_sk, &client_blob,
					 socket_type, 0);
	if (ret)
		return ret;
	ret = pkm_kacs_kunit_init_socket(&listener_sock, &listener_sk,
					 &listener_blob, socket_type, 0);
	if (ret)
		goto out;
	ret = pkm_kacs_kunit_init_socket(&accepted_sock, &accepted_sk,
					 &accepted_blob, socket_type, 1);
	if (ret)
		goto out;
	client_sec = pkm_kacs_sock(&client_sk);
	listener_sec = pkm_kacs_sock(&listener_sk);
	accepted_sec = pkm_kacs_sock(&accepted_sk);

	ret = pkm_kacs_set_socket_impersonation_level_core(&client_sock,
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
	pkm_kacs_kunit_socket_snapshot(listener_blob ?
				       pkm_kacs_sock(&listener_sk) : NULL,
				       listener_out);
	pkm_kacs_kunit_socket_snapshot(accepted_blob ?
				       pkm_kacs_sock(&accepted_sk) : NULL,
				       accepted_out);
	if (accepted_blob)
		pkm_kacs_kunit_cleanup_socket(&accepted_sk, accepted_blob);
	if (listener_blob)
		pkm_kacs_kunit_cleanup_socket(&listener_sk, listener_blob);
	if (client_blob)
		pkm_kacs_kunit_cleanup_socket(&client_sk, client_blob);
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

long pkm_kacs_kunit_open_process_token_for_subject(
	const struct pkm_kacs_kunit_process_token_open_args *args)
{
	struct pkm_kacs_process_sd process_sd = {};
	struct pkm_kacs_process_state target_state = {};

	if (!args)
		return -EINVAL;

	process_sd.bytes = args->target_process_sd_ptr;
	process_sd.len = args->target_process_sd_len;
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
	caller_state.pip_type = args->caller_pip_type;
	caller_state.pip_trust = args->caller_pip_trust;
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_check_process_setinfo_core(args->subject_token,
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
	target_state.pip_type = args->target_pip_type;
	target_state.pip_trust = args->target_pip_trust;
	target_state.process_sd = &process_sd;

	return pkm_kacs_authorize_process_access_core(
		args->subject_token, &target_state, args->caller_pip_type,
		args->caller_pip_trust, desired_access);
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
	pkm_kacs_assert_boot_caps((struct cred *)current_cred());

	if (current_cred() != current_real_cred()) {
		struct pkm_kacs_cred_security *real_sec =
			pkm_kacs_cred(current_real_cred());

		real_sec->token = kacs_rust_token_clone(system_token);
		pkm_kacs_stamp_projected_ids(real_sec);
		pkm_kacs_assert_boot_caps((struct cred *)current_real_cred());
	}

	pr_info("pkm: slow-track kernel scaffold initialized\n");
	return 0;
}

DEFINE_LSM(pkm) = {
	.id = &pkm_lsmid,
	.init = pkm_init,
	.blobs = &pkm_blob_sizes,
};
