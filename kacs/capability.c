// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/preempt.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/types.h>

#include <pkm/token.h>

#include "../kmes/event_policy.h"
#include "access_check.h"
#include "capability.h"
#include "copy_up.h"
#include "lsm_internal.h"
#include "process_access.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

u64 pkm_kacs_allow_cap_mask_u64(void)
{
	return (1ULL << CAP_CHOWN) | (1ULL << CAP_DAC_OVERRIDE) |
	       (1ULL << CAP_DAC_READ_SEARCH) | (1ULL << CAP_FOWNER) |
	       (1ULL << CAP_FSETID) | (1ULL << CAP_KILL) |
	       (1ULL << CAP_SETGID) | (1ULL << CAP_SETUID) |
	       (1ULL << CAP_NET_BROADCAST) | (1ULL << CAP_IPC_OWNER) |
	       (1ULL << CAP_LEASE) | (1ULL << CAP_NET_BIND_SERVICE);
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
	/*
	 * The Linux privileged-port floor never refuses a bind: every claim
	 * on a port reaches the reservation check in socket_bind, where the
	 * port's security descriptor decides (<pkm/net.h>).
	 */
	cap_raise(*caps, CAP_NET_BIND_SERVICE);
}

void pkm_kacs_raise_allow_compat_caps(struct cred *cred)
{
	if (!cred)
		return;

	pkm_kacs_raise_allow_kernel_caps(&cred->cap_effective);
	pkm_kacs_raise_allow_kernel_caps(&cred->cap_permitted);
	pkm_kacs_raise_allow_kernel_caps(&cred->cap_inheritable);
	pkm_kacs_raise_allow_kernel_caps(&cred->cap_bset);
}

void pkm_kacs_capget_fixup(kernel_cap_t *effective,
			   kernel_cap_t *inheritable,
			   kernel_cap_t *permitted)
{
	pkm_kacs_raise_allow_kernel_caps(effective);
	pkm_kacs_raise_allow_kernel_caps(inheritable);
	pkm_kacs_raise_allow_kernel_caps(permitted);
}

long pkm_kacs_proc_status_cap_fixup(kernel_cap_t *inheritable,
				    kernel_cap_t *permitted,
				    kernel_cap_t *effective,
				    kernel_cap_t *bset,
				    kernel_cap_t *ambient)
{
	if (!inheritable || !permitted || !effective || !bset || !ambient)
		return -EINVAL;

	pkm_kacs_raise_allow_kernel_caps(inheritable);
	pkm_kacs_raise_allow_kernel_caps(permitted);
	pkm_kacs_raise_allow_kernel_caps(effective);
	pkm_kacs_raise_allow_kernel_caps(bset);
	return 0;
}

void pkm_kacs_reset_allow_compat_caps(struct cred *cred)
{
	if (!cred)
		return;

	cred->cap_effective = CAP_EMPTY_SET;
	cred->cap_permitted = CAP_EMPTY_SET;
	cred->cap_inheritable = CAP_EMPTY_SET;
	cap_clear(cred->cap_ambient);
	pkm_kacs_raise_allow_compat_caps(cred);
}

void pkm_kacs_copy_exec_compat_caps(struct cred *new, const struct cred *old)
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

bool pkm_kacs_allow_caps_present(const kernel_cap_t *caps)
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
	       cap_raised(*caps, CAP_LEASE) &&
	       cap_raised(*caps, CAP_NET_BIND_SERVICE);
}

u64 pkm_kacs_kernel_cap_to_u64(const kernel_cap_t *caps)
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

kernel_cap_t pkm_kacs_u64_to_kernel_cap(u64 mask)
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
	case CAP_NET_BIND_SERVICE:
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
		return KACS_SE_TCB_PRIVILEGE;
	case CAP_IPC_LOCK:
		return KACS_SE_LOCK_MEMORY_PRIVILEGE;
	case CAP_SYS_MODULE:
		return KACS_SE_LOAD_DRIVER_PRIVILEGE;
	case CAP_SYS_PTRACE:
		return KACS_SE_DEBUG_PRIVILEGE;
	case CAP_SYS_BOOT:
		return KACS_SE_SHUTDOWN_PRIVILEGE;
	case CAP_SYS_NICE:
		return KACS_SE_INCREASE_BASE_PRIORITY_PRIVILEGE;
	case CAP_SYS_RESOURCE:
		return KACS_SE_INCREASE_QUOTA_PRIVILEGE;
	case CAP_SYS_TIME:
		return KACS_SE_SYSTEMTIME_PRIVILEGE;
	case CAP_AUDIT_WRITE:
		return KACS_SE_AUDIT_PRIVILEGE;
	case CAP_AUDIT_CONTROL:
	case CAP_MAC_ADMIN:
	case CAP_AUDIT_READ:
		return KACS_SE_SECURITY_PRIVILEGE;
	case CAP_PERFMON:
		/*
		 * CAP_PERFMON spans multiple Peios privilege tiers, so it
		 * OR-maps: the perfmon_capable() ceiling is satisfied by any
		 * one of these. The specific gate for the specific operation
		 * (cross-task vs system-wide profiling) is enforced at the
		 * perf_event_open syscall path.
		 */
		return KACS_SE_SYSTEM_PROFILE_PRIVILEGE |
		       KACS_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE |
		       KACS_SE_LOAD_DRIVER_PRIVILEGE;
	default:
		return 0;
	}
}

long pkm_kacs_check_capability_for_token(const void *subject_token, int cap)
{
	return pkm_kacs_check_capability_for_token_held(subject_token, cap,
						       NULL);
}

/*
 * The decision, also reporting in *held_out the privileges the token spent
 * on it: 0 for a capability every process has or no process has, and on a
 * refusal.
 */
long pkm_kacs_check_capability_for_token_held(const void *subject_token,
					      int cap, u64 *held_out)
{
	u64 privilege;
	u64 held;
	int remote_shutdown_origin = 0;

	if (held_out)
		*held_out = 0;
	if (!cap_valid(cap))
		return -EINVAL;
	if (pkm_kacs_cap_is_allow(cap)) {
		trace_kacs_capability(cap, 0, KACS_CAP_ALLOW_GRANT, 0);
		return 0;
	}
	if (cap == CAP_SETPCAP || cap == CAP_SETFCAP || cap == CAP_MAC_OVERRIDE) {
		trace_kacs_capability(cap, 0, KACS_CAP_HARD_DENY, -EPERM);
		return -EPERM;
	}

	privilege = pkm_kacs_cap_required_privilege(cap);
	if (privilege == 0)
		return -EPERM;
	if (!subject_token)
		return -EPERM;
	if (cap == CAP_SYS_BOOT) {
		remote_shutdown_origin =
			kacs_rust_token_is_remote_shutdown_origin(subject_token);
		if (remote_shutdown_origin < 0)
			return -EPERM;
	}
	/*
	 * `privilege` is the mask of privileges that satisfy this capability.
	 * For most caps it is a single bit; OR-mapped caps (e.g. CAP_PERFMON)
	 * carry several, any one of which suffices. `held` is the subset the
	 * token actually has enabled, and is what gets marked used.
	 */
	held = kacs_rust_token_enabled_privileges_in_mask(subject_token,
							  privilege);
	if (held == 0) {
		trace_kacs_capability(cap, privilege, KACS_CAP_PRIV_NOT_ENABLED,
				      -EPERM);
		return -EPERM;
	}
	if (remote_shutdown_origin > 0) {
		if (!kacs_rust_token_has_enabled_privilege(
			    subject_token,
			    KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE)) {
			trace_kacs_capability(cap,
					      KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE,
					      KACS_CAP_PRIV_NOT_ENABLED, -EPERM);
			return -EPERM;
		}
		held |= KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE;
	}
	if (!kacs_rust_token_mark_privileges_used(subject_token, held)) {
		trace_kacs_capability(cap, held, KACS_CAP_USE_MARK_FAIL,
				      -EPERM);
		return -EPERM;
	}

	if (held_out)
		*held_out = held;
	return 0;
}

/*
 * kacs.audit.privilege.used for a privilege spent at a Linux capability
 * gate or the volume-management gate (PKM §3.4).
 *
 * Recorded when, and only when, all of these hold:
 *   - the token's audit policy carries PRIVILEGE_USE_SUCCESS, the event's
 *     own switch, as for privilege use in an access check;
 *   - the caller did not pass CAP_OPT_NOAUDIT (a probe, not a use);
 *   - the check is the current task's own, in task context, in a user
 *     process: kernel threads and interrupt context only count;
 *   - this process has not already recorded this gate under this token.
 *
 * capable() can run under spinlocks and the record allocates, so this
 * only notes the use; task work writes the record on the way back to user
 * space. Returns whether the use was queued (for KUnit).
 */
static void pkm_kacs_priv_use_task_work(struct callback_head *work);

static bool pkm_kacs_priv_use_first(struct pkm_kacs_process_state *state,
				    const u8 guid[KACS_UUID_BYTES],
				    unsigned int bit, bool claim)
{
	unsigned long flags;
	bool first;

	spin_lock_irqsave(&state->priv_use_lock, flags);
	if (memcmp(state->priv_use_token_guid, guid, KACS_UUID_BYTES)) {
		memcpy(state->priv_use_token_guid, guid, KACS_UUID_BYTES);
		state->priv_use_seen = 0;
	}
	first = !(state->priv_use_seen & BIT_ULL(bit));
	if (first && claim)
		state->priv_use_seen |= BIT_ULL(bit);
	spin_unlock_irqrestore(&state->priv_use_lock, flags);
	return first;
}

static void pkm_kacs_priv_use_unclaim(struct pkm_kacs_process_state *state,
				      const u8 guid[KACS_UUID_BYTES],
				      unsigned int bit)
{
	unsigned long flags;

	spin_lock_irqsave(&state->priv_use_lock, flags);
	if (!memcmp(state->priv_use_token_guid, guid, KACS_UUID_BYTES))
		state->priv_use_seen &= ~BIT_ULL(bit);
	spin_unlock_irqrestore(&state->priv_use_lock, flags);
}

bool pkm_kacs_note_privilege_use(const struct cred *cred, unsigned int bit,
				 u64 held, unsigned int opts)
{
	const struct pkm_kacs_cred_security *sec;
	struct pkm_kacs_task_security *tsec;
	struct pkm_kacs_process_state *state;
	u8 guid[KACS_UUID_BYTES];
	const void *token;

	/* The policy first: noting a use claims it and queues task work. */
	if (!pkm_kmes_event_enabled(PKM_KMES_EV_KACS_AUDIT_PRIVILEGE_USED))
		return false;
	if (!held || (opts & CAP_OPT_NOAUDIT) || bit > PKM_KACS_PRIV_USE_VOLUME_BIT)
		return false;
	if (!in_task() || (current->flags & PF_KTHREAD) || !current->security)
		return false;
	if (!cred || cred != current_cred() || !cred->security)
		return false;
	sec = pkm_kacs_cred(cred);
	token = sec ? sec->token : NULL;
	if (!token)
		return false;
	if (!(kacs_rust_token_audit_policy(token) &
	      KACS_AUDIT_POLICY_PRIVILEGE_USE_SUCCESS))
		return false;
	tsec = pkm_kacs_task(current);
	state = tsec->process_state;
	if (!state || kacs_rust_token_guid(token, guid))
		return false;

	/*
	 * One token at a time can wait for the task work. A use under another
	 * token in the same syscall stays unclaimed and is recorded next time.
	 */
	if (tsec->priv_use_token && tsec->priv_use_token != token)
		return false;
	if (!pkm_kacs_priv_use_first(state, guid, bit, true))
		return false;

	if (!tsec->priv_use_token) {
		const void *ref = kacs_rust_token_clone(token);

		if (!ref) {
			pkm_kacs_priv_use_unclaim(state, guid, bit);
			return false;
		}
		init_task_work(&tsec->priv_use_work,
			       pkm_kacs_priv_use_task_work);
		if (task_work_add(current, &tsec->priv_use_work, TWA_RESUME)) {
			/* Exiting: no later return to user to write it on. */
			kacs_rust_token_drop(ref);
			pkm_kacs_priv_use_unclaim(state, guid, bit);
			return false;
		}
		tsec->priv_use_token = ref;
	}
	tsec->priv_use_pending |= BIT_ULL(bit);
	return true;
}

/*
 * The privileges a gate spends for `bit`, recomputed when the record is
 * written: the use was decided under the same token moments earlier.
 */
static u64 pkm_kacs_priv_use_privileges(const void *token, unsigned int bit)
{
	u64 privilege;
	u64 held;

	if (bit == PKM_KACS_PRIV_USE_VOLUME_BIT)
		privilege = KACS_SE_MANAGE_VOLUME_PRIVILEGE |
			    KACS_SE_TCB_PRIVILEGE;
	else
		privilege = pkm_kacs_cap_required_privilege((int)bit);
	held = kacs_rust_token_enabled_privileges_in_mask(token, privilege);
	if ((int)bit == CAP_SYS_BOOT &&
	    kacs_rust_token_is_remote_shutdown_origin(token) > 0 &&
	    kacs_rust_token_has_enabled_privilege(
		    token, KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE))
		held |= KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE;
	/* Disabled since: name what the gate asks for. */
	return held ? held : privilege;
}

static void pkm_kacs_priv_use_task_work(struct callback_head *work)
{
	struct pkm_kacs_task_security *tsec =
		container_of(work, struct pkm_kacs_task_security, priv_use_work);
	const void *token = tsec->priv_use_token;
	u64 pending = tsec->priv_use_pending;
	u32 pip_type = 0;
	u32 pip_trust = 0;

	/* Cleared first: a gate reached while writing queues afresh. */
	tsec->priv_use_token = NULL;
	tsec->priv_use_pending = 0;
	if (!token)
		return;
	if (pkm_kacs_current_pip_context(&pip_type, &pip_trust)) {
		pip_type = 0;
		pip_trust = 0;
	}
	while (pending) {
		unsigned int bit = __ffs64(pending);
		u64 privileges = pkm_kacs_priv_use_privileges(token, bit);

		pending &= ~BIT_ULL(bit);
		while (privileges) {
			u64 one = BIT_ULL(__ffs64(privileges));

			privileges &= ~one;
			(void)kacs_rust_emit_privilege_use(
				token,
				bit == PKM_KACS_PRIV_USE_VOLUME_BIT ?
					PKM_KACS_PRIV_USE_OP_VOLUME_MOUNT :
					PKM_KACS_PRIV_USE_OP_LINUX_CAP,
				bit == PKM_KACS_PRIV_USE_VOLUME_BIT ? CAP_SYS_ADMIN :
								      (int)bit,
				one, pip_type, pip_trust);
		}
	}
	kacs_rust_token_drop(token);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
/* The per-process dedup, claimed as a gate's first use would claim it. */
bool pkm_kacs_kunit_priv_use_first(struct pkm_kacs_process_state *state,
				   const u8 guid[KACS_UUID_BYTES],
				   unsigned int bit)
{
	return pkm_kacs_priv_use_first(state, guid, bit, true);
}
#endif

/* Drops a reference task work never got to; see pkm_kacs_task_free(). */
void pkm_kacs_priv_use_task_release(struct pkm_kacs_task_security *tsec)
{
	if (!tsec || !tsec->priv_use_token)
		return;
	kacs_rust_token_drop(tsec->priv_use_token);
	tsec->priv_use_token = NULL;
	tsec->priv_use_pending = 0;
}

long pkm_kacs_capset_core(const void *subject_token, struct cred *new,
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
	new->cap_ambient = cap_intersect(new->cap_ambient,
					 cap_intersect(*permitted,
						       *inheritable));
	pkm_kacs_raise_allow_compat_caps(new);
	return 0;
}

long pkm_kacs_prctl_capability_guard_core(const void *subject_token,
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

/*
 * Whether the current task may mount, unmount, or otherwise reshape the mount
 * tree.
 *
 * Mounting is an ADMINISTRATIVE act, not a TCB act: SeManageVolumePrivilege
 * satisfies it, and SeTcbPrivilege does too because the TCB may do anything a
 * volume manager may. Before this existed, mounting reached the kernel only as
 * CAP_SYS_ADMIN, which maps to SeTcbPrivilege alone -- so no administrator
 * could mount at all, and peios-install could not run outside a SYSTEM shell.
 *
 * CAP_SYS_ADMIN is deliberately NOT remapped. It gates dozens of unrelated
 * operations, and pointing it at a weaker privilege would hand out far more
 * than mounting. The mount path asks this narrower question instead; every
 * other CAP_SYS_ADMIN user still needs the TCB.
 *
 * Note what this privilege is worth: its holder may mount a filesystem whose
 * synthesised descriptors it chooses (policy=synth-* with --synth-sddl) and
 * may mount over an existing path, which together are enough to author policy
 * on a subtree and to shadow a system path. It is a deliberate, documented
 * property of the design -- see the privileges topic -- and it makes this a
 * highly sensitive privilege, nearer SeLoadDriverPrivilege than
 * SeChangeNotifyPrivilege. Grant it accordingly.
 *
 * Returns true when permitted. Callers are kernel mount paths patched to
 * consult this before falling back to the ordinary capability check.
 */
/*
 * The decision itself, against an explicit token.
 *
 * Split from the wrapper below for the same reason
 * pkm_kacs_check_capability_for_token is: a function that reads
 * current_cred() cannot be driven from KUnit, and the privilege arithmetic is
 * the part worth testing.
 */
bool pkm_kacs_may_manage_volumes_for_token(const void *subject_token)
{
	u64 privilege = KACS_SE_MANAGE_VOLUME_PRIVILEGE | KACS_SE_TCB_PRIVILEGE;
	u64 held;

	if (!subject_token) {
		trace_kacs_capability(CAP_SYS_ADMIN, privilege, KACS_CAP_CAPABLE,
				      -EPERM);
		return false;
	}

	held = kacs_rust_token_enabled_privileges_in_mask(subject_token,
							  privilege);
	if (held == 0) {
		trace_kacs_capability(CAP_SYS_ADMIN, privilege,
				      KACS_CAP_PRIV_NOT_ENABLED, -EPERM);
		return false;
	}
	if (!kacs_rust_token_mark_privileges_used(subject_token, held)) {
		trace_kacs_capability(CAP_SYS_ADMIN, held, KACS_CAP_USE_MARK_FAIL,
				      -EPERM);
		return false;
	}

	return true;
}

bool pkm_kacs_may_manage_volumes(void)
{
	const struct pkm_kacs_cred_security *sec;
	const struct cred *cred = current_cred();
	const void *token;
	u64 held;

	if (!cred)
		return false;
	sec = cred->security ? pkm_kacs_cred(cred) : NULL;
	token = sec ? sec->token : NULL;
	if (!pkm_kacs_may_manage_volumes_for_token(token))
		return false;
	/* The privileges the gate just spent, for the privilege-use record. */
	held = kacs_rust_token_enabled_privileges_in_mask(
		token, KACS_SE_MANAGE_VOLUME_PRIVILEGE | KACS_SE_TCB_PRIVILEGE);
	pkm_kacs_note_privilege_use(cred, PKM_KACS_PRIV_USE_VOLUME_BIT, held,
				    CAP_OPT_NONE);
	return true;
}

long pkm_kacs_capable_in_cred_ns(const struct cred *cred,
				 struct user_namespace *target_ns, int cap,
				 unsigned int opts)
{
	return pkm_kacs_capable_in_cred_ns_held(cred, target_ns, cap, opts,
						NULL);
}

long pkm_kacs_capable_in_cred_ns_held(const struct cred *cred,
				      struct user_namespace *target_ns,
				      int cap, unsigned int opts,
				      u64 *held_out)
{
	const struct pkm_kacs_cred_security *sec;

	(void)opts;

	if (held_out)
		*held_out = 0;
	if (!cap_valid(cap))
		return -EINVAL;
	if (!cred) {
		trace_kacs_capability(cap, 0, KACS_CAP_CAPABLE, -EPERM);
		return -EPERM;
	}

	sec = cred->security ? pkm_kacs_cred(cred) : NULL;
	if (!sec || !sec->token) {
		trace_kacs_capability(cap, 0, KACS_CAP_CAPABLE, -EPERM);
		return -EPERM;
	}
	/*
	 * cap_convert_nscap() performs CAP_SETFCAP before the xattr LSM hook.
	 * KACS owns the one exact-value StrataFS clone call that may cross that
	 * gate; no caller-controlled setxattr path can arm this condition. The
	 * exception lives here rather than only in the LSM capable hook because
	 * security_capable() reaches the capability LSM's cap_capable() -- and
	 * so this function -- first, and a refusal there ends the walk before
	 * pkm_kacs_capable() is consulted.
	 */
	if (cap == CAP_SETFCAP && cred == current_cred() &&
	    pkm_kacs_copy_up_allows_capability_use(target_ns))
		return 0;
	return pkm_kacs_check_capability_for_token_held(sec->token, cap,
						       held_out);
}

long pkm_kacs_capget_for_task(const struct task_struct *target,
			      kernel_cap_t *effective,
			      kernel_cap_t *inheritable,
			      kernel_cap_t *permitted)
{
	const struct cred *caller_cred;
	const struct cred *target_cred;
	const struct pkm_kacs_cred_security *caller_sec;
	const struct pkm_kacs_cred_security *target_sec;
	struct pkm_kacs_process_state *caller_state;
	struct pkm_kacs_process_state *target_state;
	const void *subject_token;
	long ret;

	if (!target || !effective || !inheritable || !permitted)
		return -EINVAL;
	if (!pkm_kacs_current_token_eval_context_allowed())
		return -EACCES;

	pkm_kacs_capget_fixup(effective, inheritable, permitted);
	if (target == current)
		return 0;

	caller_cred = current_cred();
	target_cred = get_task_cred((struct task_struct *)target);
	if (!target_cred)
		return -EACCES;
	if (!caller_cred) {
		put_cred(target_cred);
		return -EACCES;
	}

	caller_sec = pkm_kacs_cred(caller_cred);
	target_sec = pkm_kacs_cred(target_cred);
	subject_token = caller_sec ? caller_sec->token : NULL;
	caller_state = caller_sec ? caller_sec->process_state : NULL;
	target_state = target_sec ? target_sec->process_state : NULL;

	ret = pkm_kacs_check_process_capget_core(subject_token, caller_state,
						 target_state);
	put_cred(target_cred);
	trace_kacs_capability(0, 0, KACS_CAP_CAPGET, ret);
	return ret;
}

int pkm_kacs_capable(const struct cred *cred,
		     struct user_namespace *target_ns, int cap,
		     unsigned int opts)
{
	u64 held = 0;
	long ret;

	/*
	 * The StrataFS capability-clone exception is in the shared core.
	 * Every capable() decides twice, once in the patched cap_capable() and
	 * once here; only this, the LSM hook, notes a privilege use, so each
	 * use is counted once.
	 */
	ret = pkm_kacs_capable_in_cred_ns_held(cred, target_ns, cap, opts,
					       &held);
	if (!ret && held)
		pkm_kacs_note_privilege_use(cred, (unsigned int)cap, held, opts);
	return (int)ret;
}

int pkm_kacs_capset(struct cred *new, const struct cred *old,
		    const kernel_cap_t *effective,
		    const kernel_cap_t *inheritable,
		    const kernel_cap_t *permitted)
{
	const void *subject_token;
	long ret;

	(void)old;
	subject_token = pkm_kacs_current_effective_token_ptr();
	ret = pkm_kacs_capset_core(subject_token, new, effective,
				   inheritable, permitted);
	trace_kacs_capability(0, 0, KACS_CAP_CAPSET, ret);
	return (int)ret;
}

long pkm_kacs_prctl_capability_guard(int option, unsigned long arg2,
				     unsigned long arg3,
				     unsigned long arg4,
				     unsigned long arg5)
{
	const struct cred *cred = current_cred();
	const struct pkm_kacs_cred_security *sec;
	u64 ambient_mask = 0;
	long ret;

	if (!cred)
		return -EPERM;
	if (!pkm_kacs_current_token_eval_context_allowed())
		return -EPERM;

	sec = pkm_kacs_cred(cred);
	ambient_mask = pkm_kacs_kernel_cap_to_u64(&cred->cap_ambient);
	ret = pkm_kacs_prctl_capability_guard_core(
		sec ? sec->token : NULL, ambient_mask, option, arg2, arg3,
		arg4, arg5);
	trace_kacs_capability(0, 0, KACS_CAP_PRCTL_GUARD, ret);
	return ret;
}
