// SPDX-License-Identifier: GPL-2.0-only

#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/sched/user.h>
#include <linux/security.h>

#include <pkm/token.h>

#include "capability.h"
#include "copy_up.h"
#include "cred_lifecycle.h"
#include "exec.h"
#include "file_access.h"
#include "file_sd_cache.h"
#include "lsm_internal.h"
#include "mount_policy.h"
#include "primary_token.h"
#include "process_state.h"
#include "psb.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

static int pkm_kacs_check_bprm_file_execute_for_subject(
	const void *subject_token, struct linux_binprm *bprm)
{
	struct inode *inode;
	struct file *file;

	if (!subject_token || !bprm || !bprm->file)
		return -EACCES;

	file = bprm->file;
	inode = file_inode(file);
	if (!inode || !inode->i_sb)
		return -EACCES;
	if (!pkm_kacs_mount_policy_is_managed(
		    pkm_kacs_superblock_mount_policy(inode->i_sb)))
		return 0;

	return (int)pkm_kacs_authorize_live_file_access_core(
		subject_token, file, KACS_FILE_EXECUTE);
}

int pkm_kacs_bprm_check_security(struct linux_binprm *bprm)
{
	struct pkm_kacs_process_state *state;
	int ret;

	if (!bprm)
		return -EACCES;

	state = pkm_kacs_current_process_state();
	if (!state)
		return -EACCES;

	ret = pkm_kacs_check_bprm_file_execute_for_subject(
		pkm_kacs_current_effective_token_ptr(), bprm);
	if (ret)
		return ret;

	return pkm_kacs_check_pie_bprm_core(
		pkm_kacs_process_state_mitigation_bits(state),
		(const u8 *)bprm->buf, sizeof(bprm->buf));
}

static long pkm_kacs_exec_file_integrity_label(const struct file *file,
					       u32 *integrity_out)
{
	struct pkm_kacs_inode_sd_cache *cache;
	struct pkm_kacs_inode_security *sec;
	struct inode *inode;
	long ret;

	if (!file || !integrity_out)
		return -EACCES;

	inode = file_inode(file);
	if (!inode || !inode->i_security) {
		trace_kacs_exec(false, false, 0, 0,
				KACS_EXEC_INTEGRITY_NO_ISEC, -EACCES);
		return -EACCES;
	}

	sec = pkm_kacs_inode(inode);
	ret = pkm_kacs_inode_ensure_effective_cache((struct file *)file, sec);
	if (!ret) {
		cache = pkm_kacs_inode_sd_cache_get_current(inode, sec);
		if (!cache) {
			trace_kacs_exec(false, false, 0, 0,
					KACS_EXEC_INTEGRITY_NO_CACHE, -EACCES);
			return -EACCES;
		}
		if (cache->state != PKM_KACS_INODE_SD_VALID ||
		    !cache->bytes || cache->len == 0) {
			trace_kacs_exec(false, false, 0, 0,
					KACS_EXEC_INTEGRITY_INVALID_SD, -EACCES);
			ret = -EACCES;
		} else {
			ret = kacs_rust_cached_file_sd_integrity_label(
				cache->bytes, cache->len, &cache->layout,
				integrity_out);
		}
		pkm_kacs_inode_sd_cache_free(cache);
	}
	return ret;
}

static long pkm_kacs_apply_exec_primary_token(const void *primary_token,
					      const struct file *file,
					      struct cred *new,
					      bool require_file_for_npm)
{
	const void *exec_token = NULL;
	u32 file_integrity = 0;
	bool npm_derived = false;
	long ret;

	if (!primary_token || !new) {
		trace_kacs_exec(false, false, 0, 0, KACS_EXEC_BAD_ARGS, -EACCES);
		return -EACCES;
	}

	if (kacs_rust_token_has_new_process_min(primary_token)) {
		if (!file) {
			if (require_file_for_npm) {
				trace_kacs_exec(false, false, 0, 0,
						KACS_EXEC_NPM_NO_FILE, -EACCES);
				return -EACCES;
			}
		} else {
			ret = pkm_kacs_exec_file_integrity_label(
				file, &file_integrity);
			if (ret)
				return ret;

			ret = kacs_rust_token_new_process_min_exec(
				primary_token, file_integrity, &exec_token);
			if (ret) {
				trace_kacs_exec(false, false, 0, 0,
						KACS_EXEC_NPM_DERIVE_FAIL, ret);
				return ret;
			}
			npm_derived = true;
		}
	}

	if (!exec_token) {
		exec_token = kacs_rust_token_clone(primary_token);
		if (!exec_token) {
			trace_kacs_exec(false, false, 0, 0,
					KACS_EXEC_TOKEN_CLONE_FAIL, -EACCES);
			return -EACCES;
		}
	}

	ret = pkm_kacs_install_token_ref_on_cred(new, exec_token, false);
	if (ret) {
		kacs_rust_token_drop(exec_token);
		trace_kacs_exec(false, false, 0, 0,
				KACS_EXEC_TOKEN_INSTALL_FAIL, ret);
		return ret;
	}

	trace_kacs_exec(false, false, 0, 0,
			npm_derived ? KACS_EXEC_TOKEN_NPM_DERIVED :
				      KACS_EXEC_TOKEN_CLONE,
			0);
	return ret;
}

/*
 * Note this denies when exec_pip_trust is 0 because no PIP was derived at all,
 * not only when a signature was found and graded below PeiosTcb. That is
 * deliberate: for a kernel-initiated exec, "could not establish trust" and "is
 * not trusted" have to reach the same answer, or the floor would be bypassable
 * by whatever prevents the derivation from running.
 */
bool pkm_kacs_umh_exec_denied(bool usermodehelper, u32 exec_pip_trust)
{
	return usermodehelper &&
	       exec_pip_trust < PKM_KACS_PIP_TRUST_PEIOS_TCB;
}

long pkm_kacs_bprm_creds_from_file_core(const void *subject_token,
					const void *primary_token,
					const struct file *file,
					struct cred *new,
					const struct cred *old,
					bool require_file_for_npm,
					bool stage_exec_pip,
					bool usermodehelper)
{
	bool uid_changed;
	bool gid_changed;
	struct user_struct *old_user;
	u32 exec_pip_type = 0;
	u32 exec_pip_trust = 0;
	long ret;

	if (!new || !old) {
		trace_kacs_exec(false, false, 0, 0, KACS_EXEC_BAD_ARGS, -EACCES);
		return -EACCES;
	}

	if (stage_exec_pip) {
		int pip_ret;

		pkm_kacs_clear_pending_exec_pip();
		pip_ret = pkm_kacs_exec_pip_from_file(file, &exec_pip_type,
						      &exec_pip_trust);
		/*
		 * Verification could not be performed -- the ML-DSA transform
		 * was unavailable, or a key in the table was rejected by it.
		 * This is NOT the unsigned path.
		 *
		 * An unsigned binary runs with no integrity label, which is a
		 * legitimate outcome. Treating an unverifiable one the same way
		 * silently strips PIP from every process the system executes,
		 * and the result is indistinguishable from a correctly working
		 * system that happens to have no signed binaries -- so nothing
		 * would surface it until signing was deployed, at which point
		 * it would look like the signing rollout broke something.
		 *
		 * Fail the exec instead. pkm_init() probes the transform at
		 * boot and refuses to bring the LSM up without it, so reaching
		 * here means a transient failure -- allocation pressure -- and
		 * refusing that exec is recoverable in a way losing the
		 * integrity boundary is not.
		 */
		if (pip_ret < 0) {
			trace_kacs_exec(false, false, 0, 0,
					KACS_EXEC_SIGNATURE_UNVERIFIABLE,
					pip_ret);
			return -EACCES;
		}
	}

	/*
	 * The PeiosTcb floor on kernel-initiated execs.
	 *
	 * The kernel spawns usermodehelpers on its own behalf and at full
	 * privilege -- request_module() runs CONFIG_MODPROBE_PATH, and the path
	 * is a writable sysctl. Redirecting it is a well-known escalation: point
	 * it at an attacker-controlled binary and the next request_module()
	 * executes it with the kernel's authority. Requiring the exec'd binary
	 * to carry PeiosTcb trust makes redirection worthless on its own, since
	 * the attacker would also have to produce a TCB-signed binary.
	 *
	 * This is a HARD FAIL rather than a demotion to PIP None. Everywhere
	 * else an unsigned binary simply gets no integrity label and runs with
	 * whatever authority its token carries; here the exec is refused, since
	 * the caller is the kernel and there is no lesser authority to fall back
	 * to. Checked before the uid/gid gate so an unsigned helper is refused
	 * on identical grounds whether or not the exec also changes identity.
	 */
	if (pkm_kacs_umh_exec_denied(usermodehelper, exec_pip_trust)) {
		trace_kacs_exec(false, false, exec_pip_type, exec_pip_trust,
				KACS_EXEC_UMH_NOT_TCB, -EACCES);
		return -EACCES;
	}

	uid_changed = !uid_eq(new->euid, old->euid);
	gid_changed = !gid_eq(new->egid, old->egid);

	if ((uid_changed || gid_changed) && !subject_token) {
		trace_kacs_exec(uid_changed, gid_changed, exec_pip_type,
				exec_pip_trust, KACS_EXEC_ID_CHANGE_NO_TOKEN,
				-EACCES);
		return -EACCES;
	}
	if ((uid_changed || gid_changed) &&
	    kacs_rust_token_has_enabled_privilege(
		    subject_token, KACS_SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE)) {
		trace_kacs_exec(uid_changed, gid_changed, exec_pip_type,
				exec_pip_trust,
				KACS_EXEC_ID_CHANGE_PRIV_UNSUPPORTED,
				-EOPNOTSUPP);
		return -EOPNOTSUPP;
	}

	pkm_kacs_copy_exec_compat_caps(new, old);

	if (uid_changed) {
		new->uid = new->euid;
		new->suid = new->euid;
		new->fsuid = old->fsuid;

		if (new->user != old->user) {
			old_user = get_uid(old->user);
			free_uid(new->user);
			new->user = old_user;
		}
	}

	if (gid_changed) {
		new->gid = new->egid;
		new->sgid = new->egid;
		new->fsgid = old->fsgid;
	}

	ret = pkm_kacs_apply_exec_primary_token(primary_token, file, new,
					       require_file_for_npm);
	if (ret)
		return ret;

	if (stage_exec_pip)
		pkm_kacs_stage_pending_exec_pip(exec_pip_type, exec_pip_trust);

	trace_kacs_exec(uid_changed, gid_changed, exec_pip_type, exec_pip_trust,
			KACS_EXEC_CREDS_ALLOW, 0);
	return 0;
}

int pkm_kacs_bprm_creds_from_file(struct linux_binprm *bprm,
				  const struct file *file)
{
	if (!bprm || !bprm->cred)
		return -EACCES;

	return (int)pkm_kacs_bprm_creds_from_file_core(
		pkm_kacs_current_effective_token_ptr(),
		pkm_kacs_current_primary_token_ptr(), file, bprm->cred,
		current_cred(), true, true,
		pkm_kacs_current_is_usermodehelper());
}

/*
 * The mark is deliberately not cleared here or anywhere else -- see the comment
 * on pkm_kacs_task_security.usermodehelper. A usermodehelper task exists only to
 * be that helper, so leaving it set keeps a re-exec under the same floor instead
 * of letting the second exec escape it.
 */
void pkm_kacs_mark_usermodehelper(void)
{
	struct pkm_kacs_task_security *sec;

	if (!current || !current->security)
		return;

	sec = pkm_kacs_task(current);
	if (sec)
		sec->usermodehelper = true;
}

bool pkm_kacs_current_is_usermodehelper(void)
{
	const struct pkm_kacs_task_security *sec;

	if (!current || !current->security)
		return false;

	sec = pkm_kacs_task(current);
	return sec && sec->usermodehelper;
}

void pkm_kacs_bprm_committing_creds(const struct linux_binprm *bprm)
{
	long ret;

	(void)bprm;
	pkm_kacs_copy_up_task_exit(current);

	ret = pkm_kacs_revert_impersonation();
	if (ret) {
		trace_kacs_exec(false, false, 0, 0,
				KACS_EXEC_IMPERSONATION_REVERT_FAIL, ret);
		pr_warn("pkm: exec impersonation revert failed (%ld)\n", ret);
	}

	pkm_kacs_apply_pending_exec_dumpable();
}

void pkm_kacs_bprm_committed_creds(const struct linux_binprm *bprm)
{
	(void)bprm;

	trace_kacs_exec(false, false, 0, 0, KACS_EXEC_PIP_COMMITTED, 0);
	pkm_kacs_commit_pending_exec_pip();
}
