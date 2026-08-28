// SPDX-License-Identifier: GPL-2.0-only
/*
 * System V IPC objects — message queues, shared memory segments and
 * semaphore arrays — carry a security descriptor, stamped from the
 * creator's token at *get time and enforced through the LSM IPC hooks.
 * The nine-bit ipc_perm mode is never consulted: CAP_IPC_OWNER sits in the
 * always-allow set, so ipcperms() reaches ipc_permission() for every access
 * and KACS decides there.
 */

#include <linux/errno.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/kernel.h>
#include <linux/msg.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <uapi/linux/shm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/types.h>

#include <pkm/access.h>
#include <pkm/ipc.h>

#include "access_check.h"
#include "ipc.h"
#include "lsm_internal.h"
#include "sd_access.h"
#include "token_runtime.h"

#include <trace/events/kacs.h>

/* ipc/util.c, exported for the LSM: run @fn on the object under its lock. */
/* ipc_lsm_with_object(): ipc/util.c, declared in <linux/ipc.h> by our patch. */

static struct pkm_kacs_process_sd *pkm_kacs_ipc_sd_get(
	struct pkm_kacs_ipc_security *sec)
{
	struct pkm_kacs_process_sd *sd;

	spin_lock(&sec->lock);
	sd = pkm_kacs_process_sd_get(sec->sd);
	spin_unlock(&sec->lock);
	return sd;
}

/* Installs @sd (a counted reference, consumed) and returns the old one. */
static struct pkm_kacs_process_sd *pkm_kacs_ipc_sd_swap(
	struct pkm_kacs_ipc_security *sec, struct pkm_kacs_process_sd *sd)
{
	struct pkm_kacs_process_sd *old;

	spin_lock(&sec->lock);
	old = sec->sd;
	sec->sd = sd;
	spin_unlock(&sec->lock);
	return old;
}

int pkm_kacs_ipc_alloc_security(struct kern_ipc_perm *perm)
{
	struct pkm_kacs_ipc_security *sec;
	const void *token;
	const u8 *bytes;
	size_t len = 0;

	if (!perm || !perm->security)
		return -EACCES;
	sec = pkm_kacs_ipc(perm);
	spin_lock_init(&sec->lock);
	sec->sd = NULL;

	token = pkm_kacs_current_effective_token_ptr();
	if (!token) {
		trace_kacs_ipc(0, perm->id, 0, 0, KACS_IPC_ALLOC, -EACCES);
		return -EACCES;
	}
	bytes = kacs_rust_create_default_ipc_sd(token, &len);
	if (!bytes || !len) {
		trace_kacs_ipc(0, perm->id, 0, 0, KACS_IPC_ALLOC, -ENOMEM);
		return -ENOMEM;
	}
	sec->sd = pkm_kacs_process_sd_wrap_bytes(bytes, len);
	if (!sec->sd) {
		pkm_kacs_free((void *)bytes);
		trace_kacs_ipc(0, perm->id, 0, 0, KACS_IPC_ALLOC, -ENOMEM);
		return -ENOMEM;
	}
	trace_kacs_ipc(0, perm->id, 0, 0, KACS_IPC_ALLOC, 0);
	return 0;
}

void pkm_kacs_ipc_free_security(struct kern_ipc_perm *perm)
{
	struct pkm_kacs_ipc_security *sec;
	struct pkm_kacs_process_sd *old;

	if (!perm || !perm->security)
		return;
	sec = pkm_kacs_ipc(perm);
	old = pkm_kacs_ipc_sd_swap(sec, NULL);
	if (old)
		pkm_kacs_process_sd_put(old);
}

/* AccessCheck of @subject against the object's SD for @desired. */
static long pkm_kacs_ipc_authorize_for_subject(
	struct pkm_kacs_ipc_security *sec, const void *subject_token,
	u32 desired, u32 pip_type, u32 pip_trust)
{
	struct pkm_kacs_process_sd *sd;
	u32 granted = 0;
	long ret;

	if (!subject_token)
		return -EACCES;
	sd = pkm_kacs_ipc_sd_get(sec);
	if (!sd)
		return -EACCES;
	ret = kacs_rust_check_ipc_sd(subject_token, sd->bytes, sd->len, desired,
				     pip_type, pip_trust, &granted);
	pkm_kacs_process_sd_put(sd);
	return ret;
}

static long pkm_kacs_ipc_authorize(struct kern_ipc_perm *perm, u32 desired,
				   u32 cmd, u8 reason)
{
	struct pkm_kacs_ipc_security *sec;
	u32 pip_type = 0, pip_trust = 0;
	long ret;

	if (!perm || !perm->security) {
		trace_kacs_ipc(0, perm ? perm->id : -1, cmd, desired,
			       KACS_IPC_NO_SD, -EACCES);
		return -EACCES;
	}
	sec = pkm_kacs_ipc(perm);
	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (!ret)
		ret = pkm_kacs_ipc_authorize_for_subject(
			sec, pkm_kacs_current_effective_token_ptr(), desired,
			pip_type, pip_trust);
	trace_kacs_ipc(0, perm->id, cmd, desired, reason, ret);
	return ret;
}

/* The mode bits ipcperms() asked for → object rights. */
static u32 pkm_kacs_ipc_flag_to_access(short flag)
{
	u32 desired = 0;

	if (flag & S_IRUGO)
		desired |= KACS_IPC_READ;
	if (flag & S_IWUGO)
		desired |= KACS_IPC_WRITE;
	return desired;
}

int pkm_kacs_ipc_permission(struct kern_ipc_perm *perm, short flag)
{
	u32 desired = pkm_kacs_ipc_flag_to_access(flag);

	if (!desired)
		return 0;
	return pkm_kacs_ipc_authorize(perm, desired, 0, KACS_IPC_PERMISSION);
}

/*
 * *ctl commands → the right they need. Commands that address no object
 * (IPC_INFO, SHM_INFO, MSG_INFO, SEM_INFO) arrive with a NULL perm and need
 * nothing. Unknown commands need nothing here; the subsystem rejects them.
 */
static u32 pkm_kacs_ipc_ctl_access(int kind, int cmd)
{
	switch (cmd) {
	case IPC_RMID:
		return KACS_ACCESS_DELETE;
	case IPC_SET:
		return KACS_ACCESS_WRITE_DAC | KACS_ACCESS_WRITE_OWNER;
	case IPC_STAT:
		return KACS_IPC_QUERY_INFORMATION;
	default:
		break;
	}
	switch (kind) {
	case PKM_KACS_IPC_SHM:
		switch (cmd) {
		case SHM_STAT:
		case SHM_STAT_ANY:
			return KACS_IPC_QUERY_INFORMATION;
		case SHM_LOCK:
		case SHM_UNLOCK:
			return KACS_IPC_SET_INFORMATION;
		}
		break;
	case PKM_KACS_IPC_MSG:
		switch (cmd) {
		case MSG_STAT:
		case MSG_STAT_ANY:
			return KACS_IPC_QUERY_INFORMATION;
		}
		break;
	case PKM_KACS_IPC_SEM:
		switch (cmd) {
		case SEM_STAT:
		case SEM_STAT_ANY:
			return KACS_IPC_QUERY_INFORMATION;
		case GETVAL:
		case GETPID:
		case GETNCNT:
		case GETZCNT:
		case GETALL:
			return KACS_IPC_READ;
		case SETVAL:
		case SETALL:
			return KACS_IPC_WRITE;
		}
		break;
	}
	return 0;
}

static int pkm_kacs_ipc_ctl(int kind, struct kern_ipc_perm *perm, int cmd)
{
	u32 desired;

	if (!perm)
		return 0;
	desired = pkm_kacs_ipc_ctl_access(kind, cmd);
	if (!desired)
		return 0;
	return pkm_kacs_ipc_authorize(perm, desired, cmd, KACS_IPC_CTL);
}

int pkm_kacs_shm_shmctl(struct kern_ipc_perm *perm, int cmd)
{
	return pkm_kacs_ipc_ctl(PKM_KACS_IPC_SHM, perm, cmd);
}

int pkm_kacs_msg_queue_msgctl(struct kern_ipc_perm *perm, int cmd)
{
	return pkm_kacs_ipc_ctl(PKM_KACS_IPC_MSG, perm, cmd);
}

int pkm_kacs_sem_semctl(struct kern_ipc_perm *perm, int cmd)
{
	return pkm_kacs_ipc_ctl(PKM_KACS_IPC_SEM, perm, cmd);
}

/* ---- kacs_get_sd / kacs_set_sd addressed by (kind, id) ---- */

int pkm_kacs_ipc_kind_from_sd_flags(u32 flags)
{
	switch (flags & KACS_SD_AT_SYSV_MASK) {
	case KACS_SD_AT_SYSV_SHM:
		return PKM_KACS_IPC_SHM;
	case KACS_SD_AT_SYSV_MSG:
		return PKM_KACS_IPC_MSG;
	case KACS_SD_AT_SYSV_SEM:
		return PKM_KACS_IPC_SEM;
	default:
		return -EINVAL;
	}
}

static int pkm_kacs_ipc_take_sd_cb(struct kern_ipc_perm *perm, void *arg)
{
	struct pkm_kacs_process_sd **out = arg;

	if (!perm->security)
		return -EACCES;
	*out = pkm_kacs_ipc_sd_get(pkm_kacs_ipc(perm));
	return *out ? 0 : -EACCES;
}

struct pkm_kacs_ipc_swap_arg {
	struct pkm_kacs_process_sd *new_sd;
	struct pkm_kacs_process_sd *old_sd;
};

static int pkm_kacs_ipc_swap_sd_cb(struct kern_ipc_perm *perm, void *arg)
{
	struct pkm_kacs_ipc_swap_arg *swap = arg;

	if (!perm->security)
		return -EACCES;
	swap->old_sd = pkm_kacs_ipc_sd_swap(pkm_kacs_ipc(perm), swap->new_sd);
	swap->new_sd = NULL;
	return 0;
}

static long pkm_kacs_ipc_sd_authorize(struct pkm_kacs_process_sd *sd,
				      const void *subject_token, u32 desired)
{
	u32 pip_type = 0, pip_trust = 0, granted = 0;
	long ret;

	if (!subject_token || !sd)
		return -EACCES;
	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;
	return kacs_rust_check_ipc_sd(subject_token, sd->bytes, sd->len, desired,
				      pip_type, pip_trust, &granted);
}

long pkm_kacs_ipc_sd_query(int kind, int id, const void *subject_token,
			   u32 security_info, const u8 **out_sd_ptr,
			   size_t *out_sd_len)
{
	struct pkm_kacs_process_sd *sd = NULL;
	u32 desired = 0;
	long ret;

	if (!out_sd_ptr || !out_sd_len)
		return -EINVAL;
	*out_sd_ptr = NULL;
	*out_sd_len = 0;

	ret = pkm_kacs_get_sd_required_access(security_info, &desired);
	if (ret)
		return ret;
	ret = ipc_lsm_with_object(kind, id, pkm_kacs_ipc_take_sd_cb, &sd);
	if (ret) {
		trace_kacs_ipc(kind, id, 0, desired, KACS_IPC_NO_SD, ret);
		return ret;
	}
	ret = pkm_kacs_ipc_sd_authorize(sd, subject_token, desired);
	if (!ret)
		ret = kacs_rust_query_process_sd_subset(sd->bytes, sd->len,
							security_info,
							out_sd_ptr, out_sd_len);
	pkm_kacs_process_sd_put(sd);
	trace_kacs_ipc(kind, id, 0, desired, KACS_IPC_SD_QUERY, ret);
	return ret;
}

long pkm_kacs_ipc_sd_set(int kind, int id, const void *subject_token,
			 u32 security_info, const u8 *input_sd_ptr,
			 size_t input_sd_len)
{
	struct pkm_kacs_ipc_swap_arg swap = { };
	struct pkm_kacs_process_sd *sd = NULL;
	const u8 *new_bytes = NULL;
	size_t new_len = 0;
	u32 desired = 0;
	long ret;

	if (!input_sd_ptr || !input_sd_len)
		return -EINVAL;
	ret = pkm_kacs_set_sd_required_access(security_info, &desired);
	if (ret)
		return ret;
	ret = ipc_lsm_with_object(kind, id, pkm_kacs_ipc_take_sd_cb, &sd);
	if (ret) {
		trace_kacs_ipc(kind, id, 0, desired, KACS_IPC_NO_SD, ret);
		return ret;
	}
	ret = pkm_kacs_ipc_sd_authorize(sd, subject_token, desired);
	if (!ret)
		ret = kacs_rust_merge_process_sd(subject_token, sd->bytes, sd->len,
						 security_info, input_sd_ptr,
						 input_sd_len, &new_bytes,
						 &new_len);
	pkm_kacs_process_sd_put(sd);
	if (ret)
		goto out;

	swap.new_sd = pkm_kacs_process_sd_wrap_bytes(new_bytes, new_len);
	if (!swap.new_sd) {
		pkm_kacs_free((void *)new_bytes);
		ret = -ENOMEM;
		goto out;
	}
	ret = ipc_lsm_with_object(kind, id, pkm_kacs_ipc_swap_sd_cb, &swap);
	if (swap.new_sd)
		pkm_kacs_process_sd_put(swap.new_sd);
	if (swap.old_sd)
		pkm_kacs_process_sd_put(swap.old_sd);
out:
	trace_kacs_ipc(kind, id, 0, desired, KACS_IPC_SD_SET, ret);
	return ret;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
/*
 * Shims: a synthetic object with a freshly stamped default SD, checked for a
 * chosen subject at a chosen right. @perm_blob must hold pkm_blob_sizes.lbs_ipc
 * + sizeof(struct pkm_kacs_ipc_security) bytes.
 */
long pkm_kacs_kunit_ipc_check(const void *subject_token, u32 desired,
			      u32 pip_type, u32 pip_trust)
{
	struct kern_ipc_perm perm = { };
	struct pkm_kacs_ipc_security *sec;
	void *blob;
	long ret;

	blob = kzalloc(pkm_blob_sizes.lbs_ipc +
		       sizeof(struct pkm_kacs_ipc_security), GFP_KERNEL);
	if (!blob)
		return -ENOMEM;
	perm.security = blob;
	perm.id = 1;
	ret = pkm_kacs_ipc_alloc_security(&perm);
	if (!ret) {
		sec = pkm_kacs_ipc(&perm);
		ret = pkm_kacs_ipc_authorize_for_subject(sec, subject_token,
							 desired, pip_type,
							 pip_trust);
		pkm_kacs_ipc_free_security(&perm);
	}
	kfree(blob);
	return ret;
}

u32 pkm_kacs_kunit_ipc_ctl_access(int kind, int cmd)
{
	return pkm_kacs_ipc_ctl_access(kind, cmd);
}

u32 pkm_kacs_kunit_ipc_flag_access(short flag)
{
	return pkm_kacs_ipc_flag_to_access(flag);
}
#endif /* CONFIG_SECURITY_PKM_KUNIT */
