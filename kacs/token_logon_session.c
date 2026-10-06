// SPDX-License-Identifier: GPL-2.0-only

#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include <pkm/token.h>

#include "lsm_internal.h"
#include "token_fd.h"
#include "token_runtime.h"
#include "token_logon_session.h"

#include <trace/events/kacs.h>

/*
 * kacs.session.destroyed is written from process context, never from the
 * teardown itself. A session ends when its last token goes, and that is
 * usually a cred freed from an RCU callback, where the record's encoder
 * (which allocates GFP_KERNEL) cannot run. Teardown queues the session,
 * still holding the reference the session table held, and schedules this
 * work; the work writes each queued record and drops the reference.
 *
 * The record therefore follows the teardown by a scheduling delay rather
 * than within the same call, and its header names the kworker that wrote
 * it. That is no loss: from an RCU callback the header named whichever task
 * the softirq interrupted.
 */
static void pkm_kacs_session_audit_workfn(struct work_struct *work)
{
	(void)work;
	kacs_rust_session_audit_drain();
}

static DECLARE_WORK(pkm_kacs_session_audit_work, pkm_kacs_session_audit_workfn);

/* Safe from any context: schedule_work() neither sleeps nor allocates. */
void pkm_kacs_session_audit_schedule(void)
{
	schedule_work(&pkm_kacs_session_audit_work);
}

/* Waits until every record queued so far has been written. Sleeps. */
void pkm_kacs_session_audit_flush(void)
{
	flush_work(&pkm_kacs_session_audit_work);
}

long pkm_kacs_create_logon_session_core(const void *subject_token,
				  const u8 *spec, size_t spec_len,
				  u64 *logon_session_id_out)
{
	u64 logon_session_id = 0;
	long ret;

	if (!spec || !logon_session_id_out)
		return -EINVAL;

	ret = pkm_kacs_require_enabled_privilege(subject_token,
						 KACS_SE_TCB_PRIVILEGE);
	if (ret) {
		trace_kacs_logon_session(0, KACS_SES_CREATE_PRIV_DENIED, ret);
		return ret;
	}

	ret = kacs_rust_create_logon_session(subject_token, spec, spec_len,
				       ktime_get_real_seconds(), &logon_session_id);
	if (ret)
		return ret;
	if (logon_session_id > LONG_MAX)
		return -ERANGE;

	*logon_session_id_out = logon_session_id;
	trace_kacs_logon_session(logon_session_id, KACS_SES_CREATE, 0);
	return 0;
}

long pkm_kacs_destroy_empty_logon_session_core(const void *subject_token,
					 u64 auth_id)
{
	long ret;

	ret = pkm_kacs_require_enabled_privilege(subject_token,
						 KACS_SE_TCB_PRIVILEGE);
	if (ret) {
		trace_kacs_logon_session(auth_id, KACS_SES_DESTROY_PRIV_DENIED, ret);
		return ret;
	}

	ret = kacs_rust_destroy_empty_logon_session(auth_id);
	trace_kacs_logon_session(auth_id, KACS_SES_DESTROY, ret);
	return ret;
}

long pkm_kacs_create_token_core(const void *subject_token,
				const u8 *spec, size_t spec_len)
{
	const void *new_token = NULL;
	long fd;
	long ret;

	if (!subject_token || !spec)
		return -EINVAL;

	if (!kacs_rust_token_has_enabled_privilege(
		    subject_token, KACS_SE_CREATE_TOKEN_PRIVILEGE)) {
		trace_kacs_logon_session(0, KACS_SES_CREATE_TOKEN_PRIV_DENIED, -EPERM);
		return -EPERM;
	}

	ret = kacs_rust_create_token(subject_token, spec, spec_len,
				     ktime_get_real_seconds(), &new_token);
	if (ret)
		return ret;
	if (!new_token)
		return -EACCES;

	fd = pkm_kacs_open_token_fd_with_fixed_access(new_token,
						      KACS_TOKEN_ALL_ACCESS);
	kacs_rust_token_drop(new_token);
	if (fd < 0)
		return fd;
	if (!kacs_rust_token_mark_privileges_used(
		    subject_token, KACS_SE_CREATE_TOKEN_PRIVILEGE)) {
		close_fd((unsigned int)fd);
		trace_kacs_logon_session(0, KACS_SES_CREATE_TOKEN_PRIV_DENIED, -EPERM);
		return -EPERM;
	}
	trace_kacs_logon_session(0, KACS_SES_CREATE_TOKEN, fd);
	return fd;
}

SYSCALL_DEFINE2(kacs_create_token, const void __user *, spec, size_t, spec_len)
{
	const void *subject_token;
	u8 *spec_bytes;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;
	if (!spec)
		return -EINVAL;

	spec_bytes = memdup_user(spec, spec_len);
	if (IS_ERR(spec_bytes))
		return PTR_ERR(spec_bytes);

	ret = pkm_kacs_create_token_core(subject_token, spec_bytes, spec_len);
	kfree(spec_bytes);
	return ret;
}

SYSCALL_DEFINE2(kacs_create_logon_session, const void __user *, spec, size_t, spec_len)
{
	const void *subject_token;
	u8 *spec_bytes;
	u64 logon_session_id = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;
	if (!spec)
		return -EINVAL;

	spec_bytes = memdup_user(spec, spec_len);
	if (IS_ERR(spec_bytes))
		return PTR_ERR(spec_bytes);

	ret = pkm_kacs_create_logon_session_core(subject_token, spec_bytes, spec_len,
					   &logon_session_id);
	kfree(spec_bytes);
	if (ret)
		return ret;

	return (long)logon_session_id;
}

SYSCALL_DEFINE1(kacs_destroy_empty_logon_session, u64, auth_id)
{
	const void *subject_token;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	return pkm_kacs_destroy_empty_logon_session_core(subject_token, auth_id);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_create_logon_session_for_subject(const void *subject_token,
					       const u8 *spec, size_t spec_len,
					       u64 *logon_session_id_out)
{
	return pkm_kacs_create_logon_session_core(subject_token, spec, spec_len,
					    logon_session_id_out);
}

long pkm_kacs_kunit_destroy_empty_logon_session_for_subject(
	const void *subject_token, u64 auth_id)
{
	return pkm_kacs_destroy_empty_logon_session_core(subject_token, auth_id);
}

long pkm_kacs_kunit_create_token_for_subject(const void *subject_token,
					     const u8 *spec, size_t spec_len)
{
	return pkm_kacs_create_token_core(subject_token, spec, spec_len);
}
#endif /* CONFIG_SECURITY_PKM_KUNIT */
