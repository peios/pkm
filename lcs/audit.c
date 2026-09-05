// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS audit event emitters.
 */

#include <linux/errno.h>
#include <linux/jhash.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <pkm/lcs.h>

#include <trace/events/lcs.h>

#include "../kacs/token_runtime.h"
#include "../kmes/kmes.h"
#include "source_device.h"

/*
 * Hash a 16-byte key GUID to a u64 for the lcs: tracepoints. The tracepoints
 * never record raw GUID bytes; the lcs_access / lcs_audit event probes call
 * this from TP_fast_assign (compiled in the CREATE_TRACE_POINTS TU). Returns 0
 * for a NULL GUID (the "no guid in scope" sentinel). Non-static so the probe
 * bodies resolve it at link time.
 */
u64 pkm_lcs_trace_guid_hash(const u8 *guid)
{
	if (!guid)
		return 0;
	return jhash(guid, 16, 0);
}

#define PKM_LCS_SACL_MATCH_SUCCESS 0x1U
#define PKM_LCS_SACL_MATCH_FAILURE 0x2U

static const char pkm_lcs_key_open_audit_event_type[] =
	"LCS_KEY_OPEN_AUDIT";
static const char pkm_lcs_backup_start_event_type[] =
	"LCS_BACKUP_START";
static const char pkm_lcs_backup_complete_event_type[] =
	"LCS_BACKUP_COMPLETE";
static const char pkm_lcs_restore_start_event_type[] =
	"LCS_RESTORE_START";
static const char pkm_lcs_restore_complete_event_type[] =
	"LCS_RESTORE_COMPLETE";
static const char pkm_lcs_source_validation_failure_event_type[] =
	"LCS_SOURCE_VALIDATION_FAILURE";
static const char pkm_lcs_self_config_invalid_event_type[] =
	"LCS_SELF_CONFIG_INVALID";

struct pkm_lcs_audit_caller_summary {
	u8 effective_token_guid[16];
	u8 true_token_guid[16];
	u8 process_guid[16];
	const u8 *user_sid;
	size_t user_sid_len;
	u64 authentication_id;
	u64 token_id;
	u32 token_type;
	u32 impersonation_level;
	u32 integrity_level;
};

extern int lcs_rust_key_open_audit_payload(
	const struct pkm_lcs_audit_caller_summary *caller,
	const u8 key_guid[16], u32 requested_access, u32 granted_access,
	u8 allowed, u32 sacl_match_flags, u8 *output, size_t output_len,
	size_t *written_out);
extern int lcs_rust_backup_start_audit_payload(
	const struct pkm_lcs_audit_caller_summary *caller,
	const u8 key_guid[16], s32 output_fd, u8 *output, size_t output_len,
	size_t *written_out);
extern int lcs_rust_backup_complete_audit_payload(
	const struct pkm_lcs_audit_caller_summary *caller,
	const u8 key_guid[16], u32 result_errno, u8 *output,
	size_t output_len, size_t *written_out);
extern int lcs_rust_restore_start_audit_payload(
	const struct pkm_lcs_audit_caller_summary *caller,
	const u8 key_guid[16], s32 input_fd, u8 *output, size_t output_len,
	size_t *written_out);
extern int lcs_rust_restore_complete_audit_payload(
	const struct pkm_lcs_audit_caller_summary *caller,
	const u8 key_guid[16], u32 result_errno, u8 *output,
	size_t output_len, size_t *written_out);
extern int lcs_rust_source_validation_failure_audit_payload(
	u32 source_slot, const u8 *hive_name, size_t hive_name_len,
	u8 hive_name_present, u64 request_id, u8 request_id_present,
	u16 op_code, u8 op_code_present, const u8 key_guid[16],
	u8 key_guid_present, u32 validation_failure, u8 *output,
	size_t output_len, size_t *written_out);
extern int lcs_rust_self_config_invalid_audit_payload(
	const u8 *configuration_name, size_t configuration_name_len,
	u32 received_kind, u32 received_type, u32 received_u32,
	u32 retained_value, u8 *output, size_t output_len,
	size_t *written_out);

static long pkm_lcs_build_audit_caller_summary(
	const void *token, struct pkm_lcs_audit_caller_summary *caller)
{
	struct pkm_kacs_token_audit_summary token_summary = { };
	kacs_uuid_t true_token_guid;
	kacs_uuid_t process_guid;
	int ret;

	if (!token || !caller)
		return -EIO;

	memset(caller, 0, sizeof(*caller));
	ret = kacs_rust_token_audit_summary(token, &token_summary);
	if (ret)
		return -EIO;

	true_token_guid = kacs_primary_token_guid();
	process_guid = kacs_process_guid();

	memcpy(caller->effective_token_guid, token_summary.token_guid,
	       sizeof(caller->effective_token_guid));
	memcpy(caller->true_token_guid, true_token_guid.bytes,
	       sizeof(caller->true_token_guid));
	memcpy(caller->process_guid, process_guid.bytes,
	       sizeof(caller->process_guid));
	caller->user_sid = token_summary.user_sid_ptr;
	caller->user_sid_len = token_summary.user_sid_len;
	caller->authentication_id = token_summary.auth_id;
	caller->token_id = token_summary.token_id;
	caller->token_type = token_summary.token_type;
	caller->impersonation_level = token_summary.impersonation_level;
	caller->integrity_level = token_summary.integrity_level;
	return 0;
}

long pkm_lcs_emit_key_open_audit_for_token(
	const void *token, const u8 key_guid[16],
	const struct pkm_lcs_key_open_access_plan *plan)
{
	struct pkm_lcs_audit_caller_summary caller = { };
	size_t payload_len = 0;
	size_t written = 0;
	u32 sacl_match_flags;
	u32 requested_access;
	u32 granted_access;
	u8 *payload;
	long ret;

	if (!token || !key_guid || !plan)
		return -EINVAL;
	if (!plan->key_open_sacl_audit_required)
		return 0;

	ret = pkm_lcs_build_audit_caller_summary(token, &caller);
	if (ret)
		return ret;

	sacl_match_flags = plan->allowed ? PKM_LCS_SACL_MATCH_SUCCESS :
					   PKM_LCS_SACL_MATCH_FAILURE;
	requested_access = plan->mapped_desired_access;
	if (plan->maximum_allowed)
		requested_access |= MAXIMUM_ALLOWED;
	granted_access = plan->allowed ? plan->fd_granted_access : 0U;

	ret = lcs_rust_key_open_audit_payload(
		&caller, key_guid, requested_access, granted_access,
		plan->allowed ? 1U : 0U, sacl_match_flags, NULL, 0,
		&payload_len);
	if (ret)
		return -EIO;
	if (!payload_len || payload_len > U32_MAX)
		return -EIO;

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload)
		return -EIO;

	ret = lcs_rust_key_open_audit_payload(
		&caller, key_guid, requested_access, granted_access,
		plan->allowed ? 1U : 0U, sacl_match_flags, payload,
		payload_len, &written);
	if (ret || written != payload_len) {
		kfree(payload);
		trace_lcs_audit_emit_failed(LCS_AUDIT_KEY_OPEN, key_guid, 0,
					    plan->allowed ? 1U : 0U, -EIO);
		return -EIO;
	}

	pkm_kmes_emit_kernel(KMES_ORIGIN_LCS, pkm_lcs_key_open_audit_event_type,
			     sizeof(pkm_lcs_key_open_audit_event_type) - 1,
			     payload, written);
	trace_lcs_audit_emit(LCS_AUDIT_KEY_OPEN, key_guid, 0,
			     plan->allowed ? 1U : 0U, 0);
	kfree(payload);
	return 0;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
/* Fails the next backup/restore START emission, as a KMES outage would. */
static bool pkm_lcs_kunit_start_audit_fail_next;

void pkm_lcs_kunit_fail_next_start_audit(void)
{
	WRITE_ONCE(pkm_lcs_kunit_start_audit_fail_next, true);
}

static bool pkm_lcs_kunit_start_audit_should_fail(void)
{
	if (!READ_ONCE(pkm_lcs_kunit_start_audit_fail_next))
		return false;
	WRITE_ONCE(pkm_lcs_kunit_start_audit_fail_next, false);
	return true;
}
#else
static inline bool pkm_lcs_kunit_start_audit_should_fail(void)
{
	return false;
}
#endif

long pkm_lcs_emit_backup_start_audit_for_token(
	const void *token, const u8 key_guid[16], int output_fd)
{
	struct pkm_lcs_audit_caller_summary caller = { };
	size_t payload_len = 0;
	size_t written = 0;
	u8 *payload;
	long ret;

	if (!token || !key_guid)
		return -EINVAL;
	if (pkm_lcs_kunit_start_audit_should_fail())
		return -EIO;

	ret = pkm_lcs_build_audit_caller_summary(token, &caller);
	if (ret)
		return ret;

	ret = lcs_rust_backup_start_audit_payload(
		&caller, key_guid, output_fd, NULL, 0, &payload_len);
	if (ret)
		return -EIO;
	if (!payload_len || payload_len > U32_MAX)
		return -EIO;

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload)
		return -EIO;

	ret = lcs_rust_backup_start_audit_payload(
		&caller, key_guid, output_fd, payload, payload_len, &written);
	if (ret || written != payload_len) {
		kfree(payload);
		trace_lcs_audit_emit_failed(LCS_AUDIT_BACKUP_START, key_guid, 0,
					    0, -EIO);
		return -EIO;
	}

	pkm_kmes_emit_kernel(KMES_ORIGIN_LCS, pkm_lcs_backup_start_event_type,
			     sizeof(pkm_lcs_backup_start_event_type) - 1,
			     payload, written);
	trace_lcs_audit_emit(LCS_AUDIT_BACKUP_START, key_guid, 0, 0, 0);
	kfree(payload);
	return 0;
}

long pkm_lcs_emit_backup_complete_audit_for_token(
	const void *token, const u8 key_guid[16], u32 result_errno)
{
	struct pkm_lcs_audit_caller_summary caller = { };
	size_t payload_len = 0;
	size_t written = 0;
	u8 *payload;
	long ret;

	if (!token || !key_guid)
		return -EINVAL;

	ret = pkm_lcs_build_audit_caller_summary(token, &caller);
	if (ret)
		return ret;

	ret = lcs_rust_backup_complete_audit_payload(
		&caller, key_guid, result_errno, NULL, 0, &payload_len);
	if (ret)
		return -EIO;
	if (!payload_len || payload_len > U32_MAX)
		return -EIO;

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload)
		return -EIO;

	ret = lcs_rust_backup_complete_audit_payload(
		&caller, key_guid, result_errno, payload, payload_len,
		&written);
	if (ret || written != payload_len) {
		kfree(payload);
		trace_lcs_audit_emit_failed(LCS_AUDIT_BACKUP_COMPLETE, key_guid,
					    result_errno, 0, -EIO);
		return -EIO;
	}

	pkm_kmes_emit_kernel(KMES_ORIGIN_LCS,
			     pkm_lcs_backup_complete_event_type,
			     sizeof(pkm_lcs_backup_complete_event_type) - 1,
			     payload, written);
	trace_lcs_audit_emit(LCS_AUDIT_BACKUP_COMPLETE, key_guid, result_errno,
			     0, 0);
	kfree(payload);
	return 0;
}

long pkm_lcs_emit_restore_start_audit_for_token(
	const void *token, const u8 key_guid[16], int input_fd)
{
	struct pkm_lcs_audit_caller_summary caller = { };
	size_t payload_len = 0;
	size_t written = 0;
	u8 *payload;
	long ret;

	if (!token || !key_guid)
		return -EINVAL;
	if (pkm_lcs_kunit_start_audit_should_fail())
		return -EIO;

	ret = pkm_lcs_build_audit_caller_summary(token, &caller);
	if (ret)
		return ret;

	ret = lcs_rust_restore_start_audit_payload(
		&caller, key_guid, input_fd, NULL, 0, &payload_len);
	if (ret)
		return -EIO;
	if (!payload_len || payload_len > U32_MAX)
		return -EIO;

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload)
		return -EIO;

	ret = lcs_rust_restore_start_audit_payload(
		&caller, key_guid, input_fd, payload, payload_len, &written);
	if (ret || written != payload_len) {
		kfree(payload);
		trace_lcs_audit_emit_failed(LCS_AUDIT_RESTORE_START, key_guid, 0,
					    0, -EIO);
		return -EIO;
	}

	pkm_kmes_emit_kernel(KMES_ORIGIN_LCS, pkm_lcs_restore_start_event_type,
			     sizeof(pkm_lcs_restore_start_event_type) - 1,
			     payload, written);
	trace_lcs_audit_emit(LCS_AUDIT_RESTORE_START, key_guid, 0, 0, 0);
	kfree(payload);
	return 0;
}

long pkm_lcs_emit_restore_complete_audit_for_token(
	const void *token, const u8 key_guid[16], u32 result_errno)
{
	struct pkm_lcs_audit_caller_summary caller = { };
	size_t payload_len = 0;
	size_t written = 0;
	u8 *payload;
	long ret;

	if (!token || !key_guid)
		return -EINVAL;

	ret = pkm_lcs_build_audit_caller_summary(token, &caller);
	if (ret)
		return ret;

	ret = lcs_rust_restore_complete_audit_payload(
		&caller, key_guid, result_errno, NULL, 0, &payload_len);
	if (ret)
		return -EIO;
	if (!payload_len || payload_len > U32_MAX)
		return -EIO;

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload)
		return -EIO;

	ret = lcs_rust_restore_complete_audit_payload(
		&caller, key_guid, result_errno, payload, payload_len,
		&written);
	if (ret || written != payload_len) {
		kfree(payload);
		trace_lcs_audit_emit_failed(LCS_AUDIT_RESTORE_COMPLETE, key_guid,
					    result_errno, 0, -EIO);
		return -EIO;
	}

	pkm_kmes_emit_kernel(KMES_ORIGIN_LCS,
			     pkm_lcs_restore_complete_event_type,
			     sizeof(pkm_lcs_restore_complete_event_type) - 1,
			     payload, written);
	trace_lcs_audit_emit(LCS_AUDIT_RESTORE_COMPLETE, key_guid, result_errno,
			     0, 0);
	kfree(payload);
	return 0;
}

long pkm_lcs_emit_source_validation_failure_audit(
	u32 source_id, const char *hive_name, u32 hive_name_len,
	bool hive_name_present, u64 request_id, bool request_id_present,
	u16 op_code, bool op_code_present, const u8 key_guid[16],
	bool key_guid_present, u32 validation_failure)
{
	size_t payload_len = 0;
	size_t written = 0;
	u8 *payload;
	int ret;

	if (!source_id)
		return -EINVAL;
	if (hive_name_present && (!hive_name || !hive_name_len))
		return -EINVAL;
	if (!hive_name_present && (hive_name || hive_name_len))
		return -EINVAL;
	if (key_guid_present && !key_guid)
		return -EINVAL;

	ret = lcs_rust_source_validation_failure_audit_payload(
		source_id, (const u8 *)hive_name, hive_name_len,
		hive_name_present ? 1U : 0U, request_id,
		request_id_present ? 1U : 0U, op_code,
		op_code_present ? 1U : 0U, key_guid,
		key_guid_present ? 1U : 0U, validation_failure, NULL, 0,
		&payload_len);
	if (ret)
		return -EIO;
	if (!payload_len || payload_len > U32_MAX)
		return -EIO;

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload)
		return -EIO;

	ret = lcs_rust_source_validation_failure_audit_payload(
		source_id, (const u8 *)hive_name, hive_name_len,
		hive_name_present ? 1U : 0U, request_id,
		request_id_present ? 1U : 0U, op_code,
		op_code_present ? 1U : 0U, key_guid,
		key_guid_present ? 1U : 0U, validation_failure, payload,
		payload_len, &written);
	if (ret || written != payload_len) {
		kfree(payload);
		trace_lcs_audit_emit_failed(LCS_AUDIT_VALIDATION_FAILURE,
					    key_guid_present ? key_guid : NULL,
					    validation_failure, 0, -EIO);
		return -EIO;
	}

	pkm_kmes_emit_kernel(
		KMES_ORIGIN_LCS, pkm_lcs_source_validation_failure_event_type,
		sizeof(pkm_lcs_source_validation_failure_event_type) - 1,
		payload, written);
	trace_lcs_audit_emit(LCS_AUDIT_VALIDATION_FAILURE,
			     key_guid_present ? key_guid : NULL,
			     validation_failure, 0, 0);
	kfree(payload);
	return 0;
}

long pkm_lcs_emit_self_config_invalid_audit(
	const char *configuration_name, u32 configuration_name_len,
	u32 received_kind, u32 received_type, u32 received_u32,
	u32 retained_value)
{
	size_t payload_len = 0;
	size_t written = 0;
	u8 *payload;
	int ret;

	if (!configuration_name || !configuration_name_len)
		return -EINVAL;
	switch (received_kind) {
	case PKM_LCS_SELF_CONFIG_RECEIVED_MISSING:
		if (received_type || received_u32)
			return -EINVAL;
		break;
	case PKM_LCS_SELF_CONFIG_RECEIVED_WRONG_TYPE:
		if (received_type == REG_DWORD || received_u32)
			return -EINVAL;
		break;
	case PKM_LCS_SELF_CONFIG_RECEIVED_DWORD_OUT_OF_RANGE:
		if (received_type)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	ret = lcs_rust_self_config_invalid_audit_payload(
		(const u8 *)configuration_name, configuration_name_len,
		received_kind, received_type, received_u32, retained_value,
		NULL, 0, &payload_len);
	if (ret)
		return ret == -EINVAL ? -EINVAL : -EIO;
	if (!payload_len || payload_len > U32_MAX)
		return -EIO;

	payload = kmalloc(payload_len, GFP_KERNEL);
	if (!payload)
		return -EIO;

	ret = lcs_rust_self_config_invalid_audit_payload(
		(const u8 *)configuration_name, configuration_name_len,
		received_kind, received_type, received_u32, retained_value,
		payload, payload_len, &written);
	if (ret || written != payload_len) {
		kfree(payload);
		trace_lcs_audit_emit_failed(LCS_AUDIT_SELF_CONFIG_INVALID, NULL,
					    received_kind, 0,
					    ret == -EINVAL ? -EINVAL : -EIO);
		return ret == -EINVAL ? -EINVAL : -EIO;
	}

	pkm_kmes_emit_kernel(KMES_ORIGIN_LCS,
			     pkm_lcs_self_config_invalid_event_type,
			     sizeof(pkm_lcs_self_config_invalid_event_type) - 1,
			     payload, written);
	trace_lcs_audit_emit(LCS_AUDIT_SELF_CONFIG_INVALID, NULL,
			     received_kind, 0, 0);
	kfree(payload);
	return 0;
}
