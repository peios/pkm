// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source-device token authority helpers.
 */

#include <linux/errno.h>

#include <pkm/token.h>

#include <trace/events/lcs.h>

#include "../kacs/token_runtime.h"
#include "source_device.h"

long pkm_lcs_source_device_check_tcb(const void *token)
{
	if (!token) {
		trace_lcs_tcb_check(0, 0, 0, -EPERM);
		return -EPERM;
	}
	if (!kacs_rust_token_has_enabled_privilege(token,
						  KACS_SE_TCB_PRIVILEGE)) {
		trace_lcs_tcb_check(0, 0, 0, -EPERM);
		return -EPERM;
	}
	trace_lcs_tcb_check(0, 1, 0, 0);
	return 0;
}

long pkm_lcs_source_device_mark_tcb_used(const void *token)
{
	if (!kacs_rust_token_mark_privileges_used(token,
						 KACS_SE_TCB_PRIVILEGE))
		return -EPERM;

	return 0;
}

bool pkm_lcs_token_has_tcb_or_admin_authority(const void *token)
{
	bool admin;

	if (!token) {
		trace_lcs_tcb_check(0, 0, 0, -EPERM);
		return false;
	}
	if (kacs_rust_token_has_enabled_privilege(token,
						  KACS_SE_TCB_PRIVILEGE)) {
		bool ok = pkm_lcs_source_device_mark_tcb_used(token) == 0;

		trace_lcs_tcb_check(0, 1, 0, ok ? 0 : -EPERM);
		return ok;
	}

	admin = kacs_rust_token_has_enabled_administrators(token);
	trace_lcs_tcb_check(0, 0, admin ? 1 : 0, admin ? 0 : -EPERM);
	return admin;
}
