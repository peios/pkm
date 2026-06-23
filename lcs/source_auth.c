// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source-device token authority helpers.
 */

#include <linux/errno.h>

#include <pkm/token.h>

#include "../kacs/token_runtime.h"
#include "source_device.h"

long pkm_lcs_source_device_check_tcb(const void *token)
{
	if (!token)
		return -EPERM;
	if (!kacs_rust_token_has_enabled_privilege(token,
						  KACS_SE_TCB_PRIVILEGE))
		return -EPERM;
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
	if (!token)
		return false;
	if (kacs_rust_token_has_enabled_privilege(token, KACS_SE_TCB_PRIVILEGE))
		return pkm_lcs_source_device_mark_tcb_used(token) == 0;

	return kacs_rust_token_has_enabled_administrators(token);
}
