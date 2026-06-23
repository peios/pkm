// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source protocol response planning.
 */

#include <linux/errno.h>
#include <linux/string.h>

#include "rsi.h"
#include "source_device.h"

bool pkm_lcs_rsi_status_known(u32 status)
{
	switch (status) {
	case RSI_OK:
	case RSI_NOT_FOUND:
	case RSI_ALREADY_EXISTS:
	case RSI_STORAGE_ERROR:
	case RSI_NOT_EMPTY:
	case RSI_TOO_LARGE:
	case RSI_TXN_BUSY:
	case RSI_INVALID:
	case RSI_CAS_FAILED:
	case RSI_TXN_NOT_SUPPORTED:
		return true;
	default:
		return false;
	}
}

long pkm_lcs_rsi_status_errno(u32 status)
{
	switch (status) {
	case RSI_OK:
		return 0;
	case RSI_NOT_FOUND:
		return -ENOENT;
	case RSI_ALREADY_EXISTS:
		return -EEXIST;
	case RSI_STORAGE_ERROR:
		return -EIO;
	case RSI_NOT_EMPTY:
		return -ENOTEMPTY;
	case RSI_TOO_LARGE:
		return -ENOSPC;
	case RSI_TXN_BUSY:
		return -EBUSY;
	case RSI_INVALID:
		return -EINVAL;
	case RSI_CAS_FAILED:
		return -EAGAIN;
	case RSI_TXN_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	default:
		return -EIO;
	}
}

long pkm_lcs_reg_create_key_source_response_plan(
	u16 request_op_code, u32 status,
	struct pkm_lcs_reg_create_source_response_plan *plan)
{
	if (!plan)
		return -EINVAL;

	memset(plan, 0, sizeof(*plan));
	if (!pkm_lcs_rsi_status_known(status))
		return -EIO;

	switch (request_op_code) {
	case RSI_CREATE_ENTRY:
		if (status == RSI_OK) {
			plan->action = PKM_LCS_REG_CREATE_SOURCE_ACTION_CREATE_KEY;
			return 0;
		}
		if (status == RSI_ALREADY_EXISTS) {
			plan->action =
				PKM_LCS_REG_CREATE_SOURCE_ACTION_RETRY_OPEN_EXISTING;
			plan->disposition = REG_OPENED_EXISTING;
			return 0;
		}
		return pkm_lcs_rsi_status_errno(status);

	case RSI_CREATE_KEY:
		if (status == RSI_OK) {
			plan->action =
				PKM_LCS_REG_CREATE_SOURCE_ACTION_PUBLISH_CREATED_NEW;
			plan->disposition = REG_CREATED_NEW;
			return 0;
		}
		if (status == RSI_ALREADY_EXISTS)
			return -EIO;
		return pkm_lcs_rsi_status_errno(status);

	default:
		return -EINVAL;
	}
}
