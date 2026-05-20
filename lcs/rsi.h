/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_RSI_H
#define _SECURITY_PKM_LCS_RSI_H

#include <linux/types.h>

#include <pkm/lcs.h>

struct pkm_lcs_rsi_built_request {
	size_t len;
	u64 request_id;
	u64 txn_id;
	u16 op_code;
	u8 _pad[6];
};

long pkm_lcs_rsi_build_lookup_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE], const char *child_name,
	u32 child_name_len, struct pkm_lcs_rsi_built_request *built);

#endif /* _SECURITY_PKM_LCS_RSI_H */
