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

struct pkm_lcs_rsi_lookup_response_summary {
	u32 path_entry_count;
	u32 metadata_count;
	bool child_absent;
	u8 _pad[3];
};

long pkm_lcs_rsi_build_lookup_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE], const char *child_name,
	u32 child_name_len, struct pkm_lcs_rsi_built_request *built);
long pkm_lcs_rsi_validate_lookup_response(
	const u8 *frame, size_t frame_len, u64 request_id,
	u64 next_sequence,
	struct pkm_lcs_rsi_lookup_response_summary *summary);

#endif /* _SECURITY_PKM_LCS_RSI_H */
