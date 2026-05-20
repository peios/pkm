// SPDX-License-Identifier: GPL-2.0-only

#include <linux/errno.h>
#include <linux/string.h>

#include "rsi.h"

extern int lcs_rust_write_rsi_lookup_request_frame(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 *parent_guid, const u8 *child_name, u32 child_name_len,
	struct pkm_lcs_rsi_built_request *built);

long pkm_lcs_rsi_build_lookup_request(
	u8 *dst, size_t dst_len, u64 request_id, u64 txn_id,
	const u8 parent_guid[RSI_GUID_SIZE], const char *child_name,
	u32 child_name_len, struct pkm_lcs_rsi_built_request *built)
{
	if (!built)
		return -EINVAL;

	memset(built, 0, sizeof(*built));
	if (!dst || !parent_guid || !child_name)
		return -EINVAL;

	return lcs_rust_write_rsi_lookup_request_frame(
		dst, dst_len, request_id, txn_id, parent_guid,
		(const u8 *)child_name, child_name_len, built);
}
