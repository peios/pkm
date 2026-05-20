/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_KEY_FD_H
#define _SECURITY_PKM_LCS_KEY_FD_H

#include <linux/types.h>

#define PKM_LCS_GUID_BYTES 16U
#define PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES 32U

struct pkm_lcs_key_fd_publish_input {
	u32 source_id;
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u32 granted_access;
	const char * const *resolved_path;
	const u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
	u32 path_component_count;
};

struct pkm_lcs_key_fd_snapshot {
	u32 source_id;
	u32 granted_access;
	u32 path_component_count;
	u32 first_component_len;
	u32 last_component_len;
	bool orphaned;
	bool watch_armed;
	u8 _pad[2];
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u8 first_ancestor_guid[PKM_LCS_GUID_BYTES];
	u8 last_ancestor_guid[PKM_LCS_GUID_BYTES];
	char first_component[PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES];
	char last_component[PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES];
};

long pkm_lcs_key_fd_publish(const struct pkm_lcs_key_fd_publish_input *input);
long pkm_lcs_key_fd_snapshot(int fd, struct pkm_lcs_key_fd_snapshot *out);

#endif /* _SECURITY_PKM_LCS_KEY_FD_H */
