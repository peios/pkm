/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_SOURCE_DEVICE_H
#define _SECURITY_PKM_LCS_SOURCE_DEVICE_H

#include <linux/compiler_types.h>
#include <linux/types.h>

#include <pkm/lcs.h>

struct file;

enum pkm_lcs_source_fd_state {
	PKM_LCS_SOURCE_FD_UNREGISTERED = 0,
};

struct pkm_lcs_source_fd {
	enum pkm_lcs_source_fd_state state;
};

struct pkm_lcs_usercopy_ops {
	bool (*read)(void *ctx, void *dst, const void __user *src, size_t len);
	void *ctx;
};

struct pkm_lcs_source_registration_hive_copy {
	char *name;
	u32 name_len;
	u8 root_guid[16];
	u32 flags;
	u8 scope_guid[16];
};

struct pkm_lcs_source_registration_copy {
	u32 hive_count;
	u64 max_sequence;
	struct pkm_lcs_source_registration_hive_copy *hives;
};

long pkm_lcs_source_device_open_for_token(const void *token);
long pkm_lcs_source_device_open_file_for_token(const void *token,
					       struct file *file);
int pkm_lcs_source_device_release_file(struct file *file);
void pkm_lcs_source_registration_copy_destroy(
	struct pkm_lcs_source_registration_copy *registration);
long pkm_lcs_source_registration_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs, u32 max_hives,
	struct pkm_lcs_source_registration_copy *out);

#endif /* _SECURITY_PKM_LCS_SOURCE_DEVICE_H */
