/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_LCS_SOURCE_DEVICE_H
#define _SECURITY_PKM_LCS_SOURCE_DEVICE_H

struct file;

enum pkm_lcs_source_fd_state {
	PKM_LCS_SOURCE_FD_UNREGISTERED = 0,
};

struct pkm_lcs_source_fd {
	enum pkm_lcs_source_fd_state state;
};

long pkm_lcs_source_device_open_for_token(const void *token);
long pkm_lcs_source_device_open_file_for_token(const void *token,
					       struct file *file);
int pkm_lcs_source_device_release_file(struct file *file);

#endif /* _SECURITY_PKM_LCS_SOURCE_DEVICE_H */
