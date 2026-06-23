/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_SD_ACCESS_H
#define _SECURITY_PKM_KACS_SD_ACCESS_H

#include <linux/types.h>

struct file;
struct path;
struct pkm_kacs_inode_sd_cache;
struct pkm_kacs_process_state;

long pkm_kacs_validate_sd_security_info(u32 security_info);
long pkm_kacs_get_sd_required_access(u32 security_info,
				     u32 *desired_access_out);
long pkm_kacs_set_sd_required_access(u32 security_info,
				     u32 *desired_access_out);
long pkm_kacs_path_sd_lookup_flags(u32 flags, unsigned int *lookup_flags_out);

long pkm_kacs_query_file_sd_bytes_core(
	const void *subject_token, const struct pkm_kacs_inode_sd_cache *cache,
	u32 security_info, const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_prepare_new_file_sd_core(
	const void *subject_token, const struct pkm_kacs_inode_sd_cache *cache,
	u32 security_info, const u8 *input_sd_ptr, size_t input_sd_len,
	bool authorize_live, const u8 **new_sd_ptr, size_t *new_sd_len);

long pkm_kacs_query_token_sd_core(const void *subject_token,
				  const void *target_token,
				  u32 security_info,
				  const u8 **out_sd_ptr,
				  size_t *out_sd_len);
long pkm_kacs_set_token_sd_core(const void *subject_token,
				const void *target_token,
				u32 security_info,
				const u8 *input_sd_ptr,
				size_t input_sd_len);
long pkm_kacs_query_process_sd_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	const struct pkm_kacs_process_state *target_state, bool self_target,
	u32 security_info, const u8 **out_sd_ptr, size_t *out_sd_len);
long pkm_kacs_set_process_sd_core(
	const void *subject_token,
	const struct pkm_kacs_process_state *caller_state,
	struct pkm_kacs_process_state *target_state, bool self_target,
	u32 security_info, const u8 *input_sd_ptr, size_t input_sd_len);
long pkm_kacs_query_file_sd_core(const void *subject_token,
				 struct file *file, u32 security_info,
				 const u8 **out_sd_ptr,
				 size_t *out_sd_len);
long pkm_kacs_set_file_sd_core(const void *subject_token, struct file *file,
			       u32 security_info, const u8 *input_sd_ptr,
			       size_t input_sd_len);
long pkm_kacs_query_path_file_sd_core(const void *subject_token,
				      const struct path *path,
				      u32 security_info,
				      const u8 **out_sd_ptr,
				      size_t *out_sd_len);
long pkm_kacs_set_path_file_sd_core(const void *subject_token,
				    const struct path *path,
				    u32 security_info,
				    const u8 *input_sd_ptr,
				    size_t input_sd_len);

#endif /* _SECURITY_PKM_KACS_SD_ACCESS_H */
