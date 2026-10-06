/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_SD_ACCESS_H
#define _SECURITY_PKM_KACS_SD_ACCESS_H

#include <linux/types.h>

struct file;
struct path;
struct pkm_kacs_inode_sd_cache;
struct pkm_kacs_process_state;

/*
 * kacs.audit.descriptor.changed (PKM §3.9): one change to the descriptor of
 * a file, token, process or System V IPC object, by a caller authorised to
 * make it. The view is filled by the set-security path; the digests and PIP
 * state are filled by pkm_kacs_audit_descriptor_changed(). Mirrors
 * PkmKacsSdChangeView in token_runtime.rs field for field.
 */
#define PKM_KACS_SD_CHANGE_FILE 1U
#define PKM_KACS_SD_CHANGE_TOKEN 2U
#define PKM_KACS_SD_CHANGE_PROCESS 3U
#define PKM_KACS_SD_CHANGE_IPC 4U

#define PKM_KACS_SD_CHANGE_IPC_SEM 1U
#define PKM_KACS_SD_CHANGE_IPC_SHM 2U
#define PKM_KACS_SD_CHANGE_IPC_MSG 3U

struct pkm_kacs_sd_change_view {
	const void *subject_token;
	/* The token whose descriptor changed (TOKEN), or NULL. */
	const void *object_token;
	/* The file's absolute path (FILE), when it could be resolved. */
	const u8 *file_path;
	size_t file_path_len;
	/* The process's GUID, KACS_UUID_BYTES long (PROCESS), or NULL. */
	const u8 *process_guid;
	/* The descriptor before the change, when it was a stored one. */
	const u8 *old_sd;
	size_t old_sd_len;
	/* The descriptor written; NULL when the change failed. */
	const u8 *new_sd;
	size_t new_sd_len;
	s64 ipc_id;
	u8 old_digest[32];
	u8 new_digest[32];
	u32 kind;
	u32 ipc_type;
	u32 security_info;
	/* The rights the change needed, and the handle's grant and mask. */
	u32 requested;
	u32 granted;
	u32 audit_mask;
	u32 has_handle;
	u32 pip_type;
	u32 pip_trust;
	s32 err;
};

bool pkm_kacs_descriptor_change_audited(u32 security_info, u32 requested,
					u32 audit_mask);
void pkm_kacs_audit_descriptor_changed(struct pkm_kacs_sd_change_view *chg);

long pkm_kacs_validate_sd_security_info(u32 security_info);
long pkm_kacs_get_sd_required_access(u32 security_info,
				     u32 *desired_access_out);
long pkm_kacs_set_sd_required_access(u32 security_info,
				     u32 *desired_access_out);
long pkm_kacs_path_sd_lookup_flags(u32 flags, unsigned int *lookup_flags_out);

long pkm_kacs_query_file_sd_bytes_core(
	const void *subject_token, const struct pkm_kacs_inode_sd_cache *cache,
	u32 security_info, const void *caap_cache, const u8 **out_sd_ptr,
	size_t *out_sd_len);
long pkm_kacs_prepare_new_file_sd_core(
	const void *subject_token, const struct pkm_kacs_inode_sd_cache *cache,
	u32 security_info, const u8 *input_sd_ptr, size_t input_sd_len,
	bool authorize_live, const void *caap_cache, const u8 **new_sd_ptr,
	size_t *new_sd_len);

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
