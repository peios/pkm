/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_NATIVE_OPEN_H
#define _SECURITY_PKM_KACS_NATIVE_OPEN_H

#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/types.h>

#include "lsm_internal.h"

/*
 * kacs_open_how.flags carries two kinds of bit: the lookup flag
 * AT_SYMLINK_NOFOLLOW (0x100), and the privilege intents
 * KACS_BACKUP_INTENT (0x1) / KACS_RESTORE_INTENT (0x2), which FACS
 * passes into every AccessCheck the open performs so that
 * SeBackupPrivilege / SeRestorePrivilege can bypass the DACL (TRM
 * §3.2.3). The intents never reach path lookup.
 */
#define PKM_KACS_OPEN_INTENT_FLAGS (KACS_BACKUP_INTENT | KACS_RESTORE_INTENT)
#define PKM_KACS_OPEN_ALLOWED_AT_FLAGS                                        \
	(AT_SYMLINK_NOFOLLOW | PKM_KACS_OPEN_INTENT_FLAGS)
#define PKM_KACS_DIRECTORY_MUTATION_RIGHTS                                 \
	(KACS_FILE_WRITE_DATA | KACS_FILE_APPEND_DATA | KACS_FILE_DELETE_CHILD)

struct kacs_open_how;

u64 pkm_kacs_next_native_supersede_tmp_id(void);

long pkm_kacs_prepare_native_open(
	const struct kacs_open_how *how,
	struct pkm_kacs_native_open_prepared *prepared);
bool pkm_kacs_file_delete_on_close_pending(const struct file *file);
long pkm_kacs_maybe_arm_delete_on_close_for_subject(
	const void *subject_token, struct file *file, u32 create_options);
bool pkm_kacs_native_open_request_matches(struct file *file,
					  u32 *desired_access_out,
					  u32 *create_options_out,
					  u32 *privilege_intent_out);

void pkm_kacs_set_current_native_open_request(
	const struct path *path, u32 desired_access, u32 create_options,
	u32 privilege_intent);
void pkm_kacs_clear_current_native_open_request(void);
void pkm_kacs_set_current_native_create_request(
	const struct inode *parent_inode, bool directory, const u8 *sd_bytes,
	size_t sd_len);
void pkm_kacs_clear_current_native_create_request(void);
bool pkm_kacs_current_native_create_request_matches(
	const struct inode *parent_inode, bool directory,
	const u8 **sd_bytes_out, size_t *sd_len_out);

umode_t pkm_kacs_native_create_mode(bool directory);
bool pkm_kacs_special_node_mode_supported(umode_t mode);
bool pkm_kacs_existing_file_object_mode_supported(umode_t mode);

long pkm_kacs_build_created_file_sd_for_subject(
	const void *subject_token, struct file *parent_file,
	const u8 *creator_sd_ptr, size_t creator_sd_len, bool directory,
	u32 desired_access, u32 privilege_intent, const u8 **out_sd_ptr,
	size_t *out_sd_len, u32 *granted_access_out);
long pkm_kacs_do_native_supersede_open(
	const void *subject_token, const struct path *resolved_path,
	const struct kacs_open_how *how,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out);
long pkm_kacs_do_native_overwrite_open(
	const struct path *resolved_path,
	const struct pkm_kacs_native_open_prepared *prepared,
	struct file **file_out, u32 *status_out);

#endif /* _SECURITY_PKM_KACS_NATIVE_OPEN_H */
