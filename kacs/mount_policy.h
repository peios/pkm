/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_MOUNT_POLICY_H
#define _SECURITY_PKM_KACS_MOUNT_POLICY_H

#include <linux/fs.h>
#include <linux/types.h>

#include <pkm/file.h>

u32 pkm_kacs_mount_policy_for_magic(unsigned long magic);
u32 pkm_kacs_superblock_mount_policy(const struct super_block *sb);
u32 pkm_kacs_superblock_policy_generation(const struct super_block *sb);
bool pkm_kacs_mount_policy_is_managed(u32 mount_policy);
bool pkm_kacs_inode_is_ntfs(const struct inode *inode);
const char *pkm_kacs_inode_sd_xattr_name(const struct inode *inode);
bool pkm_kacs_is_canonical_sd_xattr(const struct inode *inode,
				    const char *name);
long pkm_kacs_copy_mount_policy_args_from_user(
	struct kacs_mount_policy_args *out,
	const struct kacs_mount_policy_args __user *uargs, size_t argsize);
long pkm_kacs_validate_mount_policy_args(
	const struct kacs_mount_policy_args *args);
long pkm_kacs_copy_mount_template_from_user(
	const struct kacs_mount_policy_args *args, const u8 **template_out);
u32 pkm_kacs_next_mount_policy_generation(u32 generation);
long pkm_kacs_set_mount_policy_core(
	const void *subject_token, struct super_block *sb,
	const struct kacs_mount_policy_args *args, const u8 *template_bytes);
long pkm_kacs_get_mount_policy_snapshot(
	const struct super_block *sb, struct kacs_mount_policy_args *snapshot,
	const u8 **template_out);
long pkm_kacs_mount_policy_fd_superblock(int fd, struct file **file_out,
					 struct super_block **sb_out);

#endif /* _SECURITY_PKM_KACS_MOUNT_POLICY_H */
