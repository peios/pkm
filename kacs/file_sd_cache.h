/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_FILE_SD_CACHE_H
#define _SECURITY_PKM_KACS_FILE_SD_CACHE_H

#include <linux/types.h>

struct file;
struct dentry;
struct inode;
struct pkm_kacs_inode_security;
struct pkm_kacs_inode_sd_cache;
struct super_block;

struct pkm_kacs_inode_sd_cache *pkm_kacs_inode_sd_cache_alloc(
	u8 state, const u8 *bytes, size_t len);
struct pkm_kacs_inode_sd_cache *pkm_kacs_inode_sd_cache_alloc_ex(
	u8 state, const u8 *bytes, size_t len, u8 source,
	u32 policy_generation);
bool pkm_kacs_inode_sd_cache_current(
	const struct super_block *sb,
	const struct pkm_kacs_inode_sd_cache *cache);
bool pkm_kacs_inode_try_publish_sd_cache(
	struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache *expected,
	struct pkm_kacs_inode_sd_cache *new_cache);
long pkm_kacs_missing_file_sd_policy_result(
	const struct super_block *sb,
	struct pkm_kacs_inode_sd_cache **cache_out);
long pkm_kacs_inode_resolve_effective_cache_locked(
	struct file *file, struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache **cache_out, unsigned int depth);
long pkm_kacs_inode_ensure_effective_cache(
	struct file *file, struct pkm_kacs_inode_security *sec);
long pkm_kacs_inode_ensure_effective_cache_by_inode(
	struct inode *inode, struct pkm_kacs_inode_security *sec);
void pkm_kacs_inode_replace_sd_cache_locked(
	struct pkm_kacs_inode_security *sec,
	struct pkm_kacs_inode_sd_cache *new_cache);
long pkm_kacs_inode_write_sd_xattr_locked(struct file *file,
					  const u8 *sd_bytes, size_t sd_len);
void pkm_kacs_inode_run_sd_persist(
	struct dentry *dentry, struct inode *inode,
	struct pkm_kacs_inode_security *sec);

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_fake_setxattr_locked(
	struct pkm_kacs_inode_security *sec, const u8 *sd_bytes, size_t sd_len);
#endif

#endif /* _SECURITY_PKM_KACS_FILE_SD_CACHE_H */
