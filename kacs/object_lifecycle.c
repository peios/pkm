// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include "lsm_internal.h"
#include "object_lifecycle.h"

int pkm_kacs_inode_alloc_security(struct inode *inode)
{
	struct pkm_kacs_inode_security *sec;

	if (!inode || !inode->i_security)
		return -EINVAL;

	sec = pkm_kacs_inode(inode);
	mutex_init(&sec->lock);
	RCU_INIT_POINTER(sec->sd_cache, NULL);
	atomic_set(&sec->delete_on_close_lineages, 0);
	atomic_set(&sec->signed_exec_pinned, 0);
	sec->persist_work_queued = false;
#ifdef CONFIG_SECURITY_PKM_KUNIT
	sec->kunit_fake_xattr_enabled = false;
	sec->kunit_fake_xattr_bytes = NULL;
	sec->kunit_fake_xattr_len = 0;
	sec->kunit_unlink_calls = 0;
#endif
	return 0;
}

int pkm_kacs_file_alloc_security(struct file *file)
{
	struct pkm_kacs_file_security *sec;

	if (!file || !file->f_security)
		return 0;

	sec = pkm_kacs_file(file);
	sec->granted_access = 0;
	sec->continuous_audit_mask = 0;
	sec->managed = 0;
	sec->delete_on_close = 0;
	return 0;
}

void pkm_kacs_file_release(struct file *file)
{
	struct pkm_kacs_file_security *file_sec;
	struct pkm_kacs_inode_security *inode_sec;
	struct inode *inode;
	long ret;

	if (!file || !file->f_security)
		return;

	file_sec = pkm_kacs_file(file);
	if (!file_sec->delete_on_close)
		return;

	inode = file_inode(file);
	if (!inode || !inode->i_security)
		return;

	inode_sec = pkm_kacs_inode(inode);
	ret = pkm_kacs_unlink_delete_on_close_file(file);
	if (ret && ret != -ENOENT)
		pr_warn("pkm: delete-on-close unlink failed (%ld)\n", ret);

	mutex_lock(&inode_sec->lock);
	if (atomic_read(&inode_sec->delete_on_close_lineages) > 0)
		atomic_dec(&inode_sec->delete_on_close_lineages);
	file_sec->delete_on_close = 0;
	mutex_unlock(&inode_sec->lock);
}

int pkm_kacs_file_receive(struct file *file)
{
	/*
	 * SCM_RIGHTS transfers an already-open handle. KACS keeps the original
	 * cached grant on the file security blob rather than re-authorizing the
	 * receiver as a fresh open.
	 */
	(void)file;
	return 0;
}

int pkm_kacs_sb_alloc_security(struct super_block *sb)
{
	struct pkm_kacs_superblock_security *sec;

	if (!sb || !sb->s_security)
		return 0;

	sec = pkm_kacs_sb(sb);
	mutex_init(&sec->lock);
	/*
	 * security_sb_alloc fires in alloc_super() BEFORE the filesystem
	 * type's fill_super/init_fs_context callback sets s_magic. We cannot
	 * resolve the magic-derived policy here - s_magic is always zero at
	 * this point. Leave mount_policy at the invalid sentinel 0 and let
	 * superblock_mount_policy() lazy-resolve + lazy-cache on the first
	 * read that observes a populated magic. Explicit kacs_set_mount_policy()
	 * syscalls still write a valid value here and short-circuit the
	 * lazy path.
	 */
	sec->mount_policy = 0;
	sec->policy_generation = 0;
	sec->template_sd_bytes = NULL;
	sec->template_sd_len = 0;
	return 0;
}

void pkm_kacs_sb_free_security(struct super_block *sb)
{
	struct pkm_kacs_superblock_security *sec;

	if (!sb || !sb->s_security)
		return;

	sec = pkm_kacs_sb(sb);
	mutex_lock(&sec->lock);
	if (sec->template_sd_bytes)
		pkm_kacs_free((void *)sec->template_sd_bytes);
	sec->template_sd_bytes = NULL;
	sec->template_sd_len = 0;
	mutex_unlock(&sec->lock);
	mutex_destroy(&sec->lock);
}

void pkm_kacs_inode_free_security_rcu(void *inode_security)
{
	struct pkm_kacs_inode_security *sec;
	struct pkm_kacs_inode_sd_cache *cache;

	if (!inode_security)
		return;

	sec = (struct pkm_kacs_inode_security *)((char *)inode_security +
						 pkm_blob_sizes.lbs_inode);
	cache = rcu_dereference_protected(sec->sd_cache, 1);
	RCU_INIT_POINTER(sec->sd_cache, NULL);
	atomic_set(&sec->delete_on_close_lineages, 0);
	atomic_set(&sec->signed_exec_pinned, 0);
	pkm_kacs_inode_sd_cache_free(cache);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (sec->kunit_fake_xattr_bytes)
		kfree(sec->kunit_fake_xattr_bytes);
	sec->kunit_fake_xattr_bytes = NULL;
	sec->kunit_fake_xattr_len = 0;
	sec->kunit_fake_xattr_enabled = false;
	sec->kunit_unlink_calls = 0;
#endif
}

bool pkm_kacs_inode_signed_exec_pinned(const struct inode *inode)
{
	struct pkm_kacs_inode_security *sec;

	if (!inode || !inode->i_security)
		return false;

	sec = pkm_kacs_inode((struct inode *)inode);
	return atomic_read(&sec->signed_exec_pinned) != 0;
}

int pkm_kacs_mark_signed_exec_pinned_file(const struct file *file)
{
	struct inode *inode;
	struct pkm_kacs_inode_security *sec;

	if (!file)
		return -EACCES;

	inode = file_inode((struct file *)file);
	if (!inode || !inode->i_security)
		return -EACCES;

	sec = pkm_kacs_inode(inode);
	atomic_set(&sec->signed_exec_pinned, 1);
	return 0;
}

int pkm_kacs_check_signed_exec_content_mutation_inode(const struct inode *inode)
{
	return pkm_kacs_inode_signed_exec_pinned(inode) ? -EACCES : 0;
}

int pkm_kacs_check_signed_exec_content_mutation_file(const struct file *file)
{
	if (!file)
		return -EACCES;

	return pkm_kacs_check_signed_exec_content_mutation_inode(
		file_inode((struct file *)file));
}
