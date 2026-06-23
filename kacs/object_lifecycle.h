/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_PKM_KACS_OBJECT_LIFECYCLE_H
#define _SECURITY_PKM_KACS_OBJECT_LIFECYCLE_H

#include <linux/types.h>

struct file;
struct inode;
struct super_block;

int pkm_kacs_inode_alloc_security(struct inode *inode);
int pkm_kacs_file_alloc_security(struct file *file);
void pkm_kacs_file_release(struct file *file);
int pkm_kacs_file_receive(struct file *file);
int pkm_kacs_sb_alloc_security(struct super_block *sb);
void pkm_kacs_sb_free_security(struct super_block *sb);
void pkm_kacs_inode_free_security_rcu(void *inode_security);

bool pkm_kacs_inode_signed_exec_pinned(const struct inode *inode);
int pkm_kacs_mark_signed_exec_pinned_file(const struct file *file);
int pkm_kacs_check_signed_exec_content_mutation_inode(
	const struct inode *inode);
int pkm_kacs_check_signed_exec_content_mutation_file(
	const struct file *file);

#endif /* _SECURITY_PKM_KACS_OBJECT_LIFECYCLE_H */
