// SPDX-License-Identifier: GPL-2.0-only
/*
 * PKM KACS securityfs endpoints.
 */

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "access_check.h"
#include "token_fd.h"
#include "token_runtime.h"

static struct dentry *pkm_kacs_securityfs_dir;
static struct dentry *pkm_kacs_securityfs_self;
static struct dentry *pkm_kacs_securityfs_sessions;

int pkm_kacs_securityfs_open_self_token_file(struct file *file)
{
	const void *subject_token;

	if (!file)
		return -EINVAL;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	return pkm_kacs_bind_query_token_file(file, subject_token);
}

static int pkm_kacs_securityfs_self_open(struct inode *inode,
					 struct file *file)
{
	(void)inode;
	return pkm_kacs_securityfs_open_self_token_file(file);
}

static const struct file_operations pkm_kacs_securityfs_self_fops = {
	.open = pkm_kacs_securityfs_self_open,
	.llseek = noop_llseek,
};

static ssize_t pkm_kacs_securityfs_sessions_read(struct file *file,
						 char __user *buf,
						 size_t count, loff_t *ppos)
{
	const void *subject_token;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	size_t required = 0;
	u8 *kbuf;
	int ret;
	ssize_t copied;

	(void)file;
	subject_token = pkm_kacs_current_effective_token_ptr();
	if (!subject_token)
		return -EACCES;

	ret = pkm_kacs_current_pip_context(&pip_type, &pip_trust);
	if (ret)
		return ret;

	ret = kacs_rust_check_securityfs_sessions_read(subject_token, pip_type,
						       pip_trust);
	if (ret)
		return ret;

	ret = kacs_rust_securityfs_sessions_listing(NULL, 0, &required);
	if (ret)
		return ret;
	if (*ppos >= required || !required)
		return 0;

	kbuf = kvzalloc(required, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = kacs_rust_securityfs_sessions_listing(kbuf, required, &required);
	if (ret) {
		kvfree(kbuf);
		return ret;
	}

	copied = simple_read_from_buffer(buf, count, ppos, kbuf, required);
	kvfree(kbuf);
	return copied;
}

static const struct file_operations pkm_kacs_securityfs_sessions_fops = {
	.read = pkm_kacs_securityfs_sessions_read,
	.llseek = default_llseek,
};

static int __init pkm_kacs_securityfs_init(void)
{
	int ret;

	if (pkm_kacs_securityfs_dir || pkm_kacs_securityfs_self ||
	    pkm_kacs_securityfs_sessions)
		return 0;

	pkm_kacs_securityfs_dir = securityfs_create_dir("kacs", NULL);
	if (IS_ERR(pkm_kacs_securityfs_dir)) {
		ret = PTR_ERR(pkm_kacs_securityfs_dir);
		pkm_kacs_securityfs_dir = NULL;
		pr_err("pkm: securityfs kacs dir init failed (%d)\n", ret);
		return ret;
	}

	pkm_kacs_securityfs_self = securityfs_create_file(
		"self", 0444, pkm_kacs_securityfs_dir, NULL,
		&pkm_kacs_securityfs_self_fops);
	if (IS_ERR(pkm_kacs_securityfs_self)) {
		ret = PTR_ERR(pkm_kacs_securityfs_self);
		pkm_kacs_securityfs_self = NULL;
		securityfs_remove(pkm_kacs_securityfs_dir);
		pkm_kacs_securityfs_dir = NULL;
		pr_err("pkm: securityfs kacs/self init failed (%d)\n", ret);
		return ret;
	}

	pkm_kacs_securityfs_sessions = securityfs_create_file(
		"sessions", 0444, pkm_kacs_securityfs_dir, NULL,
		&pkm_kacs_securityfs_sessions_fops);
	if (IS_ERR(pkm_kacs_securityfs_sessions)) {
		ret = PTR_ERR(pkm_kacs_securityfs_sessions);
		pkm_kacs_securityfs_sessions = NULL;
		securityfs_remove(pkm_kacs_securityfs_self);
		pkm_kacs_securityfs_self = NULL;
		securityfs_remove(pkm_kacs_securityfs_dir);
		pkm_kacs_securityfs_dir = NULL;
		pr_err("pkm: securityfs kacs/sessions init failed (%d)\n",
		       ret);
		return ret;
	}

	return 0;
}

late_initcall(pkm_kacs_securityfs_init);
