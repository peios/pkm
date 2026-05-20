// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source-device entrypoint.
 *
 * PSD-005 requires sources to obtain RSI fds through /dev/pkm_registry and
 * requires the open path to be gated by SeTcbPrivilege before any source fd is
 * issued.
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <pkm/token.h>

#include "../kacs/token_runtime.h"
#include "source_device.h"

#define PKM_LCS_MAX_HIVE_NAME_BYTES_HARD 1024U

static bool pkm_lcs_default_copy_from_user(void *ctx, void *dst,
					   const void __user *src, size_t len)
{
	(void)ctx;

	return copy_from_user(dst, src, len) == 0;
}

static const struct pkm_lcs_usercopy_ops pkm_lcs_default_usercopy_ops = {
	.read = pkm_lcs_default_copy_from_user,
};

static long pkm_lcs_source_device_check_tcb(const void *token)
{
	if (!token)
		return -EPERM;
	if (!kacs_rust_token_has_enabled_privilege(token,
						  KACS_SE_TCB_PRIVILEGE))
		return -EPERM;
	return 0;
}

static long pkm_lcs_source_device_mark_tcb_used(const void *token)
{
	if (!kacs_rust_token_mark_privileges_used(token,
						 KACS_SE_TCB_PRIVILEGE))
		return -EPERM;

	return 0;
}

long pkm_lcs_source_device_open_for_token(const void *token)
{
	long ret;

	ret = pkm_lcs_source_device_check_tcb(token);
	if (ret)
		return ret;

	return pkm_lcs_source_device_mark_tcb_used(token);
}

long pkm_lcs_source_device_open_file_for_token(const void *token,
					       struct file *file)
{
	struct pkm_lcs_source_fd *source_fd;
	long ret;

	if (!file || file->private_data)
		return -EINVAL;

	ret = pkm_lcs_source_device_check_tcb(token);
	if (ret)
		return ret;

	source_fd = kzalloc(sizeof(*source_fd), GFP_KERNEL);
	if (!source_fd)
		return -ENOMEM;
	source_fd->state = PKM_LCS_SOURCE_FD_UNREGISTERED;

	ret = pkm_lcs_source_device_mark_tcb_used(token);
	if (ret) {
		kfree(source_fd);
		return ret;
	}

	file->private_data = source_fd;
	return 0;
}

int pkm_lcs_source_device_release_file(struct file *file)
{
	struct pkm_lcs_source_fd *source_fd;

	if (!file)
		return 0;

	source_fd = file->private_data;
	file->private_data = NULL;
	kfree(source_fd);
	return 0;
}

void pkm_lcs_source_registration_copy_destroy(
	struct pkm_lcs_source_registration_copy *registration)
{
	u32 i;

	if (!registration)
		return;

	if (registration->hives) {
		for (i = 0; i < registration->hive_count; i++)
			kfree(registration->hives[i].name);
	}
	kfree(registration->hives);
	memset(registration, 0, sizeof(*registration));
}

static long pkm_lcs_source_registration_copy_hive_name(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_hive_entry *wire_hive,
	struct pkm_lcs_source_registration_hive_copy *hive)
{
	const void __user *name_ptr;
	char *name;

	if (!wire_hive->name_len)
		return -EINVAL;
	if (wire_hive->name_len > PKM_LCS_MAX_HIVE_NAME_BYTES_HARD)
		return -EINVAL;

	name_ptr = (const void __user *)(unsigned long)wire_hive->name_ptr;
	if (!name_ptr)
		return -EFAULT;

	name = kmalloc((size_t)wire_hive->name_len + 1, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	if (!ops->read(ops->ctx, name, name_ptr, wire_hive->name_len)) {
		kfree(name);
		return -EFAULT;
	}
	name[wire_hive->name_len] = '\0';

	hive->name = name;
	hive->name_len = wire_hive->name_len;
	return 0;
}

long pkm_lcs_source_registration_copy_from_user(
	const struct pkm_lcs_usercopy_ops *ops,
	const struct reg_src_register_args __user *uargs, u32 max_hives,
	struct pkm_lcs_source_registration_copy *out)
{
	struct reg_src_register_args args;
	struct reg_src_hive_entry *wire_hives;
	const void __user *hives_ptr;
	size_t hives_bytes;
	u32 i;
	long ret = 0;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	if (!ops)
		ops = &pkm_lcs_default_usercopy_ops;
	if (!ops->read)
		return -EINVAL;
	if (!uargs)
		return -EFAULT;
	if (!ops->read(ops->ctx, &args, uargs, sizeof(args)))
		return -EFAULT;

	if (args._pad)
		return -EINVAL;
	if (!args.hive_count)
		return -EINVAL;
	if (max_hives && args.hive_count > max_hives)
		return -ENOSPC;
	if (check_mul_overflow((size_t)args.hive_count,
			       sizeof(struct reg_src_hive_entry),
			       &hives_bytes))
		return -EOVERFLOW;

	hives_ptr = (const void __user *)(unsigned long)args.hives_ptr;
	if (!hives_ptr)
		return -EFAULT;

	wire_hives = kcalloc(args.hive_count, sizeof(*wire_hives), GFP_KERNEL);
	if (!wire_hives)
		return -ENOMEM;
	out->hives = kcalloc(args.hive_count, sizeof(*out->hives), GFP_KERNEL);
	if (!out->hives) {
		ret = -ENOMEM;
		goto out_free_wire;
	}
	out->hive_count = args.hive_count;
	out->max_sequence = args.max_sequence;

	if (!ops->read(ops->ctx, wire_hives, hives_ptr, hives_bytes)) {
		ret = -EFAULT;
		goto out_destroy;
	}

	for (i = 0; i < args.hive_count; i++) {
		if (wire_hives[i]._pad0 || wire_hives[i]._pad1) {
			ret = -EINVAL;
			goto out_destroy;
		}

		memcpy(out->hives[i].root_guid, wire_hives[i].root_guid,
		       sizeof(out->hives[i].root_guid));
		out->hives[i].flags = wire_hives[i].flags;
		memcpy(out->hives[i].scope_guid, wire_hives[i].scope_guid,
		       sizeof(out->hives[i].scope_guid));

		ret = pkm_lcs_source_registration_copy_hive_name(
			ops, &wire_hives[i], &out->hives[i]);
		if (ret)
			goto out_destroy;
	}

	kfree(wire_hives);
	return 0;

out_destroy:
	pkm_lcs_source_registration_copy_destroy(out);
out_free_wire:
	kfree(wire_hives);
	return ret;
}

static int pkm_lcs_source_device_open(struct inode *inode, struct file *file)
{
	return pkm_lcs_source_device_open_file_for_token(
		pkm_kacs_current_effective_token_ptr(), file);
}

static int pkm_lcs_source_device_release(struct inode *inode, struct file *file)
{
	return pkm_lcs_source_device_release_file(file);
}

static const struct file_operations pkm_lcs_source_device_fops = {
	.owner = THIS_MODULE,
	.open = pkm_lcs_source_device_open,
	.release = pkm_lcs_source_device_release,
	.llseek = noop_llseek,
};

static struct miscdevice pkm_lcs_source_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "pkm_registry",
	.fops = &pkm_lcs_source_device_fops,
};

static int __init pkm_lcs_source_device_init(void)
{
	int ret;

	ret = misc_register(&pkm_lcs_source_device);
	if (ret)
		pr_err("pkm: /dev/pkm_registry registration failed (%d)\n",
		       ret);

	return ret;
}
late_initcall(pkm_lcs_source_device_init);
