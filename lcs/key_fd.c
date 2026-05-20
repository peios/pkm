// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS key-fd carrier.
 *
 * PSD-005 key fds are capabilities: open-time AccessCheck grants are captured
 * once on an anonymous fd and later operations consult that stored mask.
 */

#include <linux/anon_inodes.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <pkm/lcs.h>

#include "key_fd.h"

struct pkm_lcs_key_fd_string_view {
	const u8 *bytes;
	u32 len;
};

struct pkm_lcs_key_fd {
	u32 source_id;
	u8 key_guid[PKM_LCS_GUID_BYTES];
	u32 granted_access;
	u32 path_component_count;
	char **resolved_path;
	u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES];
	bool orphaned;
	bool watch_armed;
};

static const struct file_operations pkm_lcs_key_fd_fops;

extern int lcs_rust_validate_key_fd_open_view(
	const u8 *key_guid, u32 granted_access,
	const struct pkm_lcs_key_fd_string_view *path_components,
	size_t path_component_count,
	const u8 (*ancestor_guids)[PKM_LCS_GUID_BYTES], size_t ancestor_count);
extern int lcs_rust_key_fd_fixed_ioctl_access_gate(u32 granted_access,
						   u32 ioctl_number);
extern int lcs_rust_key_fd_security_ioctl_access_gate(u32 granted_access,
						      u32 ioctl_number,
						      u32 security_info);

static void pkm_lcs_key_fd_free(struct pkm_lcs_key_fd *key_fd)
{
	u32 i;

	if (!key_fd)
		return;

	if (key_fd->resolved_path) {
		for (i = 0; i < key_fd->path_component_count; i++)
			kfree(key_fd->resolved_path[i]);
		kfree(key_fd->resolved_path);
	}
	kfree(key_fd->ancestor_guids);
	kfree(key_fd);
}

static int pkm_lcs_key_fd_release(struct inode *inode, struct file *file)
{
	struct pkm_lcs_key_fd *key_fd = file->private_data;

	file->private_data = NULL;
	pkm_lcs_key_fd_free(key_fd);
	return 0;
}

static const struct file_operations pkm_lcs_key_fd_fops = {
	.owner = THIS_MODULE,
	.release = pkm_lcs_key_fd_release,
	.llseek = noop_llseek,
};

static long pkm_lcs_key_fd_validate_input(
	const struct pkm_lcs_key_fd_publish_input *input,
	struct pkm_lcs_key_fd_string_view **views_out)
{
	struct pkm_lcs_key_fd_string_view *views = NULL;
	size_t len;
	u32 i;
	long ret;

	if (!views_out)
		return -EINVAL;
	*views_out = NULL;

	if (!input || !input->source_id || !input->path_component_count ||
	    !input->resolved_path || !input->ancestor_guids)
		return -EINVAL;

	views = kcalloc(input->path_component_count, sizeof(*views),
			GFP_KERNEL);
	if (!views)
		return -ENOMEM;

	for (i = 0; i < input->path_component_count; i++) {
		if (!input->resolved_path[i]) {
			ret = -EINVAL;
			goto out_free;
		}
		len = strlen(input->resolved_path[i]);
		if (len > U32_MAX) {
			ret = -EINVAL;
			goto out_free;
		}
		views[i].bytes = input->resolved_path[i];
		views[i].len = (u32)len;
	}

	ret = lcs_rust_validate_key_fd_open_view(
		input->key_guid, input->granted_access, views,
		input->path_component_count, input->ancestor_guids,
		input->path_component_count);
	if (ret)
		goto out_free;

	*views_out = views;
	return 0;

out_free:
	kfree(views);
	return ret;
}

static long pkm_lcs_key_fd_copy_input(
	const struct pkm_lcs_key_fd_publish_input *input,
	const struct pkm_lcs_key_fd_string_view *views,
	struct pkm_lcs_key_fd **key_fd_out)
{
	struct pkm_lcs_key_fd *key_fd;
	size_t guid_bytes;
	u32 i;

	if (!input || !views || !key_fd_out)
		return -EINVAL;
	*key_fd_out = NULL;

	key_fd = kzalloc(sizeof(*key_fd), GFP_KERNEL);
	if (!key_fd)
		return -ENOMEM;

	key_fd->resolved_path = kcalloc(input->path_component_count,
					sizeof(*key_fd->resolved_path),
					GFP_KERNEL);
	if (!key_fd->resolved_path)
		goto out_nomem;

	if (check_mul_overflow((size_t)input->path_component_count,
			       sizeof(*key_fd->ancestor_guids),
			       &guid_bytes))
		goto out_nomem;
	key_fd->ancestor_guids = kmemdup(input->ancestor_guids, guid_bytes,
					 GFP_KERNEL);
	if (!key_fd->ancestor_guids)
		goto out_nomem;

	for (i = 0; i < input->path_component_count; i++) {
		key_fd->resolved_path[i] = kstrndup(input->resolved_path[i],
						    views[i].len, GFP_KERNEL);
		if (!key_fd->resolved_path[i])
			goto out_nomem;
	}

	key_fd->source_id = input->source_id;
	memcpy(key_fd->key_guid, input->key_guid, sizeof(key_fd->key_guid));
	key_fd->granted_access = input->granted_access;
	key_fd->path_component_count = input->path_component_count;
	key_fd->orphaned = false;
	key_fd->watch_armed = false;

	*key_fd_out = key_fd;
	return 0;

out_nomem:
	pkm_lcs_key_fd_free(key_fd);
	return -ENOMEM;
}

long pkm_lcs_key_fd_publish(const struct pkm_lcs_key_fd_publish_input *input)
{
	struct pkm_lcs_key_fd_string_view *views = NULL;
	struct pkm_lcs_key_fd *key_fd = NULL;
	long ret;
	int fd;

	ret = pkm_lcs_key_fd_validate_input(input, &views);
	if (ret)
		return ret;

	ret = pkm_lcs_key_fd_copy_input(input, views, &key_fd);
	kfree(views);
	if (ret)
		return ret;

	fd = anon_inode_getfd("lcs-key", &pkm_lcs_key_fd_fops, key_fd,
			      O_CLOEXEC);
	if (fd < 0) {
		pkm_lcs_key_fd_free(key_fd);
		return fd;
	}

	return fd;
}

static long pkm_lcs_key_fd_get(int fd, struct fd *held,
			       struct pkm_lcs_key_fd **key_fd_out)
{
	struct file *file;

	if (!held || !key_fd_out)
		return -EINVAL;
	*key_fd_out = NULL;

	*held = fdget(fd);
	file = fd_file(*held);
	if (!file)
		return -EBADF;

	if (file->f_op != &pkm_lcs_key_fd_fops) {
		fdput(*held);
		return -EINVAL;
	}

	*key_fd_out = file->private_data;
	if (!*key_fd_out) {
		fdput(*held);
		return -EINVAL;
	}

	return 0;
}

static long pkm_lcs_key_fd_check_ioctl_common(
	int fd, unsigned int cmd,
	int (*gate)(u32 granted_access, u32 ioctl_number),
	u32 security_info, bool has_security_info)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	long ret;

	if (_IOC_TYPE(cmd) != REG_IOC_TYPE)
		return -EINVAL;

	ret = pkm_lcs_key_fd_get(fd, &held, &key_fd);
	if (ret)
		return ret;

	if (has_security_info)
		ret = lcs_rust_key_fd_security_ioctl_access_gate(
			key_fd->granted_access, _IOC_NR(cmd), security_info);
	else
		ret = gate(key_fd->granted_access, _IOC_NR(cmd));

	fdput(held);
	return ret;
}

long pkm_lcs_key_fd_check_fixed_ioctl_access(int fd, unsigned int cmd)
{
	return pkm_lcs_key_fd_check_ioctl_common(
		fd, cmd, lcs_rust_key_fd_fixed_ioctl_access_gate, 0, false);
}

long pkm_lcs_key_fd_check_security_ioctl_access(int fd, unsigned int cmd,
						u32 security_info)
{
	return pkm_lcs_key_fd_check_ioctl_common(
		fd, cmd, NULL, security_info, true);
}

static void pkm_lcs_key_fd_copy_component_snapshot(char *dst, u32 *len_out,
						   const char *src)
{
	size_t len = strlen(src);
	size_t copy_len;

	if (len_out)
		*len_out = len > U32_MAX ? U32_MAX : (u32)len;

	copy_len = min_t(size_t, len,
			 PKM_LCS_KUNIT_SNAPSHOT_COMPONENT_BYTES - 1U);
	memcpy(dst, src, copy_len);
	dst[copy_len] = '\0';
}

long pkm_lcs_key_fd_snapshot(int fd, struct pkm_lcs_key_fd_snapshot *out)
{
	struct pkm_lcs_key_fd *key_fd;
	struct fd held;
	u32 last;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	held = fdget(fd);
	if (!fd_file(held))
		return -EBADF;
	if (fd_file(held)->f_op != &pkm_lcs_key_fd_fops) {
		fdput(held);
		return -EINVAL;
	}

	key_fd = fd_file(held)->private_data;
	if (!key_fd || !key_fd->path_component_count) {
		fdput(held);
		return -EINVAL;
	}

	last = key_fd->path_component_count - 1U;
	out->source_id = key_fd->source_id;
	out->granted_access = key_fd->granted_access;
	out->path_component_count = key_fd->path_component_count;
	out->orphaned = key_fd->orphaned;
	out->watch_armed = key_fd->watch_armed;
	memcpy(out->key_guid, key_fd->key_guid, sizeof(out->key_guid));
	memcpy(out->first_ancestor_guid, key_fd->ancestor_guids[0],
	       sizeof(out->first_ancestor_guid));
	memcpy(out->last_ancestor_guid, key_fd->ancestor_guids[last],
	       sizeof(out->last_ancestor_guid));
	pkm_lcs_key_fd_copy_component_snapshot(out->first_component,
					       &out->first_component_len,
					       key_fd->resolved_path[0]);
	pkm_lcs_key_fd_copy_component_snapshot(out->last_component,
					       &out->last_component_len,
					       key_fd->resolved_path[last]);

	fdput(held);
	return 0;
}
