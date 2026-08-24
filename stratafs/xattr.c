// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cred.h>
#include <linux/kacs_stratafs.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <pkm/file.h>

#include "stratafs.h"

bool stratafs_reserved_xattr(const char *name)
{
	const size_t prefix_len = strlen(STRATAFS_XATTR_PREFIX);

	/* Everything beneath the namespace. */
	if (!strncmp(name, STRATAFS_XATTR_PREFIX, prefix_len))
		return true;
	/*
	 * And the namespace name itself. The prefix carries its trailing dot,
	 * so matching on it alone left the bare "system.stratafs" unreserved
	 * and forwarded it to the provider. Testing for the NUL is what keeps
	 * this from also reserving "system.stratafsfoo".
	 */
	if (!strncmp(name, STRATAFS_XATTR_PREFIX, prefix_len - 1) &&
	    name[prefix_len - 1] == '\0')
		return true;
	return !strcmp(name, STRATAFS_XATTR_STAGING);
}

static size_t stratafs_escaped_path_len(const char *path)
{
	size_t len = 0;

	for (; *path; path++) {
		if (*path == '\\' || *path == '\n')
			len++;
		len++;
	}
	return len;
}

static char *stratafs_copy_escaped_path(char *dst, const char *path)
{
	for (; *path; path++) {
		if (*path == '\\' || *path == '\n')
			*dst++ = '\\';
		*dst++ = *path;
	}
	return dst;
}

static int stratafs_origin_value(struct dentry *dentry, void *buffer,
				 size_t size)
{
	struct stratafs_inode_info *info = STRATAFS_I(d_inode(dentry));
	struct stratafs_dentry_info *dinfo = dentry->d_fsdata;
	struct stratafs_sb_info *sbi = STRATAFS_SB(dentry->d_sb);
	struct stratafs_paths resolved;
	const struct stratafs_paths *paths;
	struct path provider;
	bool descriptor_view = dinfo && dinfo->descriptor_view;
	bool borrowed = false;
	int selected_provider = -1;
	unsigned int provider_index;
	char *relative;
	char *value, *cursor;
	size_t length = 0;
	unsigned int i;
	int ret;

	/* Rename replaces this string under rebind_lock and frees the old one. */
	mutex_lock(&info->rebind_lock);
	relative = kstrdup(info->relative, GFP_KERNEL);
	mutex_unlock(&info->rebind_lock);
	if (!relative)
		return -ENOMEM;

	if (S_ISDIR(d_inode(dentry)->i_mode) && descriptor_view &&
	    dinfo->settled_paths) {
		paths = dinfo->settled_paths;
		borrowed = true;
		if (!dinfo->settled_origin_read_allowed) {
			ret = -EACCES;
			goto out_relative;
		}
	} else if (!S_ISDIR(d_inode(dentry)->i_mode)) {
		/*
		 * A non-directory operation is against the object resolved by VFS,
		 * not a second resolution performed part-way through getxattr().
		 * This also keeps a descriptor on its settled provider after rename or
		 * shadowing.  Take the provider through the dentry's locked snapshot:
		 * copy-up can rebind it concurrently and drop the old path reference.
		 */
		memset(&resolved, 0, sizeof(resolved));
		ret = stratafs_get_provider(dentry, &provider, &provider_index);
		if (ret)
			goto out_relative;
		resolved.path[provider_index] = provider;
		resolved.present = BIT_ULL(provider_index);
		paths = &resolved;
		selected_provider = provider_index;
	} else {
		ret = stratafs_resolve_all(dentry->d_sb, relative,
					   S_ISDIR(d_inode(dentry)->i_mode),
					   &resolved);
		if (ret)
			goto out_relative;
		paths = &resolved;
	}
	if (!descriptor_view && S_ISDIR(d_inode(dentry)->i_mode)) {
		ret = stratafs_check_paths_access(paths, sbi->count,
					  KACS_FILE_READ_EA);
		if (ret)
			goto out_paths;
	}

	for (i = 0; i < sbi->count; i++) {
		size_t base_len;

		if (!(paths->present & BIT_ULL(i)))
			continue;
		if (S_ISDIR(d_inode(dentry)->i_mode) &&
		    !d_is_dir(paths->path[i].dentry))
			continue;
		if (!S_ISDIR(d_inode(dentry)->i_mode) && i != selected_provider)
			continue;
		base_len = strlen(sbi->strata[i].path);
		length += stratafs_escaped_path_len(sbi->strata[i].path);
		if (relative[0] && base_len &&
		    sbi->strata[i].path[base_len - 1] != '/')
			length++;
		length += stratafs_escaped_path_len(relative);
		length++; /* newline, removed from the final element below */
	}
	if (length)
		length--;
	if (!buffer) {
		ret = length;
		goto out_paths;
	}
	if (size < length) {
		ret = -ERANGE;
		goto out_paths;
	}
	value = buffer;
	cursor = value;
	for (i = 0; i < sbi->count; i++) {
		size_t base_len;

		if (!(paths->present & BIT_ULL(i)))
			continue;
		if (S_ISDIR(d_inode(dentry)->i_mode) &&
		    !d_is_dir(paths->path[i].dentry))
			continue;
		if (!S_ISDIR(d_inode(dentry)->i_mode) && i != selected_provider)
			continue;
		if (cursor != value)
			*cursor++ = '\n';
		cursor = stratafs_copy_escaped_path(cursor, sbi->strata[i].path);
		base_len = strlen(sbi->strata[i].path);
		if (relative[0] && base_len &&
		    sbi->strata[i].path[base_len - 1] != '/')
			*cursor++ = '/';
		cursor = stratafs_copy_escaped_path(cursor, relative);
	}
	ret = length;
out_paths:
	if (!borrowed)
		stratafs_put_paths(&resolved, sbi->count);
out_relative:
	kfree(relative);
	return ret;
}

static int stratafs_xattr_get(const struct xattr_handler *handler,
			      struct dentry *dentry, struct inode *inode,
			      const char *name, void *buffer, size_t size)
{
	struct path provider;
	int ret;

	if (stratafs_reserved_xattr(name)) {
		if (strcmp(name, STRATAFS_XATTR_ORIGIN))
			return -ENODATA;
		return stratafs_origin_value(dentry, buffer, size);
	}
	ret = stratafs_get_provider(dentry, &provider, NULL);
	if (ret)
		return ret;
	ret = pkm_kacs_stratafs_rebind_metadata_decision(
		inode, d_inode(provider.dentry));
	if (!ret)
		ret = vfs_getxattr(mnt_idmap(provider.mnt), provider.dentry,
				   name, buffer, size);
	pkm_kacs_stratafs_end_metadata_decision(d_inode(provider.dentry));
	path_put(&provider);
	return ret;
}

static int stratafs_xattr_set(const struct xattr_handler *handler,
			      struct mnt_idmap *idmap, struct dentry *dentry,
			      struct inode *inode, const char *name,
			      const void *value, size_t size, int flags)
{
	struct path provider;
	struct file *metadata_file = NULL;
	unsigned int index;
	bool copied_up = false;
	int route;
	int ret;

	if (stratafs_reserved_xattr(name))
		return -EPERM;
	ret = stratafs_get_provider(dentry, &provider, &index);
	if (ret)
		return ret;
	route = stratafs_route_existing(dentry->d_sb, index, &provider,
					 S_ISREG(inode->i_mode) ||
					 S_ISDIR(inode->i_mode) ||
					 S_ISLNK(inode->i_mode));
	path_put(&provider);
	if (route == STRATAFS_ROUTE_READ_ONLY) {
		stratafs_audit_refusal(dentry,
					 value ? "setxattr" : "removexattr", index,
					 -EROFS,
					 false);
		return -EROFS;
	}
	if (route == STRATAFS_ROUTE_COPY_UP) {
		metadata_file = pkm_kacs_stratafs_metadata_file(inode);

		if (metadata_file)
			ret = stratafs_copy_up_metadata_file(
				metadata_file, dentry, &provider, &index);
		else
			ret = stratafs_copy_up_path(dentry, &provider, &index);
		if (ret)
			return ret;
		copied_up = true;
	} else {
		ret = stratafs_get_provider(dentry, &provider, &index);
		if (ret)
			return ret;
	}
	ret = mnt_want_write(provider.mnt);
	if (ret)
		goto out_provider;

	ret = pkm_kacs_stratafs_rebind_metadata_decision(
		inode, d_inode(provider.dentry));
	if (!ret) {
		if (value)
			ret = vfs_setxattr(mnt_idmap(provider.mnt),
					   provider.dentry, name, value,
					   size, flags);
		else
			ret = vfs_removexattr(mnt_idmap(provider.mnt),
					      provider.dentry, name);
	}
	pkm_kacs_stratafs_end_metadata_decision(d_inode(provider.dentry));
	mnt_drop_write(provider.mnt);
	if (!ret && (!copied_up || metadata_file))
		stratafs_refresh_inode(inode, &provider);
out_provider:
	path_put(&provider);
	return ret;
}

ssize_t stratafs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct path provider;
	char *raw, *src, *dst;
	ssize_t raw_len;
	size_t left;
	ssize_t result = 0;
	int ret;

	ret = stratafs_get_provider(dentry, &provider, NULL);
	if (ret)
		return ret;
	raw_len = vfs_listxattr(provider.dentry, NULL, 0);
	if (raw_len <= 0) {
		path_put(&provider);
		return raw_len;
	}
	raw = kvmalloc(raw_len, GFP_KERNEL);
	if (!raw) {
		path_put(&provider);
		return -ENOMEM;
	}
	ret = vfs_listxattr(provider.dentry, raw, raw_len);
	path_put(&provider);
	if (ret < 0) {
		result = ret;
		goto out;
	}
	raw_len = ret;
	for (src = raw, left = raw_len; left;) {
		size_t len = strnlen(src, left) + 1;

		if (len > left) {
			result = -EIO;
			goto out;
		}
		if (!stratafs_reserved_xattr(src))
			result += len;
		src += len;
		left -= len;
	}
	if (!list)
		goto out;
	if (size < result) {
		result = -ERANGE;
		goto out;
	}
	dst = list;
	for (src = raw, left = raw_len; left;) {
		size_t len = strlen(src) + 1;

		if (!stratafs_reserved_xattr(src)) {
			memcpy(dst, src, len);
			dst += len;
		}
		src += len;
		left -= len;
	}
out:
	kvfree(raw);
	return result;
}

static const struct xattr_handler stratafs_xattr_handler = {
	.prefix = "",
	.get = stratafs_xattr_get,
	.set = stratafs_xattr_set,
};

const struct xattr_handler * const stratafs_xattr_handlers[] = {
	&stratafs_xattr_handler,
	NULL,
};
