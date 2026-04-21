// SPDX-License-Identifier: GPL-2.0-only
/*
 * Slow-track PKM token-fd and self-open surface.
 *
 * Slice 22 adds only the first token handle object and the public
 * kacs_open_self_token syscall. Wider token-open syscalls and token ioctls
 * remain deliberately out of scope.
 */

#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include "token_fd.h"
#include "token_runtime.h"

#define PKM_KACS_TOKEN_OPEN_ALLOWED_MASK \
	(KACS_TOKEN_ALL_ACCESS | KACS_ACCESS_ACCESS_SYSTEM_SECURITY | \
	 KACS_ACCESS_MAXIMUM_ALLOWED | KACS_ACCESS_GENERIC_READ | \
	 KACS_ACCESS_GENERIC_WRITE | KACS_ACCESS_GENERIC_EXECUTE | \
	 KACS_ACCESS_GENERIC_ALL)

struct pkm_kacs_token_file {
	const void *token;
	u32 access_mask;
};

static int pkm_kacs_token_release(struct inode *inode, struct file *file)
{
	struct pkm_kacs_token_file *tf = file->private_data;

	if (tf) {
		if (tf->token)
			kacs_rust_token_drop(tf->token);
		kfree(tf);
	}

	return 0;
}

static const struct file_operations pkm_kacs_token_fops = {
	.release = pkm_kacs_token_release,
};

static int pkm_kacs_token_to_fd(const void *token, u32 granted_access)
{
	struct pkm_kacs_token_file *tf;
	int fd;

	tf = kmalloc(sizeof(*tf), GFP_KERNEL);
	if (!tf) {
		kacs_rust_token_drop(token);
		return -ENOMEM;
	}

	tf->token = token;
	tf->access_mask = granted_access;

	fd = anon_inode_getfd("kacs-token", &pkm_kacs_token_fops, tf, O_CLOEXEC);
	if (fd < 0) {
		kacs_rust_token_drop(token);
		kfree(tf);
	}

	return fd;
}

static long pkm_kacs_open_token_fd_for_subject(const void *subject_token,
					       const void *target_token,
					       u32 access_mask)
{
	const void *token_ref;
	u32 granted = 0;
	int ret;

	ret = kacs_rust_token_open_check(subject_token, target_token, access_mask,
					 &granted);
	if (ret)
		return ret;

	token_ref = kacs_rust_token_clone(target_token);
	if (!token_ref)
		return -EACCES;

	return pkm_kacs_token_to_fd(token_ref, granted);
}

long pkm_kacs_kunit_open_token_fd_for_subject(const void *subject_token,
					      const void *target_token,
					      u32 access_mask)
{
	if (!access_mask)
		return -EINVAL;
	if (access_mask & ~PKM_KACS_TOKEN_OPEN_ALLOWED_MASK)
		return -EINVAL;

	return pkm_kacs_open_token_fd_for_subject(subject_token, target_token,
						  access_mask);
}

long pkm_kacs_open_self_token_internal(unsigned int flags, u32 access_mask)
{
	const void *subject_token;
	const void *target_token;

	if (flags & ~KACS_REAL_TOKEN)
		return -EINVAL;
	if (!access_mask)
		return -EINVAL;
	if (access_mask & ~PKM_KACS_TOKEN_OPEN_ALLOWED_MASK)
		return -EINVAL;

	subject_token = pkm_kacs_current_effective_token_ptr();
	if (flags & KACS_REAL_TOKEN)
		target_token = pkm_kacs_current_primary_token_ptr();
	else
		target_token = subject_token;

	if (!subject_token || !target_token)
		return -EACCES;

	return pkm_kacs_open_token_fd_for_subject(subject_token, target_token,
						  access_mask);
}

SYSCALL_DEFINE2(kacs_open_self_token, unsigned int, flags, u32, access_mask)
{
	return pkm_kacs_open_self_token_internal(flags, access_mask);
}

int pkm_kacs_kunit_token_fd_snapshot(int fd, struct pkm_kacs_token_fd_view *out)
{
	struct fd f;
	struct pkm_kacs_token_file *tf;

	if (!out)
		return -EINVAL;

	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kacs_token_fops) {
		fdput(f);
		return -EINVAL;
	}

	tf = fd_file(f)->private_data;
	if (!tf) {
		fdput(f);
		return -EINVAL;
	}

	out->token = tf->token;
	out->access_mask = tf->access_mask;
	fdput(f);
	return 0;
}
