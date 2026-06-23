// SPDX-License-Identifier: GPL-2.0-only

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "tlp.h"
#include "token_runtime.h"

#define PKM_KACS_TLP_MAX_PREFIXES 64U
#define PKM_KACS_TLP_MAX_PREFIX_LEN 4096U

static DEFINE_MUTEX(pkm_kacs_tlp_cache_lock);
static char *pkm_kacs_tlp_prefixes[PKM_KACS_TLP_MAX_PREFIXES];
static size_t pkm_kacs_tlp_prefix_lens[PKM_KACS_TLP_MAX_PREFIXES];
static u32 pkm_kacs_tlp_prefix_count;

static void pkm_kacs_tlp_clear_prefixes_locked(void)
{
	u32 i;

	for (i = 0; i < pkm_kacs_tlp_prefix_count; i++) {
		kfree(pkm_kacs_tlp_prefixes[i]);
		pkm_kacs_tlp_prefixes[i] = NULL;
		pkm_kacs_tlp_prefix_lens[i] = 0;
	}
	pkm_kacs_tlp_prefix_count = 0;
}

static long pkm_kacs_tlp_replace_prefixes_kernel(
	const char * const *prefixes, const size_t *prefix_lens, u32 count)
{
	char *new_prefixes[PKM_KACS_TLP_MAX_PREFIXES] = {};
	size_t new_lens[PKM_KACS_TLP_MAX_PREFIXES] = {};
	u32 i;
	long ret = 0;

	if (count > PKM_KACS_TLP_MAX_PREFIXES)
		return -EINVAL;
	if (count != 0 && (!prefixes || !prefix_lens))
		return -EINVAL;

	for (i = 0; i < count; i++) {
		size_t len = prefix_lens[i];
		char *copy;

		if (!prefixes[i] || len == 0 ||
		    len > PKM_KACS_TLP_MAX_PREFIX_LEN) {
			ret = -EINVAL;
			goto out_free;
		}
		if (prefixes[i][0] != '/' || prefixes[i][len - 1] != '/') {
			ret = -EINVAL;
			goto out_free;
		}
		if (memchr(prefixes[i], '\0', len)) {
			ret = -EINVAL;
			goto out_free;
		}

		copy = kmalloc(len + 1, GFP_KERNEL);
		if (!copy) {
			ret = -ENOMEM;
			goto out_free;
		}
		memcpy(copy, prefixes[i], len);
		copy[len] = '\0';
		new_prefixes[i] = copy;
		new_lens[i] = len;
	}

	mutex_lock(&pkm_kacs_tlp_cache_lock);
	pkm_kacs_tlp_clear_prefixes_locked();
	for (i = 0; i < count; i++) {
		pkm_kacs_tlp_prefixes[i] = new_prefixes[i];
		pkm_kacs_tlp_prefix_lens[i] = new_lens[i];
		new_prefixes[i] = NULL;
		new_lens[i] = 0;
	}
	pkm_kacs_tlp_prefix_count = count;
	mutex_unlock(&pkm_kacs_tlp_cache_lock);

	return 0;

out_free:
	for (i = 0; i < count; i++)
		kfree(new_prefixes[i]);
	return ret;
}

static bool pkm_kacs_tlp_path_allowed(const char *path, size_t path_len)
{
	bool allowed = false;
	u32 i;

	mutex_lock(&pkm_kacs_tlp_cache_lock);
	for (i = 0; i < pkm_kacs_tlp_prefix_count; i++) {
		size_t prefix_len = pkm_kacs_tlp_prefix_lens[i];

		if (path_len >= prefix_len &&
		    memcmp(path, pkm_kacs_tlp_prefixes[i], prefix_len) == 0) {
			allowed = true;
			break;
		}
	}
	mutex_unlock(&pkm_kacs_tlp_cache_lock);

	return allowed;
}

static int pkm_kacs_check_tlp_path_core(u32 mitigation_bits,
					bool file_backed,
					bool executable_transition,
					const char *path, size_t path_len)
{
	if ((mitigation_bits & KACS_MIT_TLP) == 0)
		return 0;
	if (!executable_transition)
		return 0;
	if (!file_backed)
		return 0;
	if (!path || path_len == 0)
		return -EACCES;
	if (!pkm_kacs_tlp_path_allowed(path, path_len))
		return -EACCES;

	return 0;
}

int pkm_kacs_check_tlp_file_core(u32 mitigation_bits, struct file *file,
				 bool executable_transition)
{
	char *path_buf;
	char *resolved;
	size_t path_len;
	int ret;

	if ((mitigation_bits & KACS_MIT_TLP) == 0)
		return 0;
	if (!executable_transition)
		return 0;
	if (!file)
		return 0;

	path_buf = __getname();
	if (!path_buf)
		return -ENOMEM;

	resolved = d_path(&file->f_path, path_buf, PATH_MAX);
	if (IS_ERR(resolved)) {
		ret = -EACCES;
		goto out_putname;
	}

	path_len = strnlen(resolved,
			   (size_t)(path_buf + PATH_MAX - resolved));
	ret = pkm_kacs_check_tlp_path_core(mitigation_bits, true, true,
					   resolved, path_len);

out_putname:
	__putname(path_buf);
	return ret;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
long pkm_kacs_kunit_replace_tlp_prefixes(const char * const *prefixes,
					 const size_t *prefix_lens,
					 u32 count)
{
	return pkm_kacs_tlp_replace_prefixes_kernel(prefixes, prefix_lens,
						    count);
}

void pkm_kacs_kunit_clear_tlp_prefixes(void)
{
	mutex_lock(&pkm_kacs_tlp_cache_lock);
	pkm_kacs_tlp_clear_prefixes_locked();
	mutex_unlock(&pkm_kacs_tlp_cache_lock);
}

int pkm_kacs_kunit_check_tlp_mmap_path(u32 mitigation_bits,
				       unsigned long prot,
				       const char *path,
				       u32 file_backed)
{
	return pkm_kacs_check_tlp_path_core(
		mitigation_bits, file_backed != 0, (prot & PROT_EXEC) != 0,
		path, path ? strlen(path) : 0);
}

int pkm_kacs_kunit_check_tlp_mprotect_path(u32 mitigation_bits,
					   unsigned long vm_flags,
					   unsigned long prot,
					   const char *path,
					   u32 file_backed)
{
	return pkm_kacs_check_tlp_path_core(
		mitigation_bits, file_backed != 0,
		(prot & PROT_EXEC) != 0 && (vm_flags & VM_EXEC) == 0,
		path, path ? strlen(path) : 0);
}
#endif
