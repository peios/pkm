// SPDX-License-Identifier: GPL-2.0-only

#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/once.h>
#include <linux/random.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/user_namespace.h>

#include "stratafs.h"

static DEFINE_XARRAY(stratafs_live_mounts);
static u64 stratafs_boot_cookie;

int stratafs_register_live_mount(struct stratafs_sb_info *sbi)
{
	unsigned int attempt;
	int ret;

	get_random_once(&stratafs_boot_cookie, sizeof(stratafs_boot_cookie));
	if (!stratafs_boot_cookie)
		stratafs_boot_cookie = 1;
	for (attempt = 0; attempt < 16; attempt++) {
		sbi->mount_cookie = get_random_u64();
		if (!sbi->mount_cookie)
			continue;
		ret = xa_insert(&stratafs_live_mounts,
				(unsigned long)sbi->mount_cookie, sbi, GFP_KERNEL);
		if (ret == -EBUSY)
			continue;
		if (ret)
			return ret;
		sbi->boot_cookie = stratafs_boot_cookie;
		sbi->mount_registered = true;
		return 0;
	}
	return -EAGAIN;
}

void stratafs_unregister_live_mount(struct stratafs_sb_info *sbi)
{
	if (!sbi || !sbi->mount_registered)
		return;
	xa_erase(&stratafs_live_mounts, (unsigned long)sbi->mount_cookie);
	sbi->mount_registered = false;
	/* stage_owner_live() dereferences the entry while holding RCU. */
	synchronize_rcu();
}

bool stratafs_stage_owner_live(u64 boot_cookie, u64 mount_cookie)
{
	struct stratafs_sb_info *owner;
	bool live;

	if (boot_cookie != stratafs_boot_cookie || !mount_cookie)
		return false;
	rcu_read_lock();
	owner = xa_load(&stratafs_live_mounts, (unsigned long)mount_cookie);
	live = owner && owner->mount_cookie == mount_cookie &&
	       owner->boot_cookie == boot_cookie;
	rcu_read_unlock();
	return live;
}

enum stratafs_param {
	Opt_strata,
};

static const struct fs_parameter_spec stratafs_parameters[] = {
	fsparam_string("strata", Opt_strata),
	{}
};

static int stratafs_parse_flag(const char *start, size_t len, u32 *flags)
{
	u32 flag;

	if (len == strlen("create") && !memcmp(start, "create", len))
		flag = STRATAFS_F_CREATE;
	else if (len == strlen("ro") && !memcmp(start, "ro", len))
		flag = STRATAFS_F_RO;
	else if (len == strlen("am") && !memcmp(start, "am", len))
		flag = STRATAFS_F_AM;
	else
		return -EINVAL;

	if (*flags & flag)
		return -EINVAL;
	*flags |= flag;
	return 0;
}

static bool stratafs_escapable(char c)
{
	return c == ':' || c == '+' || c == ',' || c == '\\';
}

int stratafs_parse_strata(struct stratafs_sb_info *sbi, const char *value)
{
	const char *cursor;
	unsigned int count = 0;
	int ret = -EINVAL;

	if (!sbi || !value || !*value)
		return -EINVAL;

	cursor = value;
	while (*cursor) {
		const char *flag_start;
		char *path;
		size_t path_len = 0;
		u32 flags = 0;

		if (count == STRATAFS_MAX_STRATA || *cursor != '/')
			goto fail;

		path = kmalloc(strlen(cursor) + 1, GFP_KERNEL);
		if (!path) {
			ret = -ENOMEM;
			goto fail;
		}

		while (*cursor && *cursor != ':' && *cursor != '+') {
			if (*cursor == ',') {
				kfree(path);
				goto fail;
			}
			if (*cursor == '\\') {
				cursor++;
				if (!*cursor || !stratafs_escapable(*cursor)) {
					kfree(path);
					goto fail;
				}
			}
			path[path_len++] = *cursor++;
		}
		path[path_len] = '\0';
		if (!path_len) {
			kfree(path);
			goto fail;
		}

		while (*cursor == '+') {
			cursor++;
			flag_start = cursor;
			while (*cursor && *cursor != '+' && *cursor != ':') {
				if (*cursor == '\\' || *cursor == ',') {
					kfree(path);
					goto fail;
				}
				cursor++;
			}
			if (stratafs_parse_flag(flag_start, cursor - flag_start,
						&flags)) {
				kfree(path);
				goto fail;
			}
		}

		sbi->strata[count].path = path;
		sbi->strata[count].flags = flags;
		count++;

		if (!*cursor)
			break;
		if (*cursor++ != ':' || !*cursor)
			goto fail;
	}

	sbi->display_options = kstrdup(value, GFP_KERNEL);
	if (!sbi->display_options) {
		ret = -ENOMEM;
		goto fail;
	}
	sbi->count = count;
	return 0;

fail:
	while (count)
		kfree(sbi->strata[--count].path);
	return ret;
}

int stratafs_validate_configuration(struct stratafs_sb_info *sbi)
{
	u32 flags[STRATAFS_MAX_STRATA];
	unsigned int i;
	int create_index;

	if (!sbi)
		return -EINVAL;
	for (i = 0; i < sbi->count; i++)
		flags[i] = sbi->strata[i].flags;
	if (stratafs_rust_validate_flags(flags, sbi->count, &create_index))
		return -EINVAL;
	sbi->create_index = create_index;
	return 0;
}

/*
 * Admission runs in two passes so that entitlement is decided for the whole
 * stack before any validity condition (TRM §4.2.3). A caller with no right to
 * traverse a directory must not be able to name it as a stratum and learn from
 * the errno whether some *other* stratum exists or is a directory: the first
 * pass resolves and stats every stratum under the caller's credentials and
 * lets an EACCES from any of them win over whatever an earlier one reported;
 * only then does the second pass apply the type, duplicate and depth
 * conditions (PEI-263).
 *
 * The stat runs inside the same credential override as the walk: for
 * fsopen() + fsconfig(FSCONFIG_CMD_CREATE) issued by different tasks the two
 * halves of entitlement are otherwise decided against different principals.
 */
static int stratafs_check_initial_strata(struct super_block *sb,
					 unsigned int *stack_depth)
{
	struct stratafs_sb_info *sbi = STRATAFS_SB(sb);
	struct path resolved[STRATAFS_MAX_STRATA] = {};
	umode_t modes[STRATAFS_MAX_STRATA] = {};
	int errors[STRATAFS_MAX_STRATA] = {};
	const struct cred *old_cred;
	unsigned int i, j;
	int ret = 0;

	*stack_depth = 0;
	for (i = 0; i < sbi->count; i++) {
		struct kstat stat;

		ret = stratafs_resolve_one(sb, i, "", true, &resolved[i]);
		if (ret == -ENOENT && (sbi->strata[i].flags & STRATAFS_F_AM)) {
			ret = 0;
			continue;
		}
		if (!ret) {
			old_cred = override_creds(sbi->resolution_cred);
			ret = vfs_getattr(&resolved[i], &stat,
					  STATX_TYPE | STATX_MODE,
					  AT_STATX_SYNC_AS_STAT);
			revert_creds(old_cred);
			if (!ret)
				modes[i] = stat.mode;
		}
		if (ret == -EACCES)
			goto out;
		/*
		 * Any other resolution result is a validity condition, judged
		 * in stratum order with the rest of them below.
		 */
		errors[i] = ret;
		ret = 0;
	}

	for (i = 0; i < sbi->count; i++) {
		if (errors[i]) {
			ret = errors[i];
			goto out;
		}
		if (!resolved[i].dentry)
			continue;
		if (!S_ISDIR(modes[i])) {
			ret = -ENOTDIR;
			goto out;
		}
		for (j = 0; j < i; j++) {
			if (resolved[j].dentry &&
			    d_inode(resolved[i].dentry) ==
				    d_inode(resolved[j].dentry)) {
				ret = -EINVAL;
				goto out;
			}
		}
		*stack_depth = max_t(unsigned int, *stack_depth,
					      resolved[i].dentry->d_sb->s_stack_depth);
	}

	if (*stack_depth >= FILESYSTEM_MAX_STACK_DEPTH)
		ret = -ELOOP;
out:
	for (i = 0; i < sbi->count; i++)
		if (resolved[i].dentry)
			path_put(&resolved[i]);
	return ret;
}

static int stratafs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct stratafs_fs_context *ctx = fc->fs_private;
	struct stratafs_sb_info *sbi = ctx->sbi;
	struct stratafs_paths roots;
	struct inode *inode;
	unsigned int stack_depth;
	int provider;
	int ret;

	ctx->sbi = NULL;
	sb->s_fs_info = sbi;
	sb->s_magic = STRATAFS_MAGIC;
	sb->s_op = &stratafs_super_operations;
	sb->s_xattr = stratafs_xattr_handlers;
	set_default_d_op(sb, &stratafs_dentry_operations);
	sb->s_time_gran = 1;
	sb->s_maxbytes = MAX_LFS_FILESIZE;

	ret = stratafs_check_initial_strata(sb, &stack_depth);
	if (ret)
		goto fail;
	sb->s_stack_depth = stack_depth + 1;
	ret = stratafs_register_live_mount(sbi);
	if (ret)
		goto fail;

	ret = stratafs_resolve_all(sb, "", true, &roots);
	if (ret)
		goto fail;
	if (sbi->create_index >= 0 &&
	    (roots.present & BIT_ULL(sbi->create_index)) &&
	    d_is_dir(roots.path[sbi->create_index].dentry))
		stratafs_recover_staging_parent(
			sb, &roots.path[sbi->create_index]);
	provider = stratafs_provider_index(&roots, sbi->count);
	if (provider >= 0)
		inode = stratafs_new_inode(sb, &roots.path[provider], provider, "");
	else
		inode = stratafs_new_inode(sb, NULL, 0, "");
	stratafs_put_paths(&roots, sbi->count);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto fail;
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto fail;
	}
	sb->s_root->d_op = &stratafs_dentry_operations;
	return 0;

fail:
	sb->s_fs_info = NULL;
	stratafs_free_sbi(sbi);
	return ret;
}

static int stratafs_get_tree(struct fs_context *fc)
{
	struct stratafs_fs_context *ctx = fc->fs_private;
	int ret;

	if (!ctx->seen_strata)
		return invalfc(fc, "strata= is required");
	ret = stratafs_validate_configuration(ctx->sbi);
	if (ret)
		return invalfc(fc, "invalid stratum flag configuration");
	/*
	 * Copy-up intentionally carries no add-entry authority of its own.  A
	 * create-enabled stack therefore controls writes into a real directory
	 * outside the mount and must not be configurable by nested-userns root.
	 */
	if (ctx->sbi->create_index >= 0 &&
	    (fc->cred->user_ns != &init_user_ns ||
	     security_capable(fc->cred, &init_user_ns, CAP_SYS_ADMIN,
			      CAP_OPT_NONE)))
		return -EPERM;
	return get_tree_nodev(fc, stratafs_fill_super);
}

static int stratafs_parse_param(struct fs_context *fc,
				struct fs_parameter *param)
{
	struct stratafs_fs_context *ctx = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, stratafs_parameters, param, &result);
	if (opt < 0)
		return opt;
	if (opt != Opt_strata || !param->string || ctx->seen_strata)
		return -EINVAL;
	ctx->seen_strata = true;
	return stratafs_parse_strata(ctx->sbi, param->string);
}

/*
 * The strata grammar permits an escaped comma in a path.  The generic
 * monolithic mount-data parser splits at every comma, including an escaped
 * one, before ->parse_param() can see it.  Keep escaped characters together
 * here, as overlayfs does for its path-valued legacy options.
 */
static char *stratafs_next_option(char **options)
{
	char *begin = *options;
	char *cursor;

	if (!begin)
		return NULL;
	for (cursor = begin; *cursor; cursor++) {
		if (*cursor == '\\') {
			if (cursor[1])
				cursor++;
			continue;
		}
		if (*cursor == ',') {
			*cursor = '\0';
			*options = cursor + 1;
			return begin;
		}
	}
	*options = NULL;
	return begin;
}

static int stratafs_parse_monolithic(struct fs_context *fc, void *data)
{
	return vfs_parse_monolithic_sep(fc, data, stratafs_next_option);
}

/*
 * §2.3: "A remount MUST NOT add, remove, reorder, or re-flag strata; an
 * attempt to do so MUST fail with EINVAL."
 *
 * The test used to be on the *presence* of strata=, not on whether its value
 * differs. A remount supplying a byte-identical stack does none of the four
 * forbidden things, so the rule does not require it to fail — and refusing it
 * breaks a real workflow: `mount -o remount` tools reconstruct the whole
 * option string from /proc/self/mountinfo and replay it, so flipping a
 * stratafs mount read-only meant replaying a strata= that changed nothing.
 *
 * (That replay only compares equal because ->show_options no longer
 * double-escapes the value; see the note there.)
 */
bool stratafs_strata_unchanged(const struct stratafs_sb_info *supplied,
			       const struct stratafs_sb_info *mounted)
{
	/*
	 * Not `current`: that is the kernel's macro for the running task, and a
	 * parameter of that name expands into nonsense here.
	 */
	if (!supplied->display_options || !mounted->display_options)
		return false;
	return strcmp(supplied->display_options, mounted->display_options) == 0;
}

static int stratafs_reconfigure(struct fs_context *fc)
{
	struct stratafs_fs_context *ctx = fc->fs_private;

	if (!ctx || !ctx->seen_strata)
		return 0;
	if (!fc->root)
		return -EINVAL;
	if (!stratafs_strata_unchanged(ctx->sbi, STRATAFS_SB(fc->root->d_sb)))
		return -EINVAL;
	return 0;
}

void stratafs_free_sbi(struct stratafs_sb_info *sbi)
{
	struct stratafs_identity *identity;
	struct stratafs_staging *staging, *next_staging;
	unsigned long index;
	unsigned int i;

	if (!sbi)
		return;
	stratafs_unregister_live_mount(sbi);
	for (i = 0; i < sbi->count; i++)
		kfree(sbi->strata[i].path);
	kfree(sbi->display_options);
	list_for_each_entry_safe(staging, next_staging, &sbi->staging, list) {
		list_del(&staging->list);
		kfree(staging->relative);
		kfree(staging);
	}

	xa_for_each(&sbi->identities, index, identity) {
		xa_erase(&sbi->identities, index);
		iput(identity->inode);
		kfree(identity);
	}
	xa_destroy(&sbi->identities);
	path_put(&sbi->resolution_root);
	put_cred(sbi->resolution_cred);
	kfree(sbi);
}

static void stratafs_free_context(struct fs_context *fc)
{
	struct stratafs_fs_context *ctx = fc->fs_private;

	if (!ctx)
		return;
	stratafs_free_sbi(ctx->sbi);
	kfree(ctx);
}

static const struct fs_context_operations stratafs_context_operations = {
	.free = stratafs_free_context,
	.parse_param = stratafs_parse_param,
	.parse_monolithic = stratafs_parse_monolithic,
	.get_tree = stratafs_get_tree,
	.reconfigure = stratafs_reconfigure,
};

static int stratafs_init_fs_context(struct fs_context *fc)
{
	struct stratafs_fs_context *ctx;
	struct stratafs_sb_info *sbi;

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	sbi = kzalloc_obj(*sbi, GFP_KERNEL);
	if (!ctx || !sbi) {
		kfree(ctx);
		kfree(sbi);
		return -ENOMEM;
	}

	get_fs_root(current->fs, &sbi->resolution_root);
	sbi->resolution_cred = get_cred(fc->cred);
	mutex_init(&sbi->identity_lock);
	xa_init(&sbi->identities);
	atomic64_set(&sbi->next_ino, 1);
	mutex_init(&sbi->staging_lock);
	INIT_LIST_HEAD(&sbi->staging);
	atomic64_set(&sbi->next_stage, 0);
	sbi->create_index = -1;
	ctx->sbi = sbi;
	fc->fs_private = ctx;
	fc->ops = &stratafs_context_operations;
	return 0;
}

static struct file_system_type stratafs_type = {
	.owner = THIS_MODULE,
	.name = STRATAFS_NAME,
	.init_fs_context = stratafs_init_fs_context,
	.kill_sb = kill_anon_super,
	.fs_flags = FS_USERNS_MOUNT | FS_RENAME_DOES_D_MOVE,
};

static int __init stratafs_init(void)
{
	return register_filesystem(&stratafs_type);
}
fs_initcall(stratafs_init);

static void __exit stratafs_exit(void)
{
	unregister_filesystem(&stratafs_type);
}
module_exit(stratafs_exit);

MODULE_AUTHOR("Peios Project");
MODULE_DESCRIPTION("Peios ordered live directory stacking filesystem");
MODULE_LICENSE("GPL");
