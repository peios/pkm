// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test rendezvous and fail points.
 *
 * Conformance tests for §4's atomicity and rollback promises need two
 * things no arrangement of real filesystems can produce: a copy-up held
 * open mid-flight, and an internal step made to fail between two halves
 * of one syscall. Each hook point marks one such moment; arming it from
 * userspace either blocks the next task that reaches it until released,
 * or makes that task's step fail with a chosen errno, exactly once.
 *
 * The interface lives on securityfs, NOT debugfs: this kernel is built
 * with LOCK_DOWN_KERNEL_FORCE_INTEGRITY, and lockdown's integrity set
 * refuses every debugfs open that is not a read of an 0444 file — the
 * files would be visible and permanently untouchable. securityfs is the
 * PKM precedent anyway (kacs/securityfs.c) and lockdown does not gate
 * it. One file per point under stratafs/hooks/:
 *
 *   echo hold    > <point>    tasks reaching the point block
 *   echo fail 5  > <point>    the next task to reach it gets -EIO (once)
 *   echo clear   > <point>    disarm and wake every held task
 *   cat <point>               "<mode> waiting=<W> hits=<H>"
 *
 * `waiting` is the number of tasks currently blocked, so a test can poll
 * for its victim's arrival before acting on the held state. `hits`
 * counts arrivals the hook affected. Holds use killable waits: a held
 * task can always be removed with a fatal signal.
 *
 * Everything here is doubly gated. CONFIG_STRATAFS_FS_TEST_HOOKS builds
 * it; the files register only when the kernel was ALSO booted with
 * stratafs.test_hooks=1. Without the parameter nothing is created and
 * every hook compiles to an armed-check of a bool that is never true.
 */
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "stratafs.h"

static bool stratafs_test_hooks_on;
module_param_named(test_hooks, stratafs_test_hooks_on, bool, 0444);
MODULE_PARM_DESC(test_hooks,
		 "Register the stratafs test rendezvous/fail points in securityfs");

enum stratafs_hook_mode {
	STRATAFS_HOOK_NONE = 0,
	STRATAFS_HOOK_HOLD,
	STRATAFS_HOOK_FAIL,
};

struct stratafs_hook {
	const char *name;
	enum stratafs_hook_mode mode;
	int error;		/* negative errno armed by "fail" */
	unsigned int waiting;
	unsigned int hits;
};

static DEFINE_SPINLOCK(stratafs_hook_lock);
static DECLARE_WAIT_QUEUE_HEAD(stratafs_hook_wq);

static struct stratafs_hook stratafs_hooks[STRATAFS_HOOK_POINTS] = {
	[STRATAFS_HOOK_COPY_UP_BEGIN]	= { .name = "copy-up-begin" },
	[STRATAFS_HOOK_COPY_UP_PUBLISH]	= { .name = "copy-up-publish" },
	[STRATAFS_HOOK_RENAME_PROVIDER]	= { .name = "rename-provider" },
	[STRATAFS_HOOK_LINK_INSTALL]	= { .name = "link-install" },
};

int stratafs_test_hook(enum stratafs_test_hook_point point)
{
	struct stratafs_hook *hook = &stratafs_hooks[point];
	int ret = 0;

	if (likely(!stratafs_test_hooks_on))
		return 0;

	spin_lock(&stratafs_hook_lock);
	switch (hook->mode) {
	case STRATAFS_HOOK_NONE:
		break;
	case STRATAFS_HOOK_FAIL:
		hook->mode = STRATAFS_HOOK_NONE;
		hook->hits++;
		ret = hook->error;
		break;
	case STRATAFS_HOOK_HOLD:
		hook->hits++;
		hook->waiting++;
		spin_unlock(&stratafs_hook_lock);
		ret = wait_event_killable(
			stratafs_hook_wq,
			READ_ONCE(hook->mode) != STRATAFS_HOOK_HOLD);
		spin_lock(&stratafs_hook_lock);
		hook->waiting--;
		break;
	}
	spin_unlock(&stratafs_hook_lock);
	return ret;
}

static ssize_t stratafs_hook_read(struct file *file, char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	static const char * const modes[] = { "none", "hold", "fail" };
	struct stratafs_hook *hook = file->private_data;
	char buf[64];
	int len;

	spin_lock(&stratafs_hook_lock);
	len = scnprintf(buf, sizeof(buf), "%s waiting=%u hits=%u\n",
			modes[hook->mode], hook->waiting, hook->hits);
	spin_unlock(&stratafs_hook_lock);
	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static ssize_t stratafs_hook_write(struct file *file, const char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	struct stratafs_hook *hook = file->private_data;
	char buf[32];
	char *cmd;
	unsigned int err;

	if (count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	cmd = strim(buf);

	spin_lock(&stratafs_hook_lock);
	if (!strcmp(cmd, "hold")) {
		hook->mode = STRATAFS_HOOK_HOLD;
	} else if (!strcmp(cmd, "clear")) {
		hook->mode = STRATAFS_HOOK_NONE;
	} else if (sscanf(cmd, "fail %u", &err) == 1 && err &&
		   err <= MAX_ERRNO) {
		hook->mode = STRATAFS_HOOK_FAIL;
		hook->error = -(int)err;
	} else {
		spin_unlock(&stratafs_hook_lock);
		return -EINVAL;
	}
	spin_unlock(&stratafs_hook_lock);
	wake_up_all(&stratafs_hook_wq);
	return count;
}

static const struct file_operations stratafs_hook_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = stratafs_hook_read,
	.write = stratafs_hook_write,
	.llseek = default_llseek,
};

static int __init stratafs_test_hooks_init(void)
{
	struct dentry *dir;
	struct dentry *file;
	unsigned int i;

	if (!stratafs_test_hooks_on)
		return 0;

	dir = securityfs_create_dir("stratafs", NULL);
	if (IS_ERR(dir)) {
		pr_warn("stratafs: test hooks unavailable: %ld\n", PTR_ERR(dir));
		return 0;
	}
	dir = securityfs_create_dir("hooks", dir);
	if (IS_ERR(dir)) {
		pr_warn("stratafs: test hooks unavailable: %ld\n", PTR_ERR(dir));
		return 0;
	}
	for (i = 0; i < STRATAFS_HOOK_POINTS; i++) {
		file = securityfs_create_file(stratafs_hooks[i].name, 0600, dir,
					      &stratafs_hooks[i],
					      &stratafs_hook_fops);
		if (IS_ERR(file))
			pr_warn("stratafs: test hook %s unavailable: %ld\n",
				stratafs_hooks[i].name, PTR_ERR(file));
	}
	pr_info("stratafs: test hooks registered\n");
	return 0;
}
fs_initcall(stratafs_test_hooks_init);
