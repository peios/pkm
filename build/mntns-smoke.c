// SPDX-License-Identifier: GPL-2.0-only
/*
 * Mount namespaces as KACS objects (PEI-1173), driven through real syscalls.
 *
 * Boots as /init of a minimal initramfs on the KUnit kernel, so it runs on the
 * boot token: SYSTEM, every privilege. The privileged half checks that the
 * root table keeps today's rule and that a privileged private table behaves
 * as upstream Linux has it. The unprivileged half strips every privilege from
 * a child's own token and checks that the child can still get a private table,
 * bind, unmount and pivot inside it, and nothing else -- and that nothing it
 * mounts leaks back into the table it copied.
 *
 * pivot_root refuses to move off the initramfs rootfs, which has no parent
 * mount, so the unprivileged child is first chroot'ed (while still privileged)
 * into a tmpfs the parent prepared; from there a pivot is legal.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* <pkm/syscall.h>, <pkm/token.h> -- the smoke is built with the host libc. */
#define SYS_KACS_OPEN_SELF_TOKEN 1000
#define SYS_KACS_GET_SD 1021
#define SYS_KACS_SET_SD 1022
#define SYS_KACS_SET_MOUNT_POLICY 1027
#define KACS_TOKEN_ADJUST_PRIVS 0x0020U
#define KACS_IOC_MAGIC 0x4BU
#define KACS_PRIVILEGE_ATTR_REMOVED 0x00000004U
#define KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL 3U
#define OWNER_SECURITY_INFORMATION 0x01U
#define GROUP_SECURITY_INFORMATION 0x02U
#define DACL_SECURITY_INFORMATION 0x04U

struct kacs_adjust_privs_args {
	uint32_t count;
	uint32_t _pad;
	uint64_t data_ptr;
	uint64_t previous_enabled;
};

struct kacs_priv_entry {
	uint32_t luid;
	uint32_t attributes;
};

struct kacs_mount_policy_args {
	uint32_t policy;
	uint32_t flags;
	uint32_t generation;
	uint32_t pad0;
	uint64_t template_sd_ptr;
	uint32_t template_sd_len;
	uint32_t pad1;
};

#define KACS_IOC_ADJUST_PRIVS _IOW(KACS_IOC_MAGIC, 1, struct kacs_adjust_privs_args)

/* Every privilege bit <pkm/token.h> defines, by LUID (= bit index). */
static const uint32_t all_privilege_luids[] = {
	2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 17, 18, 19, 20, 21, 23, 24,
	28, 29, 32, 35,
};

static unsigned int checks;

static void power_off(void)
{
	fflush(NULL);
	sync();
	reboot(RB_POWER_OFF);
}

static void fail(const char *what)
{
	int saved_errno = errno;

	fprintf(stderr, "MNTNS_SMOKE_FAIL: %s: errno=%d (%s)\n", what,
		saved_errno, strerror(saved_errno));
	power_off();
	_exit(1);
}

static void check(bool condition, const char *what)
{
	checks++;
	if (!condition) {
		errno = 0;
		fail(what);
	}
}

static void check_errno(int actual, int expected, const char *what)
{
	checks++;
	if (actual != -1 || errno != expected)
		fail(what);
}

static void make_dir(const char *path)
{
	if (mkdir(path, 0755) && errno != EEXIST)
		fail(path);
}

static void write_text(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	ssize_t length = (ssize_t)strlen(text);

	if (fd < 0)
		fail(path);
	if (write(fd, text, length) != length)
		fail("write_text");
	if (close(fd))
		fail("close write_text");
}

static void expect_text(const char *path, const char *expected)
{
	char buffer[256];
	ssize_t length;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		fail(path);
	length = read(fd, buffer, sizeof(buffer) - 1);
	if (length < 0)
		fail("read expect_text");
	buffer[length] = '\0';
	if (close(fd))
		fail("close expect_text");
	checks++;
	if (strcmp(buffer, expected)) {
		fprintf(stderr, "MNTNS_SMOKE_FAIL: %s: got '%s', expected '%s'\n",
			path, buffer, expected);
		power_off();
		_exit(1);
	}
}

static void expect_absent(const char *path)
{
	struct stat st;

	errno = 0;
	check_errno(stat(path, &st), ENOENT, path);
}

/*
 * A fresh tmpfs is deny-missing under KACS: nothing on it carries a
 * descriptor, so nothing on it is reachable. Give it the synthesising
 * policy with the rootfs descriptor as template, as the StrataFS smoke does.
 * Needs the mount privilege; the callers hold it.
 */
static void seed_tmpfs_policy(const char *path)
{
	static unsigned char template_sd[65536];
	static size_t template_sd_len;
	struct kacs_mount_policy_args args = {};
	long length;
	long ret;
	int fd;

	if (!template_sd_len) {
		length = syscall(SYS_KACS_GET_SD, AT_FDCWD, "/",
				 OWNER_SECURITY_INFORMATION |
				 GROUP_SECURITY_INFORMATION |
				 DACL_SECURITY_INFORMATION,
				 template_sd, sizeof(template_sd), 0);
		if (length <= 0 || length > (long)sizeof(template_sd))
			fail("read trusted root security descriptor");
		template_sd_len = (size_t)length;
	}

	fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		fail("open tmpfs root for KACS policy");
	args.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
	args.template_sd_ptr = (uint64_t)(uintptr_t)template_sd;
	args.template_sd_len = (uint32_t)template_sd_len;
	ret = syscall(SYS_KACS_SET_MOUNT_POLICY, fd, &args, sizeof(args));
	if (ret)
		fail("seed tmpfs KACS mount policy");
	ret = syscall(SYS_KACS_SET_SD, AT_FDCWD, path,
		      OWNER_SECURITY_INFORMATION |
		      GROUP_SECURITY_INFORMATION |
		      DACL_SECURITY_INFORMATION,
		      template_sd, template_sd_len, 0);
	if (ret)
		fail("stamp tmpfs root security descriptor");
	close(fd);
}

/*
 * Strip every privilege from this process's own token. Removing a privilege
 * needs only TOKEN_ADJUST_PRIVS on the token, which its owner has, so this is
 * something any process may do to itself.
 */
static void drop_all_privileges(void)
{
	struct kacs_priv_entry entries[sizeof(all_privilege_luids) /
				       sizeof(all_privilege_luids[0])];
	struct kacs_adjust_privs_args args = {
		.count = sizeof(entries) / sizeof(entries[0]),
		.data_ptr = (uint64_t)(uintptr_t)entries,
	};
	size_t i;
	long fd;

	for (i = 0; i < args.count; i++) {
		entries[i].luid = all_privilege_luids[i];
		entries[i].attributes = KACS_PRIVILEGE_ATTR_REMOVED;
	}

	fd = syscall(SYS_KACS_OPEN_SELF_TOKEN, 0U, KACS_TOKEN_ADJUST_PRIVS);
	if (fd < 0)
		fail("open self token");
	if (ioctl((int)fd, KACS_IOC_ADJUST_PRIVS, &args))
		fail("remove every privilege");
	if (close((int)fd))
		fail("close self token");
}

static void wait_for(pid_t child, const char *what)
{
	int status;

	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		errno = 0;
		fail(what);
	}
}

/*
 * The privileged baseline: today's rule, unchanged. SYSTEM may mount in the
 * root table, may take a private table, and a private table taken with the
 * privilege is a peer of the table it copied, so what it mounts propagates
 * back -- exactly as upstream Linux has it for a same-user-namespace copy.
 */
static void test_privileged_baseline(void)
{
	pid_t child;

	if (mount("none", "/newroot", "tmpfs", 0, "mode=0755"))
		fail("mount tmpfs /newroot");
	seed_tmpfs_policy("/newroot");
	make_dir("/newroot/env");
	make_dir("/newroot/env/sub");
	make_dir("/newroot/other");
	write_text("/newroot/env/marker", "inside");
	write_text("/newroot/other/marker", "outside");
	make_dir("/shared-probe");
	write_text("/shared-probe/marker", "root");

	/* Make the root table shared so propagation is observable at all. */
	if (mount(NULL, "/", NULL, MS_SHARED | MS_REC, NULL))
		fail("make / rshared");

	child = fork();
	if (child < 0)
		fail("fork privileged child");
	if (!child) {
		if (unshare(CLONE_NEWNS))
			_exit(2);
		if (mount("none", "/shared-probe", "tmpfs", 0, "mode=0755"))
			_exit(3);
		seed_tmpfs_policy("/shared-probe");
		write_text("/shared-probe/marker", "propagated");
		_exit(0);
	}
	wait_for(child, "privileged child");
	expect_text("/shared-probe/marker", "propagated");
	if (umount2("/shared-probe", MNT_DETACH))
		fail("umount propagated tmpfs");
	expect_text("/shared-probe/marker", "root");
}

/*
 * The unprivileged half, run in a child that has been chroot'ed into the
 * tmpfs and then stripped of every privilege.
 */
static void unprivileged_child(void)
{
	if (chroot("/newroot"))
		_exit(10);
	if (chdir("/"))
		_exit(11);
	drop_all_privileges();

	/* The root table keeps today's rule: no privilege, no mounting. */
	errno = 0;
	check_errno(mount("none", "/other", "tmpfs", 0, NULL), EPERM,
		    "unprivileged tmpfs mount in the root table must be EPERM");
	errno = 0;
	check_errno(mount("/env", "/other", NULL, MS_BIND, NULL), EPERM,
		    "unprivileged bind mount in the root table must be EPERM");

	/* Only a mount namespace is unprivileged; the other types are not. */
	errno = 0;
	check_errno(unshare(CLONE_NEWUTS), EPERM,
		    "unprivileged UTS namespace must stay EPERM");
	errno = 0;
	check_errno(unshare(CLONE_NEWNS | CLONE_NEWUTS), EPERM,
		    "mount namespace with another type must stay EPERM");

	/* A private table needs no privilege. */
	check(unshare(CLONE_NEWNS) == 0,
	      "unprivileged unshare(CLONE_NEWNS) must succeed");

	/*
	 * Inside it, bind, umount, pivot_root and an allowlisted filesystem
	 * are admitted; everything else is not.
	 */
	check(mount("none", "/other", "tmpfs", 0, "mode=0755") == 0,
	      "tmpfs in a private table must succeed");
	write_text("/other/early", "early");
	expect_text("/other/early", "early");
	check(umount2("/other", 0) == 0,
	      "unmount of an own tmpfs must succeed");
	expect_text("/other/marker", "outside");
	errno = 0;
	check_errno(mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL), EPERM,
		    "propagation change in a private table must be EPERM");
	errno = 0;
	check_errno(mount("/env", "/other", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY,
			  NULL), EPERM,
		    "bind-remount in a private table must be EPERM");
	errno = 0;
	check_errno(mount("/env", "/other", NULL, MS_MOVE, NULL), EPERM,
		    "move in a private table must be EPERM");

	check(mount("/env", "/other", NULL, MS_BIND, NULL) == 0,
	      "bind mount in a private table must succeed");
	expect_text("/other/marker", "inside");
	check(umount2("/other", 0) == 0,
	      "unmount of an own bind mount must succeed");
	expect_text("/other/marker", "outside");

	/* Leave one bind in place so the parent can prove it did not leak. */
	check(mount("/env", "/other", NULL, MS_BIND | MS_REC, NULL) == 0,
	      "recursive bind mount in a private table must succeed");
	expect_text("/other/marker", "inside");

	/* Become a process whose whole world is /env. */
	check(mount("/env", "/env", NULL, MS_BIND, NULL) == 0,
	      "bind /env onto itself must succeed");
	if (chdir("/env"))
		fail("chdir /env");
	check(syscall(SYS_pivot_root, ".", ".") == 0,
	      "pivot_root onto the bind must succeed");
	check(umount2(".", MNT_DETACH) == 0,
	      "detaching the old root must succeed");
	if (chdir("/"))
		fail("chdir / after pivot");
	expect_text("/marker", "inside");
	check(access("/sub", F_OK) == 0, "/sub must be the env's own directory");
	expect_absent("/env");
	expect_absent("/other");
	expect_absent("/newroot");

	/*
	 * Inside the private root, tmpfs and proc are admitted; the tmpfs is
	 * stamped with a creator template so its files are reachable at once,
	 * with no privilege to seed it. Every other type stays refused before
	 * the type is even looked up.
	 */
	make_dir("/tmp");
	make_dir("/proc");
	check(mount("none", "/tmp", "tmpfs", 0, "mode=0755") == 0,
	      "tmpfs in a private table must succeed");
	write_text("/tmp/scratch", "scratch");
	expect_text("/tmp/scratch", "scratch");
	make_dir("/tmp/dir");
	write_text("/tmp/dir/nested", "nested");
	expect_text("/tmp/dir/nested", "nested");
	check(mount("none", "/proc", "proc", 0, NULL) == 0,
	      "proc in a private table must succeed");
	check(access("/proc/self/status", R_OK) == 0,
	      "/proc/self/status must be readable in the private proc");
	errno = 0;
	check_errno(mount("none", "/tmp", "ext4", 0, NULL), EPERM,
		    "ext4 in a private table must be EPERM");
	errno = 0;
	check_errno(mount("none", "/tmp", "stratafs", 0, "strata=/sub+ro"), EPERM,
		    "stratafs in a private table must be EPERM");
	errno = 0;
	check_errno(mount("none", "/tmp", "sysfs", 0, NULL), EPERM,
		    "sysfs in a private table must be EPERM");
	check(umount2("/proc", 0) == 0, "unmount of the private proc must succeed");
	check(umount2("/tmp", 0) == 0, "unmount of the private tmpfs must succeed");
	expect_absent("/tmp/scratch");

	printf("MNTNS_SMOKE_CHILD_CHECKS: %u\n", checks);
	fflush(NULL);
	_exit(0);
}

static void test_unprivileged_private_table(void)
{
	pid_t child = fork();

	if (child < 0)
		fail("fork unprivileged child");
	if (!child)
		unprivileged_child();
	wait_for(child, "unprivileged child");

	/*
	 * Nothing the child mounted reached this table: /newroot/other is the
	 * directory it always was, not a mount point.
	 */
	expect_text("/newroot/other/marker", "outside");
	errno = 0;
	check_errno(umount2("/newroot/other", MNT_DETACH), EINVAL,
		    "/newroot/other must not have become a mount point");
	expect_text("/newroot/env/marker", "inside");
	errno = 0;
	check_errno(umount2("/newroot/env", MNT_DETACH), EINVAL,
		    "/newroot/env must not have become a mount point");
}

int main(void)
{
	make_dir("/newroot");
	test_privileged_baseline();
	test_unprivileged_private_table();
	printf("MNTNS_SMOKE_PASS: %u parent checks\n", checks);
	power_off();
	return 0;
}
