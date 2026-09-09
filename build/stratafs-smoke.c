// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define STRATAFS_MAGIC 0x53545241UL
#define SYS_KACS_OPEN 1020
#define SYS_KACS_GET_SD 1021
#define SYS_KACS_SET_SD 1022
#define SYS_KACS_SET_MOUNT_POLICY 1027
#define KACS_DISPOSITION_SUPERSEDE 0U
#define KACS_DISPOSITION_OPEN 1U
#define KACS_DISPOSITION_OVERWRITE 4U
#define KACS_CREATE_OPT_DIRECTORY 0x0001U
#define KACS_CREATE_OPT_DELETE_ON_CLOSE 0x0002U
#define KACS_STATUS_OPENED 1U
#define KACS_STATUS_OVERWRITTEN 3U
#define KACS_STATUS_SUPERSEDED 4U
#define KACS_FILE_READ_DATA 0x00000001U
#define KACS_FILE_WRITE_DATA 0x00000002U
#define KACS_FILE_READ_EA 0x00000008U
#define KACS_FILE_EXECUTE 0x00000020U
#define KACS_ACCESS_DELETE 0x00010000U
#define KACS_ACCESS_SYNCHRONIZE 0x00100000U
#define KACS_ACCESS_GENERIC_ALL 0x10000000U
#define KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL 3U
#define OWNER_SECURITY_INFORMATION 0x01U
#define GROUP_SECURITY_INFORMATION 0x02U
#define DACL_SECURITY_INFORMATION 0x04U
#define RECOVERY_FAKE_COUNT 129U
#define RECOVERY_FAKE_PREFIX ".stratafs-stage-fake-"

struct kacs_mount_policy_args {
	uint32_t policy;
	uint32_t flags;
	uint32_t generation;
	uint32_t pad0;
	uint64_t template_sd_ptr;
	uint32_t template_sd_len;
	uint32_t pad1;
};

struct kacs_open_how {
	uint32_t desired_access;
	uint32_t create_disposition;
	uint32_t create_options;
	uint32_t flags;
	uint64_t sd_ptr;
	uint32_t sd_len;
	uint32_t pad;
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

	fprintf(stderr, "STRATAFS_SMOKE_FAIL: %s: errno=%d (%s)\n",
		what, saved_errno, strerror(saved_errno));
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

static void copy_file(const char *source, const char *destination,
		      mode_t mode)
{
	char buffer[16384];
	ssize_t length;
	int source_fd;
	int destination_fd;

	source_fd = open(source, O_RDONLY | O_CLOEXEC);
	if (source_fd < 0)
		fail("open copy source");
	destination_fd = open(destination,
			      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
	if (destination_fd < 0)
		fail("open copy destination");
	while ((length = read(source_fd, buffer, sizeof(buffer))) > 0) {
		char *cursor = buffer;
		ssize_t remaining = length;

		while (remaining > 0) {
			ssize_t written = write(destination_fd, cursor, remaining);

			if (written < 0)
				fail("write copied file");
			cursor += written;
			remaining -= written;
		}
	}
	if (length < 0)
		fail("read copy source");
	if (close(destination_fd))
		fail("close copy destination");
	if (close(source_fd))
		fail("close copy source");
}

static void read_fd_text(int fd, char *buffer, size_t size)
{
	ssize_t length;

	if (lseek(fd, 0, SEEK_SET) < 0)
		fail("lseek read_fd_text");
	length = read(fd, buffer, size - 1);
	if (length < 0)
		fail("read read_fd_text");
	buffer[length] = '\0';
}

static void expect_text(const char *path, const char *expected)
{
	char buffer[256];
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		fail(path);
	read_fd_text(fd, buffer, sizeof(buffer));
	if (close(fd))
		fail("close expect_text");
	checks++;
	if (strcmp(buffer, expected)) {
		fprintf(stderr,
			"STRATAFS_SMOKE_FAIL: %s: got '%s', expected '%s'\n",
			path, buffer, expected);
		power_off();
		_exit(1);
	}
}

static bool directory_has(DIR *dir, const char *name)
{
	struct dirent *entry;

	errno = 0;
	while ((entry = readdir(dir)) != NULL) {
		if (!strcmp(entry->d_name, name))
			return true;
	}
	if (errno)
		fail("readdir");
	return false;
}

static void expect_directory_name(const char *path, const char *name)
{
	DIR *dir = opendir(path);

	if (!dir)
		fail(path);
	check(directory_has(dir, name), name);
	if (closedir(dir))
		fail("closedir");
}

static void expect_directory_exhaustible(const char *path)
{
	DIR *dir = opendir(path);

	if (!dir)
		fail(path);
	errno = 0;
	while (readdir(dir) != NULL)
		;
	if (errno)
		fail("exhaust directory");
	if (closedir(dir))
		fail("close exhausted directory");
	check(true, "directory must be exhaustible without an iterator error");
}

static void expect_getdents_bounded(const char *path)
{
	char buffer[4096];
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd < 0)
		fail(path);
	for (;;) {
		long ret = syscall(SYS_getdents64, fd, buffer, sizeof(buffer));

		if (ret < 0)
			fail("getdents64");
		if (ret > (long)sizeof(buffer))
			fail("getdents64 returned more bytes than its buffer");
		if (!ret)
			break;
	}
	if (close(fd))
		fail("close getdents64 directory");
	check(true, "getdents64 result must remain bounded by its buffer");
}

static bool mountinfo_has(const char *mountpoint, const char *fragment)
{
	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	FILE *mountinfo;
	bool found = false;

	mountinfo = fopen("/proc/self/mountinfo", "re");
	if (!mountinfo)
		fail("open mountinfo");
	while ((length = getline(&line, &capacity, mountinfo)) >= 0) {
		(void)length;
		if (strstr(line, mountpoint) && strstr(line, " - stratafs ") &&
		    strstr(line, fragment)) {
			found = true;
			break;
		}
	}
	if (ferror(mountinfo))
		fail("read mountinfo");
	free(line);
	if (fclose(mountinfo))
		fail("close mountinfo");
	return found;
}

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

static int kacs_open_disposition(const char *path, uint32_t desired_access,
				 uint32_t disposition,
				 uint32_t create_options,
				 uint32_t expected_status)
{
	struct kacs_open_how how = {
		.desired_access = desired_access,
		.create_disposition = disposition,
		.create_options = create_options,
	};
	uint32_t status = 0;
	int fd;

	fd = (int)syscall(SYS_KACS_OPEN, AT_FDCWD, path, &how, sizeof(how),
			  &status);
	if (fd < 0) {
		fprintf(stderr, "kacs_open path: %s\n", path);
		fail("kacs_open StrataFS object");
	}
	check(status == expected_status, "kacs_open disposition status");
	return fd;
}

static int kacs_open_path(const char *path, uint32_t desired_access,
			  uint32_t create_options)
{
	return kacs_open_disposition(path, desired_access,
				     KACS_DISPOSITION_OPEN, create_options,
				     KACS_STATUS_OPENED);
}

static void test_fsync_snapshot_gate(void)
{
	char value[64];
	int fd;

	fd = kacs_open_path("/merged/lowonly", KACS_FILE_READ_DATA, 0);
	read_fd_text(fd, value, sizeof(value));
	check(!strcmp(value, "lower-data"),
	      "native handle without SYNCHRONIZE must retain its data grant");
	errno = 0;
	check_errno(fsync(fd), EACCES,
		    "fsync must require the handle SYNCHRONIZE snapshot");
	errno = 0;
	check_errno(fdatasync(fd), EACCES,
		    "fdatasync must require the handle SYNCHRONIZE snapshot");
	close(fd);

	fd = kacs_open_path("/merged/lowonly",
			    KACS_FILE_READ_DATA | KACS_ACCESS_SYNCHRONIZE, 0);
	if (fsync(fd) || fdatasync(fd))
		fail("synchronize-granted StrataFS file");
	close(fd);

	fd = kacs_open_path("/merged/dir",
			    KACS_FILE_READ_DATA | KACS_FILE_EXECUTE |
				    KACS_FILE_READ_EA,
			    KACS_CREATE_OPT_DIRECTORY);
	errno = 0;
	check_errno(fsync(fd), EACCES,
		    "directory fsync must require the handle SYNCHRONIZE snapshot");
	close(fd);

	fd = kacs_open_path("/merged/dir",
			    KACS_FILE_READ_DATA | KACS_FILE_EXECUTE |
				    KACS_FILE_READ_EA | KACS_ACCESS_SYNCHRONIZE,
			    KACS_CREATE_OPT_DIRECTORY);
	if (fsync(fd))
		fail("synchronize-granted merged directory");
	close(fd);
}

static void setup_strata(void)
{
	char path[128];
	unsigned int index;

	make_dir("/proc");
	if (mount("proc", "/proc", "proc", 0, NULL))
		fail("mount proc");
	make_dir("/lower0");
	make_dir("/lower1");
	make_dir("/merged");
	make_dir("/absent-mount");
	make_dir("/invalid-mount");
	make_dir("/escaped-mount");
	if (mount("tmpfs", "/lower0", "tmpfs", 0, "mode=0755"))
		fail("mount lower0");
	if (mount("tmpfs", "/lower1", "tmpfs", 0, "mode=0755"))
		fail("mount lower1");
	seed_tmpfs_policy("/lower0");
	seed_tmpfs_policy("/lower1");

	write_text("/lower0/highonly", "high-only");
	write_text("/lower0/common", "high-common");
	write_text("/lower0/mask", "mask-file");
	write_text("/lower0/native-supersede", "supersede-old");
	write_text("/lower0/native-delete", "delete-me");
	make_dir("/lower0/dir");
	write_text("/lower0/dir/high", "high-dir");

	write_text("/lower1/lowonly", "lower-data");
	write_text("/lower1/common", "low-common");
	write_text("/lower1/lowdest", "lower-destination");
	write_text("/lower1/hard_a", "hard-data");
	if (link("/lower1/hard_a", "/lower1/hard_b"))
		fail("lower hard link");
	write_text("/lower1/distinct", "distinct");
	make_dir("/lower1/dir");
	write_text("/lower1/dir/low", "low-dir");
	make_dir("/lower1/mask");
	write_text("/lower1/mask/child", "masked-child");
	make_dir("/lower1/hold");
	write_text("/lower1/hold/child", "held-child");
	make_dir("/lower1/nested-mask");
	make_dir("/lower1/nested-mask/held");
	write_text("/lower1/nested-mask/held/child", "nested-held-child");
	make_dir("/lower1/settled");
	write_text("/lower1/settled/low", "settled-low");
	write_text("/lower1/coherent", "coherent-low");
	write_text("/lower1/mmapfile", "mmap-lower");
	write_text("/lower1/mmap-upgrade", "upgrade-old");
	write_text("/lower1/lockfile", "lock-lower");
	write_text("/lower1/posix-lockfile", "posix-lock-lower");
	write_text("/lower1/ofd-lockfile", "ofd-lock-lower");
	write_text("/lower1/leasefile", "lease-lower");
	write_text("/lower1/xfile", "xattr-lower");
	write_text("/lower1/native-overwrite", "overwrite-old");
	write_text("/lower1/o-trunc-copyup", "copyup-truncate-old");
	write_text("/lower1/native-ftruncate", "ftruncate-old");
	write_text("/lower1/native-supersede-ro", "supersede-ro");
	write_text("/lower1/native-delete-ro", "keep-me");
	copy_file("/init", "/lower1/applet-host", 0755);
	if (symlink("applet-host", "/lower1/applet-link"))
		fail("lower executable applet symlink");
	if (setxattr("/lower1/xfile", "user.original", "preserved", 9, 0))
		fail("set lower xattr");
	make_dir("/lower1/deep");
	make_dir("/lower1/deep/a");
	write_text("/lower1/deep/a/provider", "deep-lower");
	write_text("/lower1/deep/a/unrelated", "do-not-copy");
	make_dir("/lower1/createparent");
	write_text("/lower1/exclusive", "exists-low");
	if (symlink("../common", "/lower1/sym"))
		fail("lower symlink");
	make_dir("/lower0/escape:plus+,comma\\back");
	write_text("/lower0/escape:plus+,comma\\back/value", "escaped-path");
	make_dir("/lower0/recovery-batch");
	for (index = 0; index < RECOVERY_FAKE_COUNT; index++) {
		snprintf(path, sizeof(path),
			 "/lower0/recovery-batch/%s%03u",
			 RECOVERY_FAKE_PREFIX, index);
		write_text(path, "not-private-staging");
	}
}

static int executable_probe_status(const char *path)
{
	pid_t child;
	int status;

	child = fork();
	if (child < 0)
		fail("fork executable probe");
	if (!child) {
		execl(path, "stratafs-smoke", "--exec-probe", NULL);
		_exit(errno == EACCES ? 126 : 127);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
		fail("wait executable probe");
	return WEXITSTATUS(status);
}

static void test_relative_symlink_execution(void)
{
	check(access("/lower1/applet-link", X_OK) == 0,
	      "direct provider applet symlink must be executable");
	check(executable_probe_status("/lower1/applet-link") == 73,
	      "direct provider applet symlink must execute");
	check(access("/merged/applet-link", X_OK) == 0,
	      "merged applet symlink must be executable");
	check(executable_probe_status("/merged/applet-link") == 73,
	      "merged applet symlink must execute");
}

static void test_staging_recovery_batches(void)
{
	struct dirent *entry;
	unsigned int found = 0;
	DIR *dir;

	dir = opendir("/merged/recovery-batch");
	if (!dir)
		fail("open recovery batch directory");
	errno = 0;
	while ((entry = readdir(dir)) != NULL) {
		if (!strncmp(entry->d_name, RECOVERY_FAKE_PREFIX,
			     strlen(RECOVERY_FAKE_PREFIX)))
			found++;
	}
	if (errno)
		fail("read recovery batch directory");
	if (closedir(dir))
		fail("close recovery batch directory");
	check(found == RECOVERY_FAKE_COUNT,
	      "multi-batch recovery must preserve unmarked stage-like names");
}

static void test_lookup_and_identity(void)
{
	struct stat hard_a;
	struct stat hard_b;
	struct stat distinct;
	struct stat provider;
	char link_value[64];
	ssize_t length;
	int fd;

	expect_text("/merged/highonly", "high-only");
	expect_text("/merged/lowonly", "lower-data");
	expect_text("/merged/common", "high-common");
	expect_directory_name("/merged/dir", "high");
	expect_directory_name("/merged/dir", "low");

	errno = 0;
	fd = open("/merged/mask/child", O_RDONLY | O_CLOEXEC);
	check_errno(fd, ENOTDIR, "higher file must mask lower directory");

	if (stat("/merged/hard_a", &hard_a) ||
	    stat("/merged/hard_b", &hard_b) ||
	    stat("/merged/distinct", &distinct) ||
	    stat("/lower1/hard_a", &provider))
		fail("stat identity");
	check(hard_a.st_dev == hard_b.st_dev && hard_a.st_ino == hard_b.st_ino,
	      "hard links must report equal merged identity");
	check(hard_a.st_ino != distinct.st_ino,
	      "distinct providers must report distinct inode numbers");
	check(hard_a.st_dev != provider.st_dev,
	      "merged device must differ from provider device");

	length = readlink("/merged/sym", link_value, sizeof(link_value) - 1);
	if (length < 0)
		fail("readlink merged symlink");
	link_value[length] = '\0';
	check(!strcmp(link_value, "../common"), "symlink target must be verbatim");
}

static void test_origin_and_statfs(void)
{
	char value[512];
	char list[512];
	struct statfs lower;
	struct statfs merged;
	ssize_t length;
	ssize_t offset;

	length = getxattr("/merged/lowonly", "system.stratafs.origin", value,
			  sizeof(value) - 1);
	if (length < 0)
		fail("get origin file");
	value[length] = '\0';
	check(!strcmp(value, "/lower1/lowonly"), "file origin must name provider");

	length = getxattr("/merged/dir", "system.stratafs.origin", value,
			  sizeof(value) - 1);
	if (length < 0)
		fail("get origin directory");
	value[length] = '\0';
	check(!strcmp(value, "/lower0/dir\n/lower1/dir"),
	      "directory origin must list participants in precedence order");

	length = listxattr("/merged/lowonly", list, sizeof(list));
	if (length < 0)
		fail("list merged xattrs");
	for (offset = 0; offset < length;
	     offset += (ssize_t)strlen(list + offset) + 1)
		check(strcmp(list + offset, "system.stratafs.origin") != 0,
		      "origin must be hidden from xattr listing");

	errno = 0;
	check_errno(getxattr("/merged/lowonly", "system.stratafs.unknown",
			     value, sizeof(value)), ENODATA,
		    "reserved synthetic xattr read");
	errno = 0;
	check_errno(setxattr("/merged/lowonly", "system.stratafs.origin",
			     "x", 1, 0), EPERM,
		    "origin must not be settable");

	if (statfs("/lower0", &lower) || statfs("/merged", &merged))
		fail("statfs");
	check((unsigned long)merged.f_type == STRATAFS_MAGIC,
	      "statfs must report stratafs magic");
	check(merged.f_blocks == lower.f_blocks &&
	      merged.f_bfree == lower.f_bfree &&
	      merged.f_namelen == lower.f_namelen,
	      "statfs must use create stratum capacity and name limit");
}

static void test_copy_up_descriptors(void)
{
	char buffer[256];
	char xvalue[32];
	struct stat mut_before;
	struct stat mut_after;
	struct stat path_after;
	ssize_t length;
	int old_fd;
	int mut_fd;
	int xfd;

	old_fd = open("/merged/lowonly", O_RDONLY | O_CLOEXEC);
	mut_fd = open("/merged/lowonly", O_RDWR | O_CLOEXEC);
	if (old_fd < 0 || mut_fd < 0)
		fail("open copy-up descriptors");
	if (fstat(mut_fd, &mut_before))
		fail("fstat before copy-up");
	if (pwrite(mut_fd, "COPIED", 6, 0) != 6)
		fail("pwrite copy-up");
	if (fsync(mut_fd))
		fail("fsync copied-up descriptor");
	read_fd_text(mut_fd, buffer, sizeof(buffer));
	check(!strcmp(buffer, "COPIEDdata"),
	      "mutating descriptor must be rebound to copy");
	read_fd_text(old_fd, buffer, sizeof(buffer));
	check(!strcmp(buffer, "lower-data"),
	      "other open descriptor must retain original provider");
	if (fstat(mut_fd, &mut_after) || stat("/merged/lowonly", &path_after))
		fail("stat after copy-up");
	check(mut_before.st_ino == mut_after.st_ino,
	      "mutating descriptor inode number must remain stable");
	check(mut_after.st_ino != path_after.st_ino,
	      "fresh resolution must receive a new inode after copy-up");
	expect_text("/lower0/lowonly", "COPIEDdata");
	expect_text("/lower1/lowonly", "lower-data");
	length = getxattr("/merged/lowonly", "system.stratafs.origin", buffer,
			  sizeof(buffer) - 1);
	if (length < 0)
		fail("origin after copy-up");
	buffer[length] = '\0';
	check(!strcmp(buffer, "/lower0/lowonly"),
	      "origin must change to copied-up provider");
	length = fgetxattr(old_fd, "system.stratafs.origin", buffer,
			   sizeof(buffer) - 1);
	if (length < 0)
		fail("origin on descriptor retaining old provider");
	buffer[length] = '\0';
	check(!strcmp(buffer, "/lower1/lowonly"),
	      "old descriptor origin must retain the original provider");
	length = fgetxattr(mut_fd, "system.stratafs.origin", buffer,
			   sizeof(buffer) - 1);
	if (length < 0)
		fail("origin on descriptor rebound by copy-up");
	buffer[length] = '\0';
	check(!strcmp(buffer, "/lower0/lowonly"),
	      "mutating descriptor origin must follow its copy-up rebind");
	close(old_fd);
	close(mut_fd);

	if (setxattr("/merged/xfile", "user.added", "new", 3, 0))
		fail("xattr-triggered copy-up");
	length = getxattr("/lower0/xfile", "user.original", xvalue,
			  sizeof(xvalue));
	check(length == 9 && !memcmp(xvalue, "preserved", 9),
	      "copy-up must preserve existing xattrs");
	length = getxattr("/lower0/xfile", "user.added", xvalue,
			  sizeof(xvalue));
	check(length == 3 && !memcmp(xvalue, "new", 3),
	      "metadata mutation must reach copy");

	xfd = open("/merged/deep/a/provider", O_RDWR | O_CLOEXEC);
	if (xfd < 0 || pwrite(xfd, "DEEP", 4, 0) != 4)
		fail("deep parent materialization copy-up");
	close(xfd);
	check(!access("/lower0/deep/a/provider", F_OK),
	      "copy-up must materialize missing parents");
	check(access("/lower0/deep/a/unrelated", F_OK) == -1 && errno == ENOENT,
	      "parent materialization must not copy directory contents");
}

static void test_mmap_copy_up(void)
{
	char *mapping;
	int fd;

	fd = open("/merged/mmapfile", O_RDWR | O_CLOEXEC);

	if (fd < 0)
		fail("open mmap file");
	mapping = mmap(NULL, 10, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED)
		fail("shared writable mmap");
	check(!access("/lower0/mmapfile", F_OK),
	      "shared writable mmap must copy up at establishment");
	memcpy(mapping, "MMAP", 4);
	if (msync(mapping, 10, MS_SYNC))
		fail("msync copied mapping");
	if (munmap(mapping, 10))
		fail("munmap");
	close(fd);
	expect_text("/lower0/mmapfile", "MMAP-lower");
	expect_text("/lower1/mmapfile", "mmap-lower");

	fd = open("/merged/mmap-upgrade", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		fail("open mprotect-upgrade file");
	mapping = mmap(NULL, 11, PROT_READ, MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED)
		fail("shared write-upgradable mmap");
	check(!access("/lower0/mmap-upgrade", F_OK),
	      "shared write-upgradable mmap must copy up at establishment");
	if (mprotect(mapping, 11, PROT_READ | PROT_WRITE))
		fail("mprotect shared mapping writable");
	memcpy(mapping, "UPGRADE", 7);
	if (msync(mapping, 11, MS_SYNC))
		fail("msync upgraded mapping");
	if (munmap(mapping, 11))
		fail("munmap upgraded mapping");
	close(fd);
	expect_text("/lower0/mmap-upgrade", "UPGRADE-old");
	expect_text("/lower1/mmap-upgrade", "upgrade-old");
}

static void test_lock_survives_copy_up(void)
{
	int fd;
	int lower_fd;

	fd = open("/merged/lockfile", O_RDWR | O_CLOEXEC);
	if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB))
		fail("lock merged provider before copy-up");
	if (pwrite(fd, "COPY", 4, 0) != 4)
		fail("copy up locked file");
	lower_fd = open("/lower1/lockfile", O_RDWR | O_CLOEXEC);
	if (lower_fd < 0)
		fail("open original provider after locked copy-up");
	errno = 0;
	check_errno(flock(lower_fd, LOCK_EX | LOCK_NB), EWOULDBLOCK,
		    "copy-up must retain a lock on the original provider");
	if (flock(fd, LOCK_UN))
		fail("unlock copied-up descriptor");
	if (flock(lower_fd, LOCK_EX | LOCK_NB))
		fail("unlock must release the retained provider lock");
	flock(lower_fd, LOCK_UN);
	close(lower_fd);
	close(fd);
}

static void test_ofd_lock_close_after_copy_up(void)
{
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
	};
	int fd;
	int lower_fd;

	fd = open("/merged/ofd-lockfile", O_RDWR | O_CLOEXEC);
	if (fd < 0 || fcntl(fd, F_OFD_SETLK, &lock))
		fail("take OFD lock through merged file");
	if (pwrite(fd, "COPY", 4, 0) != 4)
		fail("copy up OFD-locked file");
	lower_fd = open("/lower1/ofd-lockfile", O_RDWR | O_CLOEXEC);
	if (lower_fd < 0)
		fail("open original provider for OFD lock test");
	errno = 0;
	check(fcntl(lower_fd, F_OFD_SETLK, &lock) == -1 &&
	      (errno == EAGAIN || errno == EACCES),
	      "OFD lock must remain on original provider after copy-up");
	close(fd);
	check(fcntl(lower_fd, F_OFD_SETLK, &lock) == 0,
	      "closing merged descriptor must release provider OFD lock");
	lock.l_type = F_UNLCK;
	if (fcntl(lower_fd, F_OFD_SETLK, &lock))
		fail("release direct OFD lock");
	close(lower_fd);
}

static int child_posix_lock_result(const char *path)
{
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
	};
	pid_t child;
	int status;

	child = fork();
	if (child < 0)
		fail("fork POSIX lock contender");
	if (!child) {
		int fd = open(path, O_RDWR | O_CLOEXEC);
		int result;

		if (fd < 0)
			_exit(3);
		result = fcntl(fd, F_SETLK, &lock);
		if (!result) {
			lock.l_type = F_UNLCK;
			fcntl(fd, F_SETLK, &lock);
			close(fd);
			_exit(0);
		}
		result = errno;
		close(fd);
		_exit(result == EAGAIN || result == EACCES ? 1 : 2);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
		fail("wait POSIX lock contender");
	return WEXITSTATUS(status);
}

static void test_posix_lock_close_after_copy_up(void)
{
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
	};
	int fd;

	fd = open("/merged/posix-lockfile", O_RDWR | O_CLOEXEC);
	if (fd < 0 || fcntl(fd, F_SETLK, &lock))
		fail("take POSIX lock through merged file");
	if (pwrite(fd, "COPY", 4, 0) != 4)
		fail("copy up POSIX-locked file");
	check(child_posix_lock_result("/lower1/posix-lockfile") == 1,
	      "POSIX lock must remain on original provider after copy-up");
	close(fd);
	check(child_posix_lock_result("/lower1/posix-lockfile") == 0,
	      "closing merged descriptor must release provider POSIX lock");
}

static void test_lease_survives_copy_up(void)
{
	int fd = open("/merged/leasefile", O_RDWR | O_CLOEXEC);

	if (fd < 0)
		fail("open merged lease file");
	check(fcntl(fd, F_SETLEASE, F_WRLCK) == 0,
	      "establish lease on provider through merged file");
	check(fcntl(fd, F_GETLEASE) == F_WRLCK,
	      "query provider lease through merged file");
	if (fsetxattr(fd, "user.copy-up", "lease", 5, 0))
		fail("copy up leased file through descriptor metadata");
	if (pwrite(fd, "COPY", 4, 0) != 4)
		fail("write through metadata-rebound leased file");
	check(fcntl(fd, F_GETLEASE) == F_WRLCK,
	      "lease query must follow original provider after copy-up");
	check(fcntl(fd, F_SETLEASE, F_RDLCK) == 0 &&
	      fcntl(fd, F_GETLEASE) == F_RDLCK,
	      "lease change must reach original provider after copy-up");
	check(fcntl(fd, F_SETLEASE, F_UNLCK) == 0 &&
	      fcntl(fd, F_GETLEASE) == F_UNLCK,
	      "lease unlock must reach original provider after copy-up");
	close(fd);
}

static void test_creation_links_rename_remove(void)
{
	struct stat first;
	struct stat second;
	int fd;
	long ret;

	write_text("/merged/newfile", "new-data");
	expect_text("/lower0/newfile", "new-data");
	write_text("/merged/createparent/new", "nested-create");
	expect_text("/lower0/createparent/new", "nested-create");

	errno = 0;
	fd = open("/merged/exclusive",
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	check_errno(fd, EEXIST, "exclusive create must see lower provider");

	fd = open("/merged", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
	if (fd < 0)
		fail("O_TMPFILE in merged directory");
	if (write(fd, "tmp-data", 8) != 8)
		fail("write unnamed file");
	if (linkat(fd, "", AT_FDCWD, "/merged/tmp_link", AT_EMPTY_PATH))
		fail("link unnamed file");
	close(fd);
	expect_text("/lower0/tmp_link", "tmp-data");

	if (link("/merged/newfile", "/merged/newlink"))
		fail("hard link in provider");
	if (stat("/merged/newfile", &first) ||
	    stat("/merged/newlink", &second))
		fail("stat created links");
	check(first.st_dev == second.st_dev && first.st_ino == second.st_ino,
	      "new hard links must share merged identity");
	errno = 0;
	check_errno(link("/merged/hard_a", "/merged/lowlink"), EXDEV,
		    "hard link must not copy up read-only source");

	if (rename("/merged/newfile", "/merged/newlink"))
		fail("same-object hard-link rename");
	check(!access("/merged/newfile", F_OK) &&
	      !access("/merged/newlink", F_OK),
	      "same-object rename must preserve both names");

	write_text("/merged/rename_src", "rename-data");
	if (rename("/merged/rename_src", "/merged/rename_dst"))
		fail("normal rename");
	check(access("/merged/rename_src", F_OK) == -1 && errno == ENOENT,
	      "renamed source must disappear");
	expect_text("/merged/rename_dst", "rename-data");

	write_text("/merged/temp", "atomic-replacement");
	if (rename("/merged/temp", "/merged/lowdest"))
		fail("rename over lower destination");
	expect_text("/merged/lowdest", "atomic-replacement");
	expect_text("/lower1/lowdest", "lower-destination");

	write_text("/merged/exchange_a", "A");
	write_text("/merged/exchange_b", "B");
	ret = syscall(SYS_renameat2, AT_FDCWD, "/merged/exchange_a",
		      AT_FDCWD, "/merged/exchange_b", RENAME_EXCHANGE);
	if (ret)
		fail("RENAME_EXCHANGE");
	expect_text("/merged/exchange_a", "B");
	expect_text("/merged/exchange_b", "A");

	write_text("/merged/noreplace_src", "noreplace");
	errno = 0;
	ret = syscall(SYS_renameat2, AT_FDCWD, "/merged/noreplace_src",
		      AT_FDCWD, "/merged/exclusive", RENAME_NOREPLACE);
	check_errno((int)ret, EEXIST,
		    "RENAME_NOREPLACE must see every participating stratum");
	expect_text("/merged/noreplace_src", "noreplace");

	write_text("/merged/whiteout_src", "whiteout");
	errno = 0;
	ret = syscall(SYS_renameat2, AT_FDCWD, "/merged/whiteout_src",
		      AT_FDCWD, "/merged/whiteout_dst", RENAME_WHITEOUT);
	check_errno((int)ret, EINVAL, "RENAME_WHITEOUT must be rejected");
	expect_text("/merged/whiteout_src", "whiteout");

	errno = 0;
	ret = syscall(SYS_renameat2, AT_FDCWD, "/merged/highonly",
		      AT_FDCWD, "/merged/distinct", RENAME_EXCHANGE);
	check_errno((int)ret, EROFS,
		    "RENAME_EXCHANGE must not span provider strata");
	expect_text("/merged/highonly", "high-only");
	expect_text("/merged/distinct", "distinct");

	write_text("/merged/remove_me", "remove");
	if (unlink("/merged/remove_me"))
		fail("unlink create provider");
	errno = 0;
	check_errno(unlink("/merged/hard_a"), EROFS,
		    "unlink read-only provider must fail");
}

static void test_mount_option_escapes_and_reporting(void)
{
	static const char option[] =
		"strata=/lower0/escape\\:plus\\+\\,comma\\\\back+ro";
	static const char reported[] =
		"strata=/lower0/escape\\:plus\\+\\,comma\\\\back+ro";
	char origin[256];
	ssize_t length;

	if (mount("none", "/escaped-mount", "stratafs", 0, option))
		fail("mount escaped stratum path");
	expect_text("/escaped-mount/value", "escaped-path");
	length = getxattr("/escaped-mount/value", "system.stratafs.origin",
			  origin, sizeof(origin) - 1);
	if (length < 0)
		fail("get escaped origin");
	origin[length] = '\0';
	check(!strcmp(origin,
		      "/lower0/escape:plus+,comma\\\\back/value"),
	      "origin must escape a provider-path backslash");
	check(mountinfo_has(" /escaped-mount ", reported),
	      "mount table must reconstruct escaped stack and filesystem type");
	if (umount("/escaped-mount"))
		fail("umount escaped stratum path");
}

static void test_native_dispositions(void)
{
	struct kacs_open_how supersede_ro = {
		.desired_access = KACS_FILE_WRITE_DATA | KACS_ACCESS_DELETE,
		.create_disposition = KACS_DISPOSITION_SUPERSEDE,
	};
	uint32_t status = 0;
	const char *replacement;
	int fd;

	fd = kacs_open_disposition("/merged/native-overwrite",
				   KACS_FILE_WRITE_DATA,
				   KACS_DISPOSITION_OVERWRITE, 0,
				   KACS_STATUS_OVERWRITTEN);
	replacement = "overwrite-new";
	if (write(fd, replacement, strlen(replacement)) !=
	    (ssize_t)strlen(replacement))
		fail("write native overwrite");
	if (close(fd))
		fail("close native overwrite");
	expect_text("/merged/native-overwrite", replacement);
	expect_text("/lower0/native-overwrite", replacement);
	expect_text("/lower1/native-overwrite", "overwrite-old");

	/* Reproduce open(O_TRUNC) against an object already in create. */
	write_text("/merged/in-place-truncate", "truncate-old");
	fd = open("/merged/in-place-truncate",
		  O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd < 0)
		fail("open in-place O_TRUNC");
	replacement = "truncate-new";
	if (write(fd, replacement, strlen(replacement)) !=
	    (ssize_t)strlen(replacement))
		fail("write after in-place O_TRUNC");
	if (close(fd))
		fail("close in-place O_TRUNC");
	expect_text("/merged/in-place-truncate", replacement);
	expect_text("/lower0/in-place-truncate", replacement);

	/* O_TRUNC must copy a read-only provider up before truncating it. */
	fd = open("/merged/o-trunc-copyup", O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd < 0)
		fail("open copy-up O_TRUNC");
	replacement = "copyup-truncate-new";
	if (write(fd, replacement, strlen(replacement)) !=
	    (ssize_t)strlen(replacement))
		fail("write after copy-up O_TRUNC");
	if (close(fd))
		fail("close copy-up O_TRUNC");
	expect_text("/merged/o-trunc-copyup", replacement);
	expect_text("/lower0/o-trunc-copyup", replacement);
	expect_text("/lower1/o-trunc-copyup", "copyup-truncate-old");

	/* Match a provider created directly after StrataFS was mounted. */
	write_text("/lower1/late-o-trunc-copyup", "late-copyup-old");
	fd = open("/merged/late-o-trunc-copyup",
		  O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd < 0)
		fail("open late-provider copy-up O_TRUNC");
	replacement = "late-copyup-new";
	if (write(fd, replacement, strlen(replacement)) !=
	    (ssize_t)strlen(replacement))
		fail("write after late-provider copy-up O_TRUNC");
	if (close(fd))
		fail("close late-provider copy-up O_TRUNC");
	expect_text("/merged/late-o-trunc-copyup", replacement);
	expect_text("/lower0/late-o-trunc-copyup", replacement);
	expect_text("/lower1/late-o-trunc-copyup", "late-copyup-old");

	fd = open("/merged/native-ftruncate", O_WRONLY);
	if (fd < 0)
		fail("open ftruncate copy-up");
	if (ftruncate(fd, 0))
		fail("ftruncate copy-up");
	replacement = "ftruncate-new";
	if (write(fd, replacement, strlen(replacement)) !=
	    (ssize_t)strlen(replacement))
		fail("write after ftruncate copy-up");
	if (close(fd))
		fail("close ftruncate copy-up");
	expect_text("/merged/native-ftruncate", replacement);
	expect_text("/lower0/native-ftruncate", replacement);
	expect_text("/lower1/native-ftruncate", "ftruncate-old");

	fd = kacs_open_disposition("/merged/native-supersede",
				   KACS_FILE_WRITE_DATA | KACS_ACCESS_DELETE,
				   KACS_DISPOSITION_SUPERSEDE, 0,
				   KACS_STATUS_SUPERSEDED);
	replacement = "supersede-new";
	if (write(fd, replacement, strlen(replacement)) !=
	    (ssize_t)strlen(replacement))
		fail("write native supersede");
	if (close(fd))
		fail("close native supersede");
	expect_text("/merged/native-supersede", replacement);

	errno = 0;
	fd = (int)syscall(SYS_KACS_OPEN, AT_FDCWD,
			  "/merged/native-supersede-ro", &supersede_ro,
			  sizeof(supersede_ro), &status);
	check_errno(fd, EROFS,
		    "native supersede must not remove a read-only provider");
	expect_text("/merged/native-supersede-ro", "supersede-ro");

	fd = kacs_open_disposition(
		"/merged/native-delete",
		KACS_FILE_READ_DATA | KACS_ACCESS_DELETE,
		KACS_DISPOSITION_OPEN, KACS_CREATE_OPT_DELETE_ON_CLOSE,
		KACS_STATUS_OPENED);
	if (close(fd))
		fail("close native delete-on-close");
	errno = 0;
	check_errno(access("/merged/native-delete", F_OK), ENOENT,
		    "delete-on-close must remove the opened provider object");

	fd = kacs_open_disposition(
		"/merged/native-delete-ro",
		KACS_FILE_READ_DATA | KACS_ACCESS_DELETE,
		KACS_DISPOSITION_OPEN, KACS_CREATE_OPT_DELETE_ON_CLOSE,
		KACS_STATUS_OPENED);
	if (close(fd))
		fail("close refused native delete-on-close");
	expect_text("/merged/native-delete-ro", "keep-me");
}

static void test_same_filesystem_copy_up_truncate(void)
{
	const char *replacement = "same-filesystem-new";
	int fd;

	make_dir("/same-lower");
	make_dir("/same-merged");
	if (mount("tmpfs", "/same-lower", "tmpfs", 0, "mode=0755"))
		fail("mount same-filesystem lower");
	seed_tmpfs_policy("/same-lower");
	make_dir("/same-lower/a");
	make_dir("/same-lower/b");
	if (mount("none", "/same-merged", "stratafs", 0,
		  "strata=/same-lower/b+create:/same-lower/a+ro"))
		fail("mount same-filesystem stratafs");

	write_text("/same-lower/a/hello", "");
	fd = open("/same-merged/hello", O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd < 0)
		fail("open same-filesystem copy-up O_TRUNC");
	if (write(fd, replacement, strlen(replacement)) !=
	    (ssize_t)strlen(replacement))
		fail("write same-filesystem copy-up O_TRUNC");
	if (close(fd))
		fail("close same-filesystem copy-up O_TRUNC");
	expect_text("/same-merged/hello", replacement);
	expect_text("/same-lower/b/hello", replacement);
	expect_text("/same-lower/a/hello", "");

	if (umount("/same-merged"))
		fail("umount same-filesystem stratafs");
	if (umount("/same-lower"))
		fail("umount same-filesystem lower");
}

static void test_rootfs_copy_up_truncate(void)
{
	const char *replacement = "rootfs-new";
	int fd;

	make_dir("/rootfs-a");
	make_dir("/rootfs-b");
	make_dir("/rootfs-merged");
	if (mount("none", "/rootfs-merged", "stratafs", 0,
		  "strata=/rootfs-b+create:/rootfs-a+ro"))
		fail("mount rootfs-backed stratafs");

	write_text("/rootfs-a/hello", "");
	fd = open("/rootfs-merged/hello", O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd < 0)
		fail("open rootfs copy-up O_TRUNC");
	if (write(fd, replacement, strlen(replacement)) !=
	    (ssize_t)strlen(replacement))
		fail("write rootfs copy-up O_TRUNC");
	if (close(fd))
		fail("close rootfs copy-up O_TRUNC");
	expect_text("/rootfs-merged/hello", replacement);
	expect_text("/rootfs-b/hello", replacement);
	expect_text("/rootfs-a/hello", "");

	if (umount("/rootfs-merged"))
		fail("umount rootfs-backed stratafs");
}

static void test_overlayfs_copy_up_truncate(void)
{
	const char *replacement = "overlayfs-new";
	char path[128];
	unsigned int i;
	int fd;

	make_dir("/overlay-storage");
	make_dir("/overlay-root");
	make_dir("/overlay-outer-storage");
	make_dir("/overlay-outer");
	make_dir("/overlay-merged");
	make_dir("/overlay-etc");
	if (mount("tmpfs", "/overlay-storage", "tmpfs", 0, "mode=0755"))
		fail("mount overlay storage");
	seed_tmpfs_policy("/overlay-storage");
	if (mount("tmpfs", "/overlay-outer-storage", "tmpfs", 0,
		  "mode=0755"))
		fail("mount outer overlay storage");
	seed_tmpfs_policy("/overlay-outer-storage");
	make_dir("/overlay-storage/lower");
	make_dir("/overlay-storage/upper");
	make_dir("/overlay-storage/work");
	make_dir("/overlay-outer-storage/upper");
	make_dir("/overlay-outer-storage/work");
	make_dir("/overlay-storage/lower/retc");
	make_dir("/overlay-storage/lower/lcl-etc");
	make_dir("/overlay-storage/lower/usr-etc");
	make_dir("/overlay-storage/lower/a");
	copy_file("/init", "/overlay-storage/lower/a/applet-host", 0755);
	if (symlink("applet-host",
		    "/overlay-storage/lower/a/applet-link"))
		fail("overlay lower executable applet symlink");
	write_text("/overlay-storage/lower/retc/reconciled", "retc");
	write_text("/overlay-storage/lower/lcl-etc/local", "lcl");
	write_text("/overlay-storage/lower/usr-etc/vendor", "usr");
	for (i = 0; i < 256; i++) {
		if (snprintf(path, sizeof(path),
			     "/overlay-storage/lower/retc/entry-%03u", i) >=
		    (int)sizeof(path))
			fail("format large overlay directory entry");
		write_text(path, "retc");
	}
	if (mount("overlay", "/overlay-root", "overlay", 0,
		  "lowerdir=/overlay-storage/lower,upperdir=/overlay-storage/upper,workdir=/overlay-storage/work"))
		fail("mount overlay root");
	/* Copy the directory up so overlayfs must enumerate a merged cache. */
	write_text("/overlay-root/retc/upper-entry", "upper");
	if (mount("overlay", "/overlay-outer", "overlay", 0,
		  "lowerdir=/overlay-root,upperdir=/overlay-outer-storage/upper,workdir=/overlay-outer-storage/work"))
		fail("mount nested overlay root");
	expect_getdents_bounded("/overlay-outer/retc");
	if (mount("none", "/overlay-etc", "stratafs", 0,
		  "strata=/overlay-root/retc:/overlay-root/lcl-etc+create:/overlay-root/usr-etc+ro"))
		fail("mount overlay-backed three-tier stratafs");
	expect_directory_name("/overlay-etc", "reconciled");
	expect_directory_name("/overlay-etc", "upper-entry");
	expect_directory_name("/overlay-etc", "entry-255");
	expect_directory_exhaustible("/overlay-etc");
	make_dir("/overlay-root/b");
	if (mount("none", "/overlay-merged", "stratafs", 0,
		  "strata=/overlay-root/b+create:/overlay-root/a+ro+am"))
		fail("mount overlay-backed stratafs");
	check(access("/overlay-root/a/applet-link", X_OK) == 0,
	      "overlay provider applet symlink must be executable");
	check(executable_probe_status("/overlay-root/a/applet-link") == 73,
	      "overlay provider applet symlink must execute");
	check(access("/overlay-merged/applet-link", X_OK) == 0,
	      "merged overlay applet symlink must be executable");
	check(executable_probe_status("/overlay-merged/applet-link") == 73,
	      "merged overlay applet symlink must execute");

	write_text("/overlay-root/a/hello", "");
	fd = open("/overlay-merged/hello", O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd < 0)
		fail("open overlayfs copy-up O_TRUNC");
	if (write(fd, replacement, strlen(replacement)) !=
	    (ssize_t)strlen(replacement))
		fail("write overlayfs copy-up O_TRUNC");
	if (close(fd))
		fail("close overlayfs copy-up O_TRUNC");
	expect_text("/overlay-merged/hello", replacement);
	expect_text("/overlay-root/b/hello", replacement);
	expect_text("/overlay-root/a/hello", "");

	make_dir("/overlay-root/a/dir");
	make_dir("/overlay-merged/dir/child");
	check(!access("/overlay-merged/dir/child", F_OK),
	      "overlayfs named directory copy-up must be visible");
	check(!access("/overlay-root/b/dir/child", F_OK),
	      "overlayfs named directory copy-up must reach create stratum");
	check(access("/overlay-root/a/dir/child", F_OK) == -1 &&
		      errno == ENOENT,
	      "overlayfs named directory copy-up must not modify provider");
	expect_directory_name("/overlay-merged", "dir");

	if (umount("/overlay-merged"))
		fail("umount overlay-backed stratafs");
	if (umount("/overlay-etc"))
		fail("umount overlay-backed three-tier stratafs");
	if (umount("/overlay-outer"))
		fail("umount nested overlay root");
	if (umount("/overlay-root"))
		fail("umount overlay root");
	if (umount("/overlay-outer-storage"))
		fail("umount outer overlay storage");
	if (umount("/overlay-storage"))
		fail("umount overlay storage");
}

static void test_coherency_and_settled_directories(void)
{
	DIR *settled;
	int held;
	int nested_held;
	int child;

	expect_text("/merged/coherent", "coherent-low");
	write_text("/lower0/coherent", "coherent-high");
	expect_text("/merged/coherent", "coherent-high");
	if (unlink("/lower0/coherent"))
		fail("remove external high provider");
	expect_text("/merged/coherent", "coherent-low");

	held = open("/merged/hold", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (held < 0)
		fail("open held directory");
	write_text("/lower0/hold", "mask held directory");
	errno = 0;
	child = openat(held, "child", O_RDONLY | O_CLOEXEC);
	check_errno(child, ENOTDIR,
		    "held directory must not tunnel through a later non-directory mask");
	close(held);

	nested_held = open("/merged/nested-mask/held",
			   O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (nested_held < 0)
		fail("open nested held directory");
	write_text("/lower0/nested-mask", "mask nested ancestor");
	errno = 0;
	child = openat(nested_held, "child", O_RDONLY | O_CLOEXEC);
	check_errno(child, ENOTDIR,
		    "held directory must not tunnel through a masked ancestor");
	close(nested_held);

	settled = opendir("/merged/settled");
	if (!settled)
		fail("opendir settled");
	make_dir("/lower0/settled");
	write_text("/lower0/settled/high", "settled-high");
	check(directory_has(settled, "low"),
	      "settled directory must retain original participant");
	rewinddir(settled);
	check(!directory_has(settled, "high"),
	      "settled directory must not admit a later participant");
	closedir(settled);
	expect_directory_name("/merged/settled", "high");
	expect_directory_name("/merged/settled", "low");
}

static void test_mount_failures_and_freeze(void)
{
	pid_t child;
	int status;
	int fd;

	errno = 0;
	check_errno(mount("none", "/invalid-mount", "stratafs", 0,
			  "strata=/lower0+create+ro:/lower1"), EINVAL,
		    "create plus ro must be rejected");
	errno = 0;
	check_errno(mount("none", "/invalid-mount", "stratafs", 0,
			  "strata=/lower0:/lower0"), EINVAL,
		    "duplicate resolved strata must be rejected");
	errno = 0;
	check_errno(mount("none", "/invalid-mount", "stratafs", 0,
			  "strata=/does-not-exist"), ENOENT,
		    "missing non-am stratum must be rejected");

	child = fork();
	if (child < 0)
		fail("fork user-namespace mount test");
	if (!child) {
		if (unshare(CLONE_NEWUSER | CLONE_NEWNS))
			_exit(2);
		if (mount("none", "/invalid-mount", "stratafs", 0,
			  "strata=/lower0+ro:/lower1+ro"))
			_exit(3);
		if (umount("/invalid-mount"))
			_exit(4);
		errno = 0;
		if (mount("none", "/invalid-mount", "stratafs", 0,
			  "strata=/lower0+create:/lower1+ro") == -1 &&
		    errno == EPERM)
			_exit(0);
		_exit(1);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
		fail("wait user-namespace mount test");
	if (WEXITSTATUS(status) != 0)
		fprintf(stderr, "user-namespace mount child status=%d\n",
			WEXITSTATUS(status));
	check(WEXITSTATUS(status) == 0,
	      "nested-userns root must not configure a create stratum");

	if (mount("none", "/absent-mount", "stratafs", 0,
		  "strata=/does-not-exist+am"))
		fail("mount absent am stratum");
	errno = 0;
	fd = open("/absent-mount/new", O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
	check_errno(fd, EROFS, "absent stack cannot create");
	if (umount("/absent-mount"))
		fail("umount absent mount");

	errno = 0;
	check_errno(mount("none", "/merged", "stratafs", MS_REMOUNT,
			  "strata=/lower1+create:/lower0+ro"), EINVAL,
		    "remount must not alter strata");

	fd = open("/merged", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		fail("open merged for freeze");
	errno = 0;
	check_errno(ioctl(fd, FIFREEZE, 0), EOPNOTSUPP,
		    "stratafs must refuse freeze rather than claim lower quiescence");
	close(fd);
}

static void test_readonly_lower_mount(void)
{
	make_dir("/lower0/readonly-parent");
	make_dir("/lower1/readonly-parent");
	make_dir("/lower1/readonly-parent/copied-dir");
	if (mount("/lower0/readonly-parent", "/lower0/readonly-parent", NULL,
		  MS_BIND, NULL))
		fail("bind readonly lower directory");
	if (mount(NULL, "/lower0/readonly-parent", NULL,
		  MS_BIND | MS_REMOUNT | MS_RDONLY, NULL))
		fail("remount lower directory readonly");

	errno = 0;
	check_errno(mkdir("/merged/readonly-parent/new", 0755), EROFS,
		    "create must respect a readonly lower bind mount");
	errno = 0;
	check(access("/lower0/readonly-parent/new", F_OK) == -1 &&
	      errno == ENOENT,
	      "readonly lower create refusal must leave no object");

	errno = 0;
	check_errno(chmod("/merged/readonly-parent/copied-dir", 0700), EROFS,
		    "copy-up must respect a readonly lower bind mount");
	errno = 0;
	check(access("/lower0/readonly-parent/copied-dir", F_OK) == -1 &&
	      errno == ENOENT,
	      "readonly lower copy-up refusal must publish no object");

	/* StrataFS holds a path reference to every mounted stratum. */
	if (umount("/merged"))
		fail("unmount StrataFS before readonly lower bind");
	if (umount("/lower0/readonly-parent"))
		fail("unmount readonly lower bind");
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--exec-probe"))
		return 73;

	setup_strata();
	if (mount("none", "/merged", "stratafs", 0,
		  "strata=/lower0+create:/lower1+ro"))
		fail("mount stratafs");

	test_lookup_and_identity();
	test_relative_symlink_execution();
	test_staging_recovery_batches();
	test_origin_and_statfs();
	test_fsync_snapshot_gate();
	test_copy_up_descriptors();
	test_mmap_copy_up();
	test_lock_survives_copy_up();
	test_ofd_lock_close_after_copy_up();
	test_posix_lock_close_after_copy_up();
	test_lease_survives_copy_up();
	test_creation_links_rename_remove();
	test_mount_option_escapes_and_reporting();
	test_native_dispositions();
	test_same_filesystem_copy_up_truncate();
	test_rootfs_copy_up_truncate();
	test_overlayfs_copy_up_truncate();
	test_coherency_and_settled_directories();
	test_mount_failures_and_freeze();
	test_readonly_lower_mount();
	printf("STRATAFS_SMOKE_PASS: %u checks\n", checks);
	power_off();
	return 0;
}
