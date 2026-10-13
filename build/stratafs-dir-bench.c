// SPDX-License-Identifier: GPL-2.0-only
/* Disposable-VM PID 1: PEI-751 directory capture/read scaling and correctness.
 * No timing threshold: report measurements alongside exact listing checks.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <pkm/file.h>
#include <pkm/syscall.h>

struct bench_dirent64 {
	uint64_t ino;
	int64_t off;
	unsigned short reclen;
	unsigned char type;
	char name[];
};

static void finish(int failed)
{
	printf("STRATAFS_DIR_BENCH_%s\n", failed ? "FAIL" : "PASS");
	fflush(NULL);
	reboot(RB_POWER_OFF);
	_exit(failed);
}

static void require(int ok, const char *what)
{
	if (!ok) {
		fprintf(stderr, "FAIL: %s: errno=%d (%s)\n", what, errno,
			strerror(errno));
		finish(1);
	}
}

static uint64_t now(void)
{
	struct timespec ts;

	require(!clock_gettime(CLOCK_MONOTONIC, &ts), "clock_gettime");
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void seed_policy(const char *path)
{
	unsigned char sd[65536];
	long len = syscall(SYS_KACS_GET_SD, AT_FDCWD, "/", 7, sd, sizeof(sd), 0);
	struct kacs_mount_policy_args args = {};
	int fd;

	require(len > 0 && len <= (long)sizeof(sd), "read root SD");
	fd = open(path, O_PATH | O_DIRECTORY);
	require(fd >= 0, "open mount root");
	args.policy = KACS_MOUNT_POLICY_SYNTHESIZE_EPHEMERAL;
	args.template_sd_ptr = (uintptr_t)sd;
	args.template_sd_len = len;
	require(!syscall(SYS_KACS_SET_MOUNT_POLICY, fd, &args, sizeof(args)),
		"set fixture mount policy");
	require(!syscall(SYS_KACS_SET_SD, AT_FDCWD, path, 7, sd, len, 0),
		"set fixture root SD");
	close(fd);
}

/* Compare against the actual top provider's order, not a sorted-name guess. */
static void enumerate(int fd, unsigned int n, unsigned int *order,
		      int record, unsigned int buffer_size)
{
	char buffer[32768] __attribute__((aligned(8)));
	unsigned int seen = 0;

	for (;;) {
		long length = syscall(SYS_getdents64, fd, buffer, buffer_size);
		long at = 0;

		require(length >= 0, "getdents64");
		if (!length)
			break;
		while (at < length) {
			struct bench_dirent64 *e = (void *)(buffer + at);
			unsigned int id;
			char tail;

			require(e->reclen >= offsetof(struct bench_dirent64, name) + 1 &&
				e->reclen <= length - at, "record size");
			require(memchr(e->name, 0, e->reclen -
				offsetof(struct bench_dirent64, name)) != NULL, "terminated name");
			if (strcmp(e->name, ".") && strcmp(e->name, "..")) {
				require(sscanf(e->name, "file-%u%c", &id, &tail) == 1 &&
					id < n && seen < n, "known unique name");
				if (record)
					order[seen] = id;
				else {
					require(id == order[seen], "provider order / deduplication");
					require(e->off == (int64_t)seen + 3, "ordinal offset");
				}
				require(e->type == DT_REG, "provider type");
				seen++;
			}
			at += e->reclen;
		}
	}
	require(seen == n, "complete union");
}

static void run(unsigned int n, unsigned int layers)
{
	unsigned int *order = calloc(n, sizeof(*order));
	char path[128], options[512] = "strata=";
	int fds[4];
	uint64_t opens[4];
	unsigned int layer, i;

	require(order != NULL, "allocate expected order");
	for (layer = 0; layer < layers; layer++) {
		snprintf(path, sizeof(path), "/layer%u", layer);
		require(!mount("tmpfs", path, "tmpfs", 0, "mode=0755"), "mount tmpfs");
		seed_policy(path);
		strcat(options, layer ? ":" : "");
		strcat(options, path);
		for (i = 0; i < n; i++) {
			int fd;

			snprintf(path, sizeof(path), "/layer%u/file-%06u", layer, i);
			fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
			require(fd >= 0, "populate provider");
			close(fd);
		}
	}
	fds[0] = open("/layer0", O_RDONLY | O_DIRECTORY);
	require(fds[0] >= 0, "open provider");
	enumerate(fds[0], n, order, 1, 32768);
	close(fds[0]);
	require(!mount("none", "/merged", "stratafs", 0, options), "mount stratafs");
	/* Hold four independent snapshots concurrently, then read each in turn. */
	for (i = 0; i < 4; i++) {
		uint64_t start = now();

		fds[i] = open("/merged", O_RDONLY | O_DIRECTORY);
		opens[i] = now() - start;
		require(fds[i] >= 0, "open merged capture");
	}
	for (i = 0; i < 4; i++) {
		uint64_t start = now();
		unsigned int size = i % 2 ? 32768 : 64;

		enumerate(fds[i], n, order, 0, size);
		printf("DIR_BENCH names=%u layers=%u held_fds=4 fd=%u buffer=%u "
		       "open_ns=%llu read_ns=%llu\n", n, layers, i, size,
		       (unsigned long long)opens[i],
		       (unsigned long long)(now() - start));
		fflush(stdout);
	}
	for (i = 0; i < 4; i++)
		close(fds[i]);
	require(!umount("/merged"), "unmount merged");
	for (layer = 0; layer < layers; layer++) {
		snprintf(path, sizeof(path), "/layer%u", layer);
		require(!umount(path), "unmount provider");
	}
	free(order);
}

int main(void)
{
	static const unsigned int sizes[] = { 1000, 10000, 100000 };
	unsigned int i;
	char path[32];

	setvbuf(stdout, NULL, _IONBF, 0);
	require(getpid() == 1, "must run as init in a disposable VM");
	require(!mkdir("/merged", 0755), "mkdir merged");
	for (i = 0; i < 4; i++) {
		snprintf(path, sizeof(path), "/layer%u", i);
		require(!mkdir(path, 0755), "mkdir provider");
	}
	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		run(sizes[i], 1);
		run(sizes[i], 4);
	}
	finish(0);
}
