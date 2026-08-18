// SPDX-License-Identifier: GPL-2.0-only
//
// Initramfs PID 1 that proves the module-signing chain end to end.
//
// With CONFIG_MODULE_SIG_FORCE=y a module load succeeding *means* its appended
// signature verified against a key in .builtin_trusted_keys -- so a successful
// finit_module() exercises the whole chain: the ML-DSA-65 key from the keyring,
// sign-file's signature at modules_install, and the kernel's PKCS#7 verify.
//
// The module ships zstd-compressed. MODULE_INIT_COMPRESSED_FILE has the kernel
// decompress it internally (CONFIG_MODULE_DECOMPRESS), which is what keeps the
// verified bytes and the loaded bytes the same object.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MODULE_INIT_COMPRESSED_FILE
#define MODULE_INIT_COMPRESSED_FILE 4
#endif

/*
 * This runs as PID 1, so returning would panic the kernel ("attempted to kill
 * init") and muddy the harness's failure detection. Power off instead.
 */
static void finish(int status)
{
	fflush(NULL);
	sync();
	reboot(RB_POWER_OFF);
	_exit(status);
}

static int load_module(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	long ret;

	if (fd < 0)
		return -errno;
	ret = syscall(SYS_finit_module, fd, "", MODULE_INIT_COMPRESSED_FILE);
	if (ret < 0)
		ret = -errno;
	close(fd);
	return (int)ret;
}

int main(void)
{
	int checks = 0;
	int rc;

	/*
	 * A correctly signed module must get past verification. Distinguish
	 * that from the module's own init declining: with MODULE_SIG_FORCE the
	 * signature is checked before init runs, so -ENODEV from a driver that
	 * found no hardware still proves the signature was accepted, whereas
	 * -EKEYREJECTED/-ENOKEY/-EBADMSG mean it was not.
	 */
	rc = load_module("/good.ko.zst");
	if (rc == -EKEYREJECTED || rc == -ENOKEY || rc == -EBADMSG) {
		printf("MODSIG_SMOKE_FAIL: signature rejected (%d: %s)\n",
		       rc, strerror(-rc));
		finish(1);
	}
	if (rc != 0)
		printf("modsig-smoke: verified; init returned %d (%s)\n",
		       rc, strerror(-rc));
	checks++;

	/* A corrupted copy of the same module must not. */
	rc = load_module("/bad.ko.zst");
	if (rc == 0) {
		printf("MODSIG_SMOKE_FAIL: corrupted module was accepted\n");
		finish(1);
	}
	checks++;
	printf("modsig-smoke: corrupted module rejected with %d (%s)\n",
	       rc, strerror(-rc));

	printf("MODSIG_SMOKE_PASS: %d checks\n", checks);
	finish(0);
	return 0;
}
