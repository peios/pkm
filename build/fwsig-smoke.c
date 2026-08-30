// SPDX-License-Identifier: GPL-2.0-only
//
// Initramfs PID 1 that proves firmware signature verification (PEI-493) end
// to end, through the loader's own self-test module.
//
// test_firmware's trigger_request pulls a named file through the real
// request_firmware() path with no hardware. The write returns the loader's
// verdict: it succeeds when the file loaded and fails when it did not. Each
// blob under /lib/firmware was signed on the host with the same dev TCB key
// the kernel was built to trust; this init stamps the signature into the
// security.peios.sig xattr (a cpio cannot carry one) exactly as peipkg does
// at install, then asks for each blob in turn.
//
// FWSIG_MODE=enforce|log arrives in the environment from the kernel command
// line (an unrecognised key=value is handed to init) and says which verdict
// to expect for the unsigned and tampered blobs: refused under enforce,
// loaded under log. The signed blobs must load either way.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef MODULE_INIT_COMPRESSED_FILE
#define MODULE_INIT_COMPRESSED_FILE 4
#endif

#define SIG_LEN 3310
#define SIG_XATTR "security.peios.sig"
#define TRIGGER "/sys/devices/virtual/misc/test_firmware/trigger_request"

static int checks;

static void finish(int status)
{
	fflush(NULL);
	sync();
	reboot(RB_POWER_OFF);
	_exit(status);
}

static void fail(const char *what, int err)
{
	printf("FWSIG_SMOKE_FAIL: %s (%d: %s)\n", what, err, strerror(err));
	finish(1);
}

static void stamp(const char *file, const char *sigpath)
{
	unsigned char sig[SIG_LEN];
	int fd = open(sigpath, O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		fail(sigpath, errno);
	n = read(fd, sig, sizeof(sig));
	close(fd);
	if (n != SIG_LEN) {
		printf("FWSIG_SMOKE_FAIL: %s is %zd bytes, expected %d\n",
		       sigpath, n, SIG_LEN);
		finish(1);
	}
	if (setxattr(file, SIG_XATTR, sig, sizeof(sig), 0) != 0)
		fail(file, errno);
}

static int trigger(const char *name)
{
	int fd = open(TRIGGER, O_WRONLY | O_CLOEXEC);
	ssize_t n;
	int err = 0;

	if (fd < 0)
		fail(TRIGGER, errno);
	n = write(fd, name, strlen(name));
	if (n < 0)
		err = -errno;
	close(fd);
	return err;
}

static void expect(const char *name, int want_load)
{
	int rc = trigger(name);

	if (want_load && rc != 0) {
		printf("FWSIG_SMOKE_FAIL: %s should have loaded (%d: %s)\n",
		       name, rc, strerror(-rc));
		finish(1);
	}
	if (!want_load && rc == 0) {
		printf("FWSIG_SMOKE_FAIL: %s should have been refused\n", name);
		finish(1);
	}
	printf("fwsig-smoke: %s -> %s\n", name,
	       rc == 0 ? "loaded" : strerror(-rc));
	checks++;
}

int main(void)
{
	const char *mode = getenv("FWSIG_MODE");
	int enforce;
	int fd;

	if (!mode || (strcmp(mode, "enforce") && strcmp(mode, "log"))) {
		printf("FWSIG_SMOKE_FAIL: FWSIG_MODE must be enforce or log\n");
		finish(1);
	}
	enforce = strcmp(mode, "enforce") == 0;

	if (mount("sysfs", "/sys", "sysfs", 0, NULL) != 0)
		fail("mount /sys", errno);

	/* What peipkg does at install: content first, then the xattr. */
	stamp("/lib/firmware/fwsig-good.bin", "/fwsig-good.sig");
	stamp("/lib/firmware/fwsig-goodz.bin.zst", "/fwsig-goodz.sig");
	/* A valid signature for different bytes: the tamper case. */
	stamp("/lib/firmware/fwsig-bad.bin", "/fwsig-good.sig");

	fd = open("/test_firmware.ko.zst", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		fail("/test_firmware.ko.zst", errno);
	if (syscall(SYS_finit_module, fd, "", MODULE_INIT_COMPRESSED_FILE) != 0)
		fail("finit_module test_firmware", errno);
	close(fd);

	/* Signed at PeiosTcb: loads in both modes. */
	expect("fwsig-good.bin", 1);
	/* Signed over the compressed bytes; the kernel decompresses after. */
	expect("fwsig-goodz.bin", 1);
	/* No signature at all. */
	expect("fwsig-unsigned.bin", !enforce);
	/* A signature that does not match the bytes. */
	expect("fwsig-bad.bin", !enforce);

	printf("FWSIG_SMOKE_PASS: %d checks (%s)\n", checks, mode);
	finish(0);
	return 0;
}
