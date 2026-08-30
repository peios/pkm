#!/usr/bin/env bash
# Boot the modular kernel with a minimal initramfs and prove firmware
# signature verification (PEI-493): a blob signed with the TCB key loads, an
# unsigned or tampered one is refused under kacs_fwsig=enforce and merely
# logged under kacs_fwsig=log. Booted once per mode.
#
# Signing happens here on the host with the keyring's TCB private key -- the
# same key whose public half build.kernel compiled into the kernel -- using
# the PIP blob format from PSPK ch.3: 0x01 followed by an ML-DSA-65 signature
# over the SHA-256 of the file. OpenSSL >= 3.5 signs ML-DSA natively and its
# output verifies with the kernel's FIPS 204 implementation.
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 <kernel-tree> <modules-staging-root>" >&2
	exit 2
fi

tree=$(cd "$1" && pwd) || exit 1
root=$(cd "$2" && pwd) || exit 1
bzimage="$tree/arch/x86/boot/bzImage"
logdir=${PKM_FWSIG_LOGDIR:-$tree}
qemu=${QEMU_BIN:-qemu-system-x86_64}
timeout_s=${PKM_FWSIG_TIMEOUT:-120}
key=${PKM_FWSIG_KEY:-${PEKIT_KEYRING_TCB_PRIV:-}}

[[ -f "$bzimage" ]] || { echo "bzImage not found: $bzimage" >&2; exit 1; }
[[ -n "$key" && -r "$key" ]] || {
	echo "TCB signing key not found (set PEKIT_KEYRING_TCB_PRIV via --keyring, or PKM_FWSIG_KEY)" >&2
	exit 1
}
command -v "$qemu" >/dev/null || { echo "qemu not found: $qemu" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
command -v zstd >/dev/null || { echo "zstd not found" >&2; exit 1; }

moddir=$(find "$root/lib/modules" -maxdepth 1 -mindepth 1 -type d | head -1)
[[ -d "$moddir" ]] || { echo "no module tree under $root" >&2; exit 1; }
testmod=$(find "$moddir" -name 'test_firmware.ko*' | head -1)
[[ -n "$testmod" ]] || {
	echo "test_firmware module not found under $moddir (CONFIG_TEST_FIRMWARE=m?)" >&2
	exit 1
}
[[ "$testmod" == *.zst ]] || { echo "expected a zstd-compressed module: $testmod" >&2; exit 1; }

work="$(mktemp -d "${TMPDIR:-/tmp}/pkm-fwsig-smoke.XXXXXX")"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
mkdir -p "$work/root/lib/firmware" "$work/root/sys"

# sign <file> <out>: the 3310-byte PIP blob for the file's on-disk bytes.
sign() {
	openssl dgst -sha256 -binary "$1" >"$work/hash"
	openssl pkeyutl -sign -inkey "$key" -rawin -in "$work/hash" -out "$work/sig"
	{ printf '\001'; cat "$work/sig"; } >"$2"
	local size
	size=$(stat -c %s "$2")
	[[ $size -eq 3310 ]] || { echo "signature blob is $size bytes, expected 3310" >&2; exit 1; }
}

gcc -static -O2 -Wall -Wextra -Werror -o "$work/root/init" build/fwsig-smoke.c
cp "$testmod" "$work/root/test_firmware.ko.zst"

fw="$work/root/lib/firmware"
head -c 4096 /dev/urandom >"$fw/fwsig-good.bin"
head -c 4096 /dev/urandom >"$fw/fwsig-unsigned.bin"
# From a file, not a pipe: the kernel's zstd path needs the frame to carry
# its content size, which zstd only writes when it knows the input length.
head -c 8192 /dev/urandom >"$work/goodz.bin"
zstd -q -19 "$work/goodz.bin" -o "$fw/fwsig-goodz.bin.zst"
# Same signature as the good blob, different bytes.
cp "$fw/fwsig-good.bin" "$fw/fwsig-bad.bin"
printf '\xff' | dd of="$fw/fwsig-bad.bin" bs=1 seek=2048 count=1 conv=notrunc status=none

sign "$fw/fwsig-good.bin" "$work/root/fwsig-good.sig"
sign "$fw/fwsig-goodz.bin.zst" "$work/root/fwsig-goodz.sig"

(
	cd "$work/root"
	find . -print0 | cpio --null -o --format=newc --quiet >"$work/initrd.cpio"
)

boot() {
	local mode=$1
	local log="$logdir/fwsig-$mode-qemu.log"
	# loglevel=5 so the check's KERN_WARNING verdicts reach the serial log.
	local append="console=ttyS0 quiet loglevel=5 panic=-1 kunit.enable=0 rdinit=/init kacs_fwsig=$mode FWSIG_MODE=$mode"
	local status fail=0

	echo "test-fwsig: booting $bzimage via $qemu (kacs_fwsig=$mode)"
	set +e
	timeout "${timeout_s}s" "$qemu" \
		-m 2048 -smp 2 -nographic -no-reboot -serial mon:stdio \
		-machine accel=kvm:tcg -kernel "$bzimage" -initrd "$work/initrd.cpio" \
		-append "$append" >"$log" 2>&1
	status=$?
	set -e

	grep -Fq "FWSIG_SMOKE_PASS: 4 checks ($mode)" "$log" || {
		echo "  MISSING: FWSIG_SMOKE_PASS ($mode)"; fail=1; }
	grep -Eq 'FWSIG_SMOKE_FAIL:|BUG:|Kernel panic|Oops:|Call Trace:' "$log" && {
		echo "  FOUND: failure signature ($mode)"; fail=1; }
	[[ $status -eq 0 ]] || { echo "  QEMU exited with status $status ($mode)"; fail=1; }
	# The verdict must be said out loud in both modes: what was refused, or
	# what log mode let through.
	if [[ $mode == log ]]; then
		grep -Eq 'pkm: firmware .*loaded \(kacs_fwsig=log\)' "$log" || {
			echo "  MISSING: log-mode warning for the unsigned/tampered blobs"; fail=1; }
	else
		grep -Eq 'pkm: firmware .*; refused' "$log" || {
			echo "  MISSING: refusal warning for the unsigned/tampered blobs"; fail=1; }
	fi

	if [[ $fail -ne 0 ]]; then
		echo "test-fwsig: FAILED in $mode mode (log $log)" >&2
		tail -60 "$log" >&2
		exit 1
	fi
}

boot enforce
boot log

echo "test-fwsig: PASS — signed firmware loads; unsigned and tampered refused under enforce, logged under log"
