#!/usr/bin/env bash
# Boot the modular kernel with a minimal initramfs and prove the module-signing
# chain: a signed module loads, a corrupted one does not.
#
# With CONFIG_MODULE_SIG_FORCE=y a successful load *is* the proof -- it can only
# succeed if the appended signature verified against .builtin_trusted_keys.
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 <kernel-tree> <modules-staging-root>" >&2
	exit 2
fi

tree=$(cd "$1" && pwd) || exit 1
root=$(cd "$2" && pwd) || exit 1
bzimage="$tree/arch/x86/boot/bzImage"
log=${PKM_MODSIG_LOG:-$tree/modsig-qemu.log}
qemu=${QEMU_BIN:-qemu-system-x86_64}
timeout_s=${PKM_MODSIG_TIMEOUT:-120}

[[ -f "$bzimage" ]] || { echo "bzImage not found: $bzimage" >&2; exit 1; }
command -v "$qemu" >/dev/null || { echo "qemu not found: $qemu" >&2; exit 1; }

moddir=$(find "$root/lib/modules" -maxdepth 1 -mindepth 1 -type d | head -1)
[[ -d "$moddir" ]] || { echo "no module tree under $root" >&2; exit 1; }

# Pick a module with no dependencies of its own, so the load exercises signature
# verification rather than dependency resolution (which needs modprobe, and
# therefore a userspace we deliberately do not have here).
# Prefer a dependency-free pure-software module: anything under arch/ gates on
# CPU features or absent hardware, so its init can fail for reasons that have
# nothing to do with the signature.
leaf=$(awk -F: '$2 ~ /^[[:space:]]*$/ { print $1 }' "$moddir/modules.dep" |
	grep -E '^kernel/(crypto|lib)/' | head -1)
[[ -n "$leaf" ]] || leaf=$(awk -F: '$2 ~ /^[[:space:]]*$/ { print $1; exit }' \
	"$moddir/modules.dep")
[[ -n "$leaf" ]] || { echo "no dependency-free module found" >&2; exit 1; }
echo "test-modsig: using $leaf"

work="$(mktemp -d "${TMPDIR:-/tmp}/pkm-modsig-smoke.XXXXXX")"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
mkdir -p "$work/root"

gcc -static -O2 -Wall -Wextra -Werror -o "$work/root/init" build/modsig-smoke.c
cp "$moddir/$leaf" "$work/root/good.ko.zst"

# Corrupt a byte well inside the compressed stream. Whether this surfaces as a
# decompression error or a signature mismatch does not matter -- what is being
# asserted is that a tampered file is not loaded.
cp "$work/root/good.ko.zst" "$work/root/bad.ko.zst"
size=$(stat -c %s "$work/root/bad.ko.zst")
printf '\xff' | dd of="$work/root/bad.ko.zst" bs=1 seek=$((size / 2)) \
	count=1 conv=notrunc status=none

(
	cd "$work/root"
	find . -print0 | cpio --null -o --format=newc --quiet >"$work/initrd.cpio"
)

append='console=ttyS0 quiet loglevel=4 panic=-1 kunit.enable=0 rdinit=/init'
echo "test-modsig: booting $bzimage via $qemu"
set +e
timeout "${timeout_s}s" "$qemu" \
	-m 2048 -smp 2 -nographic -no-reboot -serial mon:stdio \
	-machine accel=kvm:tcg -kernel "$bzimage" -initrd "$work/initrd.cpio" \
	-append "$append" >"$log" 2>&1
status=$?
set -e

fail=0
grep -Fq 'MODSIG_SMOKE_PASS: 2 checks' "$log" || {
	echo "  MISSING: MODSIG_SMOKE_PASS"; fail=1; }
grep -Eq 'MODSIG_SMOKE_FAIL:|BUG:|Kernel panic|Oops:|Call Trace:' "$log" && {
	echo "  FOUND: failure signature"; fail=1; }
[[ $status -eq 0 ]] || { echo "  QEMU exited with status $status"; fail=1; }

if [[ $fail -ne 0 ]]; then
	echo "test-modsig: FAILED (log $log)" >&2
	tail -60 "$log" >&2
	exit 1
fi

echo "test-modsig: PASS — signed module loaded, corrupted module rejected"
