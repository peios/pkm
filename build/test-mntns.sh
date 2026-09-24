#!/usr/bin/env bash
# Boot a KACS-enabled kernel with a minimal initramfs and exercise mount
# namespaces as KACS objects through real userspace syscalls (PEI-1173).
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <kernel-tree-or-bzImage>" >&2
	exit 2
fi

if [[ -d "$1" ]]; then
	bzimage="$1/arch/x86/boot/bzImage"
	log="$1/mntns-qemu.log"
else
	bzimage="$1"
	log="$(cd "$(dirname "$bzimage")" && pwd)/mntns-qemu.log"
fi
[[ -f "$bzimage" ]] || {
	echo "bzImage not found: $bzimage" >&2
	exit 1
}

qemu=${QEMU_BIN:-qemu-system-x86_64}
timeout_s=${PKM_MNTNS_TIMEOUT:-120}
log=${PKM_MNTNS_LOG:-$log}
command -v "$qemu" >/dev/null || {
	echo "qemu not found: $qemu" >&2
	exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/pkm-mntns-smoke.XXXXXX")"
cleanup()
{
	rm -rf -- "$work"
}
trap cleanup EXIT
mkdir -p "$work/root"

gcc -static -O2 -Wall -Wextra -Werror \
	-o "$work/root/init" build/mntns-smoke.c
(
	cd "$work/root"
	find . -print0 |
		cpio --null -o --format=newc --quiet >"$work/initrd.cpio"
)

append='console=ttyS0 quiet loglevel=4 panic=-1 kunit.enable=0 rdinit=/init'
qemu_args=(
	-m 2048 -smp 2 -nographic -no-reboot -serial mon:stdio
	-machine accel=kvm:tcg
	-cpu max
	-kernel "$bzimage"
	-initrd "$work/initrd.cpio"
	-append "$append"
)

echo "test-mntns: booting $bzimage via $qemu"
set +e
timeout "${timeout_s}s" "$qemu" "${qemu_args[@]}" >"$log" 2>&1
status=$?
set -e

fail=0
# Both counts are pinned so a check that silently stops running is noticed.
child_marker='MNTNS_SMOKE_CHILD_CHECKS: 54'
pass_marker='MNTNS_SMOKE_PASS: 6 parent checks'
fatal_re='MNTNS_SMOKE_FAIL:|BUG:|Kernel panic|Oops:|KASAN:|UBSAN:|NULL pointer|Call Trace:|INFO: task .* blocked for more than|WARNING:'
grep -Fq "$child_marker" "$log" || {
	echo "  MISSING: $child_marker"
	fail=1
}
grep -Fq "$pass_marker" "$log" || {
	echo "  MISSING: $pass_marker"
	fail=1
}
grep -Eq "$fatal_re" "$log" && {
	echo "  FOUND: kernel or smoke failure signature"
	fail=1
}
if [[ $status -ne 0 ]]; then
	echo "  QEMU exited with status $status"
	fail=1
fi

if [[ $fail -ne 0 ]]; then
	echo "test-mntns: FAILED (log $log)" >&2
	echo "----- log tail -----" >&2
	tail -80 "$log" >&2
	exit 1
fi

echo "test-mntns: PASS — mount namespaces as KACS objects passed in QEMU"
