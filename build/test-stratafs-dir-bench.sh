#!/usr/bin/env bash
# Measure StrataFS directory capture and getdents in a disposable VM.
# Reports 1k/10k/100k names, one/four duplicate-heavy layers and four open fds.
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <kernel-tree-or-bzImage>" >&2
	exit 2
fi

if [[ -d "$1" ]]; then
	bzimage="$1/arch/x86/boot/bzImage"
	log="$1/stratafs-dir-bench-qemu.log"
else
	bzimage="$1"
	log="$(cd "$(dirname "$bzimage")" && pwd)/stratafs-dir-bench-qemu.log"
fi
[[ -f "$bzimage" ]] || {
	echo "bzImage not found: $bzimage" >&2
	exit 1
}

qemu=${QEMU_BIN:-qemu-system-x86_64}
timeout_s=${PKM_STRATAFS_DIR_BENCH_TIMEOUT:-1200}
log=${PKM_STRATAFS_DIR_BENCH_LOG:-$log}
command -v "$qemu" >/dev/null || {
	echo "qemu not found: $qemu" >&2
	exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/pkm-stratafs-dir-bench.XXXXXX")"
cleanup()
{
	rm -rf -- "$work"
}
trap cleanup EXIT
mkdir -p "$work/root"

gcc -Iuapi -static -O2 -Wall -Wextra -Werror \
	-o "$work/root/init" build/stratafs-dir-bench.c
(
	cd "$work/root"
	find . -print0 |
		cpio --null -o --format=newc --quiet >"$work/initrd.cpio"
)

append='console=ttyS0 quiet loglevel=4 panic=-1 kunit.enable=0 rdinit=/init'
qemu_args=(
	-m 4096 -smp 2 -nographic -no-reboot -serial mon:stdio
	-machine accel=kvm:tcg
	-cpu max
	-kernel "$bzimage"
	-initrd "$work/initrd.cpio"
	-append "$append"
)

echo "test-stratafs-dir-bench: booting $bzimage via $qemu"
set +e
timeout "${timeout_s}s" "$qemu" "${qemu_args[@]}" >"$log" 2>&1
status=$?
set -e

fail=0
rows=$(grep -c '^DIR_BENCH ' "$log" || true)
if [[ $rows -ne 24 ]]; then
	echo "  EXPECTED 24 measurement rows, got $rows"
	fail=1
fi
pass_marker='STRATAFS_DIR_BENCH_PASS'
fatal_re='STRATAFS_DIR_BENCH_FAIL|FAIL:|stratafs: staging recovery scan failed:|BUG:|Kernel panic|Oops:|KASAN:|UBSAN:|NULL pointer|Call Trace:|INFO: task .* blocked for more than|WARNING:'
grep -Fq "$pass_marker" "$log" || {
	echo "  MISSING: $pass_marker"
	fail=1
}
grep -Eq "$fatal_re" "$log" && {
	echo "  FOUND: kernel or StrataFS failure signature"
	fail=1
}
if [[ $status -ne 0 ]]; then
	echo "  QEMU exited with status $status"
	fail=1
fi

if [[ $fail -ne 0 ]]; then
	echo "test-stratafs-dir-bench: FAILED (log $log)" >&2
	echo "----- log tail -----" >&2
	tail -80 "$log" >&2
	exit 1
fi

echo "test-stratafs-dir-bench: PASS — directory benchmark checks passed in QEMU"
