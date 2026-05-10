#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

kernel_image=${1:-"$script_dir/out-kunit/bzImage"}
initrd_image=${2:-"/home/jack/projects/peios/depr/provium/testdata/minimal.cpio.gz"}
qemu_bin=${QEMU_BIN:-qemu-system-x86_64}
log_file=${KUNIT_QEMU_LOG:-${TMPDIR:-/tmp}/pkm-slice19-kunit.log}
qemu_timeout=${KUNIT_QEMU_TIMEOUT:-420s}
suite_marker='pkm: kunit scaffold smoke passed'
suite_summary_regex='# pkm_kunit_scaffold: pass:[0-9]+ fail:0 skip:[0-9]+ total:[0-9]+'
fatal_regex='BUG:|Kernel panic|Oops:|INFO: task .* blocked for more than|EXPECTATION FAILED|ASSERTION FAILED|not ok [0-9]+|# .*fail:[1-9]'

if [[ ! -f "$kernel_image" ]]; then
	echo "check-kunit-scaffold: kernel image not found: $kernel_image" >&2
	exit 1
fi

if [[ ! -f "$initrd_image" ]]; then
	echo "check-kunit-scaffold: initrd not found: $initrd_image" >&2
	exit 1
fi

if ! command -v "$qemu_bin" >/dev/null 2>&1; then
	echo "check-kunit-scaffold: qemu binary not found: $qemu_bin" >&2
	exit 1
fi

rm -f "$log_file"

set +e
timeout "$qemu_timeout" "$qemu_bin" \
	-m 2048 \
	-smp 2 \
	-nographic \
	-no-reboot \
	-serial mon:stdio \
	-kernel "$kernel_image" \
	-initrd "$initrd_image" \
	-append 'console=ttyS0 loglevel=7 ignore_loglevel panic=-1 kunit.enable=1 kunit_shutdown=poweroff' \
	>"$log_file" 2>&1
qemu_status=$?
set -e

if (( qemu_status != 0 )); then
	echo "check-kunit-scaffold: qemu failed or timed out (exit $qemu_status, log $log_file)" >&2
	exit 1
fi

if ! grep -F "$suite_marker" "$log_file" >/dev/null 2>&1; then
	echo "check-kunit-scaffold: KUnit marker not observed (log $log_file)" >&2
	exit 1
fi

if ! grep -E "$suite_summary_regex" "$log_file" >/dev/null 2>&1; then
	echo "check-kunit-scaffold: complete passing scaffold summary not observed (log $log_file)" >&2
	exit 1
fi

if grep -E "$fatal_regex" "$log_file" >/dev/null 2>&1; then
	echo "check-kunit-scaffold: kernel/KUnit failure signature observed (log $log_file)" >&2
	exit 1
fi

echo "check-kunit-scaffold: observed complete passing KUnit scaffold (log $log_file)"
exit 0
