#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

kernel_image=${1:-"$script_dir/out-kunit/bzImage"}
initrd_image=${2:-"/home/jack/projects/peios/depr/provium/testdata/minimal.cpio.gz"}
qemu_bin=${QEMU_BIN:-qemu-system-x86_64}
log_file=${TMPDIR:-/tmp}/pkm-slice19-kunit.log
qemu_timeout=${KUNIT_QEMU_TIMEOUT:-180s}
suite_marker='pkm: kunit scaffold smoke passed'

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

if grep -F "$suite_marker" "$log_file" >/dev/null 2>&1; then
	echo "check-kunit-scaffold: observed KUnit marker"
	exit 0
fi

echo "check-kunit-scaffold: KUnit marker not observed (qemu exit $qemu_status)" >&2
exit 1
