#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)

kernel_image=${1:-"$script_dir/out/bzImage"}
initrd_image=${2:-"/home/jack/projects/peios/depr/provium/testdata/minimal.cpio.gz"}
qemu_bin=${QEMU_BIN:-qemu-system-x86_64}
log_file=${TMPDIR:-/tmp}/pkm-slice17-boot.log
boot_marker='pkm: slow-track kernel scaffold initialized'

if [[ ! -f "$kernel_image" ]]; then
	echo "check-boot-scaffold: kernel image not found: $kernel_image" >&2
	exit 1
fi

if [[ ! -f "$initrd_image" ]]; then
	echo "check-boot-scaffold: initrd not found: $initrd_image" >&2
	exit 1
fi

if ! command -v "$qemu_bin" >/dev/null 2>&1; then
	echo "check-boot-scaffold: qemu binary not found: $qemu_bin" >&2
	exit 1
fi

rm -f "$log_file"

set +e
timeout 30s "$qemu_bin" \
	-m 2048 \
	-smp 2 \
	-nographic \
	-no-reboot \
	-serial mon:stdio \
	-kernel "$kernel_image" \
	-initrd "$initrd_image" \
	-append 'console=ttyS0 loglevel=7 ignore_loglevel init=/sbin/real-init' \
	2>&1 | tee "$log_file"
qemu_status=${PIPESTATUS[0]}
set -e

if grep -F "$boot_marker" "$log_file" >/dev/null 2>&1; then
	echo "check-boot-scaffold: observed boot marker"
	exit 0
fi

echo "check-boot-scaffold: boot marker not observed (qemu exit $qemu_status)" >&2
exit 1
