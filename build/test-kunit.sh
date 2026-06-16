#!/usr/bin/env bash
# Boot a KUnit-enabled PKM bzImage in QEMU and assert the suite passes.
# Ported from the old check-kunit-scaffold.sh, de-hardcoded.
#
# usage: test-kunit.sh <kernel-tree-or-bzImage>
# env:
#   PKM_KUNIT_INITRD   optional initrd; omitted -> boot without one
#                      (kunit_shutdown=poweroff fires before init is needed)
#   QEMU_BIN           qemu binary (default qemu-system-x86_64)
#   PKM_KUNIT_TIMEOUT  seconds (default 420)
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <kernel-tree-or-bzImage>" >&2
	exit 2
fi

# accept either a tree or a direct bzImage path
if [[ -d "$1" ]]; then
	bzimage="$1/arch/x86/boot/bzImage"
else
	bzimage="$1"
fi
[[ -f "$bzimage" ]] || { echo "bzImage not found: $bzimage" >&2; exit 1; }

qemu=${QEMU_BIN:-qemu-system-x86_64}
command -v "$qemu" >/dev/null || { echo "qemu not found: $qemu" >&2; exit 1; }
initrd=${PKM_KUNIT_INITRD:-}
timeout_s=${PKM_KUNIT_TIMEOUT:-420}
# Persist the full serial log next to the kernel (a mounted out/ dir) so it
# survives a --rm container; mktemp in the container's /tmp would be lost.
if [[ -d "$1" ]]; then
	log="$1/kunit-qemu.log"
else
	log="$(cd "$(dirname "$bzimage")" && pwd)/kunit-qemu.log"
fi
log=${PKM_KUNIT_LOG:-$log}

# KTAP / suite markers emitted by the PKM KUnit suites.
suite_marker='pkm: kunit scaffold smoke passed'
summary_re='# pkm_kunit_scaffold: pass:[0-9]+ fail:0 skip:[0-9]+ total:[0-9]+'
fatal_re='BUG:|Kernel panic|Oops:|INFO: task .* blocked for more than|EXPECTATION FAILED|ASSERTION FAILED|not ok [0-9]+|# .*fail:[1-9]'

append='console=ttyS0 loglevel=7 ignore_loglevel panic=-1 kunit.enable=1 kunit_shutdown=poweroff'
[[ -n "${PKM_KUNIT_FILTER:-}" ]] && append+=" kunit.filter_glob=${PKM_KUNIT_FILTER}"

qemu_args=(
	-m 2048 -smp 2 -nographic -no-reboot -serial mon:stdio
	-machine accel=kvm:tcg                           # kvm if available, else tcg fallback
	-kernel "$bzimage"
	-append "$append"
)
[[ -n "$initrd" ]] && qemu_args+=(-initrd "$initrd")

echo "test-kunit: booting $bzimage ${initrd:+(initrd: $initrd) }via $qemu"
set +e
timeout "${timeout_s}s" "$qemu" "${qemu_args[@]}" >"$log" 2>&1
status=$?
set -e

fail=0
grep -Fq  "$suite_marker" "$log" || { echo "  MISSING: KUnit smoke marker"; fail=1; }
grep -Eq  "$summary_re"   "$log" || { echo "  MISSING: passing suite summary"; fail=1; }
grep -Eq  "$fatal_re"     "$log" && { echo "  FOUND: kernel/KUnit failure signature"; fail=1; }

if [[ $fail -ne 0 ]]; then
	echo "test-kunit: FAILED (qemu exit $status, log $log)" >&2
	echo "----- log tail -----" >&2
	tail -40 "$log" >&2
	exit 1
fi

echo "test-kunit: PASS — PKM KUnit suite passed in QEMU"
