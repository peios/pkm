#!/usr/bin/env bash
# Produce the kernel debuginfo + debugsource trees from a built kernel tree.
#
# Mirrors glibc's build-time debug handling, adapted for the kernel: the kernel
# ships the WHOLE vmlinux as its debug artifact (crash/gdb want the full image),
# rather than stripping a production binary — vmlinux is never installed at
# runtime (the bzImage is), so there is nothing to strip.
#
# usage: make-debuginfo.sh <built-kernel-tree> <out-dir>
#   <out-dir> receives:
#     usr/lib/debug/lib/modules/<ver>/vmlinux       -> kernel-debuginfo
#     usr/lib/debug/.build-id/<xx>/<rest>.debug     -> kernel-debuginfo (build-id symlink)
#     usr/src/debug/kernel-<ver>/**                 -> kernel-debugsource
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 <built-kernel-tree> <out-dir>" >&2
	exit 2
fi

tree=$(cd "$1" && pwd) || exit 1
out=$2
[[ -f "$tree/vmlinux" ]] || { echo "no vmlinux in $tree (build the kernel first)" >&2; exit 1; }

ver=$(make -s -C "$tree" kernelrelease)
dbg="$out/usr/lib/debug/lib/modules/$ver"
mkdir -p "$dbg"
cp "$tree/vmlinux" "$dbg/vmlinux"

# Rewrite the baked-in build-path prefix in the DWARF to a stable, leak-free
# /usr/src/debug path (so .debug doesn't carry the builder's path and source
# paths resolve on a target), and capture the NUL-separated list of sources it
# references.
srclist=$(mktemp)
debugedit -b "$tree" -d "/usr/src/debug/kernel-$ver" -l "$srclist" "$dbg/vmlinux"

# build-id index: gdb/crash/debuginfod resolve the symbols by the kernel's
# build-id at /usr/lib/debug/.build-id/<xx>/<rest>.debug.
bid=$(readelf -n "$dbg/vmlinux" | sed -n 's/.*Build ID: *//p' | head -1)
if [[ -n "$bid" ]]; then
	mkdir -p "$out/usr/lib/debug/.build-id/${bid:0:2}"
	ln -sf "../../lib/modules/$ver/vmlinux" \
		"$out/usr/lib/debug/.build-id/${bid:0:2}/${bid:2}.debug"
fi

# Stage the referenced sources for kernel-debugsource.
src="$out/usr/src/debug/kernel-$ver"
while IFS= read -r -d '' rel; do
	[[ -z "$rel" || "$rel" == */ ]] && continue
	[[ -f "$tree/$rel" ]] || continue
	mkdir -p "$src/$(dirname "$rel")"
	cp "$tree/$rel" "$src/$rel"
done < "$srclist"
rm -f "$srclist"

echo "make-debuginfo: $ver — vmlinux + build-id ${bid:0:12}… + $(find "$src" -type f 2>/dev/null | wc -l) source files"
