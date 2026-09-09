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
# Compiler-side path remapping deliberately uses the upstream kernel version:
# it is available before Kbuild has materialized include/config/kernel.release,
# and remains stable across Peios package revisions of the same source base.
# Install debug sources at that exact path so both C and Rust DWARF resolve.
basever=$(make -s -C "$tree" kernelversion)
debug_root="/usr/src/debug/kernel-$basever"
dbg="$out/usr/lib/debug/lib/modules/$ver"
mkdir -p "$dbg"
cp "$tree/vmlinux" "$dbg/vmlinux"

# debugedit 5.3 does not understand LLVM/Rust's DWARF-5 .debug_names
# accelerator.  Worse, it returns success after printing a warning, leaving
# most paths untouched and producing an incomplete source list.  The section
# is optional (debuggers fall back to .debug_info), so remove it from the
# separate debug artifact before rewriting paths.  The runtime kernel and its
# build ID are unchanged.
if readelf -S "$dbg/vmlinux" | grep '[.]debug_names' >/dev/null; then
	objcopy --remove-section=.debug_names "$dbg/vmlinux"
fi

# Rewrite the baked-in build-path prefix in the DWARF to a stable, leak-free
# /usr/src/debug path (so .debug doesn't carry the builder's path and source
# paths resolve on a target), and capture the NUL-separated list of sources it
# references.
srclist=$(mktemp)
debugedit -b "$tree" -d "$debug_root" -l "$srclist" "$dbg/vmlinux"

# A successful exit alone is insufficient with older debugedit.  Assert that
# the build root is actually absent from the rewritten DWARF/string tables.
if strings "$dbg/vmlinux" | grep -F "$tree" >/dev/null; then
	echo "make-debuginfo: build path remains after debugedit: $tree" >&2
	exit 1
fi

# build-id index: gdb/crash/debuginfod resolve the symbols by the kernel's
# build-id at /usr/lib/debug/.build-id/<xx>/<rest>.debug.
bid=$(readelf -n "$dbg/vmlinux" | sed -n 's/.*Build ID: *//p' | head -1)
if [[ -n "$bid" ]]; then
	mkdir -p "$out/usr/lib/debug/.build-id/${bid:0:2}"
	ln -sf "../../lib/modules/$ver/vmlinux" \
		"$out/usr/lib/debug/.build-id/${bid:0:2}/${bid:2}.debug"
fi

# Stage the referenced sources for kernel-debugsource. A full vmlinux's DWARF
# references tens of thousands of sources, so the filtered list is copied in ONE
# cpio pass — a per-file mkdir+cp loop here spawns ~2 processes per file and takes
# the better part of an hour; cpio does the whole set in seconds. The bash filter
# below is builtin-only (no spawns): drop empty/dir entries and anything not
# present in the tree, re-emitting NUL-separated paths relative to $tree for cpio.
src="$out$debug_root"
mkdir -p "$src"
while IFS= read -r -d '' rel; do
	[[ -z "$rel" || "$rel" == */ ]] && continue
	[[ -f "$tree/$rel" ]] && printf '%s\0' "$rel"
done < "$srclist" | (cd "$tree" && cpio --null --quiet -pdm "$src")
rm -f "$srclist"

echo "make-debuginfo: $ver — vmlinux + build-id ${bid:0:12}… + $(find "$src" -type f 2>/dev/null | wc -l) source files"
