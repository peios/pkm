#!/usr/bin/env bash
# Carve the initramfs module subset out of the installed module tree and give it
# its own dependency index.
#
# The initramfs is a separate root: it gets its own copy of the modules it needs
# to reach the real root, not a view onto the main root's set. Which modules
# those are is policy, and lives in build/config/irf-modules.list rather than
# here.
#
# THE INDEX IS REGENERATED, NOT COPIED. The main tree's modules.dep describes
# all ~6449 modules; against a subset it would name dependencies that are not
# present, so modprobe would resolve a chain and then fail on a missing file.
# depmod is re-run over the carved tree so the index describes exactly what is
# there. It has to happen here, at build time, for the same reason the main
# tree's index does: peipkg-compose runs no install-time side effects, so a
# composed initramfs root would otherwise carry no index at all — and the boot
# that needs the index is the one that would have had to create it.
#
# usage: install-modules-irf.sh <source-dir> <full-module-root> <staging-root> <System.map>
#
# <source-dir> is the pkm source tree, for build/config/irf-modules.list. The
# release is taken from the installed tree rather than by asking the kernel
# Makefile: install-modules.sh has already created exactly one release directory
# there, so reading it needs no build tree and cannot disagree with what was
# actually installed. <System.map> is the built kernel's symbol table, which
# lets depmod say which symbols a module imports that neither vmlinux nor any
# module in the subset provides.
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 <source-dir> <full-module-root> <staging-root> <System.map>" >&2
	exit 2
fi

srcdir=$(cd "$1" && pwd) || exit 1
full=$(cd "$2" && pwd) || exit 1
root=$3
sysmap=$4
[[ -s "$sysmap" ]] || { echo "missing System.map: $sysmap" >&2; exit 1; }

list="$srcdir/build/config/irf-modules.list"
[[ -r "$list" ]] || { echo "missing module list: $list" >&2; exit 1; }

shopt -s nullglob
releases=("$full"/lib/modules/*/)
shopt -u nullglob
[[ ${#releases[@]} -eq 1 ]] || {
	echo "expected exactly one release under $full/lib/modules, found ${#releases[@]}" >&2
	exit 1
}
release=$(basename "${releases[0]}")

src="$full/lib/modules/$release"

mkdir -p "$root"
root=$(cd "$root" && pwd)
dst="$root/lib/modules/$release"
mkdir -p "$dst/kernel"

# Copy each listed subtree, preserving its position under kernel/ so the paths
# depmod records match the paths modprobe will look up.
copied=0
skipped=()
excluded=()
while read -r path; do
	path=${path%%#*}
	path=$(echo "$path" | tr -d '[:space:]')
	[[ -n "$path" ]] || continue
	if [[ "$path" == -* ]]; then
		# Applied after the copy loop: an exclusion must win over an earlier
		# directory line whatever order the two appear in.
		excluded+=("${path#-}")
		continue
	fi
	if [[ ! -e "$src/kernel/$path" ]]; then
		skipped+=("$path")
		continue
	fi
	mkdir -p "$dst/kernel/$(dirname "$path")"
	cp -a "$src/kernel/$path" "$dst/kernel/$(dirname "$path")/"
	copied=$((copied + 1))
done < "$list"

[[ "$copied" -gt 0 ]] || { echo "module list matched nothing under $src/kernel" >&2; exit 1; }
for path in "${excluded[@]}"; do
	rm -rf "$dst/kernel/$path"
done
if [[ ${#skipped[@]} -gt 0 ]]; then
	echo "install-modules-irf: not present in this build, skipped: ${skipped[*]}"
fi

# depmod reads these as inputs: modules.order fixes resolution order when two
# modules provide the same symbol, and modules.builtin(.modinfo) tell it which
# dependencies are already inside vmlinux and therefore need no module. Without
# them a built-in dependency looks unresolvable and depmod warns on every module
# that has one.
for f in modules.order modules.builtin modules.builtin.modinfo; do
	[[ -e "$src/$f" ]] && cp -a "$src/$f" "$dst/$f"
done

# -b takes the tree as a root; naming the release explicitly matters because a
# bare depmod indexes the *running* kernel, which is the build host's, not the
# one just built.
#
# -e -F: report every symbol a module imports that neither vmlinux (System.map)
# nor another module in THIS tree exports. Over a subset that is the failure
# the dangling-file check below cannot see: depmod does not record a dependency
# it cannot resolve, so e1000e without drivers/ptp, and ptp without drivers/pps,
# each produced a clean index and an "Unknown symbol" at boot. depmod only
# warns, so the warnings are the assertion.
unresolved=$(depmod -e -F "$sysmap" -b "$root" "$release" 2>&1 | grep -i "needs unknown symbol" || true)
[[ -z "$unresolved" ]] || {
	echo "initramfs module set has unresolved symbols — add the providing subtree to irf-modules.list:" >&2
	echo "$unresolved" | head -20 >&2
	exit 1
}

for f in modules.dep modules.dep.bin modules.alias modules.alias.bin \
	 modules.symbols modules.symbols.bin; do
	[[ -s "$dst/$f" ]] || { echo "missing or empty index file: $f" >&2; exit 1; }
done

# The index must describe this tree and no other. A modules.dep line naming a
# module that was not copied means modprobe would resolve a dependency chain and
# then fail on a missing file — the exact failure regenerating the index is
# meant to prevent, so assert it rather than trust it.
missing=$(cut -d: -f1 "$dst/modules.dep" | while read -r m; do
	[[ -e "$dst/$m" ]] || echo "$m"
done | head -5)
[[ -z "$missing" ]] || {
	echo "index references modules not in the tree:" >&2
	echo "$missing" >&2
	exit 1
}

count=$(find "$dst" -name '*.ko*' | wc -l)
size=$(du -sm "$dst" | cut -f1)
echo "install-modules-irf: $count modules (${size}M) for $release at $dst"
