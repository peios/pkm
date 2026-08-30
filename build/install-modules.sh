#!/usr/bin/env bash
# Install the built kernel modules into a staging root, indexed and ready to
# package. Runs inside the build image (needs make + kmod on PATH).
#
# `make modules_install` runs depmod itself, against the kernel release it just
# built, so the index (modules.dep, modules.alias, modules.symbols, ...) is
# correct by construction and ships inside the package. That is deliberate:
# peipkg-compose runs no install-time side effects, so a composed root would
# otherwise carry no index at all -- and first boot cannot depend on an index
# that only first boot would create. The peipkg `depmod` side effect then serves
# its real purpose, reindexing after an out-of-tree module is added.
#
# usage: install-modules.sh <kernel-tree> <staging-root>
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 <kernel-tree> <staging-root>" >&2
	exit 2
fi

tree=$(cd "$1" && pwd) || exit 1
root=$2

make=(make LLVM="${PKM_LLVM:--18}")
[[ -n "${PKM_HOSTCC:-}" ]] && make+=(HOSTCC="$PKM_HOSTCC")

# depmod: the kernel resolves $(DEPMOD) through PATH and only WARNS when it
# misses -- the index assertion at the bottom of this script is what turns that
# into an error. Peios ships depmod in /usr/libexec rather than on PATH,
# because it is machine-facing (pkgs ec92d66), so on a composed build root the
# default finds nothing. Prefer whatever is on PATH, so the container build is
# unchanged, and fall back to the Peios location.
depmod_bin="${PKM_DEPMOD:-}"
if [[ -z "$depmod_bin" ]]; then
	if command -v depmod >/dev/null 2>&1; then
		depmod_bin=depmod
	elif [[ -x /usr/libexec/depmod ]]; then
		depmod_bin=/usr/libexec/depmod
	fi
fi
[[ -n "$depmod_bin" ]] && make+=(DEPMOD="$depmod_bin")

mkdir -p "$root"
root=$(cd "$root" && pwd)

cd "$tree"

# INSTALL_MOD_STRIP=1 strips debug info from the installed modules; the debug
# info is carried separately by the debuginfo stage.
"${make[@]}" modules_install INSTALL_MOD_PATH="$root" INSTALL_MOD_STRIP=1

release=$("${make[@]}" -s kernelrelease)
moddir="$root/lib/modules/$release"

[[ -d "$moddir" ]] || { echo "modules not installed at $moddir" >&2; exit 1; }

# modules_install symlinks build/ and source/ back into the build tree. Those
# are absolute paths into a directory that will not exist on target, and
# kernel-devel provides the real build/ tree, so drop them.
rm -f "$moddir/build" "$moddir/source"

# Assert the index actually landed -- without it modprobe resolves nothing and
# autoloading is silently dead, with no error pointing at the cause.
for f in modules.dep modules.dep.bin modules.alias modules.alias.bin \
	 modules.symbols modules.symbols.bin modules.builtin modules.order; do
	[[ -s "$moddir/$f" ]] || { echo "missing or empty index file: $f" >&2; exit 1; }
done

count=$(find "$moddir" -name '*.ko*' | wc -l)
[[ "$count" -gt 0 ]] || { echo "no modules installed" >&2; exit 1; }

echo "install-modules: $count modules installed for $release at $moddir"
