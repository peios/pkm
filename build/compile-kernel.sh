#!/usr/bin/env bash
# Compile a configured PKM kernel tree to a bzImage. Monolithic — no modules,
# no modules_install (a temporary dev simplification; production will be modular,
# so modules_install returns then). Runs inside the build image (needs LLVM 18 + Rust 1.83 +
# bindgen on PATH). Expects configure-kernel.sh to have produced .config.
#
# usage: compile-kernel.sh <configured-kernel-tree>
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <configured-kernel-tree>" >&2
	exit 2
fi

tree=$(cd "$1" && pwd) || exit 1
if [[ ! -f "$tree/Makefile" ]] || ! grep -q '^VERSION =' "$tree/Makefile"; then
	echo "not a Linux source root: $tree" >&2
	exit 1
fi
if [[ ! -f "$tree/.config" ]]; then
	echo "no .config in $tree — run configure-kernel.sh first" >&2
	exit 1
fi

# Pin the inputs mkcompile_h bakes into compile.h so an unchanged tree relinks
# identically (reproducibility, and so a random container hostname doesn't churn
# vmlinux every run). Release builds can override the timestamp via env.
export KBUILD_BUILD_USER=pkm
export KBUILD_BUILD_HOST=pkm-build
# Default the build timestamp to the source's commit date — pekit exports
# PEKIT_SOURCE_TIMESTAMP as unix seconds (the source tree's latest commit; 0 when
# it isn't a git checkout) — so the stamp tracks the actual release and stays
# reproducible. Fall back to a fixed epoch otherwise. An explicit
# KBUILD_BUILD_TIMESTAMP in the env still wins.
src_ts=${PEKIT_SOURCE_TIMESTAMP:-0}
[ "$src_ts" -gt 0 ] 2>/dev/null || src_ts=1735689600   # fallback: 2025-01-01T00:00:00Z
: "${KBUILD_BUILD_TIMESTAMP:=@${src_ts}}"
export KBUILD_BUILD_TIMESTAMP

cd "$tree"

# PKM_LLVM selects kbuild's LLVM argument: "-18" (default — the container's
# Debian-versioned tool names) or "1" (a composed peipkg root: unversioned
# names only). CC follows the same suffix; ccache wraps it only where it
# exists (the container mounts a cache volume; a pristine root has none —
# it caches C across the fresh per-build source copy, Rust/link are not
# cached but are the minority). PKM_HOSTCC overrides the host-tool compiler
# where clang can't drive userspace links (the peipkg root sets gcc).
llvm=${PKM_LLVM:--18}
if [[ "$llvm" == 1 ]]; then cc=clang; else cc="clang${llvm}"; fi
command -v ccache >/dev/null 2>&1 && cc="ccache $cc"
hostcc=()
[[ -n "${PKM_HOSTCC:-}" ]] && hostcc=(HOSTCC="$PKM_HOSTCC")
# The host programs Kbuild builds -- fixdep, modpost, objtool and the rest --
# ship in kernel-devel, so they link with the distribution's flags like any
# other shipped program: full RELRO, packed relative relocations, a build ID.
# Kbuild takes host link flags only from HOSTLDFLAGS (C, C++ and Rust host
# programs and objtool alike), never from LDFLAGS, so pass the build's LDFLAGS
# through there unless the caller set HOSTLDFLAGS itself.
hostld=()
if [[ -n "${HOSTLDFLAGS:-}" ]]; then
	hostld=(HOSTLDFLAGS="$HOSTLDFLAGS")
elif [[ -n "${LDFLAGS:-}" ]]; then
	hostld=(HOSTLDFLAGS="$LDFLAGS")
fi
# Likewise their compile flags come only from HOSTCFLAGS, and a Peios root
# requires control-flow protection (endbr landing pads and the IBT/SHSTK
# property) in every shipped program. Pass the build's -fcf-protection through
# there, and only that: Kbuild sets its own warnings and optimisation for host
# programs, and objtool's build takes HOSTCFLAGS too.
hostc=()
if [[ -n "${HOSTCFLAGS:-}" ]]; then
	hostc=(HOSTCFLAGS="$HOSTCFLAGS")
else
	cet=
	for f in ${CFLAGS:-}; do
		case $f in -fcf-protection*) cet="$cet $f" ;; esac
	done
	[[ -n "$cet" ]] && hostc=(HOSTCFLAGS="${cet# }")
fi
# Normalize compiler-recorded paths before they enter DWARF.  debugedit in the
# reference build image does not understand rustc's .debug_names section, so a
# post-link rewrite alone can leave the absolute Pekit worktree in vmlinux.
# Use the same source root the debuginfo package installs, making both C and
# Rust debug information reproducible and usable without disclosing the build
# host's directory layout.
basever=$(make -s kernelversion)
debug_root="/usr/src/debug/kernel-$basever"
# Clang otherwise embeds its entire command line in DW_AT_producer, including
# the left-hand (host) path of -fdebug-prefix-map.  The remap fixes source
# references; suppressing recorded switches makes the debug artifact itself
# independent of the workspace path too.
kcflags="-gno-record-gcc-switches -fdebug-prefix-map=$tree=$debug_root -fmacro-prefix-map=$tree=$debug_root"
krustflags="--remap-path-prefix=$tree=$debug_root"
# PKM_JOBS caps parallelism. The default is every core, which is right on a
# build farm and wrong on a workstation sharing the machine: twelve concurrent
# clang processes through the vmlinux link and module generation is what took
# this build out to the OOM killer once, with no error in the log -- the build
# simply stopped mid-line, because the whole process group was signalled.
make LLVM="$llvm" CC="$cc" "${hostcc[@]}" "${hostc[@]}" "${hostld[@]}" \
	KCFLAGS="$kcflags" KRUSTFLAGS="$krustflags" \
	-j"${PKM_JOBS:-$(nproc)}"

echo ""
echo "compile-kernel: built"
ls -la arch/x86/boot/bzImage System.map 2>&1
