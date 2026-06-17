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

# Versioned LLVM tools (/usr/bin) are always on PATH; ccache caches C across the
# fresh per-build source copy. Rust/link are not cached but are the minority.
make LLVM=-18 CC="ccache clang-18" -j"$(nproc)"

echo ""
echo "compile-kernel: built"
ls -la arch/x86/boot/bzImage System.map 2>&1
