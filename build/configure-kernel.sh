#!/usr/bin/env bash
# Configure a staged PKM kernel tree: vendored base + PKM fragment, narrowed to
# the QEMU device set and made monolithic (all built-in). Runs inside the build
# image (needs make + clang + rustc + bindgen on PATH). No target compilation.
#
# usage: configure-kernel.sh <kernel-tree> [profile]
#   profile: production (default) | kunit
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
	echo "usage: $0 <kernel-tree> [production|kunit]" >&2
	exit 2
fi

tree=$(cd "$1" && pwd) || exit 1
profile=${2:-production}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cfg="$here/config"
repo=$(cd "$here/.." && pwd)

if [[ ! -f "$tree/Makefile" ]] || ! grep -q '^VERSION =' "$tree/Makefile"; then
	echo "not a Linux source root: $tree" >&2
	exit 1
fi

# Versioned LLVM tools in /usr/bin are always on PATH (login-shell-proof).
make=(make LLVM=-18)

cd "$tree"

# 1. vendored base, resolved against this kernel version
cp "$cfg/config.x86_64.base" .config
"${make[@]}" olddefconfig

# 2. narrow modules to the QEMU-needed device set
LSMOD="$cfg/lsmod.txt" "${make[@]}" localmodconfig

# 3. force PKM / hardening / boot choices (after narrowing, so they survive it)
./scripts/kconfig/merge_config.sh -m .config "$cfg/pkm.fragment"

# 4. KUnit profile overlay
if [[ "$profile" == kunit ]]; then
	./scripts/kconfig/merge_config.sh -m .config "$cfg/kunit.fragment"
fi

# 5. resolve all merged choices
"${make[@]}" olddefconfig

# 6. monolithic, LAST: flip every module to built-in. Must come after the final
#    olddefconfig — a `default m` tristate (e.g. WATCHDOG_PRETIMEOUT_GOV_SEL)
#    would otherwise be re-modularized by a later resolve. The build's
#    syncconfig preserves these =y values, so nothing re-modularizes.
"${make[@]}" mod2yesconfig

# 7. invariant gate (same checker the old flow used)
bash "$repo/kernel/verify-kernel-config.sh" .config

echo "configure-kernel: $profile .config ready at $tree/.config"
