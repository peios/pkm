#!/usr/bin/env bash
# Configure a staged PKM kernel tree: vendored base + PKM fragment.
#
# The base config is Arch's, carrying ~6300 modules. Which of them survive
# depends on the profile:
#
#   production  Arch's module set is kept intact. Everything the boot path
#               needs is forced =y by pkm.fragment, so the kernel still boots
#               with zero modules loaded; the rest build as signed modules.
#   kunit       Narrowed to the QEMU device set and flattened to all-built-in.
#               The test kernel must not depend on the module stack to boot.
# Runs inside the build image (needs make + clang + rustc + bindgen on PATH). No
# target compilation.
#
# usage: configure-kernel.sh <kernel-tree> [profile]
#   profile: production (default) | kunit
#   localversion: optional CONFIG_LOCALVERSION suffix (e.g. "-peios-0.20.1-rc1"),
#                 baked into .config so `uname -r` / `make kernelrelease` become
#                 <linux>-<suffix> consistently across compile + debuginfo.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
	echo "usage: $0 <kernel-tree> [production|kunit] [localversion]" >&2
	exit 2
fi

tree=$(cd "$1" && pwd) || exit 1
profile=${2:-production}
localversion=${3:-}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cfg="$here/config"
repo=$(cd "$here/.." && pwd)

if [[ ! -f "$tree/Makefile" ]] || ! grep -q '^VERSION =' "$tree/Makefile"; then
	echo "not a Linux source root: $tree" >&2
	exit 1
fi

# PKM_LLVM selects kbuild's LLVM argument: "-18" (default — the container's
# Debian-versioned tool names: clang-18, ld.lld-18, ...) or "1" (a composed
# peipkg root, where upstream LLVM installs only the unversioned names).
# PKM_HOSTCC overrides the host-tool compiler (kconfig etc.) where clang
# can't drive userspace links — the peipkg root sets gcc until its clang
# driver learns the /usr/lib/<triplet> layout.
make=(make LLVM="${PKM_LLVM:--18}")
[[ -n "${PKM_HOSTCC:-}" ]] && make+=(HOSTCC="$PKM_HOSTCC")

cd "$tree"

# 1. vendored base, resolved against this kernel version
cp "$cfg/config.x86_64.base" .config
"${make[@]}" olddefconfig

# 2. KUnit only: narrow modules to the QEMU-needed device set. The production
#    profile keeps Arch's full module set — lsmod.txt was captured from a single
#    machine and describes that machine, not Peios's target hardware.
if [[ "$profile" == kunit ]]; then
	LSMOD="$cfg/lsmod.txt" "${make[@]}" localmodconfig
fi

# 3. force PKM / hardening / boot choices (after narrowing, so they survive it)
./scripts/kconfig/merge_config.sh -m .config "$cfg/pkm.fragment"

# 4. KUnit profile overlay
if [[ "$profile" == kunit ]]; then
	./scripts/kconfig/merge_config.sh -m .config "$cfg/kunit.fragment"
fi

# 4b. stamp the Peios release suffix into CONFIG_LOCALVERSION (overrides the
#     empty default in pkm.fragment), so `uname -r` is <linux>-peios-<pkmver>.
#     Set after the fragment merges, before the resolve below preserves it.
if [[ -n "$localversion" ]]; then
	./scripts/config --file .config --set-str LOCALVERSION "$localversion"
fi

# 4c. point module signing at the Peios module-signing key. Set explicitly
#     rather than left at the default `certs/signing_key.pem`, which
#     certs/Makefile treats as a request to autogenerate an ephemeral keypair —
#     non-reproducible, and leaving no key to sign anything with later.
#     Deliberately a different key from the KACS TCB key; see PEI-218.
if [[ -n "${PKM_MODSIG_KEY:-}" ]]; then
	./scripts/config --file .config --set-str MODULE_SIG_KEY "$PKM_MODSIG_KEY"
fi

# 5. resolve all merged choices
"${make[@]}" olddefconfig

# 6. KUnit only, LAST: flip every module to built-in. Must come after the final
#    olddefconfig — a `default m` tristate (e.g. WATCHDOG_PRETIMEOUT_GOV_SEL)
#    would otherwise be re-modularized by a later resolve. The build's
#    syncconfig preserves these =y values, so nothing re-modularizes.
if [[ "$profile" == kunit ]]; then
	"${make[@]}" mod2yesconfig
fi

# 7. invariant gate (same checker the old flow used)
bash "$repo/kernel/verify-kernel-config.sh" .config

echo "configure-kernel: $profile .config ready at $tree/.config"
