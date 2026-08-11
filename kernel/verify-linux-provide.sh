#!/bin/sh
# Assert that a package's `linux-*` virtual provide names the Linux version the
# recipe is actually building.
#
# kernel-headers publishes `linux-kernel-headers = <ver>` and kernel publishes
# `linux-kernel = <ver>`, so that consumers can say "I need Linux UAPI >= X"
# without depending on pkm's own SemVer, which tracks the PKM UAPI / KACS ABI
# and says nothing about Linux. Those provides are static TOML — pekit has no
# build-derived templating for `provides` — so nothing stops [env]
# KERNEL_VERSION being bumped while the provide is left behind, which would
# publish a package claiming to carry a UAPI it does not.
#
# So the build asserts it, in both directions:
#   1. the declared provide matches KERNEL_VERSION, and
#   2. KERNEL_VERSION matches what the staged tree's own Makefile says,
#      catching a pin that disagrees with the source actually checked out.
#
# Usage: verify-linux-provide.sh <package-file> <provide-name> <kernel-version> [staged-tree]
set -eu

pkgfile=${1:?usage: verify-linux-provide.sh <package-file> <provide-name> <kernel-version> [staged-tree]}
provide=${2:?missing provide name}
kver=${3:?missing kernel version}
tree=${4:-}

# KERNEL_VERSION is a git tag ("v7.0.9"); the provide is a bare version.
expected=${kver#v}

declared=$(sed -n "s/^[[:space:]]*${provide}[[:space:]]*=[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$pkgfile" | head -1)

if [ -z "$declared" ]; then
	echo "verify-linux-provide: $pkgfile declares no \`$provide\` — it must publish the Linux version as a virtual provide" >&2
	exit 1
fi

if [ "$declared" != "$expected" ]; then
	echo "verify-linux-provide: $pkgfile declares $provide = \"$declared\" but KERNEL_VERSION is \"$kver\" (expected \"$expected\")." >&2
	echo "  Bump the provide in lockstep with KERNEL_VERSION, or consumers gated on the Linux UAPI resolve against a version this package does not carry." >&2
	exit 1
fi

# Cross-check the pin against the tree that was actually staged.
if [ -n "$tree" ] && [ -f "$tree/Makefile" ]; then
	v=$(sed -n 's/^VERSION = *//p'    "$tree/Makefile" | head -1)
	p=$(sed -n 's/^PATCHLEVEL = *//p' "$tree/Makefile" | head -1)
	s=$(sed -n 's/^SUBLEVEL = *//p'   "$tree/Makefile" | head -1)
	actual="$v.$p.$s"
	if [ "$actual" != "$expected" ]; then
		echo "verify-linux-provide: staged tree is Linux $actual but KERNEL_VERSION is \"$kver\"." >&2
		exit 1
	fi
fi

echo "verify-linux-provide: $provide = $expected ✓"
