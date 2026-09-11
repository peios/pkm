#!/usr/bin/env bash
# Apply the PKM kernel-integration patch series to a Linux source tree.
#
# Each patch is a plain unified diff against the pinned kernel version; the
# `series` file lists them in apply order. This replaces the old imperative
# in-tree installer: a patch either applies cleanly or fails
# loudly. On a kernel-version bump, re-run with PKM_PATCH_3WAY=1 to use Git's
# 3-way fallback while rebasing the series in a developer checkout. Production
# builds use GNU patch and therefore do not need Git in the build root.
#
# usage: apply-patches.sh <linux-tree> [patches-dir]
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
	echo "usage: $0 <linux-tree> [patches-dir]" >&2
	exit 2
fi

linux=$(cd "$1" 2>/dev/null && pwd) || { echo "no such linux tree: $1" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
patches=${2:-$here/patches}
patches=$(cd "$patches" 2>/dev/null && pwd) || { echo "no such patches dir: $2" >&2; exit 1; }

[[ -f "$patches/series" ]] || { echo "no series file in: $patches" >&2; exit 1; }

# --- guard: $linux must be a Linux source root, not a wrapper dir ---
# Catches the classic mistake of pointing at a parent dir that merely *contains*
# the tree (e.g. a copy that nested it one level down).
if [[ ! -f "$linux/Makefile" ]] || ! grep -q '^VERSION =' "$linux/Makefile" \
	|| [[ ! -f "$linux/security/security.c" ]]; then
	echo "not a Linux source root (no kernel Makefile / security/security.c): $linux" >&2
	echo "  hint: pass the tree root itself, not a directory that contains it" >&2
	exit 1
fi

count=0
while IFS= read -r entry || [[ -n "$entry" ]]; do
	entry=${entry%%#*}                       # strip comments
	entry=$(printf '%s' "$entry" | tr -d '[:space:]')
	[[ -z "$entry" ]] && continue
	patch="$patches/$entry"
	[[ -f "$patch" ]] || { echo "missing patch in series: $entry" >&2; exit 1; }

	if [[ "${PKM_PATCH_3WAY:-0}" == "1" ]]; then
		git -C "$linux" apply --whitespace=nowarn --3way "$patch" || {
			echo "FAILED to apply with 3-way fallback: $entry" >&2
			exit 1
		}
	else
		# --fuzz=0 makes context drift fatal; --forward rejects an already-
		# applied or reversed patch instead of interacting or silently undoing it.
		patch --directory "$linux" --strip=1 --batch --forward --fuzz=0 \
			--input "$patch" || {
			echo "FAILED to apply: $entry" >&2
			exit 1
		}
	fi
	count=$((count + 1))
done < "$patches/series"

echo "apply-patches: applied $count patches cleanly into $linux"
