#!/usr/bin/env bash
# Apply the PKM kernel-integration patch series to a Linux source tree.
#
# Each patch is a plain unified diff against the pinned kernel version; the
# `series` file lists them in apply order. This replaces the old imperative
# in-tree installer: a patch either applies cleanly or fails
# loudly. On a kernel-version bump, re-run with PKM_PATCH_3WAY=1 to fall back
# to a 3-way merge and surface conflicts as ordinary .rej/<<< markers.
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

# --- defeat stray parent-repo resolution ---
# `git apply` run inside SOME git repo treats patches whose target paths are
# absent/untracked as "Skipped" and STILL exits 0. If $linux is not its own
# git root, git would walk up and resolve an unrelated ancestor repo, silently
# skipping every patch. Stop the upward search at $linux's parent so git uses
# the tree's own repo, or no repo at all (plain-file mode hard-errors on a
# missing target) — never an ancestor.
export GIT_CEILING_DIRECTORIES
GIT_CEILING_DIRECTORIES=$(dirname "$linux")

apply_flags=(--whitespace=nowarn)
if [[ "${PKM_PATCH_3WAY:-0}" == "1" ]]; then
	apply_flags+=(--3way)
fi

count=0
while IFS= read -r entry || [[ -n "$entry" ]]; do
	entry=${entry%%#*}                       # strip comments
	entry=$(printf '%s' "$entry" | tr -d '[:space:]')
	[[ -z "$entry" ]] && continue
	patch="$patches/$entry"
	[[ -f "$patch" ]] || { echo "missing patch in series: $entry" >&2; exit 1; }

	# Capture output: a skip prints "Skipped patch" and exits 0 — treat as failure.
	out=$(git -C "$linux" apply "${apply_flags[@]}" "$patch" 2>&1) || {
		[[ -n "$out" ]] && echo "$out" >&2
		echo "FAILED to apply: $entry" >&2
		exit 1
	}
	if grep -q 'Skipped patch' <<<"$out"; then
		echo "$out" >&2
		echo "SKIPPED (target not found / not applied): $entry" >&2
		exit 1
	fi
	count=$((count + 1))
done < "$patches/series"

echo "apply-patches: applied $count patches cleanly into $linux"
