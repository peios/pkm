#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <pkm-new-root>" >&2
	exit 2
fi

repo_root=$1

die() {
	echo "verify-scaffold: $*" >&2
	exit 1
}

for forbidden in \
	"$repo_root/events" \
	"$repo_root/fuzz" \
	"$repo_root/kernel/patches"; do
	if [[ -e "$forbidden" ]]; then
		die "forbidden path present: $forbidden"
	fi
done

for required in \
	"$repo_root/crates/kacs-core/src/lib.rs" \
	"$repo_root/kacs/access_check.c" \
	"$repo_root/kacs/access_check.h" \
	"$repo_root/kacs/access_check.rs" \
	"$repo_root/kacs/kacs_rust.rs" \
	"$repo_root/kacs/kunit.c" \
	"$repo_root/kacs/lsm.c"; do
	if [[ ! -f "$required" ]]; then
		die "required slow-track source file missing: $required"
	fi
done

if grep -q 'syscall_64.tbl' "$repo_root/kernel/Dockerfile"; then
	die "kernel/Dockerfile still mutates the syscall table"
fi

if [[ -d "$repo_root/kacs" ]] && \
	rg -n 'eventfd' "$repo_root/kacs" >/dev/null; then
	die "legacy eventfd plumbing found in kacs subtree"
fi
