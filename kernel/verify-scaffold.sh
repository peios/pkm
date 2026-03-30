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
	"$repo_root/Cargo.lock" \
	"$repo_root/events" \
	"$repo_root/fuzz" \
	"$repo_root/kernel/patches" \
	"$repo_root/target"; do
	if [[ -e "$forbidden" ]]; then
		die "forbidden path present: $forbidden"
	fi
done

expected_files=$(cat <<'EOF'
/crates/kacs-core/src/lib.rs
/kacs/kacs_rust.rs
/kacs/lsm.c
EOF
)

actual_files=$(find \
	"$repo_root/crates/kacs-core/src" \
	"$repo_root/kacs" \
	-type f | sed "s#^$repo_root##" | sort)

if [[ "$actual_files" != "$expected_files" ]]; then
	echo "verify-scaffold: unexpected scaffold source file set" >&2
	echo "expected:" >&2
	printf '%s\n' "$expected_files" >&2
	echo "actual:" >&2
	printf '%s\n' "$actual_files" >&2
	exit 1
fi

if grep -q 'syscall_64.tbl' "$repo_root/kernel/Dockerfile"; then
	die "kernel/Dockerfile still mutates the syscall table"
fi

if rg -n 'SYSCALL_DEFINE|late_initcall|securityfs_create|eventfd|call_int_hook' \
	"$repo_root/kacs" "$repo_root/crates/kacs-core/src" >/dev/null; then
	die "live implementation markers found in scaffold source files"
fi
