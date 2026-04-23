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
	"$repo_root/kacs/caap_cache.c" \
	"$repo_root/kacs/caap_cache.h" \
	"$repo_root/kacs/caap_cache.rs" \
	"$repo_root/kacs/kacs_rust.rs" \
	"$repo_root/kacs/kunit.c" \
	"$repo_root/kacs/token_fd.c" \
	"$repo_root/kacs/token_fd.h" \
	"$repo_root/kacs/token_runtime.h" \
	"$repo_root/kacs/token_runtime.rs" \
	"$repo_root/kacs/lsm.c"; do
	if [[ ! -f "$required" ]]; then
		die "required slow-track source file missing: $required"
	fi
done

if grep -q 'syscall_64.tbl' "$repo_root/kernel/Dockerfile"; then
	die "kernel/Dockerfile still mutates the syscall table"
fi

for syscall in \
	"1000 kacs_open_self_token" \
	"1023 kacs_access_check" \
	"1024 kacs_access_check_list" \
	"1025 kacs_set_caap"; do
	number=${syscall%% *}
	name=${syscall#* }
	if ! rg -q "^[[:space:]]*${number}[[:space:]]+${name}\$" \
		"$repo_root/kernel/install-pkm-subtree.sh"; then
		die "install-pkm-subtree.sh does not stage syscall ${number} ${name}"
	fi
done

if [[ -d "$repo_root/kacs" ]] && \
	rg -n 'eventfd' "$repo_root/kacs" >/dev/null; then
	die "legacy eventfd plumbing found in kacs subtree"
fi
