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
	"$repo_root/kacs/kmes.c" \
	"$repo_root/kacs/kmes.h" \
	"$repo_root/kacs/kmes_payload.rs" \
	"$repo_root/kacs/kmes_validate.rs" \
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
	"1001 kacs_open_process_token" \
	"1002 kacs_open_thread_token" \
	"1005 kacs_set_psb" \
	"1010 kacs_open_peer_token" \
	"1011 kacs_impersonate_peer" \
	"1012 kacs_revert" \
	"1013 kacs_set_impersonation_level" \
	"1021 kacs_get_sd" \
	"1022 kacs_set_sd" \
	"1090 kmes_emit" \
	"1091 kmes_attach" \
	"1092 kmes_emit_batch" \
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

if ! rg -q 'PTRACE_MODE_GETFD' "$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the PTRACE_MODE_GETFD patch"
fi

if ! rg -q 'PTRACE_MODE_ATTACH_REALCREDS \| PTRACE_MODE_GETFD' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not patch pidfd_getfd to carry PTRACE_MODE_GETFD"
fi

if ! rg -q 'PTRACE_MODE_PIDFD_OPEN' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the PTRACE_MODE_PIDFD_OPEN patch"
fi

if ! rg -q 'PTRACE_MODE_PROC_QUERY_LIMITED' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the PTRACE_MODE_PROC_QUERY_LIMITED patch"
fi

if ! rg -q 'PTRACE_MODE_PROC_QUERY_INFORMATION' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the PTRACE_MODE_PROC_QUERY_INFORMATION patch"
fi

if ! rg -q 'PTRACE_MODE_READ_FSCREDS \|' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'PTRACE_MODE_PIDFD_OPEN' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not patch pidfd_open to carry PTRACE_MODE_PIDFD_OPEN"
fi

if ! rg -q 'proc_pkm_check_task_metadata_access' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the procfs metadata visibility patch"
fi

if ! rg -q 'pkm_kacs_sched_setaffinity' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the sched_setaffinity KACS patch"
fi

if ! rg -q 'pkm_kacs_capable_in_cred_ns' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the commoncap capability switchboard patch"
fi

if ! rg -q 'pkm_kacs_prctl_capability_guard' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the prctl capability guard patch"
fi

if ! rg -q 'PTRACE_MODE_PROC_QUERY_INFORMATION' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'PTRACE_MODE_PROC_QUERY_LIMITED' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not patch procfs metadata checks to the ratified KACS query modes"
fi

if ! rg -Fq 'security_task_prctl(option, arg2,' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not patch arch_prctl shadow-stack ops through security_task_prctl"
fi

if [[ -d "$repo_root/kacs" ]] && \
	rg -n 'eventfd' "$repo_root/kacs" >/dev/null; then
	die "legacy eventfd plumbing found in kacs subtree"
fi
