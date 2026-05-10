#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <pkm-new-root>" >&2
	exit 2
fi

repo_root=$1
install_script="$repo_root/kernel/install-pkm-subtree.sh"

die() {
	echo "verify-scaffold: $*" >&2
	exit 1
}

require_install_literal() {
	local needle=$1
	local message=$2

	if ! rg -Fq "$needle" "$install_script"; then
		die "$message"
	fi
}

require_install_block() {
	local needle=$1
	local message=$2
	local contents

	contents=$(<"$install_script")
	if [[ "$contents" != *"$needle"* ]]; then
		die "$message"
	fi
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
	"$repo_root/kacs/builtin_signing_keys.h" \
	"$repo_root/kacs/token_fd.c" \
	"$repo_root/kacs/token_fd.h" \
	"$repo_root/kacs/token_runtime.h" \
	"$repo_root/kacs/token_runtime.rs" \
	"$repo_root/kernel/crypto/ed25519.c" \
	"$repo_root/kernel/crypto/ed25519-hacl.c" \
	"$repo_root/kernel/crypto/ed25519-hacl.h" \
	"$repo_root/kernel/scripts/update-ed25519-hacl.py" \
	"$repo_root/kernel/scripts/generate-kacs-builtin-signing-keys.py" \
	"$repo_root/kacs/lsm.c"; do
	if [[ ! -f "$required" ]]; then
		die "required slow-track source file missing: $required"
	fi
done

if grep -q 'syscall_64.tbl' "$repo_root/kernel/Dockerfile"; then
	die "kernel/Dockerfile still mutates the syscall table"
fi

if ! rg -q 'openssl' "$repo_root/kernel/Dockerfile"; then
	die "kernel/Dockerfile does not install OpenSSL for module signing"
fi

for required_config in \
	'--set-val STRICT_DEVMEM y' \
	'--set-val MODULE_SIG y' \
	'--set-val MODULE_SIG_FORCE y' \
	'--set-val MODULE_SIG_ALL y' \
	'--set-str MODULE_SIG_KEY "certs/signing_key.pem"'; do
	if ! rg -Fq -- "$required_config" "$repo_root/kernel/Dockerfile"; then
		die "kernel/Dockerfile does not force required config: $required_config"
	fi
done

for required_dep in \
	'depends on STRICT_DEVMEM' \
	'depends on MODULE_SIG_FORCE'; do
	if ! rg -Fq "$required_dep" "$repo_root/pkm_kconfig"; then
		die "pkm_kconfig missing required dependency: $required_dep"
	fi
done

if ! rg -q 'CONFIG_STRICT_DEVMEM' "$repo_root/kacs/lsm.c" || \
   ! rg -q 'CONFIG_MODULE_SIG_FORCE' "$repo_root/kacs/lsm.c"; then
	die "lsm.c does not fail closed on missing PIP build hardening config"
fi

for syscall in \
	"1000 kacs_open_self_token" \
	"1001 kacs_open_process_token" \
	"1002 kacs_open_thread_token" \
	"1003 kacs_create_token" \
	"1004 kacs_create_session" \
	"1005 kacs_set_psb" \
	"1010 kacs_open_peer_token" \
	"1011 kacs_impersonate_peer" \
	"1012 kacs_revert" \
	"1013 kacs_set_impersonation_level" \
	"1020 kacs_open" \
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

require_install_literal 'strcmp(name, "stat") == 0' \
	"install-pkm-subtree.sh does not stage /proc/<pid>/stat metadata classification"
require_install_literal 'PTRACE_MODE_PROC_QUERY_LIMITED;' \
	"install-pkm-subtree.sh does not map /proc/<pid>/stat to PROCESS_QUERY_LIMITED"
require_install_literal 'strcmp(name, "cmdline") == 0' \
	"install-pkm-subtree.sh does not stage /proc/<pid>/cmdline metadata classification"
require_install_literal 'strcmp(name, "status") == 0' \
	"install-pkm-subtree.sh does not stage /proc/<pid>/status metadata classification"
require_install_literal 'strcmp(name, "io") == 0' \
	"install-pkm-subtree.sh does not stage /proc/<pid>/io metadata classification"
require_install_literal 'strcmp(name, "cgroup") == 0' \
	"install-pkm-subtree.sh does not stage /proc/<pid>/cgroup metadata classification"
require_install_literal 'PTRACE_MODE_PROC_QUERY_INFORMATION;' \
	"install-pkm-subtree.sh does not map detailed procfs metadata to PROCESS_QUERY_INFORMATION"
require_install_block $'if (strcmp(name, "stat") == 0)\n\t\treturn PTRACE_MODE_READ_FSCREDS |\n\t\t       PTRACE_MODE_PROC_QUERY_LIMITED;' \
	"install-pkm-subtree.sh does not map /proc/<pid>/stat exactly to PROCESS_QUERY_LIMITED"
require_install_block $'if (strcmp(name, "cmdline") == 0 || strcmp(name, "status") == 0 ||\n\t    strcmp(name, "io") == 0 || strcmp(name, "cgroup") == 0)\n\t\treturn PTRACE_MODE_READ_FSCREDS |\n\t\t       PTRACE_MODE_PROC_QUERY_INFORMATION;' \
	"install-pkm-subtree.sh does not map detailed procfs metadata exactly to PROCESS_QUERY_INFORMATION"
require_install_literal 'ret = proc_pkm_check_task_metadata_access(tsk, file);' \
	"install-pkm-subtree.sh does not patch proc_pid_cmdline_read through the KACS metadata gate"
require_install_literal 'ret = proc_pkm_check_task_metadata_access(task, m->file);' \
	"install-pkm-subtree.sh does not patch proc_single_show through the KACS metadata gate"
require_install_literal 'if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_PROC_QUERY_INFORMATION)) {' \
	"install-pkm-subtree.sh does not patch /proc/<pid>/io to the ratified query-information mode"
require_install_literal 'permitted = ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_PROC_QUERY_LIMITED | PTRACE_MODE_NOAUDIT);' \
	"install-pkm-subtree.sh does not patch /proc/<pid>/stat to the ratified query-limited mode"

if ! rg -q 'proc_pid_token_operations' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'proc_tid_token_operations' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the procfs token inspection patch"
fi

if ! rg -q 'pkm_kacs_file_sd_xattr_get' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'pkm_kacs_file_sd_xattr_set' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'pkm_kacs_file_sd_xattr_remove' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the fd raw SD xattr guard patch"
fi

for fd_metadata_symbol in \
	"pkm_kacs_file_getattr" \
	"pkm_kacs_file_statfs" \
	"pkm_kacs_file_chmod" \
	"pkm_kacs_file_chown" \
	"pkm_kacs_file_utimens" \
	"pkm_kacs_file_fileattr_get" \
	"pkm_kacs_file_fileattr_set" \
	"pkm_kacs_file_listxattr" \
	"pkm_kacs_file_end_metadata" \
	"pkm_kacs_path_fileattr_set" \
	"pkm_kacs_path_access" \
	"pkm_kacs_open_by_handle_at"; do
	if ! rg -q "$fd_metadata_symbol" \
		"$repo_root/kernel/install-pkm-subtree.sh"; then
		die "install-pkm-subtree.sh does not stage fd metadata patch: $fd_metadata_symbol"
	fi
done

for metadata_hook_symbol in \
	"inode_getattr" \
	"inode_setattr" \
	"inode_file_getattr" \
	"inode_file_setattr" \
	"inode_listxattr" \
	"inode_permission" \
	"inode_create" \
	"inode_link" \
	"inode_unlink" \
	"inode_symlink" \
	"inode_mkdir" \
	"inode_rmdir" \
	"inode_mknod" \
	"inode_rename" \
	"inode_readlink"; do
	if ! rg -q "LSM_HOOK_INIT\\(${metadata_hook_symbol}," \
		"$repo_root/kacs/lsm.c"; then
		die "lsm.c does not register metadata hook: $metadata_hook_symbol"
	fi
done

if ! rg -q 'pkm_kacs_inode_rename_flags' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'RENAME_WHITEOUT' "$repo_root/kacs/lsm.c"; then
	die "install-pkm-subtree.sh does not stage the namespace rename flags gate"
fi

if ! rg -q 'static long do_handle_open\(int mountdirfd, struct file_handle __user \*ufh,' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'pkm_kacs_open_by_handle_at\(\)' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the open_by_handle_at KACS privilege gate"
fi

if ! rg -q 'SYSCALL_DEFINE1\(fchdir, unsigned int, fd\)' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'fd_file\(f\)->f_mode & FMODE_PATH' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'security_file_permission\(fd_file\(f\),' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the fchdir FILE_TRAVERSE patch"
fi

if ! rg -q 'int vfs_fallocate\(struct file \*file, int mode,' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'pkm_kacs_file_fallocate\(file, mode\)' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the fallocate KACS patch"
fi

if ! rg -q 'pkm_kacs_file_begin_write_intent' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'ssize_t ksys_pwrite64' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'static ssize_t do_pwritev' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'int io_write\(struct io_kiocb \*req' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'static int aio_write\(struct kiocb \*req' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the positioned write-intent patches"
fi

if ! rg -q 'pkm_kacs_sched_setaffinity' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the sched_setaffinity KACS patch"
fi

if ! rg -q 'pkm_kacs_perf_event_open' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'kernel/events/core.c' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the perf_event_open KACS patch"
fi

if ! rg -q 'pkm_kacs_current_fsuid_kuid' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'pkm_kacs_current_fsuid_fsgid' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the projected fsuid/fsgid patch"
fi

if ! rg -q 'pkm_kacs_capable_in_cred_ns' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the commoncap capability switchboard patch"
fi

if ! rg -q 'pkm_kacs_capget_for_task' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the commoncap capget reporting patch"
fi

if ! rg -q 'pkm_kacs_proc_status_cap_fixup' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'fs/proc/array.c' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the proc status capability reporting patch"
fi

if ! rg -q 'CRYPTO_ED25519' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'ed25519-hacl.c' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'ed25519_generic-y' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'ed25519_tv_template' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'alg = "ed25519"' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the Ed25519 crypto verifier and testmgr vectors"
fi

if ! rg -q 'CRYPTO_ED25519' "$repo_root/pkm_kconfig"; then
	die "pkm_kconfig does not select the Ed25519 crypto verifier"
fi

if ! rg -q 'PKM_KACS_TCB_PUBKEY_HEX' "$repo_root/kernel/Makefile" || \
   ! rg -q 'PKM_KACS_TCB_PUBKEY_HEX' "$repo_root/kernel/Dockerfile" || \
   ! rg -q 'generate-kacs-builtin-signing-keys.py' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'builtin_signing_keys.h' "$repo_root/kernel/install-pkm-subtree.sh"; then
	die "kernel scaffold does not stage built-in KACS signing key generation"
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
