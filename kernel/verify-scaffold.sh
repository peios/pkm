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
	"$repo_root/crates/lcs-core/src/lib.rs" \
	"$repo_root/kacs/access_check.c" \
	"$repo_root/kacs/access_check.h" \
	"$repo_root/kacs/access_check.rs" \
	"$repo_root/kacs/caap_cache.c" \
	"$repo_root/kacs/caap_cache.h" \
	"$repo_root/kacs/caap_cache.rs" \
	"$repo_root/kacs/kacs_rust.rs" \
	"$repo_root/kacs/kmes_payload.rs" \
	"$repo_root/kacs/kunit.c" \
	"$repo_root/kacs/builtin_signing_keys.h" \
	"$repo_root/kacs/token_fd.c" \
	"$repo_root/kacs/token_fd.h" \
	"$repo_root/kacs/token_runtime.h" \
	"$repo_root/kacs/token_runtime.rs" \
	"$repo_root/lcs/key_fd.c" \
	"$repo_root/lcs/key_fd.h" \
	"$repo_root/lcs/rsi.c" \
	"$repo_root/lcs/rsi.h" \
	"$repo_root/lcs/source_device.c" \
	"$repo_root/lcs/source_device.h" \
	"$repo_root/lcs/kunit.c" \
	"$repo_root/lcs/rust_ingress.rs" \
	"$repo_root/kmes/kmes.c" \
	"$repo_root/kmes/kmes.h" \
	"$repo_root/kmes/kmes_validate.rs" \
	"$repo_root/kernel/crypto/ed25519.c" \
	"$repo_root/kernel/crypto/ed25519-hacl.c" \
	"$repo_root/kernel/crypto/ed25519-hacl.h" \
	"$repo_root/kernel/scripts/update-ed25519-hacl.py" \
	"$repo_root/kernel/scripts/generate-kacs-builtin-signing-keys.py" \
	"$repo_root/kernel/verify-generated-tree.sh" \
	"$repo_root/kernel/verify-kernel-config.sh" \
	"$repo_root/uapi/pkm/pkm.h" \
	"$repo_root/uapi/pkm/syscall.h" \
	"$repo_root/uapi/pkm/sid.h" \
	"$repo_root/uapi/pkm/sd.h" \
	"$repo_root/uapi/pkm/token.h" \
	"$repo_root/uapi/pkm/access.h" \
	"$repo_root/uapi/pkm/file.h" \
	"$repo_root/uapi/pkm/kmes.h" \
	"$repo_root/uapi/pkm/lcs.h" \
	"$repo_root/uapi/smoke_test.c" \
	"$repo_root/uapi/check-userspace-clean.sh" \
	"$repo_root/uapi/check-codegen-safe.sh" \
	"$repo_root/kacs/lsm.c"; do
	if [[ ! -f "$required" ]]; then
		die "required slow-track source file missing: $required"
	fi
done

verify_tmp=$(mktemp -d "${TMPDIR:-/tmp}/pkm-verify-scaffold.XXXXXX")
trap 'rm -rf "$verify_tmp"' EXIT
generated_key_header="$verify_tmp/builtin_signing_keys.h"

if python3 "$repo_root/kernel/scripts/generate-kacs-builtin-signing-keys.py" \
	--out "$generated_key_header" >/dev/null 2>&1; then
	die "signing-key generator accepts an empty production TCB public key"
fi

python3 "$repo_root/kernel/scripts/generate-kacs-builtin-signing-keys.py" \
	--allow-empty --out "$generated_key_header"
if grep -Fq '.public_key = {' "$generated_key_header"; then
	die "signing-key generator emits a key for the KUnit empty-key allowance"
fi

python3 "$repo_root/kernel/scripts/generate-kacs-builtin-signing-keys.py" \
	--pubkey-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
	--out "$generated_key_header"
key_entry_count=$(grep -F -c '.public_key = {' "$generated_key_header" || true)
if [[ "$key_entry_count" != "1" ]]; then
	die "signing-key generator does not emit exactly one TCB key entry"
fi
if ! grep -Fq 'PKM_KACS_PIP_TYPE_PROTECTED' "$generated_key_header" || \
   ! grep -Fq 'PKM_KACS_PIP_TRUST_PEIOS_TCB' "$generated_key_header" || \
   ! grep -Fq '{ { 0 }, 0, 0 }' "$generated_key_header"; then
	die "signing-key generator output does not carry the TCB tier and terminator"
fi

if grep -q 'syscall_64.tbl' "$repo_root/kernel/Dockerfile"; then
	die "kernel/Dockerfile still mutates the syscall table"
fi

config_check_good="$verify_tmp/kernel.config"
cat > "$config_check_good" <<'EOF'
CONFIG_SECURITY_PKM=y
CONFIG_RUST=y
# CONFIG_SECURITY_SELINUX is not set
# CONFIG_SECURITY_APPARMOR is not set
# CONFIG_SECURITY_SMACK is not set
# CONFIG_SECURITY_TOMOYO is not set
# CONFIG_BPF_LSM is not set
CONFIG_LSM="landlock,lockdown,yama,integrity,pkm"
CONFIG_STRICT_DEVMEM=y
CONFIG_MODULE_SIG_FORCE=y
EOF
"$repo_root/kernel/verify-kernel-config.sh" "$config_check_good"

config_check_bad="$verify_tmp/kernel-bad.config"
cp "$config_check_good" "$config_check_bad"
sed -i 's/CONFIG_BPF_LSM is not set/CONFIG_BPF_LSM=y/' \
	"$config_check_bad"
if "$repo_root/kernel/verify-kernel-config.sh" "$config_check_bad" \
	>/dev/null 2>&1; then
	die "kernel config verifier accepts CONFIG_BPF_LSM=y"
fi

if ! rg -Fq 'verify-generated-tree.sh /build/linux' \
	"$repo_root/kernel/Dockerfile"; then
	die "kernel/Dockerfile does not validate the generated kernel tree"
fi

if ! rg -Fq 'verify-generated-tree.sh" "$kernel"' \
	"$repo_root/kernel/kunit-fast-build.sh"; then
	die "kunit-fast-build.sh does not validate the generated kernel tree"
fi

if ! rg -Fq 'verify-kernel-config.sh /build/linux/.config' \
	"$repo_root/kernel/Dockerfile"; then
	die "kernel/Dockerfile does not validate the generated kernel config"
fi

if ! rg -Fq 'verify-kernel-config.sh" "$kernel/.config"' \
	"$repo_root/kernel/kunit-fast-build.sh"; then
	die "kunit-fast-build.sh does not validate the generated kernel config"
fi

if ! rg -Fq 'cp .config /out/kernel.config' \
	"$repo_root/kernel/Makefile" || \
   ! rg -Fq 'cp .config "$out/kernel.config"' \
	"$repo_root/kernel/kunit-fast-build.sh"; then
	die "kernel builds do not export the generated .config"
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

rust_init_line=$(rg -n 'ret = kacs_rust_init\(\);' "$repo_root/kacs/lsm.c" |
	cut -d: -f1)
caap_init_line=$(rg -n 'ret = pkm_kacs_caap_cache_init\(\);' \
	"$repo_root/kacs/lsm.c" | cut -d: -f1)
kmes_init_line=$(rg -n 'ret = pkm_kmes_init\(\);' "$repo_root/kacs/lsm.c" |
	cut -d: -f1)
hook_add_line=$(rg -n 'security_add_hooks\(pkm_hooks' "$repo_root/kacs/lsm.c" |
	cut -d: -f1)
if [[ -z "$rust_init_line" || -z "$caap_init_line" ||
      -z "$kmes_init_line" || -z "$hook_add_line" ]]; then
	die "lsm.c missing expected pkm_init initialization calls"
fi
if (( hook_add_line <= rust_init_line || hook_add_line <= caap_init_line ||
      hook_add_line <= kmes_init_line )); then
	die "lsm.c registers KACS hooks before fallible substrate initialization"
fi
if ! rg -Fq 'pkm_kacs_caap_cache_destroy();' "$repo_root/kacs/lsm.c"; then
	die "lsm.c does not clean up CAAP cache on pre-hook initialization failure"
fi

for syscall in \
	"1000 kacs_open_self_token" \
	"1001 kacs_open_process_token" \
	"1002 kacs_open_thread_token" \
	"1003 kacs_create_token" \
	"1004 kacs_create_session" \
	"1005 kacs_set_psb" \
	"1006 kacs_destroy_empty_session" \
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
	"1025 kacs_set_caap" \
	"1026 kacs_get_mount_policy" \
	"1027 kacs_set_mount_policy" \
	"1100 reg_open_key"; do
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

require_install_block $'#ifdef CONFIG_SECURITY_PKM\n\treturn security_task_kill(t, info, sig, NULL);\n#endif' \
	"install-pkm-subtree.sh does not bypass native signal UID/CAP_KILL prechecks under PKM"
require_install_block $'#ifdef CONFIG_SECURITY_PKM\n\treturn security_ptrace_access_check(task, mode);\n#endif' \
	"install-pkm-subtree.sh does not bypass native ptrace UID/GID/CAP_SYS_PTRACE/dumpability prechecks under PKM"
require_install_block $'#ifndef CONFIG_SECURITY_PKM\n\tif (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {\n\t\tmm = ERR_PTR(-EPERM);' \
	"install-pkm-subtree.sh does not neutralize move_pages native ptrace precheck under PKM"
require_install_block $'#ifndef CONFIG_SECURITY_PKM\n\tif (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {\n\t\trcu_read_unlock();\n\t\terr = -EPERM;' \
	"install-pkm-subtree.sh does not neutralize migrate_pages native ptrace precheck under PKM"
require_install_literal 'PKM: gate migrate_pages before native node/capability constraints' \
	"install-pkm-subtree.sh does not move migrate_pages KACS process-SD gate before native node/capability constraints"
require_install_literal 'vm_write ? PTRACE_MODE_ATTACH_REALCREDS :' \
	"install-pkm-subtree.sh does not split process_vm_readv from process_vm_writev ptrace modes"
require_install_literal '(file->f_mode & FMODE_WRITE) ? PTRACE_MODE_ATTACH :' \
	"install-pkm-subtree.sh does not split read-only /proc/<pid>/mem from write-capable opens"

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
	"install-pkm-subtree.sh does not map basic procfs metadata to PROCESS_QUERY_LIMITED"
for proc_query_limited_name in \
	"stat" \
	"statm" \
	"comm" \
	"wchan" \
	"schedstat" \
	"cpuset" \
	"cgroup" \
	"cpu_resctrl_groups" \
	"oom_score" \
	"sessionid" \
	"patch_state" \
	"stack_depth" \
	"arch_status"; do
	require_install_literal "strcmp(name, \"${proc_query_limited_name}\") == 0" \
		"install-pkm-subtree.sh does not stage /proc/<pid>/${proc_query_limited_name} metadata classification"
done
for proc_query_information_name in \
	"cmdline" \
	"status" \
	"io" \
	"limits" \
	"sched" \
	"autogroup" \
	"timens_offsets" \
	"personality" \
	"syscall" \
	"latency" \
	"timers" \
	"timerslack_ns" \
	"mounts" \
	"mountinfo" \
	"mountstats" \
	"coredump_filter" \
	"oom_adj" \
	"oom_score_adj" \
	"loginuid" \
	"make-it-fail" \
	"fail-nth" \
	"uid_map" \
	"gid_map" \
	"projid_map" \
	"setgroups" \
	"seccomp_cache" \
	"ksm_merging_pages" \
	"ksm_stat"; do
	require_install_literal "strcmp(name, \"${proc_query_information_name}\") == 0" \
		"install-pkm-subtree.sh does not stage /proc/<pid>/${proc_query_information_name} metadata classification"
done
require_install_literal 'PTRACE_MODE_PROC_QUERY_INFORMATION;' \
	"install-pkm-subtree.sh does not map detailed procfs metadata to PROCESS_QUERY_INFORMATION"
require_install_block $'strcmp(name, "arch_status") == 0)\n\t\treturn PTRACE_MODE_READ_FSCREDS |\n\t\t       PTRACE_MODE_PROC_QUERY_LIMITED;' \
	"install-pkm-subtree.sh does not map basic procfs metadata exactly to PROCESS_QUERY_LIMITED"
require_install_block $'strcmp(name, "ksm_stat") == 0)\n\t\treturn PTRACE_MODE_READ_FSCREDS |\n\t\t       PTRACE_MODE_PROC_QUERY_INFORMATION;' \
	"install-pkm-subtree.sh does not map detailed procfs metadata exactly to PROCESS_QUERY_INFORMATION"
require_install_literal 'ret = proc_pkm_check_task_metadata_access(tsk, file);' \
	"install-pkm-subtree.sh does not patch proc_pid_cmdline_read through the KACS metadata gate"
require_install_literal 'ret = proc_pkm_check_task_metadata_access(task, m->file);' \
	"install-pkm-subtree.sh does not patch proc_single_show through the KACS metadata gate"
for proc_read_gate in \
	"latency" \
	"oom_adj" \
	"oom_score_adj" \
	"loginuid" \
	"sessionid" \
	"make-it-fail" \
	"fail-nth" \
	"sched" \
	"autogroup" \
	"timens_offsets" \
	"comm" \
	"timers" \
	"coredump_filter" \
	"mount namespace"; do
	require_install_literal "PKM: gate /proc/<pid>/${proc_read_gate} read metadata" \
		"install-pkm-subtree.sh does not patch /proc/<pid>/${proc_read_gate} read metadata through the KACS gate"
done
require_install_literal 'if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_PROC_QUERY_INFORMATION)) {' \
	"install-pkm-subtree.sh does not patch /proc/<pid>/io to the ratified query-information mode"
require_install_literal 'permitted = ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_PROC_QUERY_LIMITED | PTRACE_MODE_NOAUDIT);' \
	"install-pkm-subtree.sh does not patch /proc/<pid>/stat to the ratified query-limited mode"
if ! rg -q 'pkm_kacs_proc_process_setinfo' "$repo_root/kacs/lsm.c" || \
   ! rg -q 'pkm_kacs_proc_process_setinfo' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'proc_pkm_check_task_setinfo_access' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "procfs mutation setinfo helper is not staged"
fi
for proc_write_gate in \
	"latency writes" \
	"sched writes" \
	"autogroup writes" \
	"timens_offsets writes" \
	"oom adjustment writes" \
	"make-it-fail writes" \
	"fail-nth writes" \
	"coredump_filter writes" \
	"clear_refs writes"; do
	require_install_literal "PKM: gate /proc/<pid>/${proc_write_gate}" \
		"install-pkm-subtree.sh does not patch /proc/<pid>/${proc_write_gate} through the KACS set-information gate"
done
require_install_literal 'PKM: gate /proc/<pid> id-map open intent' \
	"install-pkm-subtree.sh does not patch /proc/<pid> id-map open intent through the KACS read/write intent gates"
require_install_literal 'PKM: gate /proc/<pid>/setgroups open intent' \
	"install-pkm-subtree.sh does not patch /proc/<pid>/setgroups open intent through the KACS read/write intent gates"
require_install_literal 'PKM: fail closed on multiprocess mm OOM fan-out' \
	"install-pkm-subtree.sh does not fail closed on multiprocess OOM fan-out"

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
	"inode_follow_link" \
	"inode_set_acl" \
	"inode_remove_acl" \
	"inode_getsecurity" \
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

if rg -q 'LSM_HOOK_INIT\(path_' "$repo_root/kacs/lsm.c"; then
	die "lsm.c registers forbidden KACS path hooks"
fi

if ! rg -q 'pkm_kacs_inode_rename_flags' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'RENAME_WHITEOUT' "$repo_root/kacs/lsm.c"; then
	die "install-pkm-subtree.sh does not stage the namespace rename flags gate"
fi

if ! rg -q 'LSM_HOOK_INIT\(file_receive, pkm_kacs_file_receive\)' \
	"$repo_root/kacs/lsm.c"; then
	die "lsm.c does not register the SCM_RIGHTS file_receive allow hook"
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

if ! rg -q 'timerslack_ns_write' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'timerslack_ns_show' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the timerslack KACS precheck patch"
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

if ! rg -Fq 'current_real_cred()->uid' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -Fq 'current_real_cred()->gid' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the projected getuid/getgid patch"
fi

if ! rg -q 'pkm_kacs_project_cred_uid_gid' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q 'net/core/sock.c' \
	"$repo_root/kernel/install-pkm-subtree.sh"; then
	die "install-pkm-subtree.sh does not stage the SO_PEERCRED projection patch"
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

if ! rg -Fq 'scripts/config --set-str LSM "landlock,lockdown,yama,integrity,pkm"' \
	"$repo_root/kernel/Dockerfile" || \
   ! rg -Fq 'scripts/config --set-str LSM "landlock,lockdown,yama,integrity,pkm"' \
	"$repo_root/kernel/kunit-fast-build.sh"; then
	die "PKM builds do not force pkm to the end of the mutable LSM order"
fi

if ! rg -Fq 'LSM_HOOK_INIT(bprm_creds_from_file, pkm_kacs_bprm_creds_from_file)' \
	"$repo_root/kacs/lsm.c" || \
   ! rg -Fq 'pkm_kacs_copy_exec_compat_caps(new, old)' \
	"$repo_root/kacs/lsm.c" || \
   ! rg -q 'pkm_kunit_exec_cap_reprojection_suppresses_filecap_grants' \
	"$repo_root/kacs/kunit.c"; then
	die "KACS exec reprojection does not verify file-capability suppression"
fi

for required_commoncap_bypass in \
	'cap_ptrace_access_check(struct task_struct *child, unsigned int mode)' \
	'cap_ptrace_traceme(struct task_struct *parent)' \
	'static int cap_safe_nice(struct task_struct *p)'; do
	if ! rg -Fq "$required_commoncap_bypass" \
		"$repo_root/kernel/install-pkm-subtree.sh"; then
		die "install-pkm-subtree.sh does not stage commoncap bypass: $required_commoncap_bypass"
	fi
done

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
   ! rg -q 'require-tcb-pubkey' "$repo_root/kernel/Makefile" || \
   ! rg -q 'PKM_KACS_TCB_PUBKEY_HEX' "$repo_root/kernel/Dockerfile" || \
   ! rg -q 'PKM_KACS_ALLOW_EMPTY_TCB_PUBKEY' "$repo_root/kernel/Dockerfile" || \
   ! rg -q 'generate-kacs-builtin-signing-keys.py' \
	"$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q -- '--allow-empty' "$repo_root/kernel/install-pkm-subtree.sh" || \
   ! rg -q -- '--allow-empty' \
	"$repo_root/kernel/scripts/generate-kacs-builtin-signing-keys.py" || \
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

# The PKM UAPI headers must compile with an ordinary, non-kernel C compiler —
# the precondition for the binding generator and for userspace consumers.
if ! bash "$repo_root/uapi/check-userspace-clean.sh" >/dev/null; then
	die "PKM UAPI headers are not userspace-clean (uapi/check-userspace-clean.sh failed)"
fi

# ... and they must stay within the codegen-safe subset of C, so the Rust
# and Go binding generators reproduce every struct layout faithfully.
if ! bash "$repo_root/uapi/check-codegen-safe.sh" >/dev/null; then
	die "PKM UAPI headers leave the codegen-safe subset (uapi/check-codegen-safe.sh failed)"
fi
