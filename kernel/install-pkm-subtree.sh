#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 <pkm-source-root> <kernel-root>" >&2
	exit 2
fi

src_root=$1
kernel_root=$2
pkm_dir="$kernel_root/security/pkm"

require_file() {
	local path=$1

	if [[ ! -f "$path" ]]; then
		echo "required file missing: $path" >&2
		exit 1
	fi
}

append_line_once() {
	local line=$1
	local file=$2

	if ! grep -Fqx "$line" "$file"; then
		printf '%s\n' "$line" >> "$file"
	fi
}

insert_line_after_exact_once() {
	local anchor=$1
	local line=$2
	local file=$3
	local anchor_line

	if grep -Fqx "$line" "$file"; then
		return
	fi

	anchor_line=$(grep -nF "$anchor" "$file" | head -n1 | cut -d: -f1 || true)
	if [[ -z "$anchor_line" ]]; then
		echo "could not find anchor '$anchor' in $file" >&2
		exit 1
	fi

	sed -i "$((anchor_line + 1))i\\${line}" "$file"
}

replace_line_once() {
	local from=$1
	local to=$2
	local file=$3

	if grep -Fqx "$to" "$file"; then
		return
	fi

	if ! grep -Fqx "$from" "$file"; then
		echo "could not find line to replace in $file: $from" >&2
		exit 1
	fi

	sed -i "s|^${from//|/\\|}\$|${to//|/\\|}|" "$file"
}

replace_line_after_anchor_once() {
	local anchor=$1
	local from=$2
	local to=$3
	local file=$4

	python - "$file" "$anchor" "$from" "$to" <<'PY'
from pathlib import Path
import sys

file_path, anchor, old, new = sys.argv[1:]
path = Path(file_path)
text = path.read_text()

anchor_idx = text.find(anchor)
if anchor_idx == -1:
    sys.stderr.write(f"could not find anchor '{anchor}' in {file_path}\n")
    sys.exit(1)

new_idx = text.find(new, anchor_idx)
if new_idx != -1:
    sys.exit(0)

old_idx = text.find(old, anchor_idx)
if old_idx == -1:
    sys.stderr.write(
        f"could not find line to replace after anchor '{anchor}' in {file_path}: {old}\n"
    )
    sys.exit(1)

text = text[:old_idx] + new + text[old_idx + len(old):]
path.write_text(text)
PY
}

insert_block_before_exact_once() {
	local anchor=$1
	local marker=$2
	local block=$3
	local file=$4
	local tmp

	if grep -Fq "$marker" "$file"; then
		return
	fi

	if ! grep -Fqx "$anchor" "$file"; then
		echo "could not find anchor '$anchor' in $file" >&2
		exit 1
	fi

	tmp=$(mktemp)
	awk -v anchor="$anchor" -v block="$block" '
		$0 == anchor {
			printf "%s\n", block
			inserted = 1
		}
		{ print }
		END {
			if (!inserted)
				exit 1
		}
	' "$file" > "$tmp" || {
		rm -f "$tmp"
		echo "failed to insert block before '$anchor' in $file" >&2
		exit 1
	}
	mv "$tmp" "$file"
}

insert_source_kconfig() {
	local file=$1
	local source_line='source "security/pkm/Kconfig"'
	local insert_line

	if grep -Fqx "$source_line" "$file"; then
		return
	fi

	insert_line=$(grep -n '^endmenu$' "$file" | tail -n1 | cut -d: -f1 || true)
	if [[ -z "$insert_line" ]]; then
		echo "could not find endmenu anchor in $file" >&2
		exit 1
	fi

	sed -i "${insert_line}i\\${source_line}" "$file"
}

insert_x86_64_syscall_once() {
	local file=$1
	local number=$2
	local name=$3
	local line
	local insert_line

	if grep -Eq "^[[:space:]]*${number}[[:space:]]+common[[:space:]]+${name}[[:space:]]+sys_${name}\$" \
		"$file"; then
		return
	fi

	if grep -Eq "^[[:space:]]*${number}[[:space:]]+common[[:space:]]+" "$file"; then
		echo "syscall number ${number} already occupied in $file" >&2
		exit 1
	fi

	if grep -Eq "^[[:space:]]*[0-9]+[[:space:]]+common[[:space:]]+${name}[[:space:]]+sys_${name}\$" \
		"$file"; then
		echo "syscall name ${name} already present with a different number in $file" >&2
		exit 1
	fi

	line=$(printf '%s\tcommon\t%s\t\tsys_%s' "$number" "$name" "$name")
	insert_line=$(awk -v number="$number" '
		$1 ~ /^[0-9]+$/ && ($1 + 0) > (number + 0) {
			print NR
			exit
		}
	' "$file")
	if [[ -n "$insert_line" ]]; then
		sed -i "${insert_line}i\\${line}" "$file"
	else
		printf '%s\n' "$line" >> "$file"
	fi
}

require_file "$src_root/kacs/lsm.c"
require_file "$src_root/kacs/access_check.c"
require_file "$src_root/kacs/access_check.h"
require_file "$src_root/kacs/access_check.rs"
require_file "$src_root/kacs/caap_cache.c"
require_file "$src_root/kacs/caap_cache.h"
require_file "$src_root/kacs/caap_cache.rs"
require_file "$src_root/kacs/kacs_rust.rs"
require_file "$src_root/kacs/kmes_payload.rs"
require_file "$src_root/kacs/kunit.c"
require_file "$src_root/kacs/builtin_signing_keys.h"
require_file "$src_root/kacs/token_fd.c"
require_file "$src_root/kacs/token_fd.h"
require_file "$src_root/kacs/token_runtime.h"
require_file "$src_root/kacs/token_runtime.rs"
require_file "$src_root/kmes/kmes.c"
require_file "$src_root/kmes/kmes.h"
require_file "$src_root/kmes/kmes_validate.rs"
require_file "$src_root/kernel/crypto/ed25519.c"
require_file "$src_root/kernel/crypto/ed25519-hacl.c"
require_file "$src_root/kernel/crypto/ed25519-hacl.h"
require_file "$src_root/kernel/scripts/update-ed25519-hacl.py"
require_file "$src_root/kernel/scripts/generate-kacs-builtin-signing-keys.py"
require_file "$src_root/pkm_kconfig"
require_file "$src_root/pkm_makefile"
require_file "$src_root/kernel/stage-kacs-core.sh"
require_file "$kernel_root/crypto/Kconfig"
require_file "$kernel_root/crypto/Makefile"
require_file "$kernel_root/crypto/testmgr.c"
require_file "$kernel_root/crypto/testmgr.h"
require_file "$kernel_root/security/Makefile"
require_file "$kernel_root/security/Kconfig"
require_file "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl"
require_file "$kernel_root/arch/x86/kernel/process_64.c"
require_file "$kernel_root/fs/aio.c"
require_file "$kernel_root/fs/proc/base.c"
require_file "$kernel_root/fs/proc/array.c"
require_file "$kernel_root/fs/open.c"
require_file "$kernel_root/fs/read_write.c"
require_file "$kernel_root/fs/file_attr.c"
require_file "$kernel_root/fs/stat.c"
require_file "$kernel_root/fs/statfs.c"
require_file "$kernel_root/fs/utimes.c"
require_file "$kernel_root/fs/xattr.c"
require_file "$kernel_root/include/linux/cred.h"
require_file "$kernel_root/include/linux/ptrace.h"
require_file "$kernel_root/io_uring/rw.c"
require_file "$kernel_root/kernel/events/core.c"
require_file "$kernel_root/kernel/pid.c"
require_file "$kernel_root/kernel/ptrace.c"
require_file "$kernel_root/kernel/sched/syscalls.c"
require_file "$kernel_root/kernel/signal.c"
require_file "$kernel_root/kernel/sys.c"
require_file "$kernel_root/mm/mempolicy.c"
require_file "$kernel_root/mm/migrate.c"
require_file "$kernel_root/mm/process_vm_access.c"
require_file "$kernel_root/security/commoncap.c"
require_file "$kernel_root/security/security.c"

rm -rf "$pkm_dir"
mkdir -p "$pkm_dir/kacs"
mkdir -p "$pkm_dir/kmes"

install -m 0644 "$src_root/kacs/lsm.c" "$pkm_dir/kacs/lsm.c"
install -m 0644 "$src_root/kacs/access_check.c" "$pkm_dir/kacs/access_check.c"
install -m 0644 "$src_root/kacs/access_check.h" "$pkm_dir/kacs/access_check.h"
install -m 0644 "$src_root/kacs/access_check.rs" "$pkm_dir/kacs/access_check.rs"
install -m 0644 "$src_root/kacs/caap_cache.c" "$pkm_dir/kacs/caap_cache.c"
install -m 0644 "$src_root/kacs/caap_cache.h" "$pkm_dir/kacs/caap_cache.h"
install -m 0644 "$src_root/kacs/caap_cache.rs" "$pkm_dir/kacs/caap_cache.rs"
install -m 0644 "$src_root/kacs/kacs_rust.rs" "$pkm_dir/kacs/kacs_rust.rs"
install -m 0644 "$src_root/kacs/kmes_payload.rs" "$pkm_dir/kacs/kmes_payload.rs"
install -m 0644 "$src_root/kacs/kunit.c" "$pkm_dir/kacs/kunit.c"
install -m 0644 "$src_root/kacs/builtin_signing_keys.h" "$pkm_dir/kacs/builtin_signing_keys.h"
install -m 0644 "$src_root/kacs/token_fd.c" "$pkm_dir/kacs/token_fd.c"
install -m 0644 "$src_root/kacs/token_fd.h" "$pkm_dir/kacs/token_fd.h"
install -m 0644 "$src_root/kacs/token_runtime.h" "$pkm_dir/kacs/token_runtime.h"
install -m 0644 "$src_root/kacs/token_runtime.rs" "$pkm_dir/kacs/token_runtime.rs"
install -m 0644 "$src_root/kmes/kmes.c" "$pkm_dir/kmes/kmes.c"
install -m 0644 "$src_root/kmes/kmes.h" "$pkm_dir/kmes/kmes.h"
install -m 0644 "$src_root/kmes/kmes_validate.rs" "$pkm_dir/kmes/kmes_validate.rs"
install -m 0644 "$src_root/pkm_kconfig" "$pkm_dir/Kconfig"
install -m 0644 "$src_root/pkm_makefile" "$pkm_dir/Makefile"
install -m 0644 "$src_root/kernel/crypto/ed25519.c" "$kernel_root/crypto/ed25519.c"
install -m 0644 "$src_root/kernel/crypto/ed25519-hacl.c" "$kernel_root/crypto/ed25519-hacl.c"
install -m 0644 "$src_root/kernel/crypto/ed25519-hacl.h" "$kernel_root/crypto/ed25519-hacl.h"

signing_key_args=(
	--pubkey-hex "${PKM_KACS_TCB_PUBKEY_HEX:-}"
	--out "$pkm_dir/kacs/builtin_signing_keys.h"
)
if [[ "${PKM_KACS_ALLOW_EMPTY_TCB_PUBKEY:-0}" == "1" ]]; then
	signing_key_args+=(--allow-empty)
fi
python3 "$src_root/kernel/scripts/generate-kacs-builtin-signing-keys.py" \
	"${signing_key_args[@]}"

"$src_root/kernel/stage-kacs-core.sh" \
	"$src_root/crates/kacs-core/src" \
	"$pkm_dir/kacs/kacs_core"

append_line_once 'obj-$(CONFIG_SECURITY_PKM) += pkm/' "$kernel_root/security/Makefile"
insert_source_kconfig "$kernel_root/security/Kconfig"
insert_block_before_exact_once 'config CRYPTO_ECRDSA' \
	'config CRYPTO_ED25519' \
	'config CRYPTO_ED25519
	tristate "Ed25519 signature verification"
	depends on 64BIT
	select CRYPTO_SIG
	select CRYPTO_LIB_SHA512
	help
	  Ed25519 signature verification (RFC 8032).

	  Only signature verification is implemented.

' \
	"$kernel_root/crypto/Kconfig"
insert_block_before_exact_once 'crypto_acompress-y := acompress.o' \
	'obj-$(CONFIG_CRYPTO_ED25519)' \
	'ed25519_generic-y := ed25519.o
ed25519_generic-y += ed25519-hacl.o
obj-$(CONFIG_CRYPTO_ED25519) += ed25519_generic.o

' \
	"$kernel_root/crypto/Makefile"
insert_block_before_exact_once '#ifdef CONFIG_CPU_BIG_ENDIAN' \
	'ed25519_tv_template' \
	'/*
 * Ed25519 test vectors from RFC 8032, section 7.1.
 */
static const struct sig_testvec ed25519_tv_template[] = {
	{
	.key =
	"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a"
	"\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a",
	.key_len = 32,
	.m = "",
	.m_size = 0,
	.c =
	"\xe5\x56\x43\x00\xc3\x60\xac\x72\x90\x86\xe2\xcc\x80\x6e\x82\x8a"
	"\x84\x87\x7f\x1e\xb8\xe5\xd9\x74\xd8\x73\xe0\x65\x22\x49\x01\x55"
	"\x5f\xb8\x82\x15\x90\xa3\x3b\xac\xc6\x1e\x39\x70\x1c\xf9\xb4\x6b"
	"\xd2\x5b\xf5\xf0\x59\x5b\xbe\x24\x65\x51\x41\x43\x8e\x7a\x10\x0b",
	.c_size = 64,
	.public_key_vec = true,
	}, {
	.key =
	"\x3d\x40\x17\xc3\xe8\x43\x89\x5a\x92\xb7\x0a\xa7\x4d\x1b\x7e\xbc"
	"\x9c\x98\x2c\xcf\x2e\xc4\x96\x8c\xc0\xcd\x55\xf1\x2a\xf4\x66\x0c",
	.key_len = 32,
	.m = "\x72",
	.m_size = 1,
	.c =
	"\x92\xa0\x09\xa9\xf0\xd4\xca\xb8\x72\x0e\x82\x0b\x5f\x64\x25\x40"
	"\xa2\xb2\x7b\x54\x16\x50\x3f\x8f\xb3\x76\x22\x23\xeb\xdb\x69\xda"
	"\x08\x5a\xc1\xe4\x3e\x15\x99\x6e\x45\x8f\x36\x13\xd0\xf1\x1d\x8c"
	"\x38\x7b\x2e\xae\xb4\x30\x2a\xee\xb0\x0d\x29\x16\x12\xbb\x0c\x00",
	.c_size = 64,
	.public_key_vec = true,
	},
};

' \
	"$kernel_root/crypto/testmgr.h"
insert_block_before_exact_once '		.alg = "ecdsa-nist-p192",' \
	'		.alg = "ed25519",' \
	'		.alg = "ed25519",
		.test = alg_test_sig,
		.suite = {
			.sig = __VECS(ed25519_tv_template)
		}
	}, {
' \
	"$kernel_root/crypto/testmgr.c"
insert_block_before_exact_once 'int cap_capget(const struct task_struct *target, kernel_cap_t *effective,' \
	'extern long pkm_kacs_capget_for_task' \
	'#ifdef CONFIG_SECURITY_PKM
extern long pkm_kacs_capget_for_task(const struct task_struct *target,
				     kernel_cap_t *effective,
				     kernel_cap_t *inheritable,
				     kernel_cap_t *permitted);
#endif

' \
	"$kernel_root/security/commoncap.c"
replace_line_after_anchor_once 'int cap_capget(const struct task_struct *target, kernel_cap_t *effective,' \
	'	return 0;' \
	'#ifdef CONFIG_SECURITY_PKM
	return pkm_kacs_capget_for_task(target, effective, inheritable,
					permitted);
#else
	return 0;
#endif
' \
	"$kernel_root/security/commoncap.c"
insert_block_before_exact_once 'static inline void task_cap(struct seq_file *m, struct task_struct *p)' \
	'extern long pkm_kacs_proc_status_cap_fixup' \
	'#ifdef CONFIG_SECURITY_PKM
extern long pkm_kacs_proc_status_cap_fixup(kernel_cap_t *inheritable,
					   kernel_cap_t *permitted,
					   kernel_cap_t *effective,
					   kernel_cap_t *bset,
					   kernel_cap_t *ambient);
#endif

' \
	"$kernel_root/fs/proc/array.c"
replace_line_after_anchor_once 'static inline void task_cap(struct seq_file *m, struct task_struct *p)' \
	'	rcu_read_unlock();' \
	'	rcu_read_unlock();

#ifdef CONFIG_SECURITY_PKM
	pkm_kacs_proc_status_cap_fixup(&cap_inheritable, &cap_permitted,
				       &cap_effective, &cap_bset,
				       &cap_ambient);
#endif
' \
	"$kernel_root/fs/proc/array.c"
insert_block_before_exact_once 'int cap_capable(const struct cred *cred, struct user_namespace *target_ns,' \
	'extern long pkm_kacs_capable_in_cred_ns' \
	'#ifdef CONFIG_SECURITY_PKM
extern long pkm_kacs_capable_in_cred_ns(const struct cred *cred,
					struct user_namespace *target_ns,
					int cap, unsigned int opts);
#endif

' \
	"$kernel_root/security/commoncap.c"
replace_line_after_anchor_once 'int cap_capable(const struct cred *cred, struct user_namespace *target_ns,' \
	'	int ret = cap_capable_helper(cred, target_ns, cred_ns, cap);' \
	'#ifdef CONFIG_SECURITY_PKM
	int ret = pkm_kacs_capable_in_cred_ns(cred, target_ns, cap, opts);
#else
	int ret = cap_capable_helper(cred, target_ns, cred_ns, cap);
#endif
' \
	"$kernel_root/security/commoncap.c"
replace_line_after_anchor_once 'int cap_ptrace_access_check(struct task_struct *child, unsigned int mode)' \
	'	const kernel_cap_t *caller_caps;' \
	'	const kernel_cap_t *caller_caps;

#ifdef CONFIG_SECURITY_PKM
	return 0;
#endif
' \
	"$kernel_root/security/commoncap.c"
replace_line_after_anchor_once 'int cap_ptrace_traceme(struct task_struct *parent)' \
	'	const struct cred *cred, *child_cred;' \
	'	const struct cred *cred, *child_cred;

#ifdef CONFIG_SECURITY_PKM
	return 0;
#endif
' \
	"$kernel_root/security/commoncap.c"
replace_line_after_anchor_once 'static int cap_safe_nice(struct task_struct *p)' \
	'	int is_subset, ret = 0;' \
	'	int is_subset, ret = 0;

#ifdef CONFIG_SECURITY_PKM
	return 0;
#endif
' \
	"$kernel_root/security/commoncap.c"
insert_block_before_exact_once 'int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,' \
	'extern int pkm_kacs_inode_rename_flags' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_inode_rename_flags(struct inode *old_dir,
				       struct dentry *old_dentry,
				       struct inode *new_dir,
				       struct dentry *new_dentry,
				       unsigned int flags);
#endif

' \
	"$kernel_root/security/security.c"
replace_line_after_anchor_once 'int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,' \
	'	if (flags & RENAME_EXCHANGE) {' \
	'#ifdef CONFIG_SECURITY_PKM
	{
		int pkm_ret = pkm_kacs_inode_rename_flags(
			old_dir, old_dentry, new_dir, new_dentry, flags);
		if (pkm_ret)
			return pkm_ret;
	}
#endif

	if (flags & RENAME_EXCHANGE) {' \
	"$kernel_root/security/security.c"
insert_line_after_exact_once '#define PTRACE_MODE_REALCREDS	0x10' \
	'#define PTRACE_MODE_GETFD	0x20' \
	"$kernel_root/include/linux/ptrace.h"
insert_line_after_exact_once '#define PTRACE_MODE_GETFD	0x20' \
	'#define PTRACE_MODE_PIDFD_OPEN	0x40' \
	"$kernel_root/include/linux/ptrace.h"
insert_line_after_exact_once '#define PTRACE_MODE_PIDFD_OPEN	0x40' \
	'#define PTRACE_MODE_PROC_QUERY_LIMITED	0x80' \
	"$kernel_root/include/linux/ptrace.h"
insert_line_after_exact_once '#define PTRACE_MODE_PROC_QUERY_LIMITED	0x80' \
	'#define PTRACE_MODE_PROC_QUERY_INFORMATION	0x100' \
	"$kernel_root/include/linux/ptrace.h"
replace_line_after_anchor_once 'static int check_kill_permission(int sig, struct kernel_siginfo *info,' \
	'	if (!same_thread_group(current, t) &&
	    !kill_ok_by_cred(t)) {' \
	'#ifdef CONFIG_SECURITY_PKM
	return security_task_kill(t, info, sig, NULL);
#endif

	if (!same_thread_group(current, t) &&
	    !kill_ok_by_cred(t)) {' \
	"$kernel_root/kernel/signal.c"
replace_line_after_anchor_once 'static int __ptrace_may_access(struct task_struct *task, unsigned int mode)' \
	'	rcu_read_lock();' \
	'#ifdef CONFIG_SECURITY_PKM
	return security_ptrace_access_check(task, mode);
#endif

	rcu_read_lock();' \
	"$kernel_root/kernel/ptrace.c"
replace_line_after_anchor_once 'static struct mm_struct *find_mm_struct(pid_t pid, nodemask_t *mem_nodes)' \
	'	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
		mm = ERR_PTR(-EPERM);
		goto out;
	}' \
	'#ifndef CONFIG_SECURITY_PKM
	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
		mm = ERR_PTR(-EPERM);
		goto out;
	}
#endif' \
	"$kernel_root/mm/migrate.c"
replace_line_after_anchor_once 'static int kernel_migrate_pages(pid_t pid, unsigned long maxnode,' \
	'	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
		rcu_read_unlock();
		err = -EPERM;
		goto out_put;
	}
	rcu_read_unlock();' \
	'#ifndef CONFIG_SECURITY_PKM
	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
		rcu_read_unlock();
		err = -EPERM;
		goto out_put;
	}
#endif
	rcu_read_unlock();' \
	"$kernel_root/mm/mempolicy.c"
replace_line_after_anchor_once 'static int kernel_migrate_pages(pid_t pid, unsigned long maxnode,' \
	'	err = security_task_movememory(task);
	if (err)
		goto out_put;' \
	'#ifndef CONFIG_SECURITY_PKM
	err = security_task_movememory(task);
	if (err)
		goto out_put;
#endif' \
	"$kernel_root/mm/mempolicy.c"
insert_block_before_exact_once '	task_nodes = cpuset_mems_allowed(task);' \
	'PKM: gate migrate_pages before native node/capability constraints' \
	'#ifdef CONFIG_SECURITY_PKM
	/* PKM: gate migrate_pages before native node/capability constraints. */
	err = security_task_movememory(task);
	if (err)
		goto out_put;
#endif

' \
	"$kernel_root/mm/mempolicy.c"
replace_line_after_anchor_once 'static ssize_t process_vm_rw_core(pid_t pid, struct iov_iter *iter,' \
	'	mm = mm_access(task, PTRACE_MODE_ATTACH_REALCREDS);' \
	'	mm = mm_access(task, vm_write ? PTRACE_MODE_ATTACH_REALCREDS :
				      PTRACE_MODE_READ_REALCREDS);' \
	"$kernel_root/mm/process_vm_access.c"
replace_line_after_anchor_once 'static int mem_open(struct inode *inode, struct file *file)' \
	'	return __mem_open(inode, file, PTRACE_MODE_ATTACH);' \
	'	return __mem_open(inode, file,
			  (file->f_mode & FMODE_WRITE) ? PTRACE_MODE_ATTACH :
						 PTRACE_MODE_READ);' \
	"$kernel_root/fs/proc/base.c"
replace_line_once '	if (ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS))' \
	'	if (ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS | PTRACE_MODE_GETFD))' \
	"$kernel_root/kernel/pid.c"
insert_block_before_exact_once '	fd = pidfd_create(p, flags);' \
	'	if (!ptrace_may_access(task,' \
	'	{
		struct task_struct *task;

		task = get_pid_task(p, PIDTYPE_PID);
	if (!task) {
		put_pid(p);
		return -ESRCH;
	}
	if (!ptrace_may_access(task,
			       PTRACE_MODE_READ_FSCREDS |
			       PTRACE_MODE_PIDFD_OPEN)) {
		put_task_struct(task);
		put_pid(p);
		return -EACCES;
	}
	put_task_struct(task);
	}
' \
	"$kernel_root/kernel/pid.c"
insert_block_before_exact_once '		return shstk_prctl(task, option, arg2);' \
	'security_task_prctl(option, arg2,' \
	'		if (option != ARCH_SHSTK_STATUS) {
			int lsm_ret = security_task_prctl(option, arg2,
							  0, 0, 0);
			if (lsm_ret != -ENOSYS)
				return lsm_ret;
		}
' \
	"$kernel_root/arch/x86/kernel/process_64.c"
insert_block_before_exact_once 'static inline int __normal_prio(int policy, int rt_prio, int nice)' \
	'extern long pkm_kacs_sched_setaffinity' \
	'#ifdef CONFIG_SECURITY_PKM
extern long pkm_kacs_sched_setaffinity(struct task_struct *task);
#endif

' \
	"$kernel_root/kernel/sched/syscalls.c"
replace_line_after_anchor_once 'long sched_setaffinity(pid_t pid, const struct cpumask *in_mask)' \
	'	if (!check_same_owner(p)) {
		guard(rcu)();
		if (!ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE))
			return -EPERM;
	}
' \
	'#ifdef CONFIG_SECURITY_PKM
	retval = pkm_kacs_sched_setaffinity(p);
	if (retval)
		return retval;
#else
	if (!check_same_owner(p)) {
		guard(rcu)();
		if (!ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE))
			return -EPERM;
	}
#endif
' \
	"$kernel_root/kernel/sched/syscalls.c"
replace_line_after_anchor_once 'static ssize_t timerslack_ns_write(struct file *file, const char __user *buf,' \
	'		rcu_read_lock();
		if (!ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE)) {
			rcu_read_unlock();
			count = -EPERM;
			goto out;
		}
		rcu_read_unlock();
' \
	'#ifndef CONFIG_SECURITY_PKM
		rcu_read_lock();
		if (!ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE)) {
			rcu_read_unlock();
			count = -EPERM;
			goto out;
		}
		rcu_read_unlock();
#endif
' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static int timerslack_ns_show(struct seq_file *m, void *v)' \
	'		rcu_read_lock();
		if (!ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE)) {
			rcu_read_unlock();
			err = -EPERM;
			goto out;
		}
		rcu_read_unlock();
' \
	'#ifndef CONFIG_SECURITY_PKM
		rcu_read_lock();
		if (!ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE)) {
			rcu_read_unlock();
			err = -EPERM;
			goto out;
		}
		rcu_read_unlock();
#endif
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once 'SYSCALL_DEFINE5(perf_event_open,' \
	'extern long pkm_kacs_perf_event_open' \
	'#ifdef CONFIG_SECURITY_PKM
extern long pkm_kacs_perf_event_open(struct task_struct *task);
#endif

' \
	"$kernel_root/kernel/events/core.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE5(perf_event_open,' \
	'		if (IS_ERR(task)) {
			err = PTR_ERR(task);
			goto err_fd;
		}
' \
	'		if (IS_ERR(task)) {
			err = PTR_ERR(task);
			goto err_fd;
		}
#ifdef CONFIG_SECURITY_PKM
		err = pkm_kacs_perf_event_open(task);
		if (err)
			goto err_task;
#endif
' \
	"$kernel_root/kernel/events/core.c"
insert_block_before_exact_once '#define current_uid()		(current_cred_xxx(uid))' \
	'extern kuid_t pkm_kacs_current_fsuid_kuid' \
	'#ifdef CONFIG_SECURITY_PKM
extern kuid_t pkm_kacs_current_fsuid_kuid(void);
extern kgid_t pkm_kacs_current_fsgid_kgid(void);
extern void pkm_kacs_current_fsuid_fsgid(kuid_t *fsuid, kgid_t *fsgid);
#endif

' \
	"$kernel_root/include/linux/cred.h"
replace_line_after_anchor_once '#define current_sgid()		(current_cred_xxx(sgid))' \
	'#define current_fsuid() 	(current_cred_xxx(fsuid))' \
	'#ifdef CONFIG_SECURITY_PKM
#define current_fsuid()		(pkm_kacs_current_fsuid_kuid())
#else
#define current_fsuid()		(current_cred_xxx(fsuid))
#endif
' \
	"$kernel_root/include/linux/cred.h"
replace_line_after_anchor_once '#ifdef CONFIG_SECURITY_PKM
#define current_fsuid()		(pkm_kacs_current_fsuid_kuid())
#else
#define current_fsuid()		(current_cred_xxx(fsuid))
#endif
' \
	'#define current_fsgid() 	(current_cred_xxx(fsgid))' \
	'#ifdef CONFIG_SECURITY_PKM
#define current_fsgid()		(pkm_kacs_current_fsgid_kgid())
#else
#define current_fsgid()		(current_cred_xxx(fsgid))
#endif
' \
	"$kernel_root/include/linux/cred.h"
replace_line_after_anchor_once '#define current_euid_egid(_euid, _egid)		\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_euid) = __cred->euid;		\
	*(_egid) = __cred->egid;		\
} while(0)
' \
	'#define current_fsuid_fsgid(_fsuid, _fsgid)	\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_fsuid) = __cred->fsuid;		\
	*(_fsgid) = __cred->fsgid;		\
} while(0)
' \
	'#ifdef CONFIG_SECURITY_PKM
#define current_fsuid_fsgid(_fsuid, _fsgid)	\
do {						\
	pkm_kacs_current_fsuid_fsgid((_fsuid), (_fsgid)); \
} while (0)
#else
#define current_fsuid_fsgid(_fsuid, _fsgid)	\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_fsuid) = __cred->fsuid;		\
	*(_fsgid) = __cred->fsgid;		\
} while(0)
#endif
' \
	"$kernel_root/include/linux/cred.h"
replace_line_after_anchor_once 'SYSCALL_DEFINE0(getuid)' \
	'	return from_kuid_munged(current_user_ns(), current_uid());' \
	'#ifdef CONFIG_SECURITY_PKM
	return from_kuid_munged(current_user_ns(), current_real_cred()->uid);
#else
	return from_kuid_munged(current_user_ns(), current_uid());
#endif' \
	"$kernel_root/kernel/sys.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE0(getgid)' \
	'	return from_kgid_munged(current_user_ns(), current_gid());' \
	'#ifdef CONFIG_SECURITY_PKM
return from_kgid_munged(current_user_ns(), current_real_cred()->gid);
#else
return from_kgid_munged(current_user_ns(), current_gid());
#endif' \
	"$kernel_root/kernel/sys.c"
insert_block_before_exact_once 'static void cred_to_ucred(struct pid *pid, const struct cred *cred,' \
	'extern void pkm_kacs_project_cred_uid_gid' \
	'#ifdef CONFIG_SECURITY_PKM
extern void pkm_kacs_project_cred_uid_gid(const struct cred *cred,
					  kuid_t *uid, kgid_t *gid);
#endif

' \
	"$kernel_root/net/core/sock.c"
replace_line_after_anchor_once 'static void cred_to_ucred(struct pid *pid, const struct cred *cred,' \
	'		ucred->uid = from_kuid_munged(current_ns, cred->euid);
		ucred->gid = from_kgid_munged(current_ns, cred->egid);' \
	'#ifdef CONFIG_SECURITY_PKM
		kuid_t projected_uid;
		kgid_t projected_gid;

		pkm_kacs_project_cred_uid_gid(cred, &projected_uid,
					      &projected_gid);
		ucred->uid = from_kuid_munged(current_ns, projected_uid);
		ucred->gid = from_kgid_munged(current_ns, projected_gid);
#else
		ucred->uid = from_kuid_munged(current_ns, cred->euid);
		ucred->gid = from_kgid_munged(current_ns, cred->egid);
#endif' \
	"$kernel_root/net/core/sock.c"
insert_block_before_exact_once 'SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,' \
	'extern long pkm_kacs_prctl_capability_guard' \
	'#ifdef CONFIG_SECURITY_PKM
extern long pkm_kacs_prctl_capability_guard(int option, unsigned long arg2,
					    unsigned long arg3,
					    unsigned long arg4,
					    unsigned long arg5);
#endif

' \
	"$kernel_root/kernel/sys.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,' \
	'	error = security_task_prctl(option, arg2, arg3, arg4, arg5);' \
	'#ifdef CONFIG_SECURITY_PKM
	error = pkm_kacs_prctl_capability_guard(option, arg2, arg3, arg4,
						 arg5);
	if (error)
		return error;
#endif
	error = security_task_prctl(option, arg2, arg3, arg4, arg5);' \
	"$kernel_root/kernel/sys.c"
insert_block_before_exact_once 'ssize_t ksys_pwrite64(unsigned int fd, const char __user *buf,' \
	'extern int pkm_kacs_file_begin_write_intent' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_begin_write_intent(struct file *file, u32 rwf_flags,
					    bool positioned);
extern void pkm_kacs_file_end_write_intent(struct file *file);
#endif

' \
	"$kernel_root/fs/read_write.c"
replace_line_after_anchor_once 'ssize_t ksys_pwrite64(unsigned int fd, const char __user *buf,' \
	'		return vfs_write(fd_file(f), buf, count, &pos);' \
	'		{
#ifdef CONFIG_SECURITY_PKM
			ssize_t pkm_ret;

			pkm_ret = pkm_kacs_file_begin_write_intent(
				fd_file(f), 0, true);
			if (pkm_ret)
				return pkm_ret;
			pkm_ret = vfs_write(fd_file(f), buf, count, &pos);
			pkm_kacs_file_end_write_intent(fd_file(f));
			return pkm_ret;
#else
			return vfs_write(fd_file(f), buf, count, &pos);
#endif
		}' \
	"$kernel_root/fs/read_write.c"
replace_line_after_anchor_once 'static ssize_t do_writev(unsigned long fd, const struct iovec __user *vec,' \
	'		ret = vfs_writev(fd_file(f), vec, vlen, ppos, flags);' \
	'		{
#ifdef CONFIG_SECURITY_PKM
			ret = pkm_kacs_file_begin_write_intent(
				fd_file(f), (u32)flags, false);
			if (!ret) {
				ret = vfs_writev(fd_file(f), vec, vlen, ppos,
						 flags);
				pkm_kacs_file_end_write_intent(fd_file(f));
			}
#else
			ret = vfs_writev(fd_file(f), vec, vlen, ppos, flags);
#endif
		}' \
	"$kernel_root/fs/read_write.c"
replace_line_after_anchor_once 'static ssize_t do_pwritev(unsigned long fd, const struct iovec __user *vec,' \
	'			ret = vfs_writev(fd_file(f), vec, vlen, &pos, flags);' \
	'			{
#ifdef CONFIG_SECURITY_PKM
				ret = pkm_kacs_file_begin_write_intent(
					fd_file(f), (u32)flags, true);
				if (!ret) {
					ret = vfs_writev(fd_file(f), vec,
							 vlen, &pos, flags);
					pkm_kacs_file_end_write_intent(
						fd_file(f));
				}
#else
				ret = vfs_writev(fd_file(f), vec, vlen, &pos,
						 flags);
#endif
			}' \
	"$kernel_root/fs/read_write.c"
insert_block_before_exact_once 'int io_write(struct io_kiocb *req, unsigned int issue_flags)' \
	'extern int pkm_kacs_file_begin_write_intent' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_begin_write_intent(struct file *file, u32 rwf_flags,
					    bool positioned);
extern void pkm_kacs_file_end_write_intent(struct file *file);
#endif

' \
	"$kernel_root/io_uring/rw.c"
replace_line_after_anchor_once 'int io_write(struct io_kiocb *req, unsigned int issue_flags)' \
	'	ret = rw_verify_area(WRITE, req->file, ppos, req->cqe.res);' \
	'#ifdef CONFIG_SECURITY_PKM
	ret = pkm_kacs_file_begin_write_intent(
		req->file, (u32)rw->flags,
		ppos && !(req->flags & REQ_F_CUR_POS));
	if (unlikely(ret))
		return ret;
	ret = rw_verify_area(WRITE, req->file, ppos, req->cqe.res);
	pkm_kacs_file_end_write_intent(req->file);
#else
	ret = rw_verify_area(WRITE, req->file, ppos, req->cqe.res);
#endif' \
	"$kernel_root/io_uring/rw.c"
insert_block_before_exact_once 'static int aio_write(struct kiocb *req, const struct iocb *iocb,' \
	'extern int pkm_kacs_file_begin_write_intent' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_begin_write_intent(struct file *file, u32 rwf_flags,
					    bool positioned);
extern void pkm_kacs_file_end_write_intent(struct file *file);
#endif

' \
	"$kernel_root/fs/aio.c"
replace_line_after_anchor_once 'static int aio_write(struct kiocb *req, const struct iocb *iocb,' \
	'	ret = rw_verify_area(WRITE, file, &req->ki_pos, iov_iter_count(&iter));' \
	'#ifdef CONFIG_SECURITY_PKM
	ret = pkm_kacs_file_begin_write_intent(file, (u32)iocb->aio_rw_flags,
					       true);
	if (!ret) {
		ret = rw_verify_area(WRITE, file, &req->ki_pos,
				     iov_iter_count(&iter));
		pkm_kacs_file_end_write_intent(file);
	}
#else
	ret = rw_verify_area(WRITE, file, &req->ki_pos, iov_iter_count(&iter));
#endif' \
	"$kernel_root/fs/aio.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE1(fchdir, unsigned int, fd)' \
	'	error = file_permission(fd_file(f), MAY_EXEC | MAY_CHDIR);' \
	'#ifdef CONFIG_SECURITY_PKM
	if (fd_file(f)->f_mode & FMODE_PATH)
		error = file_permission(fd_file(f), MAY_EXEC | MAY_CHDIR);
	else
		error = security_file_permission(fd_file(f),
						 MAY_EXEC | MAY_CHDIR);
#else
	error = file_permission(fd_file(f), MAY_EXEC | MAY_CHDIR);
#endif
' \
	"$kernel_root/fs/open.c"
insert_block_before_exact_once 'static long do_handle_open(int mountdirfd, struct file_handle __user *ufh,' \
	'extern int pkm_kacs_open_by_handle_at' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_open_by_handle_at(void);
#endif

' \
	"$kernel_root/fs/fhandle.c"
replace_line_after_anchor_once 'static long do_handle_open(int mountdirfd, struct file_handle __user *ufh,' \
	'	retval = handle_to_path(mountdirfd, ufh, &path, open_flag);' \
	'#ifdef CONFIG_SECURITY_PKM
	retval = pkm_kacs_open_by_handle_at();
	if (retval)
		return retval;
#endif
	retval = handle_to_path(mountdirfd, ufh, &path, open_flag);' \
	"$kernel_root/fs/fhandle.c"
insert_block_before_exact_once 'static bool access_need_override_creds(int flags)' \
	'extern int pkm_kacs_path_access' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_path_access(const struct path *path, int mode);
#endif

' \
	"$kernel_root/fs/open.c"
replace_line_after_anchor_once 'static int do_faccessat(int dfd, const char __user *filename, int mode, int flags)' \
	'	if (access_need_override_creds(flags)) {
		old_cred = access_override_creds();
		if (!old_cred)
			return -ENOMEM;
	}
' \
	'#ifndef CONFIG_SECURITY_PKM
	if (access_need_override_creds(flags)) {
		old_cred = access_override_creds();
		if (!old_cred)
			return -ENOMEM;
	}
#endif
' \
	"$kernel_root/fs/open.c"
replace_line_after_anchor_once 'static int do_faccessat(int dfd, const char __user *filename, int mode, int flags)' \
	'	res = inode_permission(mnt_idmap(path.mnt), inode, mode | MAY_ACCESS);' \
	'#ifdef CONFIG_SECURITY_PKM
	res = pkm_kacs_path_access(&path, mode);
	if (res)
		goto out_path_release;
#endif
	res = inode_permission(mnt_idmap(path.mnt), inode, mode | MAY_ACCESS);' \
	"$kernel_root/fs/open.c"
insert_block_before_exact_once 'int vfs_fstat(int fd, struct kstat *stat)' \
	'extern int pkm_kacs_file_getattr' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_getattr(struct file *file);
extern void pkm_kacs_file_end_metadata(struct file *file);
#endif

' \
	"$kernel_root/fs/stat.c"
replace_line_after_anchor_once 'int vfs_fstat(int fd, struct kstat *stat)' \
	'	return vfs_getattr(&fd_file(f)->f_path, stat, STATX_BASIC_STATS, 0);' \
	'#ifdef CONFIG_SECURITY_PKM
	{
		int ret = pkm_kacs_file_getattr(fd_file(f));
		if (ret)
			return ret;
		ret = vfs_getattr(&fd_file(f)->f_path, stat,
				  STATX_BASIC_STATS, 0);
		pkm_kacs_file_end_metadata(fd_file(f));
		return ret;
	}
#else
	return vfs_getattr(&fd_file(f)->f_path, stat, STATX_BASIC_STATS, 0);
#endif
' \
	"$kernel_root/fs/stat.c"
replace_line_after_anchor_once 'static int vfs_statx_fd(int fd, int flags, struct kstat *stat,' \
	'	return vfs_statx_path(&fd_file(f)->f_path, flags, stat, request_mask);' \
	'#ifdef CONFIG_SECURITY_PKM
	{
		int ret = pkm_kacs_file_getattr(fd_file(f));
		if (ret)
			return ret;
		ret = vfs_statx_path(&fd_file(f)->f_path, flags, stat,
				     request_mask);
		pkm_kacs_file_end_metadata(fd_file(f));
		return ret;
	}
#else
	return vfs_statx_path(&fd_file(f)->f_path, flags, stat, request_mask);
#endif
' \
	"$kernel_root/fs/stat.c"
insert_block_before_exact_once 'int fd_statfs(int fd, struct kstatfs *st)' \
	'extern int pkm_kacs_file_statfs' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_statfs(struct file *file);
#endif

' \
	"$kernel_root/fs/statfs.c"
replace_line_after_anchor_once 'int fd_statfs(int fd, struct kstatfs *st)' \
	'	return vfs_statfs(&fd_file(f)->f_path, st);' \
	'#ifdef CONFIG_SECURITY_PKM
	{
		int ret = pkm_kacs_file_statfs(fd_file(f));
		if (ret)
			return ret;
	}
#endif
	return vfs_statfs(&fd_file(f)->f_path, st);' \
	"$kernel_root/fs/statfs.c"
insert_block_before_exact_once 'int vfs_fchmod(struct file *file, umode_t mode)' \
	'extern int pkm_kacs_file_chmod' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_chmod(struct file *file);
extern int pkm_kacs_file_chown(struct file *file);
extern void pkm_kacs_file_end_metadata(struct file *file);
#endif

' \
	"$kernel_root/fs/open.c"
replace_line_after_anchor_once 'int vfs_fchmod(struct file *file, umode_t mode)' \
	'	audit_file(file);
	return chmod_common(&file->f_path, mode);' \
	'#ifdef CONFIG_SECURITY_PKM
	{
		int ret = pkm_kacs_file_chmod(file);
		if (ret)
			return ret;
		audit_file(file);
		ret = chmod_common(&file->f_path, mode);
		pkm_kacs_file_end_metadata(file);
		return ret;
	}
#else
	audit_file(file);
	return chmod_common(&file->f_path, mode);
#endif
' \
	"$kernel_root/fs/open.c"
replace_line_after_anchor_once 'int vfs_fchown(struct file *file, uid_t user, gid_t group)' \
	'	error = mnt_want_write_file(file);
	if (error)
		return error;
	audit_file(file);
	error = chown_common(&file->f_path, user, group);
	mnt_drop_write_file(file);
	return error;' \
	'	error = mnt_want_write_file(file);
	if (error)
		return error;
#ifdef CONFIG_SECURITY_PKM
	error = pkm_kacs_file_chown(file);
	if (error) {
		mnt_drop_write_file(file);
		return error;
	}
#endif
	audit_file(file);
	error = chown_common(&file->f_path, user, group);
#ifdef CONFIG_SECURITY_PKM
	pkm_kacs_file_end_metadata(file);
#endif
	mnt_drop_write_file(file);
	return error;' \
	"$kernel_root/fs/open.c"
insert_block_before_exact_once 'static int do_utimes_fd(int fd, struct timespec64 *times, int flags)' \
	'extern int pkm_kacs_file_utimens' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_utimens(struct file *file);
extern void pkm_kacs_file_end_metadata(struct file *file);
#endif

' \
	"$kernel_root/fs/utimes.c"
replace_line_after_anchor_once 'static int do_utimes_fd(int fd, struct timespec64 *times, int flags)' \
	'	return vfs_utimes(&fd_file(f)->f_path, times);' \
	'#ifdef CONFIG_SECURITY_PKM
	{
		int ret = pkm_kacs_file_utimens(fd_file(f));
		if (ret)
			return ret;
		ret = vfs_utimes(&fd_file(f)->f_path, times);
		pkm_kacs_file_end_metadata(fd_file(f));
		return ret;
	}
#else
	return vfs_utimes(&fd_file(f)->f_path, times);
#endif
' \
	"$kernel_root/fs/utimes.c"
insert_block_before_exact_once 'int ioctl_getflags(struct file *file, unsigned int __user *argp)' \
	'extern int pkm_kacs_file_fileattr_get' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_fileattr_get(struct file *file);
extern int pkm_kacs_file_fileattr_set(struct file *file);
extern void pkm_kacs_file_end_metadata(struct file *file);
extern int pkm_kacs_path_fileattr_set(const struct path *path);
extern void pkm_kacs_path_end_metadata(const struct path *path);
#endif

' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'int ioctl_getflags(struct file *file, unsigned int __user *argp)' \
	'	err = vfs_fileattr_get(file->f_path.dentry, &fa);' \
	'#ifdef CONFIG_SECURITY_PKM
	err = pkm_kacs_file_fileattr_get(file);
	if (err)
		return err;
#endif
	err = vfs_fileattr_get(file->f_path.dentry, &fa);
#ifdef CONFIG_SECURITY_PKM
	pkm_kacs_file_end_metadata(file);
#endif' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'int ioctl_setflags(struct file *file, unsigned int __user *argp)' \
	'			err = vfs_fileattr_set(idmap, dentry, &fa);' \
	'#ifdef CONFIG_SECURITY_PKM
			err = pkm_kacs_file_fileattr_set(file);
			if (err) {
				mnt_drop_write_file(file);
				return err;
			}
#endif
			err = vfs_fileattr_set(idmap, dentry, &fa);
#ifdef CONFIG_SECURITY_PKM
			pkm_kacs_file_end_metadata(file);
#endif' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'int ioctl_fsgetxattr(struct file *file, void __user *argp)' \
	'	err = vfs_fileattr_get(file->f_path.dentry, &fa);' \
	'#ifdef CONFIG_SECURITY_PKM
	err = pkm_kacs_file_fileattr_get(file);
	if (err)
		return err;
#endif
	err = vfs_fileattr_get(file->f_path.dentry, &fa);
#ifdef CONFIG_SECURITY_PKM
	pkm_kacs_file_end_metadata(file);
#endif' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'int ioctl_fssetxattr(struct file *file, void __user *argp)' \
	'			err = vfs_fileattr_set(idmap, dentry, &fa);' \
	'#ifdef CONFIG_SECURITY_PKM
			err = pkm_kacs_file_fileattr_set(file);
			if (err) {
				mnt_drop_write_file(file);
				return err;
			}
#endif
			err = vfs_fileattr_set(idmap, dentry, &fa);
#ifdef CONFIG_SECURITY_PKM
			pkm_kacs_file_end_metadata(file);
#endif' \
	"$kernel_root/fs/file_attr.c"
insert_block_before_exact_once 'SYSCALL_DEFINE5(file_getattr, int, dfd, const char __user *, filename,' \
	'extern int pkm_kacs_file_fileattr_get' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_fileattr_get(struct file *file);
extern int pkm_kacs_file_fileattr_set(struct file *file);
extern void pkm_kacs_file_end_metadata(struct file *file);
extern int pkm_kacs_path_fileattr_set(const struct path *path);
extern void pkm_kacs_path_end_metadata(const struct path *path);
#endif

' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE5(file_getattr, int, dfd, const char __user *, filename,' \
	'	struct file_kattr fa;
	int error;' \
	'	struct file_kattr fa;
#ifdef CONFIG_SECURITY_PKM
	struct file *pkm_fileattr_file = NULL;
#endif
	int error;' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE5(file_getattr, int, dfd, const char __user *, filename,' \
	'		filepath = fd_file(f)->f_path;' \
	'#ifdef CONFIG_SECURITY_PKM
		pkm_fileattr_file = fd_file(f);
		error = pkm_kacs_file_fileattr_get(pkm_fileattr_file);
		if (error)
			return error;
		filepath = pkm_fileattr_file->f_path;
#else
		filepath = fd_file(f)->f_path;
#endif
' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE5(file_getattr, int, dfd, const char __user *, filename,' \
	'	error = vfs_fileattr_get(filepath.dentry, &fa);' \
	'	error = vfs_fileattr_get(filepath.dentry, &fa);
#ifdef CONFIG_SECURITY_PKM
	if (pkm_fileattr_file)
		pkm_kacs_file_end_metadata(pkm_fileattr_file);
#endif' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE5(file_setattr, int, dfd, const char __user *, filename,' \
	'	struct file_kattr fa;
	int error;' \
	'	struct file_kattr fa;
#ifdef CONFIG_SECURITY_PKM
	struct file *pkm_fileattr_file = NULL;
#endif
	int error;' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE5(file_setattr, int, dfd, const char __user *, filename,' \
	'		filepath = fd_file(f)->f_path;' \
	'#ifdef CONFIG_SECURITY_PKM
		pkm_fileattr_file = fd_file(f);
		error = pkm_kacs_file_fileattr_set(pkm_fileattr_file);
		if (error)
			return error;
		filepath = pkm_fileattr_file->f_path;
#else
		filepath = fd_file(f)->f_path;
#endif
' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE5(file_setattr, int, dfd, const char __user *, filename,' \
	'	error = mnt_want_write(filepath.mnt);
	if (!error) {' \
	'	error = mnt_want_write(filepath.mnt);
#ifdef CONFIG_SECURITY_PKM
	if (error && pkm_fileattr_file)
		pkm_kacs_file_end_metadata(pkm_fileattr_file);
#endif
	if (!error) {' \
	"$kernel_root/fs/file_attr.c"
replace_line_after_anchor_once 'SYSCALL_DEFINE5(file_setattr, int, dfd, const char __user *, filename,' \
	'		error = vfs_fileattr_set(mnt_idmap(filepath.mnt),
					 filepath.dentry, &fa);' \
	'	#ifdef CONFIG_SECURITY_PKM
		if (!pkm_fileattr_file) {
			error = pkm_kacs_path_fileattr_set(&filepath);
			if (error) {
				mnt_drop_write(filepath.mnt);
				return error;
			}
		}
#endif
		error = vfs_fileattr_set(mnt_idmap(filepath.mnt),
					 filepath.dentry, &fa);
#ifdef CONFIG_SECURITY_PKM
		if (pkm_fileattr_file)
			pkm_kacs_file_end_metadata(pkm_fileattr_file);
		else
			pkm_kacs_path_end_metadata(&filepath);
#endif' \
	"$kernel_root/fs/file_attr.c"
insert_block_before_exact_once 'int vfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)' \
	'extern int pkm_kacs_file_fallocate' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_fallocate(struct file *file, int mode);
#endif

' \
	"$kernel_root/fs/open.c"
replace_line_after_anchor_once 'int vfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)' \
	'	ret = security_file_permission(file, MAY_WRITE);' \
	'#ifdef CONFIG_SECURITY_PKM
	ret = pkm_kacs_file_fallocate(file, mode);
#else
	ret = security_file_permission(file, MAY_WRITE);
#endif
' \
	"$kernel_root/fs/open.c"
insert_block_before_exact_once 'static ssize_t proc_pid_cmdline_read(struct file *file, char __user *buf,' \
	'static unsigned int proc_pkm_metadata_ptrace_mode' \
	'static unsigned int proc_pkm_metadata_ptrace_mode(const struct file *file)
{
	const char *name;

	if (!file)
		return 0;

	name = file_dentry(file)->d_name.name;
	if (strcmp(name, "stat") == 0 || strcmp(name, "statm") == 0 ||
	    strcmp(name, "comm") == 0 || strcmp(name, "wchan") == 0 ||
	    strcmp(name, "schedstat") == 0 || strcmp(name, "cpuset") == 0 ||
	    strcmp(name, "cgroup") == 0 ||
	    strcmp(name, "cpu_resctrl_groups") == 0 ||
	    strcmp(name, "oom_score") == 0 ||
	    strcmp(name, "sessionid") == 0 ||
	    strcmp(name, "patch_state") == 0 ||
	    strcmp(name, "stack_depth") == 0 ||
	    strcmp(name, "arch_status") == 0)
		return PTRACE_MODE_READ_FSCREDS |
		       PTRACE_MODE_PROC_QUERY_LIMITED;
	if (strcmp(name, "cmdline") == 0 || strcmp(name, "status") == 0 ||
	    strcmp(name, "io") == 0 || strcmp(name, "limits") == 0 ||
	    strcmp(name, "sched") == 0 ||
	    strcmp(name, "autogroup") == 0 ||
	    strcmp(name, "timens_offsets") == 0 ||
	    strcmp(name, "personality") == 0 ||
	    strcmp(name, "syscall") == 0 ||
	    strcmp(name, "latency") == 0 ||
	    strcmp(name, "timers") == 0 ||
	    strcmp(name, "timerslack_ns") == 0 ||
	    strcmp(name, "mounts") == 0 ||
	    strcmp(name, "mountinfo") == 0 ||
	    strcmp(name, "mountstats") == 0 ||
	    strcmp(name, "coredump_filter") == 0 ||
	    strcmp(name, "oom_adj") == 0 ||
	    strcmp(name, "oom_score_adj") == 0 ||
	    strcmp(name, "loginuid") == 0 ||
	    strcmp(name, "make-it-fail") == 0 ||
	    strcmp(name, "fail-nth") == 0 ||
	    strcmp(name, "uid_map") == 0 ||
	    strcmp(name, "gid_map") == 0 ||
	    strcmp(name, "projid_map") == 0 ||
	    strcmp(name, "setgroups") == 0 ||
	    strcmp(name, "seccomp_cache") == 0 ||
	    strcmp(name, "ksm_merging_pages") == 0 ||
	    strcmp(name, "ksm_stat") == 0)
		return PTRACE_MODE_READ_FSCREDS |
		       PTRACE_MODE_PROC_QUERY_INFORMATION;

	return 0;
}

static int proc_pkm_check_task_metadata_access(struct task_struct *task,
					       const struct file *file)
{
	unsigned int mode;

	mode = proc_pkm_metadata_ptrace_mode(file);
	if (mode == 0)
		return 0;
	if (!ptrace_may_access(task, mode))
		return -EACCES;

	return 0;
}

#ifdef CONFIG_SECURITY_PKM
extern long pkm_kacs_proc_process_setinfo(struct task_struct *task);
#endif

static int proc_pkm_check_task_setinfo_access(struct task_struct *task)
{
#ifdef CONFIG_SECURITY_PKM
	long ret;

	ret = pkm_kacs_proc_process_setinfo(task);
	if (ret)
		return (int)ret;
#endif

	return 0;
}

' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	ret = get_task_cmdline(tsk, buf, count, pos);' \
	'	ret = proc_pkm_check_task_metadata_access(tsk, file);' \
	'	ret = proc_pkm_check_task_metadata_access(tsk, file);
	if (ret) {
		put_task_struct(tsk);
		return ret;
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	ret = PROC_I(inode)->op.proc_show(m, ns, pid, task);' \
	'	ret = proc_pkm_check_task_metadata_access(task, m->file);' \
	'	ret = proc_pkm_check_task_metadata_access(task, m->file);
	if (ret) {
		put_task_struct(task);
		return ret;
	}
' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static int lstats_show_proc(struct seq_file *m, void *v)' \
	'	if (!task)
		return -ESRCH;' \
	'	if (!task)
		return -ESRCH;
	/* PKM: gate /proc/<pid>/latency read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(task, m->file);

		if (ret) {
			put_task_struct(task);
			return ret;
		}
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	if (task->signal->oom_score_adj == OOM_SCORE_ADJ_MAX)' \
	'PKM: gate /proc/<pid>/oom_adj read metadata' \
	'	/* PKM: gate /proc/<pid>/oom_adj read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(task, file);

		if (ret) {
			put_task_struct(task);
			return ret;
		}
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	oom_score_adj = task->signal->oom_score_adj;' \
	'PKM: gate /proc/<pid>/oom_score_adj read metadata' \
	'	/* PKM: gate /proc/<pid>/oom_score_adj read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(task, file);

		if (ret) {
			put_task_struct(task);
			return ret;
		}
	}
' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static ssize_t proc_loginuid_read(struct file * file, char __user * buf,' \
	'	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",' \
	'	/* PKM: gate /proc/<pid>/loginuid read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(task, file);

		if (ret) {
			put_task_struct(task);
			return ret;
		}
	}
	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static ssize_t proc_sessionid_read(struct file * file, char __user * buf,' \
	'	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",' \
	'	/* PKM: gate /proc/<pid>/sessionid read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(task, file);

		if (ret) {
			put_task_struct(task);
			return ret;
		}
	}
	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	make_it_fail = task->make_it_fail;' \
	'PKM: gate /proc/<pid>/make-it-fail read metadata' \
	'	/* PKM: gate /proc/<pid>/make-it-fail read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(task, file);

		if (ret) {
			put_task_struct(task);
			return ret;
		}
	}
' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static ssize_t proc_fail_nth_read(struct file *file, char __user *buf,' \
	'	len = snprintf(numbuf, sizeof(numbuf), "%u\n", task->fail_nth);' \
	'	/* PKM: gate /proc/<pid>/fail-nth read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(task, file);

		if (ret) {
			put_task_struct(task);
			return ret;
		}
	}
	len = snprintf(numbuf, sizeof(numbuf), "%u\n", task->fail_nth);
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	proc_sched_show_task(p, ns, m);' \
	'PKM: gate /proc/<pid>/sched read metadata' \
	'	/* PKM: gate /proc/<pid>/sched read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(p, m->file);

		if (ret) {
			put_task_struct(p);
			return ret;
		}
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	proc_sched_autogroup_show_task(p, m);' \
	'PKM: gate /proc/<pid>/autogroup read metadata' \
	'	/* PKM: gate /proc/<pid>/autogroup read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(p, m->file);

		if (ret) {
			put_task_struct(p);
			return ret;
		}
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	proc_timens_show_offsets(p, m);' \
	'PKM: gate /proc/<pid>/timens_offsets read metadata' \
	'	/* PKM: gate /proc/<pid>/timens_offsets read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(p, m->file);

		if (ret) {
			put_task_struct(p);
			return ret;
		}
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	proc_task_name(m, p, false);' \
	'PKM: gate /proc/<pid>/comm read metadata' \
	'	/* PKM: gate /proc/<pid>/comm read metadata. */
	{
		int ret = proc_pkm_check_task_metadata_access(p, m->file);

		if (ret) {
			put_task_struct(p);
			return ret;
		}
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	tp = __seq_open_private(file, &proc_timers_seq_ops,' \
	'PKM: gate /proc/<pid>/timers read metadata' \
	'#ifdef CONFIG_SECURITY_PKM
	{
		struct task_struct *task;
		int ret;

		/* PKM: gate /proc/<pid>/timers read metadata. */
		task = get_proc_task(inode);
		if (!task)
			return -ESRCH;
		ret = proc_pkm_check_task_metadata_access(task, file);
		put_task_struct(task);
		if (ret)
			return ret;
	}
#endif

' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static ssize_t proc_coredump_filter_read(struct file *file, char __user *buf,' \
	'	ret = 0;' \
	'	/* PKM: gate /proc/<pid>/coredump_filter read metadata. */
	ret = proc_pkm_check_task_metadata_access(task, file);
	if (ret) {
		put_task_struct(task);
		return ret;
	}
	ret = 0;' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static ssize_t lstats_write(struct file *file, const char __user *buf,' \
	'	if (!task)
		return -ESRCH;
	clear_tsk_latency_tracing(task);' \
	'	if (!task)
		return -ESRCH;
	/* PKM: gate /proc/<pid>/latency writes. */
	{
		int ret = proc_pkm_check_task_setinfo_access(task);

		if (ret) {
			put_task_struct(task);
			return ret;
		}
	}
	clear_tsk_latency_tracing(task);' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	proc_sched_set_task(p);' \
	'PKM: gate /proc/<pid>/sched writes' \
	'	/* PKM: gate /proc/<pid>/sched writes. */
	{
		int ret = proc_pkm_check_task_setinfo_access(p);

		if (ret) {
			put_task_struct(p);
			return ret;
		}
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	err = proc_sched_autogroup_set_nice(p, nice);' \
	'PKM: gate /proc/<pid>/autogroup writes' \
	'	/* PKM: gate /proc/<pid>/autogroup writes. */
	err = proc_pkm_check_task_setinfo_access(p);
	if (err) {
		put_task_struct(p);
		return err;
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	ret = proc_timens_set_offset(file, p, offsets, noffsets);' \
	'PKM: gate /proc/<pid>/timens_offsets writes' \
	'	/* PKM: gate /proc/<pid>/timens_offsets writes. */
	ret = proc_pkm_check_task_setinfo_access(p);
	if (ret) {
		put_task_struct(p);
		goto out;
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	mutex_lock(&oom_adj_mutex);' \
	'PKM: gate /proc/<pid>/oom adjustment writes' \
	'#ifdef CONFIG_SECURITY_PKM
	/* PKM: gate /proc/<pid>/oom adjustment writes. */
	err = proc_pkm_check_task_setinfo_access(task);
	if (err) {
		put_task_struct(task);
		return err;
	}
#endif

' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	task->signal->oom_score_adj = oom_adj;' \
	'PKM: fail closed on multiprocess mm OOM fan-out' \
	'#ifdef CONFIG_SECURITY_PKM
	/* PKM: fail closed on multiprocess mm OOM fan-out. */
	if (mm) {
		mmdrop(mm);
		mm = NULL;
		err = -EACCES;
		goto err_unlock;
	}
#endif

' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	task->make_it_fail = make_it_fail;' \
	'PKM: gate /proc/<pid>/make-it-fail writes' \
	'	/* PKM: gate /proc/<pid>/make-it-fail writes. */
	rv = proc_pkm_check_task_setinfo_access(task);
	if (rv) {
		put_task_struct(task);
		return rv;
	}
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	task->fail_nth = n;' \
	'PKM: gate /proc/<pid>/fail-nth writes' \
	'	/* PKM: gate /proc/<pid>/fail-nth writes. */
	err = proc_pkm_check_task_setinfo_access(task);
	if (err) {
		put_task_struct(task);
		return err;
	}
' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static ssize_t proc_coredump_filter_write(struct file *file,' \
	'	mm = get_task_mm(task);' \
	'	/* PKM: gate /proc/<pid>/coredump_filter writes. */
	ret = proc_pkm_check_task_setinfo_access(task);
	if (ret)
		goto out_no_mm;
	mm = get_task_mm(task);
' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static int proc_id_map_open(struct inode *inode, struct file *file,' \
	'	if (task) {
		rcu_read_lock();' \
	'	if (task) {
		/* PKM: gate /proc/<pid> id-map open intent. */
		if (file->f_mode & FMODE_READ) {
			ret = proc_pkm_check_task_metadata_access(task, file);
			if (ret) {
				put_task_struct(task);
				goto err;
			}
		}
		if (file->f_mode & FMODE_WRITE) {
			ret = proc_pkm_check_task_setinfo_access(task);
			if (ret) {
				put_task_struct(task);
				goto err;
			}
		}
		rcu_read_lock();' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static int proc_setgroups_open(struct inode *inode, struct file *file)' \
	'	if (task) {
		rcu_read_lock();' \
	'	if (task) {
		/* PKM: gate /proc/<pid>/setgroups open intent. */
		if (file->f_mode & FMODE_READ) {
			ret = proc_pkm_check_task_metadata_access(task, file);
			if (ret) {
				put_task_struct(task);
				goto err;
			}
		}
		if (file->f_mode & FMODE_WRITE) {
			ret = proc_pkm_check_task_setinfo_access(task);
			if (ret) {
				put_task_struct(task);
				goto err;
			}
		}
		rcu_read_lock();' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once 'static ssize_t clear_refs_write(struct file *file, const char __user *buf,' \
	'extern long pkm_kacs_proc_process_setinfo' \
	'#ifdef CONFIG_SECURITY_PKM
extern long pkm_kacs_proc_process_setinfo(struct task_struct *task);
#endif

' \
	"$kernel_root/fs/proc/task_mmu.c"
insert_block_before_exact_once '	mm = get_task_mm(task);' \
	'PKM: gate /proc/<pid>/clear_refs writes' \
	'#ifdef CONFIG_SECURITY_PKM
	/* PKM: gate /proc/<pid>/clear_refs writes. */
	rv = pkm_kacs_proc_process_setinfo(task);
	if (rv) {
		put_task_struct(task);
		return rv;
	}
#endif

' \
	"$kernel_root/fs/proc/task_mmu.c"
insert_line_after_exact_once '#include <linux/nsproxy.h>' \
	'#include <linux/ptrace.h>' \
	"$kernel_root/fs/proc_namespace.c"
insert_block_before_exact_once '	task_lock(task);' \
	'PKM: gate /proc/<pid>/mount namespace read metadata' \
	'#ifdef CONFIG_SECURITY_PKM
	/* PKM: gate /proc/<pid>/mount namespace read metadata. */
	if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS |
			       PTRACE_MODE_PROC_QUERY_INFORMATION)) {
		put_task_struct(task);
		ret = -EACCES;
		goto err;
	}
#endif

' \
	"$kernel_root/fs/proc_namespace.c"
insert_block_before_exact_once 'static const struct pid_entry tgid_base_stuff[] = {' \
	'static const struct file_operations proc_pid_token_operations' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_proc_open_process_token_file(struct file *file,
						 struct task_struct *task);
extern int pkm_kacs_proc_open_thread_token_file(struct file *file,
						struct task_struct *task);

static int proc_pid_token_open(struct inode *inode, struct file *file)
{
	struct task_struct *task;
	int ret;

	task = get_proc_task(inode);
	if (!task)
		return -ESRCH;

	ret = pkm_kacs_proc_open_process_token_file(file, task);
	put_task_struct(task);
	return ret;
}

static int proc_tid_token_open(struct inode *inode, struct file *file)
{
	struct task_struct *task;
	int ret;

	task = get_proc_task(inode);
	if (!task)
		return -ESRCH;

	ret = pkm_kacs_proc_open_thread_token_file(file, task);
	put_task_struct(task);
	return ret;
}

static const struct file_operations proc_pid_token_operations = {
	.open		= proc_pid_token_open,
	.llseek		= noop_llseek,
};

static const struct file_operations proc_tid_token_operations = {
	.open		= proc_tid_token_open,
	.llseek		= noop_llseek,
};
#endif

' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	REG("auxv",       S_IRUSR, proc_auxv_operations),' \
	'REG("token",      S_IRUGO, proc_pid_token_operations)' \
	'#ifdef CONFIG_SECURITY_PKM
	REG("token",      S_IRUGO, proc_pid_token_operations),
#endif
' \
	"$kernel_root/fs/proc/base.c"
insert_block_before_exact_once '	REG("auxv",      S_IRUSR, proc_auxv_operations),' \
	'REG("token",     S_IRUGO, proc_tid_token_operations)' \
	'#ifdef CONFIG_SECURITY_PKM
	REG("token",     S_IRUGO, proc_tid_token_operations),
#endif
' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static int do_io_accounting(struct task_struct *task, struct seq_file *m, int whole)' \
	'	if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)) {' \
	'	if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_PROC_QUERY_INFORMATION)) {' \
	"$kernel_root/fs/proc/base.c"
replace_line_after_anchor_once 'static int do_task_stat(struct seq_file *m, struct pid_namespace *ns,' \
	'	permitted = ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_NOAUDIT);' \
	'	permitted = ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_PROC_QUERY_LIMITED | PTRACE_MODE_NOAUDIT);' \
	"$kernel_root/fs/proc/array.c"
insert_block_before_exact_once 'int setxattr_copy(const char __user *name, struct kernel_xattr_ctx *ctx)' \
	'extern int pkm_kacs_file_sd_xattr_get' \
	'#ifdef CONFIG_SECURITY_PKM
extern int pkm_kacs_file_sd_xattr_get(struct file *file, const char *name);
extern int pkm_kacs_file_sd_xattr_set(struct file *file, const char *name);
extern int pkm_kacs_file_sd_xattr_remove(struct file *file, const char *name);
extern int pkm_kacs_file_listxattr(struct file *file);
extern void pkm_kacs_file_end_metadata(struct file *file);
#endif

' \
	"$kernel_root/fs/xattr.c"
replace_line_after_anchor_once 'int file_setxattr(struct file *f, struct kernel_xattr_ctx *ctx)' \
	'	int error = mnt_want_write_file(f);' \
	'#ifdef CONFIG_SECURITY_PKM
	int error = pkm_kacs_file_sd_xattr_set(f, ctx->kname->name);
	if (error)
		return error;
#else
	int error = 0;
#endif
	error = mnt_want_write_file(f);
#ifdef CONFIG_SECURITY_PKM
	if (error)
		pkm_kacs_file_end_metadata(f);
#endif' \
	"$kernel_root/fs/xattr.c"
replace_line_after_anchor_once 'int file_setxattr(struct file *f, struct kernel_xattr_ctx *ctx)' \
	'		error = do_setxattr(file_mnt_idmap(f), f->f_path.dentry, ctx);' \
	'		error = do_setxattr(file_mnt_idmap(f), f->f_path.dentry, ctx);
#ifdef CONFIG_SECURITY_PKM
		pkm_kacs_file_end_metadata(f);
#endif' \
	"$kernel_root/fs/xattr.c"
replace_line_after_anchor_once 'ssize_t file_getxattr(struct file *f, struct kernel_xattr_ctx *ctx)' \
	'	audit_file(f);' \
	'#ifdef CONFIG_SECURITY_PKM
	ssize_t error = pkm_kacs_file_sd_xattr_get(f, ctx->kname->name);
	if (error)
		return error;
#endif
	audit_file(f);' \
	"$kernel_root/fs/xattr.c"
replace_line_after_anchor_once 'ssize_t file_getxattr(struct file *f, struct kernel_xattr_ctx *ctx)' \
	'	return do_getxattr(file_mnt_idmap(f), f->f_path.dentry, ctx);' \
	'#ifdef CONFIG_SECURITY_PKM
	error = do_getxattr(file_mnt_idmap(f), f->f_path.dentry, ctx);
	pkm_kacs_file_end_metadata(f);
	return error;
#else
	return do_getxattr(file_mnt_idmap(f), f->f_path.dentry, ctx);
#endif
' \
	"$kernel_root/fs/xattr.c"
replace_line_after_anchor_once 'ssize_t file_listxattr(struct file *f, char __user *list, size_t size)' \
	'	audit_file(f);' \
	'#ifdef CONFIG_SECURITY_PKM
	{
		int ret = pkm_kacs_file_listxattr(f);
		if (ret)
			return ret;
	}
#endif
	audit_file(f);' \
	"$kernel_root/fs/xattr.c"
replace_line_after_anchor_once 'static int file_removexattr(struct file *f, struct xattr_name *kname)' \
	'	int error = mnt_want_write_file(f);' \
	'#ifdef CONFIG_SECURITY_PKM
	int error = pkm_kacs_file_sd_xattr_remove(f, kname->name);
	if (error)
		return error;
#else
	int error = 0;
#endif
	error = mnt_want_write_file(f);
#ifdef CONFIG_SECURITY_PKM
	if (error)
		pkm_kacs_file_end_metadata(f);
#endif' \
	"$kernel_root/fs/xattr.c"
replace_line_after_anchor_once 'static int file_removexattr(struct file *f, struct xattr_name *kname)' \
	'		error = removexattr(file_mnt_idmap(f),
				    f->f_path.dentry, kname->name);' \
	'		error = removexattr(file_mnt_idmap(f),
				    f->f_path.dentry, kname->name);
#ifdef CONFIG_SECURITY_PKM
		pkm_kacs_file_end_metadata(f);
#endif' \
	"$kernel_root/fs/xattr.c"
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1000 kacs_open_self_token
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1001 kacs_open_process_token
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1002 kacs_open_thread_token
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1003 kacs_create_token
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1004 kacs_create_session
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1005 kacs_set_psb
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1006 kacs_destroy_empty_session
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1010 kacs_open_peer_token
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1011 kacs_impersonate_peer
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1012 kacs_revert
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1013 kacs_set_impersonation_level
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1020 kacs_open
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1021 kacs_get_sd
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1022 kacs_set_sd
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1090 kmes_emit
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1092 kmes_emit_batch
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1023 kacs_access_check
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1024 kacs_access_check_list
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1025 kacs_set_caap
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1026 kacs_get_mount_policy
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1027 kacs_set_mount_policy
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1091 kmes_attach
