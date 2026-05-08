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
require_file "$src_root/kacs/kmes.c"
require_file "$src_root/kacs/kmes.h"
require_file "$src_root/kacs/kmes_payload.rs"
require_file "$src_root/kacs/kmes_validate.rs"
require_file "$src_root/kacs/kunit.c"
require_file "$src_root/kacs/token_fd.c"
require_file "$src_root/kacs/token_fd.h"
require_file "$src_root/kacs/token_runtime.h"
require_file "$src_root/kacs/token_runtime.rs"
require_file "$src_root/pkm_kconfig"
require_file "$src_root/pkm_makefile"
require_file "$src_root/kernel/stage-kacs-core.sh"
require_file "$kernel_root/security/Makefile"
require_file "$kernel_root/security/Kconfig"
require_file "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl"
require_file "$kernel_root/arch/x86/kernel/process_64.c"
require_file "$kernel_root/fs/proc/base.c"
require_file "$kernel_root/fs/proc/array.c"
require_file "$kernel_root/fs/xattr.c"
require_file "$kernel_root/include/linux/cred.h"
require_file "$kernel_root/include/linux/ptrace.h"
require_file "$kernel_root/kernel/pid.c"
require_file "$kernel_root/kernel/sched/syscalls.c"
require_file "$kernel_root/kernel/sys.c"
require_file "$kernel_root/security/commoncap.c"

rm -rf "$pkm_dir"
mkdir -p "$pkm_dir/kacs"

install -m 0644 "$src_root/kacs/lsm.c" "$pkm_dir/kacs/lsm.c"
install -m 0644 "$src_root/kacs/access_check.c" "$pkm_dir/kacs/access_check.c"
install -m 0644 "$src_root/kacs/access_check.h" "$pkm_dir/kacs/access_check.h"
install -m 0644 "$src_root/kacs/access_check.rs" "$pkm_dir/kacs/access_check.rs"
install -m 0644 "$src_root/kacs/caap_cache.c" "$pkm_dir/kacs/caap_cache.c"
install -m 0644 "$src_root/kacs/caap_cache.h" "$pkm_dir/kacs/caap_cache.h"
install -m 0644 "$src_root/kacs/caap_cache.rs" "$pkm_dir/kacs/caap_cache.rs"
install -m 0644 "$src_root/kacs/kacs_rust.rs" "$pkm_dir/kacs/kacs_rust.rs"
install -m 0644 "$src_root/kacs/kmes.c" "$pkm_dir/kacs/kmes.c"
install -m 0644 "$src_root/kacs/kmes.h" "$pkm_dir/kacs/kmes.h"
install -m 0644 "$src_root/kacs/kmes_payload.rs" "$pkm_dir/kacs/kmes_payload.rs"
install -m 0644 "$src_root/kacs/kmes_validate.rs" "$pkm_dir/kacs/kmes_validate.rs"
install -m 0644 "$src_root/kacs/kunit.c" "$pkm_dir/kacs/kunit.c"
install -m 0644 "$src_root/kacs/token_fd.c" "$pkm_dir/kacs/token_fd.c"
install -m 0644 "$src_root/kacs/token_fd.h" "$pkm_dir/kacs/token_fd.h"
install -m 0644 "$src_root/kacs/token_runtime.h" "$pkm_dir/kacs/token_runtime.h"
install -m 0644 "$src_root/kacs/token_runtime.rs" "$pkm_dir/kacs/token_runtime.rs"
install -m 0644 "$src_root/pkm_kconfig" "$pkm_dir/Kconfig"
install -m 0644 "$src_root/pkm_makefile" "$pkm_dir/Makefile"

"$src_root/kernel/stage-kacs-core.sh" \
	"$src_root/crates/kacs-core/src" \
	"$pkm_dir/kacs/kacs_core"

append_line_once 'obj-$(CONFIG_SECURITY_PKM) += pkm/' "$kernel_root/security/Makefile"
insert_source_kconfig "$kernel_root/security/Kconfig"
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
insert_block_before_exact_once 'static ssize_t proc_pid_cmdline_read(struct file *file, char __user *buf,' \
	'static unsigned int proc_pkm_metadata_ptrace_mode' \
	'static unsigned int proc_pkm_metadata_ptrace_mode(const struct file *file)
{
	const char *name;

	if (!file)
		return 0;

	name = file_dentry(file)->d_name.name;
	if (strcmp(name, "stat") == 0)
		return PTRACE_MODE_READ_FSCREDS |
		       PTRACE_MODE_PROC_QUERY_LIMITED;
	if (strcmp(name, "cmdline") == 0 || strcmp(name, "status") == 0 ||
	    strcmp(name, "io") == 0 || strcmp(name, "cgroup") == 0)
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
	error = mnt_want_write_file(f);' \
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
replace_line_after_anchor_once 'static int file_removexattr(struct file *f, struct xattr_name *kname)' \
	'	int error = mnt_want_write_file(f);' \
	'#ifdef CONFIG_SECURITY_PKM
	int error = pkm_kacs_file_sd_xattr_remove(f, kname->name);
	if (error)
		return error;
#else
	int error = 0;
#endif
	error = mnt_want_write_file(f);' \
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
	1091 kmes_attach
