#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <linux-tree>" >&2
	exit 2
fi

linux_tree=$1
proc_base="$linux_tree/fs/proc/base.c"
proc_array="$linux_tree/fs/proc/array.c"
proc_namespace="$linux_tree/fs/proc_namespace.c"
proc_task_mmu="$linux_tree/fs/proc/task_mmu.c"
read_write="$linux_tree/fs/read_write.c"
aio="$linux_tree/fs/aio.c"
fhandle="$linux_tree/fs/fhandle.c"
file_attr="$linux_tree/fs/file_attr.c"
open="$linux_tree/fs/open.c"
stat="$linux_tree/fs/stat.c"
statfs="$linux_tree/fs/statfs.c"
utimes="$linux_tree/fs/utimes.c"
xattr="$linux_tree/fs/xattr.c"
io_uring_rw="$linux_tree/io_uring/rw.c"
security_core="$linux_tree/security/security.c"
commoncap="$linux_tree/security/commoncap.c"
pkm_makefile="$linux_tree/security/pkm/Makefile"
lcs_source_device="$linux_tree/security/pkm/lcs/source_device.c"
lcs_source_device_h="$linux_tree/security/pkm/lcs/source_device.h"
lcs_kunit="$linux_tree/security/pkm/lcs/kunit.c"
lcs_core_mod="$linux_tree/security/pkm/lcs/lcs_core/mod.rs"
ptrace_h="$linux_tree/include/linux/ptrace.h"
cred_h="$linux_tree/include/linux/cred.h"
pid="$linux_tree/kernel/pid.c"
sys="$linux_tree/kernel/sys.c"
sched_syscalls="$linux_tree/kernel/sched/syscalls.c"
events_core="$linux_tree/kernel/events/core.c"
sock="$linux_tree/net/core/sock.c"

die() {
	echo "verify-generated-tree: $*" >&2
	exit 1
}

require_literal() {
	local needle=$1
	local file=$2
	local message=$3

	if ! grep -Fq "$needle" "$file"; then
		die "$message"
	fi
}

require_literal_once() {
	local needle=$1
	local file=$2
	local message=$3
	local count

	count=$(grep -F -c "$needle" "$file" || true)
	if [[ "$count" != "1" ]]; then
		die "$message (found $count)"
	fi
}

require_file() {
	local file=$1

	if [[ ! -f "$file" ]]; then
		die "generated source missing: $file"
	fi
}

for required_source in \
	"$proc_base" \
	"$proc_array" \
	"$proc_namespace" \
	"$proc_task_mmu" \
	"$read_write" \
	"$aio" \
	"$fhandle" \
	"$file_attr" \
	"$open" \
	"$stat" \
	"$statfs" \
	"$utimes" \
	"$xattr" \
	"$io_uring_rw" \
	"$security_core" \
	"$commoncap" \
	"$pkm_makefile" \
	"$lcs_source_device" \
	"$lcs_source_device_h" \
	"$lcs_kunit" \
	"$lcs_core_mod" \
	"$ptrace_h" \
	"$cred_h" \
	"$pid" \
	"$sys" \
	"$sched_syscalls" \
	"$events_core" \
	"$sock"; do
	require_file "$required_source"
done

require_literal 'lcs/source_device.o' "$pkm_makefile" \
	"generated PKM Makefile does not build the LCS source device"
require_literal 'lcs/kunit.o' "$pkm_makefile" \
	"generated PKM Makefile does not build the LCS KUnit suite"

require_literal 'crate::lcs_core::error' "$linux_tree/security/pkm/lcs/lcs_core/abi.rs" \
	"generated LCS core was not rewritten for nested kernel module paths"
require_literal 'crate::kacs_core::Sid' "$linux_tree/security/pkm/lcs/lcs_core/audit.rs" \
	"generated LCS core was not rewritten for kernel KACS core paths"

require_literal \
	'extern int pkm_kacs_file_begin_write_intent(struct file *file, u32 rwf_flags,' \
	"$read_write" \
	"generated read_write.c is missing the KACS write-intent declaration"
require_literal \
	'pkm_ret = pkm_kacs_file_begin_write_intent(' \
	"$read_write" \
	"generated pwrite64 path does not call the KACS write-intent gate"
require_literal \
	'ret = pkm_kacs_file_begin_write_intent(' \
	"$read_write" \
	"generated pwritev/writev path does not call the KACS write-intent gate"
require_literal \
	'pkm_kacs_file_end_write_intent(fd_file(f));' \
	"$read_write" \
	"generated positioned-write paths do not clear KACS write intent"
require_literal 'ssize_t ksys_pwrite64' "$read_write" \
	"generated read_write.c is missing ksys_pwrite64"
require_literal 'static ssize_t do_pwritev' "$read_write" \
	"generated read_write.c is missing do_pwritev"

require_literal 'int io_write(struct io_kiocb *req' "$io_uring_rw" \
	"generated io_uring write source is missing io_write"
require_literal \
	'ret = pkm_kacs_file_begin_write_intent(' \
	"$io_uring_rw" \
	"generated io_uring write path does not call the KACS write-intent gate"
require_literal \
	'pkm_kacs_file_end_write_intent(req->file);' \
	"$io_uring_rw" \
	"generated io_uring write path does not clear KACS write intent"

require_literal 'static int aio_write(struct kiocb *req' "$aio" \
	"generated AIO source is missing aio_write"
require_literal \
	'ret = pkm_kacs_file_begin_write_intent(file, (u32)iocb->aio_rw_flags,' \
	"$aio" \
	"generated AIO write path does not call the KACS write-intent gate"
require_literal 'pkm_kacs_file_end_write_intent(file);' "$aio" \
	"generated AIO write path does not clear KACS write intent"

require_literal 'extern int pkm_kacs_path_access(const struct path *path, int mode);' \
	"$open" \
	"generated open.c is missing the KACS faccessat declaration"
require_literal '#ifndef CONFIG_SECURITY_PKM' "$open" \
	"generated faccessat path does not suppress native DAC override under KACS"
require_literal 'res = pkm_kacs_path_access(&path, mode);' "$open" \
	"generated faccessat path does not call the KACS access gate"
require_literal 'security_file_permission(fd_file(f),' "$open" \
	"generated fchdir path does not route non-O_PATH fds through file permission"
require_literal 'pkm_kacs_file_chmod(file);' "$open" \
	"generated fchmod path does not call the KACS chmod gate"
require_literal 'pkm_kacs_file_chown(file);' "$open" \
	"generated fchown path does not call the KACS chown gate"
require_literal 'pkm_kacs_file_fallocate(file, mode);' "$open" \
	"generated fallocate path does not call the KACS fallocate gate"

require_literal 'extern int pkm_kacs_open_by_handle_at(void);' "$fhandle" \
	"generated fhandle source is missing the KACS open_by_handle_at declaration"
require_literal 'retval = pkm_kacs_open_by_handle_at();' "$fhandle" \
	"generated open_by_handle_at path does not call the KACS gate"

require_literal 'extern int pkm_kacs_file_getattr(struct file *file);' "$stat" \
	"generated stat source is missing the KACS getattr declaration"
require_literal 'int ret = pkm_kacs_file_getattr(fd_file(f));' "$stat" \
	"generated fstat/statx-fd path does not call the KACS getattr gate"
require_literal 'pkm_kacs_file_end_metadata(fd_file(f));' "$stat" \
	"generated fstat/statx-fd path does not clear KACS metadata intent"

require_literal 'extern int pkm_kacs_file_statfs(struct file *file);' "$statfs" \
	"generated statfs source is missing the KACS fd statfs declaration"
require_literal 'int ret = pkm_kacs_file_statfs(fd_file(f));' "$statfs" \
	"generated fd statfs path does not call the KACS gate"

require_literal 'extern int pkm_kacs_file_utimens(struct file *file);' "$utimes" \
	"generated utimes source is missing the KACS fd utimens declaration"
require_literal 'int ret = pkm_kacs_file_utimens(fd_file(f));' "$utimes" \
	"generated futimens path does not call the KACS gate"
require_literal 'pkm_kacs_file_end_metadata(fd_file(f));' "$utimes" \
	"generated futimens path does not clear KACS metadata intent"

require_literal 'extern int pkm_kacs_file_fileattr_get(struct file *file);' \
	"$file_attr" \
	"generated file_attr source is missing the KACS fileattr get declaration"
require_literal 'extern int pkm_kacs_path_fileattr_set(const struct path *path);' \
	"$file_attr" \
	"generated file_attr source is missing the KACS path fileattr set declaration"
require_literal 'err = pkm_kacs_file_fileattr_get(file);' "$file_attr" \
	"generated fileattr ioctl get path does not call the KACS gate"
require_literal 'err = pkm_kacs_file_fileattr_set(file);' "$file_attr" \
	"generated fileattr ioctl set path does not call the KACS gate"
require_literal 'error = pkm_kacs_path_fileattr_set(&filepath);' "$file_attr" \
	"generated path fileattr set path does not call the KACS gate"
require_literal 'pkm_kacs_path_end_metadata(&filepath);' "$file_attr" \
	"generated path fileattr set path does not clear KACS metadata intent"

require_literal 'extern int pkm_kacs_file_sd_xattr_get(struct file *file, const char *name);' \
	"$xattr" \
	"generated xattr source is missing the KACS fd getxattr declaration"
require_literal 'extern int pkm_kacs_file_sd_xattr_set(struct file *file, const char *name);' \
	"$xattr" \
	"generated xattr source is missing the KACS fd setxattr declaration"
require_literal 'extern int pkm_kacs_file_sd_xattr_remove(struct file *file, const char *name);' \
	"$xattr" \
	"generated xattr source is missing the KACS fd removexattr declaration"
require_literal 'extern int pkm_kacs_file_listxattr(struct file *file);' "$xattr" \
	"generated xattr source is missing the KACS fd listxattr declaration"
require_literal 'pkm_kacs_file_sd_xattr_set(f, ctx->kname->name);' "$xattr" \
	"generated fsetxattr path does not call the KACS gate"
require_literal 'pkm_kacs_file_sd_xattr_get(f, ctx->kname->name);' "$xattr" \
	"generated fgetxattr path does not call the KACS gate"
require_literal 'pkm_kacs_file_listxattr(f);' "$xattr" \
	"generated flistxattr path does not call the KACS gate"
require_literal 'pkm_kacs_file_sd_xattr_remove(f, kname->name);' "$xattr" \
	"generated fremovexattr path does not call the KACS gate"
require_literal 'pkm_kacs_file_end_metadata(f);' "$xattr" \
	"generated fd xattr paths do not clear KACS metadata intent"

require_literal 'pkm_kacs_inode_rename_flags(' "$security_core" \
	"generated LSM security core does not pass rename flags to KACS"

require_literal 'PTRACE_MODE_GETFD' "$ptrace_h" \
	"generated ptrace mode header is missing PTRACE_MODE_GETFD"
require_literal 'PTRACE_MODE_PIDFD_OPEN' "$ptrace_h" \
	"generated ptrace mode header is missing PTRACE_MODE_PIDFD_OPEN"
require_literal 'PTRACE_MODE_PROC_QUERY_LIMITED' "$ptrace_h" \
	"generated ptrace mode header is missing PTRACE_MODE_PROC_QUERY_LIMITED"
require_literal 'PTRACE_MODE_PROC_QUERY_INFORMATION' "$ptrace_h" \
	"generated ptrace mode header is missing PTRACE_MODE_PROC_QUERY_INFORMATION"
require_literal 'PTRACE_MODE_ATTACH_REALCREDS | PTRACE_MODE_GETFD' "$pid" \
	"generated pidfd_getfd path does not carry the KACS GETFD mode"
require_literal 'PTRACE_MODE_PIDFD_OPEN' "$pid" \
	"generated pidfd_open path does not carry the KACS PIDFD_OPEN mode"

require_literal 'pkm_kacs_current_fsuid_kuid' "$cred_h" \
	"generated credential header is missing projected fsuid support"
require_literal 'pkm_kacs_current_fsgid_kgid' "$cred_h" \
	"generated credential header is missing projected fsgid support"
require_literal 'pkm_kacs_current_fsuid_fsgid' "$cred_h" \
	"generated credential header is missing paired projected fsuid/fsgid support"
require_literal '#define current_fsuid()' "$cred_h" \
	"generated credential header does not route current_fsuid through KACS"
require_literal '#define current_fsgid()' "$cred_h" \
	"generated credential header does not route current_fsgid through KACS"
require_literal 'current_real_cred()->uid' "$sys" \
	"generated getuid path does not use the real credential source"
require_literal 'current_real_cred()->gid' "$sys" \
	"generated getgid path does not use the real credential source"
require_literal 'pkm_kacs_prctl_capability_guard' "$sys" \
	"generated prctl path does not call the KACS capability guard"
require_literal 'pkm_kacs_project_cred_uid_gid' "$sock" \
	"generated SO_PEERCRED path does not project credentials through KACS"

require_literal 'pkm_kacs_capget_for_task' "$commoncap" \
	"generated commoncap source is missing KACS capget reporting"
require_literal 'pkm_kacs_capable_in_cred_ns' "$commoncap" \
	"generated commoncap source is missing the KACS capability switchboard"
require_literal 'return 0;' "$commoncap" \
	"generated commoncap source is missing KACS native-bypass returns"

require_literal 'pkm_kacs_proc_status_cap_fixup' "$proc_array" \
	"generated proc status path does not call KACS capability fixup"
require_literal 'PTRACE_MODE_PROC_QUERY_LIMITED | PTRACE_MODE_NOAUDIT' \
	"$proc_array" \
	"generated proc stat path does not carry the KACS limited-query mode"
require_literal 'proc_pkm_check_task_metadata_access' "$proc_base" \
	"generated procfs source is missing KACS metadata gate"
require_literal 'proc_pkm_check_task_setinfo_access' "$proc_base" \
	"generated procfs source is missing KACS setinfo gate"
require_literal 'PTRACE_MODE_PROC_QUERY_INFORMATION' "$proc_base" \
	"generated procfs source is missing KACS query-information classification"
require_literal 'PTRACE_MODE_PROC_QUERY_LIMITED' "$proc_base" \
	"generated procfs source is missing KACS query-limited classification"
require_literal 'PKM: gate /proc/<pid>/clear_refs writes' "$proc_task_mmu" \
	"generated proc task_mmu source does not gate clear_refs writes"
require_literal 'PTRACE_MODE_PROC_QUERY_INFORMATION' "$proc_namespace" \
	"generated proc namespace source does not gate mount metadata"

require_literal 'pkm_kacs_sched_setaffinity(p);' "$sched_syscalls" \
	"generated sched_setaffinity path does not call KACS"
require_literal 'pkm_kacs_perf_event_open(task);' "$events_core" \
	"generated perf_event_open path does not call KACS"

require_literal_once \
	'extern int pkm_kacs_proc_open_process_token_file(struct file *file,' \
	"$proc_base" \
	"procfs generated tree is missing the process-token opener declaration"
require_literal_once \
	'extern int pkm_kacs_proc_open_thread_token_file(struct file *file,' \
	"$proc_base" \
	"procfs generated tree is missing the thread-token opener declaration"
require_literal_once \
	'static int proc_pid_token_open(struct inode *inode, struct file *file)' \
	"$proc_base" \
	"procfs generated tree is missing proc_pid_token_open"
require_literal_once \
	'static int proc_tid_token_open(struct inode *inode, struct file *file)' \
	"$proc_base" \
	"procfs generated tree is missing proc_tid_token_open"
require_literal_once \
	'ret = pkm_kacs_proc_open_process_token_file(file, task);' \
	"$proc_base" \
	"procfs generated tree does not bind /proc/<pid>/token to KACS"
require_literal_once \
	'ret = pkm_kacs_proc_open_thread_token_file(file, task);' \
	"$proc_base" \
	"procfs generated tree does not bind /proc/<pid>/task/<tid>/token to KACS"
require_literal_once \
	'static const struct file_operations proc_pid_token_operations = {' \
	"$proc_base" \
	"procfs generated tree is missing process token file operations"
require_literal_once \
	'static const struct file_operations proc_tid_token_operations = {' \
	"$proc_base" \
	"procfs generated tree is missing thread token file operations"
require_literal_once \
	'REG("token",      S_IRUGO, proc_pid_token_operations),' \
	"$proc_base" \
	"procfs generated tree is missing /proc/<pid>/token entry"
require_literal_once \
	'REG("token",     S_IRUGO, proc_tid_token_operations),' \
	"$proc_base" \
	"procfs generated tree is missing /proc/<pid>/task/<tid>/token entry"

require_literal '#ifdef CONFIG_SECURITY_PKM' "$proc_base" \
	"procfs generated tree has token entries without CONFIG_SECURITY_PKM guards"
