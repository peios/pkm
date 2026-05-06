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
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1000 kacs_open_self_token
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1001 kacs_open_process_token
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1002 kacs_open_thread_token
insert_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1012 kacs_revert
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
