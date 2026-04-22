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

append_x86_64_syscall_once() {
	local file=$1
	local number=$2
	local name=$3
	local line

	if grep -Eq "^[[:space:]]*${number}[[:space:]]+common[[:space:]]+${name}[[:space:]]+sys_${name}\$" \
		"$file"; then
		return
	fi

	line=$(printf '%s\tcommon\t%s\t\tsys_%s' "$number" "$name" "$name")
	printf '%s\n' "$line" >> "$file"
}

require_file "$src_root/kacs/lsm.c"
require_file "$src_root/kacs/access_check.c"
require_file "$src_root/kacs/access_check.h"
require_file "$src_root/kacs/access_check.rs"
require_file "$src_root/kacs/caap_cache.c"
require_file "$src_root/kacs/caap_cache.h"
require_file "$src_root/kacs/caap_cache.rs"
require_file "$src_root/kacs/kacs_rust.rs"
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
append_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1000 kacs_open_self_token
append_x86_64_syscall_once "$kernel_root/arch/x86/entry/syscalls/syscall_64.tbl" \
	1025 kacs_set_caap
