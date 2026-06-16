#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 && $# -ne 3 ]]; then
	echo "usage: $0 <rust-core-src-dir> <kernel-dest-dir> [kernel-module-root]" >&2
	exit 2
fi

src_dir=$1
dest_dir=$2
module_root=${3:-}

if [[ -n "$module_root" && ! "$module_root" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
	echo "invalid kernel module root: $module_root" >&2
	exit 2
fi

if [[ ! -d "$src_dir" ]]; then
	echo "missing Rust core source directory: $src_dir" >&2
	exit 1
fi

rm -rf "$dest_dir"
mkdir -p "$dest_dir"

shopt -s nullglob
mapfile -t rs_files < <(find "$src_dir" -type f -name '*.rs' | sort)
shopt -u nullglob

if [[ ${#rs_files[@]} -eq 0 ]]; then
	echo "no Rust source files found in: $src_dir" >&2
	exit 1
fi

for file in "${rs_files[@]}"; do
	rel_path=${file#"$src_dir"/}
	dest_path="$dest_dir/$rel_path"
	dest_parent=$(dirname "$dest_path")
	mkdir -p "$dest_parent"

	if [[ "$rel_path" == "lib.rs" ]]; then
		PKM_STAGE_MODULE_ROOT="$module_root" awk '
			BEGIN { module_root = ENVIRON["PKM_STAGE_MODULE_ROOT"] }
			/^#\[cfg\(not\(feature = "kernel"\)\)\]$/ { held = $0; next }
			/^extern crate alloc;$/ { held = ""; next }
			/^#!\[/ { next }
			{
				if (held != "") { print held; held = "" }
				if (module_root != "")
					gsub(/crate::/, "crate::" module_root "::")
				if (module_root != "")
					gsub(/kacs_core::/, "crate::kacs_core::")
				# Cores reference bare peios_uapi::CONST; the kernel build
				# vendors those constants as the crate-root peios_uapi module
				# (staged from uapi/generated/rust). Run last so it rewrites
				# only the bare core paths, never an already-rewritten crate one.
				gsub(/peios_uapi::/, "crate::peios_uapi::")
				print
			}
			END { if (held != "") print held }
		' "$file" > "$dest_dir/mod.rs"
	else
		# Non-lib.rs files. With a module_root, rewrite intra-/cross-core
		# `crate::`/`kacs_core::` paths; always rewrite the bare `peios_uapi::`
		# constant paths to the crate-root module (see the lib.rs branch).
		PKM_STAGE_MODULE_ROOT="$module_root" awk '
			BEGIN { module_root = ENVIRON["PKM_STAGE_MODULE_ROOT"] }
			{
				if (module_root != "")
					gsub(/crate::/, "crate::" module_root "::")
				if (module_root != "")
					gsub(/kacs_core::/, "crate::kacs_core::")
				gsub(/peios_uapi::/, "crate::peios_uapi::")
				print
			}
		' "$file" > "$dest_path"
	fi
done

if [[ ! -f "$dest_dir/mod.rs" ]]; then
	echo "lib.rs was not staged into mod.rs" >&2
	exit 1
fi
