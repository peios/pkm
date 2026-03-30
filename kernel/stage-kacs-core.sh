#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 <kacs-core-src-dir> <kernel-dest-dir>" >&2
	exit 2
fi

src_dir=$1
dest_dir=$2

if [[ ! -d "$src_dir" ]]; then
	echo "missing kacs-core source directory: $src_dir" >&2
	exit 1
fi

rm -rf "$dest_dir"
mkdir -p "$dest_dir"

shopt -s nullglob
rs_files=("$src_dir"/*.rs)
shopt -u nullglob

if [[ ${#rs_files[@]} -eq 0 ]]; then
	echo "no Rust source files found in: $src_dir" >&2
	exit 1
fi

for file in "${rs_files[@]}"; do
	base=$(basename "$file")

	if [[ "$base" == "lib.rs" ]]; then
		awk '
			/^#!\[/ { next }
			/^extern crate alloc;$/ { next }
			{ print }
		' "$file" > "$dest_dir/mod.rs"
	else
		install -m 0644 "$file" "$dest_dir/$base"
	fi
done

if [[ ! -f "$dest_dir/mod.rs" ]]; then
	echo "lib.rs was not staged into mod.rs" >&2
	exit 1
fi
