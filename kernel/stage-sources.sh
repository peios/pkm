#!/usr/bin/env bash
# Stage PKM's own source files into a (patched) Linux tree.
#
# The patch series (apply-patches.sh) edits pre-existing kernel files; this
# script adds the *new* files PKM contributes: the security/pkm subtree, the
# UAPI headers, the in-kernel Ed25519 sources, the generated TCB signing-key
# header, and the path-rewritten Rust cores. Together they leave a complete,
# ready-to-configure kernel source tree. No compilation happens here.
#
# usage: stage-sources.sh <pkm-root> <kernel-tree> [tcb-pubkey-hex]
#   tcb-pubkey-hex omitted/empty -> emit a terminator-only key table
#   (KUnit / placeholder builds). The build farm injects the real key.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
	echo "usage: $0 <pkm-root> <kernel-tree> [tcb-pubkey-hex]" >&2
	exit 2
fi

pkm=$(cd "$1" && pwd) || exit 1
tree=$(cd "$2" && pwd) || exit 1
pubkey=${3:-}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# guard: refuse to stage into something that isn't a Linux source root
if [[ ! -f "$tree/Makefile" ]] || ! grep -q '^VERSION =' "$tree/Makefile"; then
	echo "not a Linux source root: $tree" >&2
	exit 1
fi

pkm_dir="$tree/security/pkm"
uapi_dir="$tree/include/uapi/pkm"

rm -rf "$pkm_dir" "$uapi_dir"
mkdir -p "$pkm_dir/kacs" "$pkm_dir/lcs" "$pkm_dir/kmes" "$uapi_dir"

# --- flat C / H / Rust sources (these dirs contain exactly the staged set) ---
install -m 0644 "$pkm"/kacs/* "$pkm_dir/kacs/"
install -m 0644 "$pkm"/lcs/*  "$pkm_dir/lcs/"
install -m 0644 "$pkm"/kmes/* "$pkm_dir/kmes/"

# --- UAPI headers: explicit list. The umbrella pkm.h includes every other
#     header (incl. psb.h), so the whole set must be staged together; staging
#     pkm.h without psb.h leaves <pkm/pkm.h> unbuildable (an old-installer bug
#     this list fixes). ---
for h in pkm psb syscall sid sd token access file process kmes lcs; do
	install -m 0644 "$pkm/uapi/pkm/$h.h" "$uapi_dir/$h.h"
done

# --- Kconfig + Makefile fragments for security/pkm ---
install -m 0644 "$here/Kconfig"  "$pkm_dir/Kconfig"
install -m 0644 "$here/Makefile" "$pkm_dir/Makefile"

# --- in-kernel Ed25519 verifier sources (staged into crypto/) ---
install -m 0644 "$here/crypto/ed25519.c"       "$tree/crypto/ed25519.c"
install -m 0644 "$here/crypto/ed25519-hacl.c"  "$tree/crypto/ed25519-hacl.c"
install -m 0644 "$here/crypto/ed25519-hacl.h"  "$tree/crypto/ed25519-hacl.h"

# --- generated TCB built-in signing-key header (overwrites the copied stub) ---
genargs=(--pubkey-hex "$pubkey" --out "$pkm_dir/kacs/builtin_signing_keys.h")
[[ -z "$pubkey" ]] && genargs+=(--allow-empty)
python3 "$here/scripts/generate-kacs-builtin-signing-keys.py" "${genargs[@]}"

# --- Generated UAPI Rust constants, vendored as the in-kernel `peios_uapi`
#     module. The Rust cores reference `peios_uapi::<CONST>` as the single
#     source of truth for ABI values; stage-rust-core.sh rewrites those paths
#     to `crate::peios_uapi::` and kacs_rust.rs mounts this file as the module.
#     Only zconst.rs (constants) is needed — the cores use no generated types. ---
install -m 0644 "$pkm/uapi/generated/rust/src/zconst.rs" "$pkm_dir/kacs/peios_uapi.rs"

# --- Rust cores, path-rewritten for nested in-kernel module paths ---
"$here/stage-rust-core.sh" "$pkm/crates/kacs-core/src" "$pkm_dir/kacs/kacs_core"
"$here/stage-rust-core.sh" "$pkm/crates/lcs-core/src"  "$pkm_dir/lcs/lcs_core" lcs_core

echo "stage-sources: staged PKM sources into $tree"
