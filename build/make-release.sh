#!/usr/bin/env bash
# REFERENCE ONLY — not wired into the pekit pipeline. Pre-rewrite snapshot of
# the old Makefile-driven release staging, kept for the manifest.json schema +
# provenance logic. To be rewritten as a `build.release` pekit stage alongside
# real TCB-key signing once pekit keyrings land. The $OUT/$DOCKERFILE env
# interface below is from the old flow and no longer matches the layout.
#
# Stage a pkm kernel release into $RELEASE from an already-built kernel in $OUT.
#
# This does NOT publish anything. It assembles the handoff contract that the
# Peios build farm consumes from a GitHub Release: the bzImage payload plus a
# manifest.json describing version + provenance so the farm can package it into
# a .peipkg without inferring anything. Cutting the git tag and uploading the
# release/ contents to GitHub is a separate, deliberate step done by a human.
#
# Inputs (env): VERSION OUT RELEASE DOCKERFILE PKM_ROOT
set -euo pipefail

: "${VERSION:?VERSION is required (e.g. v0.20.0-alpha2)}"
: "${OUT:?OUT is required (the kernel build output dir)}"
: "${RELEASE:?RELEASE is required (the staging output dir)}"
: "${DOCKERFILE:?DOCKERFILE is required}"
: "${PKM_ROOT:?PKM_ROOT is required (the pkm repo root)}"

bzimage="$OUT/bzImage"
config="$OUT/kernel.config"
sysmap="$OUT/System.map"
arch_base="$PKM_ROOT/kernel/config.x86_64.base"

for f in "$bzimage" "$config"; do
	[[ -f "$f" ]] || { echo "missing build artifact: $f — run 'make kernel' first" >&2; exit 1; }
done
if [[ ! -f "$sysmap" ]]; then
	echo "missing $sysmap — rebuild the kernel with 'make kernel' to capture System.map" >&2
	exit 1
fi

sha256() { sha256sum "$1" | cut -d' ' -f1; }
size()   { stat -c%s "$1"; }

# Provenance parsed from the (single-source-of-truth) Dockerfile.
kernel_base=$(grep -oE 'KERNEL_VERSION=v[0-9.]+' "$DOCKERFILE" | head -1 | cut -d= -f2)
arch_commit=$(grep -oE '[0-9a-f]{40}' "$DOCKERFILE" | head -1)
rust_ver=$(grep -oE 'toolchain install [0-9]+\.[0-9]+\.[0-9]+' "$DOCKERFILE" | grep -oE '[0-9.]+' | head -1)
llvm_ver=$(grep -oE 'clang[0-9]+' "$DOCKERFILE" | head -1 | grep -oE '[0-9]+')
arch_cfg_sha256=$(sha256 "$arch_base")

pkm_commit=$(git -C "$PKM_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
if [[ -n "$(git -C "$PKM_ROOT" status --porcelain 2>/dev/null)" ]]; then
	pkm_dirty=true
else
	pkm_dirty=false
fi

# Stage artifacts.
rm -rf "$RELEASE"
mkdir -p "$RELEASE"
install -m 0644 "$bzimage" "$RELEASE/bzImage"
install -m 0644 "$config"  "$RELEASE/config"
install -m 0644 "$sysmap"  "$RELEASE/System.map"

built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

cat > "$RELEASE/manifest.json" <<EOF
{
  "schema_version": 1,
  "name": "kernel",
  "version": "$VERSION",
  "description": "Peios kernel (Linux $kernel_base base + PKM)",
  "kernel_base": "$kernel_base",
  "source": {
    "pkm_repo": "https://github.com/peios/pkm",
    "pkm_commit": "$pkm_commit",
    "pkm_dirty": $pkm_dirty
  },
  "base_config": {
    "origin": "archlinux/packaging/packages/linux",
    "commit": "$arch_commit",
    "sha256": "$arch_cfg_sha256"
  },
  "toolchain": {
    "rust": "$rust_ver",
    "llvm": "$llvm_ver"
  },
  "modules": "none (monolithic; all drivers built-in for v1)",
  "artifacts": {
    "bzImage": { "sha256": "$(sha256 "$RELEASE/bzImage")", "size": $(size "$RELEASE/bzImage") },
    "config": { "sha256": "$(sha256 "$RELEASE/config")", "size": $(size "$RELEASE/config") },
    "System.map": { "sha256": "$(sha256 "$RELEASE/System.map")", "size": $(size "$RELEASE/System.map") }
  },
  "built_at": "$built_at"
}
EOF

if [[ "$pkm_dirty" == "true" ]]; then
	echo "WARNING: pkm working tree is dirty — manifest records pkm_dirty=true." >&2
	echo "         A real release should be cut from a clean, committed tree." >&2
fi

echo ""
echo "Staged release for $VERSION → $RELEASE"
echo "  (not published — upload these to a GitHub Release manually)"
echo ""
ls -l "$RELEASE"
