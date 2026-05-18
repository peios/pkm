#!/usr/bin/env bash
# Fast KUnit iteration build — runs *inside* the kunit base container.
#
# The hermetic `make kunit-kernel` target rebuilds the whole kernel in a
# fresh --rm container every run. This script instead builds in a persistent
# volume mounted at /build, so the kernel object tree survives between runs
# and `make` only recompiles what actually changed.
#
# install-pkm-subtree does two jobs: it stages the KACS sources into
# security/pkm (deterministically — safe to repeat) and it patches ~30
# existing kernel files in place. The in-place patching is NOT idempotent
# (its fs/proc/base.c hook re-appends on every run), so re-running it each
# iteration would corrupt the tree. The hermetic build dodges this by
# running it exactly once; here we do too:
#
#   * init run  — run install-pkm-subtree against the pristine base-image
#                 tree and snapshot the files it *modifies* (patch targets,
#                 told apart from files it *creates* by a pristine listing).
#   * later run — run it again for its deterministic security/pkm staging,
#                 then force-restore every patch target to that first,
#                 correct application so the non-idempotency cannot bite.
#
# Mtimes of unchanged staged sources are restored too, so `make` rebuilds
# only genuine edits instead of relinking vmlinux and every module.
set -euo pipefail

kernel=/build/linux
src=/pkm-src
out=/out
ref=/build/.pkm-fast-ref       # staged-source mirror (KACS/crypto), per-run
ref_init=/build/.pkm-fast-init # kernel patch-target snapshot, immutable
hashfile=/build/.pkm-fast-hash # install-pkm-subtree.sh hash captured at init

# Pin the inputs `mkcompile_h` bakes into include/generated/compile.h.
# Every `docker run` gets a fresh random hostname; without pinning, that
# alone changes compile.h and relinks vmlinux on an unchanged tree.
export KBUILD_BUILD_USER=pkm
export KBUILD_BUILD_HOST=pkm-kunit-fast
export KBUILD_BUILD_TIMESTAMP='2026-01-01 00:00:00 UTC'

cd "$kernel"

installer="$src/kernel/install-pkm-subtree.sh"
cur_hash=$(sha256sum "$installer" | cut -d' ' -f1)

# init when the build tree has no patch-target snapshot yet.
init=0
if [[ ! -d "$ref_init" ]]; then
	init=1
elif [[ "$(cat "$hashfile" 2>/dev/null)" != "$cur_hash" ]]; then
	echo "kunit-fast-build: install-pkm-subtree.sh changed since this build" >&2
	echo "  tree was initialised — its kernel patches may now differ. Run" >&2
	echo "  'make kunit-clean-fast' and retry to reinitialise from clean." >&2
	exit 1
fi

# On init, list the pristine tree so files install-pkm-subtree *modifies*
# (patch targets) can be told apart from files it *creates* (staged source).
pristine=
if (( init )); then
	pristine=$(mktemp)
	find . -type f > "$pristine"
fi

# 1. Snapshot the PKM subtree, objects included — staging `rm -rf`s
#    security/pkm, which would otherwise discard its compiled objects.
prev_pkm=
if [[ -d security/pkm ]]; then
	prev_pkm=$(mktemp -d)
	cp -a security/pkm/. "$prev_pkm/"
fi

# 2. Run install-pkm-subtree and capture every file it touched, by
#    timestamp — no hardcoded file list, so this cannot drift from it.
marker=$(mktemp)
PKM_KACS_TCB_PUBKEY_HEX="" PKM_KACS_ALLOW_EMPTY_TCB_PUBKEY=1 \
	bash "$installer" "$src" "$kernel"
mapfile -d '' -t touched < <(find . -newer "$marker" -type f -print0)
rm -f "$marker"

# 3a. Restore the PKM build artifacts (objects, .cmd, .d, built-in.a, ...)
#     staging deleted with security/pkm but did not regenerate. Excluding
#     source extensions means a source file deleted/renamed this iteration
#     is not resurrected; `cp -n` never clobbers freshly-staged source.
if [[ -n "$prev_pkm" ]]; then
	( cd "$prev_pkm" && find . -type f \
		! -name '*.c' ! -name '*.h' ! -name '*.rs' \
		! -name 'Kconfig' ! -name 'Makefile' \
		-exec cp -an --parents '{}' "$kernel/security/pkm/" ';' )
	rm -rf "$prev_pkm"
fi

if (( init )); then
	# 3b. Partition touched files: those that pre-existed are patch targets
	#     (snapshot immutably); the rest are staged sources (per-run mirror).
	mkdir -p "$ref" "$ref_init"
	for f in "${touched[@]}"; do
		rel=${f#./}
		if grep -qxF "$f" "$pristine"; then
			dst=$ref_init
		else
			dst=$ref
		fi
		mkdir -p "$dst/$(dirname "$rel")"
		cp -a "$f" "$dst/$rel"
	done
	rm -f "$pristine"
	echo "$cur_hash" > "$hashfile"

	# 3b'. Enable PKM + KUnit config — init only. .config then persists in
	#      the build-tree volume; rewriting it every run churns its mtime
	#      and forces a syncconfig pass. X86_DECODER_SELFTEST decodes ~7.6M
	#      instructions on every build — skip it for the fast loop; it
	#      exercises the kernel's instruction decoder, not KACS/KUnit.
	scripts/config --enable SECURITY_PKM
	scripts/config --set-str LSM "landlock,lockdown,yama,integrity,pkm"
	scripts/config --enable KUNIT
	scripts/config --enable SECURITY_PKM_KUNIT
	scripts/config --disable X86_DECODER_SELFTEST
	make LLVM=1 olddefconfig
else
	# 3c. Force-restore patch targets to their canonical init application
	#     (content + mtime); restore staged-source mtimes when byte-identical
	#     to the last run so `make` skips them.
	for f in "${touched[@]}"; do
		rel=${f#./}
		if [[ -e "$ref_init/$rel" ]]; then
			cp -a "$ref_init/$rel" "$f"
		elif [[ -f "$ref/$rel" ]] && cmp -s "$f" "$ref/$rel"; then
			touch -r "$ref/$rel" "$f"
		fi
	done
	# 3d. Refresh the staged-source mirror for next run's mtime compare.
	rm -rf "$ref"
	for f in "${touched[@]}"; do
		rel=${f#./}
		[[ -e "$ref_init/$rel" ]] && continue
		mkdir -p "$ref/$(dirname "$rel")"
		cp -a "$f" "$ref/$rel"
	done
fi

# 3e. Validate patch-target output in the generated kernel tree. This catches
#     drift in non-idempotent kernel-file patches after the installer or the
#     base Linux source changes.
bash "$src/kernel/verify-generated-tree.sh" "$kernel"
bash "$src/kernel/verify-kernel-config.sh" "$kernel/.config"

# 4. Incremental build.
make LLVM=1 CC="ccache clang" -j"$(nproc)"
cp arch/x86/boot/bzImage "$out/"
cp .config "$out/kernel.config"

echo ""
echo "kunit-fast-build: bzImage -> $out/bzImage"
echo "kunit-fast-build: .config -> $out/kernel.config"
