# pkm-new

`pkm-new` is the clean slow-track KACS workspace.

It intentionally preserves only the build plumbing needed to stage a fresh
PKM/KACS subtree into a pinned Linux kernel build. It does not preserve any
inherited KACS semantics, syscall ABI wiring, event transport, or fast-track
kernel patching.

## Current State

- The KACS normative source is the ratified spec under
  `learn/content/kacs/v0.20/`.
- The `crates/kacs-core/src/` tree contains the closed pure-core slow-track
  implementation slices.
- The `kacs/` subtree currently contains only an inert kernel-resident
  scaffold: enough to compile into the pinned kernel image and prove a minimal
  boot-time init path, but no live KACS semantics yet.
- No inherited syscall-table mutation is present.
- No inherited kernel patchset is present.
- No inherited event subsystem implementation is present.

## What Remains On Purpose

- A pinned Dockerized kernel build in [kernel/Dockerfile](kernel/Dockerfile)
- A host-side build entry point in [kernel/Makefile](kernel/Makefile)
- A small PKM subtree installer in
  [kernel/install-pkm-subtree.sh](kernel/install-pkm-subtree.sh)
- A Rust source staging helper in
  [kernel/stage-kacs-core.sh](kernel/stage-kacs-core.sh)
- A scaffold verifier in
  [kernel/verify-scaffold.sh](kernel/verify-scaffold.sh)
- Kernel subtree metadata in [pkm_kconfig](pkm_kconfig) and
  [pkm_makefile](pkm_makefile)

## Build Flow

1. `make -C kernel verify-scaffold`
2. `make -C kernel image`
3. `make -C kernel kernel`

For PKM-owned KUnit smoke infrastructure:

1. `make -C kernel kunit-image`
2. `make -C kernel kunit-kernel`
3. `make -C kernel kunit-smoke`

The Docker image clones the pinned kernel version, configures the toolchain,
stages the PKM subtree from this repo, enables `SECURITY_PKM`, and builds the
kernel. The image does not inject syscall registrations or apply any external
patches.

### Fast KUnit iteration loop

`kunit-kernel` rebuilds the whole kernel from scratch in a fresh container on
every run. For tight iteration on KACS/KUnit sources, use the `-fast` variants:

1. `make -C kernel kunit-smoke-fast`

This builds the kernel in a persistent Docker volume (`pkm-new-kunit-buildtree`)
so only changed objects recompile, and stages PKM source at runtime instead of
rebuilding the Docker image. It is **non-hermetic** — use `kunit-smoke` for
trustworthy or CI results, `kunit-smoke-fast` for the dev loop.

Run `make -C kernel kunit-clean-fast` to discard the persistent build tree.
That is needed only after bumping the kernel version or toolchain, or if a fast
build fails in a way unrelated to your change; ordinary source edits never
require it.

## Deliberate Omissions

The following must be reintroduced only when their spec-driven implementation
slice is opened:

- syscall registration
- ioctl/ABI registration
- event transport
- kernel patchset changes
- live KACS policy or AccessCheck semantics

Until then, this tree should remain obviously scaffold-only.
