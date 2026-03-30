# pkm-new

`pkm-new` is the clean slow-track KACS workspace.

It intentionally preserves only the build plumbing needed to stage a fresh
PKM/KACS subtree into a pinned Linux kernel build. It does not preserve any
inherited KACS semantics, syscall ABI wiring, event transport, or fast-track
kernel patching.

## Current State

- The KACS normative source is the ratified spec under
  `learn/content/kacs/v0.20/`.
- The source files in `kacs/` and `crates/kacs-core/src/` are scaffolds only.
- No KACS behavior is implemented yet.
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

The Docker image clones the pinned kernel version, configures the toolchain,
stages the PKM subtree from this repo, enables `SECURITY_PKM`, and builds the
kernel. The image does not inject syscall registrations or apply any external
patches.

## Deliberate Omissions

The following must be reintroduced only when their spec-driven implementation
slice is opened:

- syscall registration
- ioctl/ABI registration
- event transport
- kernel patchset changes
- KACS policy or AccessCheck semantics

Until then, this tree should remain obviously scaffold-only.
