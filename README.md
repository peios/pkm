# pkm — Peios Kernel Module

`pkm` is the Peios kernel workspace. It carries the PKM security subsystem
(KACS, KMES, LCS) and a declarative, reproducible build pipeline that grafts
that subsystem onto a pinned upstream Linux tree, compiles a hardened monolithic
kernel, and emits the full Peios kernel package family (`.peipkg`) — the kernel
image, its development/debug artifacts, and the in-tree userspace tooling.

The build is driven entirely by [pekit](../pekit) and runs inside a pinned,
snapshot-reproducible container image, so a checkout plus Docker is the only
prerequisite.

- **Kernel base:** Linux `v7.0.9` (pinned in `build/toolchain.lock`).
- **Profile:** monolithic — every driver built in (`=y`), no loadable modules.
- **Target:** `x86_64` (QEMU/virtio guest profile).
- **Security model:** KACS is the sole MAC LSM; `CONFIG_LSM="landlock,lockdown,yama,integrity,pkm"`.

> The normative KACS / KMES / LCS specifications live outside this repo under
> `../learn/specs/`. This README documents the implementation and its build,
> not the specs.

---

## Table of contents

- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Build pipeline](#build-pipeline)
- [How PKM grafts into the kernel](#how-pkm-grafts-into-the-kernel)
- [TCB signing keyring](#tcb-signing-keyring)
- [Packaging](#packaging)
- [UAPI and language bindings](#uapi-and-language-bindings)
- [Testing](#testing)
- [Reproducibility](#reproducibility)
- [Conventions](#conventions)
- [Known limitations & roadmap](#known-limitations--roadmap)

---

## Architecture

PKM is a security subsystem that lives inside the kernel as the `security/pkm`
LSM, backed by pure-Rust semantic cores and a canonical C UAPI:

- **KACS** — the access-control system: token / process / file enforcement,
  Rust ingress, and KACS-specific KMES payload emission.
- **KMES** — the event substrate: a standalone runtime plus a syscall-side event
  validator, used by KACS and by userspace.
- **LCS** — the registry source device, key / transaction fds, and the RSI
  bridge.
- **Rust cores** (`crates/kacs-core`, `crates/lcs-core`) — the pure,
  `no_std`-friendly semantic cores. They are vendored into the kernel as
  path-rewritten in-tree Rust modules at stage time (the kernel builds them with
  its own Kbuild Rust toolchain; there is no cargo step in the kernel build).
- **UAPI** (`uapi/pkm`) — the canonical C headers: the single source of truth
  for every PKM ABI shape, from which all language bindings are generated.

The signing trust anchor (the **TCB** key) is embedded into the kernel at build
time and is supplied by the build environment, never committed — see
[TCB signing keyring](#tcb-signing-keyring).

---

## Repository layout

### Source

| Path | Contents |
|---|---|
| `uapi/pkm/` | **Canonical** PKM UAPI C headers — the single source of truth for every ABI shape. |
| `uapi/generated/{go,lua,rust}/` | Bindings mechanically generated from `uapi/pkm` by each dir's `gen.sh`. Never hand-edited; kept honest by the drift gate. |
| `kacs/` | KACS kernel glue: token/process/file enforcement, Rust ingress, KMES payload emission, KUnit tests. |
| `kmes/` | Standalone KMES runtime, public KMES header, syscall-side event validator. |
| `lcs/` | LCS kernel glue: registry source device, key/transaction fds, RSI bridge, KUnit tests. |
| `crates/kacs-core/` | Pure-Rust KACS semantic core (consumed by the kernel Rust module). |
| `crates/lcs-core/` | Pure-Rust LCS semantic core (consumed by the kernel Rust module). |
| `kernel/` | The graft: patch series, source-staging scripts, in-kernel Ed25519 crypto, config verifier. |
| `regman/` | regman fragments documenting the registry knobs the PKM kernel reads. |
| `tools/` | Peios-side helper tooling (e.g. `tools/lcs`). Distinct from the *kernel's* `tools/`, which is packaged separately — see [Packaging](#packaging). |

### Build & packaging

| Path | Contents |
|---|---|
| `pekit.toml` | The build pipeline: every `[build.*]` / `[test.*]` stage. |
| `build/toolchain.lock` | Single source of truth for all pins (kernel tag, base image, snapshot date, LLVM/Rust/bindgen versions). |
| `build/Containerfile` | The pinned, reproducible toolchain image (`pkm-build`). |
| `build/build-image.sh` | Builds the image from `toolchain.lock`. |
| `build/configure-kernel.sh` | Produces the `.config` for a profile, then asserts the security invariants. |
| `build/compile-kernel.sh` | `make LLVM=-18` with pinned `KBUILD_BUILD_*` for reproducibility. |
| `build/make-debuginfo.sh` | Splits `vmlinux` debug info + build-id index, sanitizes & stages debug sources. |
| `build/build-tools.sh` | Builds the in-tree userspace tools into a DESTDIR image. |
| `build/test-kunit.sh` | Boots the KUnit kernel in QEMU and asserts the suite passes. |
| `build/config/` | `config.x86_64.base`, `pkm.fragment`, `kunit.fragment`, `lsmod.txt`. |
| `env.pekit.toml` | The container `[wrap]` — runs every stage inside `pkm-build` rootless. |
| `kvm.env.pekit.toml` | `--env kvm` variant: adds `--device /dev/kvm` for accelerated QEMU. |
| `packages.pekit/package.pekit.toml` | Base package metadata, inherited by every member. |
| `packages.pekit/<name>.package.pekit.toml` | Per-package `[files]` maps for the kernel family + userspace tools. |
| `*.keyring.pekit.toml` | Per-developer/environment TCB keyrings (gitignored — never committed). |

Build outputs land in `out/build/<stage>/` and packages in
`out/package/<name>/`. **`out/` is generated — never edit it by hand.**

---

## Prerequisites

- **Docker** (rootless-capable; the user must be able to run `docker`).
- **[pekit](../pekit)** on `PATH`.
- A POSIX shell. The kernel C/Rust toolchain, QEMU, and every build dependency
  live *inside* the image — nothing else is required on the host.

KVM is optional: `test.kunit` uses `-machine accel=kvm:tcg` and falls back to
TCG, so the default flow is portable. Use `--env kvm` to force acceleration.

---

## Quick start

```sh
# 1. Build the toolchain image once (rebuilds only when toolchain.lock changes).
build/build-image.sh                      # -> image `pkm-build`

# 2. Fetch + graft the source (config-agnostic; this is the kernel-source tree).
pekit build upstream                      # clone the pinned kernel
pekit build source                        # apply kernel/patches + stage PKM sources

# 3. Build + boot-test the KUnit kernel.
pekit build kunit  --no-build=upstream,source
pekit test  kunit  --no-build=upstream,source     # QEMU boot, assert the suite

# 4. Build the production kernel with the TCB key injected from a keyring.
pekit build kernel --keyring=dev --no-build=upstream,source

# 5. Derived artifacts.
pekit build headers   --no-build=upstream,source
pekit build debuginfo --keyring=dev --no-build=upstream,source,kernel
pekit build tools     --no-build=upstream,source

# 6. Package (Peios version is independent of the kernel release — see Packaging).
pekit package kernel --version 0.20.0 --no-build=…
```

`--no-build=<stages>` reuses already-built stage outputs instead of rebuilding
them — pass the upstream stages you want to keep.

---

## Build pipeline

Every stage's command runs inside `pkm-build` (via `env.pekit.toml`), reads its
dependencies' outputs as `$PEKIT_<NEED>_OUT`, and writes to `$PEKIT_OUT`
(`out/build/<stage>/`).

| Stage | Needs | Produces |
|---|---|---|
| `build.upstream` | — | A shallow clone of the pinned `v7.0.9` tree. |
| `build.source` | `upstream` | The grafted, **config-agnostic** kernel source (patches applied, PKM sources staged, `.git` stripped). This is the shippable kernel-source tree. |
| `build.kunit` | `source` | KUnit-config monolithic `bzImage` (for the boot test). |
| `build.kernel` | `source` | Production-config monolithic `bzImage`, with the TCB key embedded. |
| `build.headers` | `source` | Sanitized userspace UAPI (`make headers_install`). |
| `build.debuginfo` | `kernel` | `vmlinux` debug info + build-id index, plus path-sanitized debug sources. |
| `build.tools` | `source` | The in-tree userspace tools (perf, bpftool, …) as a DESTDIR image. |
| `test.kunit` | `kunit` | Boots in QEMU; asserts the KUnit suite passes (build/run split). |
| `build.uapi` | — | Regenerates `uapi/generated/**` in place from `uapi/pkm`. |
| `test.uapi` | — | Drift gate: headers compile standalone **and** committed bindings == fresh regen. |

`build.kernel` and `build.kunit` each take the config-agnostic `build.source`
tree, configure it for their profile via `build/configure-kernel.sh`, and
compile. The config flow is: `config.x86_64.base` → `olddefconfig` →
`localmodconfig` (`lsmod.txt`) → merge `pkm.fragment` (+ `kunit.fragment` for the
KUnit profile) → `olddefconfig` → `mod2yesconfig` (last, to force the monolithic
profile) → `verify-kernel-config.sh`.

---

## How PKM grafts into the kernel

The graft is split into two halves so each is verifiable:

- **Edits to existing Linux files** live in `kernel/patches/` — a named,
  feature-split patch series (`series` sets apply order). `kernel/apply-patches.sh`
  is the gate: each patch applies cleanly or **fails loudly** (it refuses a
  non-kernel target and treats a "skipped" patch as an error).
- **New files** are added by `kernel/stage-sources.sh`: the `security/pkm`
  subtree, the UAPI headers, the in-kernel Ed25519 sources (`kernel/crypto/`),
  the path-rewritten Rust cores (`kernel/stage-rust-core.sh`), and the generated
  signing-key header.

There are no white-box "did the tree get staged correctly" checks — a clean
`make LLVM=-18` plus the KUnit suite prove the tree actually builds and behaves.
The one thing neither the patches nor the compile cover is the set of `.config`
security invariants, so `build/configure-kernel.sh` runs
`kernel/verify-kernel-config.sh`, which asserts them (sole-MAC LSM order,
`STRICT_DEVMEM`, `MODULE_SIG_FORCE`, …).

---

## TCB signing keyring

`build.kernel` embeds the TCB (trusted compute base) public key into the kernel
as the KACS built-in signing anchor. The key is supplied by a **keyring** file,
never committed:

```sh
pekit build kernel --keyring=dev          # loads dev.keyring.pekit.toml
```

A keyring's `[tcb]` table is flattened into the stage environment:

- `pub`  → `$PEKIT_KEYRING_TCB_PUB`  — the hex pubkey, embedded by `build.kernel`.
- `priv` → `$PEKIT_KEYRING_TCB_PRIV` — path to the signing key (for signing).

`*.keyring.pekit.toml` is gitignored. Generate a local dev key with:

```sh
openssl genpkey -algorithm ed25519 -out kacs-tcb-dev.key
```

The production build farm holds the real TCB key and injects it the same way;
this decoupling is why the build environment is the swappable "provider" and the
pipeline itself stays key-agnostic.

---

## Packaging

Packaging is driven by `pekit package <name> --version <v>`, producing a
`.peipkg` per package under `out/package/<name>/`. Each package is described by
`packages.pekit/<name>.package.pekit.toml` (a `[files]` map of
`"<stage>:<glob>" = "<dest>"`) inheriting base metadata from
`packages.pekit/package.pekit.toml`. pekit discovers packages in the repo root
and in the `package.pekit/` / `packages.pekit/` subdirectories.

### Versioning

The **kernel release** (`7.0.9`, the `uname` version, used in install paths) is
the clean upstream base. The **Peios package version** is independent and
supplied at package time via `--version` (SemVer'd against the PKM UAPI / KACS
ABI). They are deliberately separate: the base is provenance, the package
version is Peios's.

### Layout policy (PSD-009)

The `.peipkg` format enforces a strict install layout (`peipkg` §3.4): a fixed
set of permitted top-level destinations, and everything arch-specific under the
multiarch triplet `usr/lib/x86_64-linux-peios/`. Consequences visible here:
helper trees (e.g. perf-core) and all shared libraries live under the triplet;
there is no `sbin` (bin-only); `usr/src` is reserved for debug sources. Library
packages are split `lib*` / `lib*-devel` per convention.

### The package family

**Kernel (5):**

| Package | Contents |
|---|---|
| `kernel` | The bootable monolithic `bzImage` + `System.map` + `.config`. |
| `kernel-headers` | Sanitized userspace UAPI (`usr/include`). |
| `kernel-devel` | Out-of-tree module build kit under `usr/lib/<triplet>/modules/<release>/build`. |
| `kernel-debuginfo` | `vmlinux` debug info + build-id index. |
| `kernel-debugsource` | The DWARF-referenced kernel sources. |

> `kernel-modules` is intentionally absent — the kernel is monolithic, so there
> is nothing to split until a non-monolithic build exists.

**Userspace tools** (built from the kernel's in-tree `tools/`, packaged with
unprefixed names since they are userspace, not the kernel): `perf` (+ `perf-devel`,
`libperf`, `libperf-devel`, `python3-perf`), `bpftool`, `cpupower` (+ `cpupower-libs`,
`cpupower-libs-devel`), `turbostat`, `rtla`, `rv`, `x86_energy_perf_policy`,
`intel-speed-select`, `amd_pstate_tracer`, `intel_pstate_tracer`, `gpio-utils`,
`iio-utils`, `spi-utils`, `bootconfig`, `tmon`, `latency-collector`, `mm-tools`,
`freefall`, `cgroup-tools`, `usbip` (+ `usbip-devel`), `getdelays`, `hv`,
`kvm_stat`, `thermal-engine`, `thermometer`, `libthermal` (+ `libthermal-devel`,
`libthermal-tools`).

These build from the *same* staged source as the kernel (`build.tools` →
`needs = source`), so they share one pipeline rather than a separate one; only
their extra userspace build dependencies live in the image, unused by
`build.kernel`. Each package's `.toml` records its runtime shared-library
dependencies as a comment (to become real `[dependencies]` once the Peios
userspace layer that provides those libraries exists).

> **`python3-perf` caveat:** the `perf.so` it ships is ABI-bound to the build
> image's CPython (its `cpython-3xx` tag), so it installs but will not import on
> a Peios machine until rebuilt against the Peios interpreter. This is the same
> "built against image userspace, rebuild against Peios userspace" status the
> whole tools family shares.

Excluded by design (as upstream distros also do): in-tree *test* programs and
API *examples* (`testusb`, `pcitest`, `vringh_test`, `rtctest`, the `*_example`
programs, …) and `tools/testing/selftests`.

---

## UAPI and language bindings

`uapi/pkm/*.h` is the canonical ABI. The bindings under
`uapi/generated/{go,lua,rust}/` are mechanically regenerated from it:

```sh
pekit build uapi          # regenerate uapi/generated/** in place
pekit test  uapi          # drift gate (see below)
```

`build.uapi` runs each binding's `gen.sh` (each runs a codegen-safety lint
first). `test.uapi` is the matching gate: it asserts the canonical headers
compile standalone with a stock userspace compiler (`check-userspace-clean.sh`)
**and** that the committed bindings exactly match a fresh regen (diffed in a
throwaway copy — it never mutates the tree). The generated Rust crate
(`peios-uapi`, a Cargo workspace member) and the Go/Lua bindings must never be
hand-edited.

---

## Testing

- **`pekit test kunit`** — boots the KUnit-config kernel in QEMU and asserts the
  in-kernel KUnit suite passes (it persists the QEMU log and checks for the pass
  marker + a `pass:N fail:0` summary). `PKM_KUNIT_FILTER` narrows the suite.
- **`pekit test uapi`** — the UAPI drift / standalone-compile gate described
  above.

---

## Reproducibility

The toolchain image is built purely from pins in `build/toolchain.lock`, so the
same checkout yields the same image:

| Pin | Value |
|---|---|
| Kernel | `v7.0.9` |
| Base image | `debian:trixie` by digest |
| apt snapshot | `snapshot.debian.org` @ `20260610T000000Z` (all three suites) |
| LLVM | `18` (kernel builds `LLVM=-18`) |
| Rust | `1.83.0` (kernel Kbuild toolchain) |
| bindgen | `0.65.1` |

The image is a pure toolchain — it carries no kernel or PKM source; those arrive
via the mounted working tree, and `pekit` is bind-mounted at runtime. The
container runs rootless (`--user`, Rust in world-readable `/opt`), so build
outputs are owned by the host user. ccache persists across runs in the
`pkm-ccache` volume. `build.source` strips `.git` so the staged tree is not
git-dirty, keeping the kernel release a clean `7.0.9`. `compile-kernel.sh` pins
`KBUILD_BUILD_USER/HOST/TIMESTAMP`.

This image decoupling is the stepping stone to Peios self-hosting the kernel
build: the `pekit.toml` is environment-agnostic, and the container is the
swappable provider.

---

## Conventions

- **Never edit `out/`.** Change the source, the patch series, or a config
  fragment, then re-run the relevant `pekit` stage.
- **Never hand-edit `uapi/generated/**`.** Edit `uapi/pkm` and run
  `pekit build uapi`; `pekit test uapi` enforces this.
- **The patch series is the contract for existing-file edits.** New files go
  through `stage-sources.sh`. A patch that does not apply cleanly is a hard
  failure, by design.
- **Keyrings are never committed.** `*.keyring.pekit.toml` and key material are
  gitignored; the environment provides the TCB key.
- **`build.source` is config-agnostic.** Profile selection (production vs KUnit)
  happens only in the kernel/kunit stages.

### Git hooks

A tracked **pre-push** hook (`.githooks/pre-push`) runs the UAPI drift gate
(`pekit test uapi`) before a push, but only when a pushed commit touches `uapi/`.
It is read-only (regenerates into a throwaway copy) and needs the `pkm-build`
container. Enable it once per clone:

```sh
git config core.hooksPath .githooks
```

Bypass deliberately with `git push --no-verify`. This is local fast-feedback —
the authoritative gate is `pekit test uapi` in CI.

---

## Known limitations & roadmap

- **`kernel-modules`** — blocked on a non-monolithic kernel build; the current
  profile builds everything in.
- **Runtime package dependencies** — the userspace tool packages declare their
  shared-library needs only as `.toml` comments today; they become real
  `[dependencies]` once the Peios userspace layer that provides those libraries
  is built out.
- **`python3-perf`** — ships, but its `perf.so` must be rebuilt against the
  Peios CPython to import (ABI-bound to the build image's interpreter).
- **`test.boot`** — booting the production kernel and asserting init is a future
  stage (modeled on `test.kunit`) once a real initrd is wired.
