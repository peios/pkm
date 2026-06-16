# pkm

`pkm` is the Peios kernel workspace. It stages the PKM security subtree into a
pinned Linux kernel build and carries the slow-track KACS implementation plus
the KMES event substrate used by KACS and userspace tooling.

## Source Layout

- `uapi/pkm/` contains the canonical PKM UAPI: the C headers are the single
  source of truth for every PKM ABI shape. The language bindings under
  `uapi/generated/{go,lua,rust}/` are mechanically generated from these headers
  by each directory's `gen.sh`, kept in sync by the codegen-drift gate, and
  must never be edited by hand.
- `kacs/` contains KACS kernel glue, token/process/file enforcement, KUnit
  tests, Rust ingress, and KACS-specific KMES payload emission.
- `kmes/` contains the standalone KMES runtime, public KMES header, and
  syscall-side event validator.
- `lcs/` contains LCS kernel glue: the registry source device, key/transaction
  fds, RSI bridge, and KUnit tests.
- `crates/kacs-core/` contains the pure Rust KACS semantic core used by the
  kernel Rust module.
- `crates/lcs-core/` contains the pure Rust LCS semantic core used by the
  kernel Rust module.
- `regman/` contains the regman fragments documenting the registry knobs the
  PKM kernel reads.
- `kernel/` contains the Dockerized kernel build, subtree installer, generated
  tree verifiers, and KUnit smoke harness.
- `kernel/crypto/` contains the in-kernel Ed25519 implementation staged for
  KACS signing support.

The normative KACS, KMES, and LCS specs live outside this repo under
`../learn/specs/`.

## Build Flow

The build runs through [pekit](../pekit); `env.pekit.toml` transparently runs
every stage inside the pinned toolchain image, so you only ever call `pekit`.

Build the toolchain image once (it rebuilds only when `build/toolchain.lock`
changes):

```sh
build/build-image.sh                 # -> image `pkm-build`
```

Then drive the pipeline — each stage's output lands in `out/build/<stage>/`:

```sh
pekit build upstream                 # clone the pinned kernel (build/toolchain.lock)
pekit build source                   # apply kernel/patches + stage PKM sources
pekit build kunit                    # configure(kunit) + compile -> bzImage
pekit test  kunit                    # boot in QEMU, assert the KUnit suite passes
pekit build kernel                   # production-config bzImage (see key note below)
```

`--no-build=upstream[,source,...]` reuses prior stage outputs; `--env kvm` runs
QEMU with `/dev/kvm` (the default falls back to TCG, so it stays portable).

`build.source` is config-agnostic — it is the shippable kernel-source package.
`build.kernel`/`build.kunit` take it, configure for a profile, and compile a
monolithic (all-built-in) bzImage. The production TCB signing key is not yet
injected (pending pekit keyrings); `build.kernel` currently uses an allow-empty
placeholder key.

## How PKM grafts into the kernel

`kernel/patches/` is a named, feature-split patch series (`series` sets apply
order) covering every edit to pre-existing Linux files; `kernel/stage-sources.sh`
adds the new files (the `security/pkm` subtree, UAPI headers, Ed25519 sources,
the path-rewritten Rust cores, the generated signing-key header).

`kernel/apply-patches.sh` is the gate: a patch applies cleanly or fails loudly
(it refuses a non-kernel target and treats a skipped patch as an error), which
is why the old white-box `verify-scaffold`/`verify-generated-tree` checks are
gone — `make LLVM=-18` plus the KUnit suite then prove the tree actually builds
and behaves. `build/configure-kernel.sh` still runs
`kernel/verify-kernel-config.sh`, which asserts the `.config` security
invariants (sole-MAC LSM order, `STRICT_DEVMEM`, `MODULE_SIG_FORCE`) — those are
covered by neither the patches nor the compile.

Do not edit `out/` trees by hand. Change the source, patch series, or config
fragment, then re-run the relevant `pekit` stage.

## Notes

- The build image is `pkm-build`; ccache persists in the `pkm-ccache` volume.
- A `test.boot` stage (boot the production kernel, assert init) is a future
  addition, modeled on `build/test-kunit.sh`, once a real initrd is wired
  (provium territory).
- Release packaging (`manifest.json`) is pending: `build/make-release.sh` is the
  pre-rewrite reference, to become a `build.release` stage alongside TCB-key
  signing once pekit keyrings land.
