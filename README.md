# pkm

`pkm` is the Peios kernel workspace. It stages the PKM security subtree into a
pinned Linux kernel build and carries the slow-track KACS implementation plus
the KMES event substrate used by KACS and userspace tooling.

## Source Layout

- `kacs/` contains KACS kernel glue, token/process/file enforcement, KUnit
  tests, Rust ingress, and KACS-specific KMES payload emission.
- `kmes/` contains the standalone KMES runtime, public KMES header, and
  syscall-side event validator.
- `crates/kacs-core/` contains the pure Rust KACS semantic core used by the
  kernel Rust module.
- `crates/peios-uapi/` contains userspace Rust bindings for PKM UAPI shapes.
- `crates/libp-*` contains early userspace/test clients for the PKM ABI.
- `kernel/` contains the Dockerized kernel build, subtree installer, generated
  tree verifiers, and KUnit smoke harness.
- `kernel/crypto/` contains the in-kernel Ed25519 implementation staged for
  KACS signing support.

The normative KACS and KMES specs live outside this repo under
`../learn/specs/psd-004--kacs/` and `../learn/specs/psd-003--kmes/`.
For KACS behavior changes, follow the top-level `AGENTS.md` and
`KACS_IMPLEMENTATION_CONTRACT.md` workflow before editing code.

## Build Flow

Run scaffold verification before kernel builds:

```sh
make -C kernel verify-scaffold
```

Non-KUnit kernel builds require a TCB public key:

```sh
PKM_KACS_TCB_PUBKEY_HEX=<hex-encoded-ed25519-public-key> make -C kernel kernel
```

The build writes:

- `kernel/out/bzImage`
- `kernel/out/kernel.config`
- `kernel/out/lib/modules/`

The Docker build clones the pinned kernel version, stages PKM into
`security/pkm`, enables `SECURITY_PKM`, verifies generated kernel patches and
required hardening config, then builds the kernel and modules.

## KUnit

For a hermetic KUnit smoke run:

```sh
make -C kernel kunit-smoke
```

For normal development iteration:

```sh
make -C kernel kunit-smoke-fast
```

The fast path keeps an incremental kernel build tree in the Docker volume
`pkm-new-kunit-buildtree` and stages PKM source at runtime. It is intended for
the inner dev loop. Use `kunit-smoke` for a clean trust boundary or CI-style
result.

If the fast build reports that staged scripts or generated-patch inputs changed,
reset the persistent build tree:

```sh
make -C kernel kunit-clean-fast
```

## Build Hygiene

The scaffold and generated-tree gates are part of the contract:

- `kernel/verify-scaffold.sh` checks that required PKM source files and init
  ordering are present before staging.
- `kernel/install-pkm-subtree.sh` installs this repo's PKM files into the
  kernel tree.
- `kernel/verify-generated-tree.sh` checks that generated Linux call-site
  patches are present.
- `kernel/verify-kernel-config.sh` checks required KACS/PIP hardening options.

Do not edit generated kernel output directly. Update the source, installer, or
generator scripts, then rerun the relevant verification gate.

## Notes

The Docker image and volume names still use the historical `pkm-new-*` prefixes.
Those names are build-cache identifiers only; the active workspace is `pkm`.
