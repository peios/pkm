FROM archlinux:latest AS base
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# Kernel build dependencies (C only — Rust via rustup, LLVM 18 pinned)
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
        base-devel \
        bc \
        cpio \
        git \
        inetutils \
        kmod \
        libelf \
        openssl \
        pahole \
        perl \
        python \
        xmlto \
        clang18 \
        llvm18 \
        lld18 \
        ccache \
    && pacman -Scc --noconfirm

# LLVM 18 tools live in /usr/lib/llvm18/bin/ on Arch
ENV PATH="/usr/lib/llvm18/bin:/root/.cargo/bin:${PATH}"

# Pinned kernel version — bump deliberately, not accidentally
ARG KERNEL_VERSION=v7.0.9

# Clone kernel source at the pinned version (shallow for speed)
RUN git clone --depth 1 --branch ${KERNEL_VERSION} \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \
    /build/linux

# Install Rust via rustup. Use 1.83.0: satisfies CALL_PADDING (>= 1.81),
# close enough to kernel 6.19's expected range, avoids bleeding-edge issues.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain none && \
    rustup toolchain install 1.83.0 --component rust-src && \
    rustup default 1.83.0

# Install the exact bindgen version the kernel requires
RUN BINDGEN_VERSION=$(/build/linux/scripts/min-tool-version.sh bindgen) && \
    echo "Kernel requires bindgen >= ${BINDGEN_VERSION}" && \
    cargo install --locked --version ${BINDGEN_VERSION} bindgen-cli

# Point bindgen at LLVM 18's libclang (not the system default)
ENV LIBCLANG_PATH="/usr/lib/llvm18/lib"

# Start from Arch's kernel config — VENDORED for reproducibility.
# Frozen from gitlab.archlinux.org archlinux/packaging/packages/linux at commit
# c2c442f4327a9ef6c6c7230bcb5efccdb05e6e9e (tag 7.0.10.arch1-1, 2026-05-23).
# Previously fetched from `main` at build time, which made the resulting kernel
# non-reproducible (Arch's config is a moving target). To refresh: re-fetch the
# raw config at a chosen commit, update this comment's SHA, and rebuild.
COPY kernel/config.x86_64.base /build/linux/.config

WORKDIR /build/linux

# Resolve new/removed config options against this kernel version
RUN make LLVM=1 olddefconfig

# Enable Rust support and verify the toolchain works
RUN make LLVM=1 rustavailable
RUN scripts/config --enable RUST
RUN make LLVM=1 olddefconfig

# Disable LSMs that conflict with KACS (§15.5)
RUN scripts/config \
        --disable SECURITY_SELINUX \
        --disable SECURITY_APPARMOR \
        --disable SECURITY_TOMOYO \
        --disable SECURITY_SMACK \
        --disable BPF_LSM \
        --set-str LSM "landlock,lockdown,yama,integrity" && \
    make LLVM=1 olddefconfig

# Strip to only modules a QEMU VM needs (fast builds)
COPY kernel/lsmod.txt /build/linux/lsmod.txt
RUN LSMOD=/build/linux/lsmod.txt make LLVM=1 localmodconfig

# Re-enable Rust (localmodconfig strips it since no stock module uses Rust)
RUN scripts/config --enable RUST && make LLVM=1 olddefconfig

# Provium requirements: force built-in (not =m modules)
RUN scripts/config \
        --set-val BLK_DEV_INITRD y \
        --set-val RD_GZIP y \
        --set-val NET_9P y \
        --set-val NET_9P_VIRTIO y \
        --set-val 9P_FS y \
        --set-val 9P_FS_POSIX_ACL y \
        --set-val VSOCKETS y \
        --set-val VIRTIO_VSOCKETS y \
        --set-val VHOST y \
        --set-val VHOST_VSOCK y \
        --set-val VIRTIO y \
        --set-val VIRTIO_PCI y \
        --set-val VIRTIO_MMIO y \
        --set-val VIRTIO_BLK y \
        --set-val VIRTIO_CONSOLE y \
        --set-val VIRTIO_NET y \
        --set-val DEVTMPFS y \
        --set-val DEVTMPFS_MOUNT y \
        --set-val TMPFS y \
        --set-val BLK_DEV_LOOP y \
        --set-val SQUASHFS y \
        --set-val OVERLAY_FS y \
        --set-val STRICT_DEVMEM y \
        --set-val MODULE_SIG y \
        --set-val MODULE_SIG_FORCE y \
        --set-val MODULE_SIG_ALL y \
        --set-val MODULE_SIG_SHA512 y \
        --set-str MODULE_SIG_KEY "certs/signing_key.pem" \
        --set-val VT y \
        --set-val VT_CONSOLE y \
        --set-val VGA_CONSOLE y \
        --set-val FRAMEBUFFER_CONSOLE y \
        --set-val DRM y \
        --set-val DRM_BOCHS y \
        --set-val SERIAL_8250 y \
        --set-val SERIAL_8250_CONSOLE y \
        --set-val ATA y \
        --set-val ATA_PIIX y \
        --set-val SATA_AHCI y \
        --set-val BLK_DEV_SR y \
        --set-val ISO9660_FS y \
        --set-val FAT_FS y \
        --set-val VFAT_FS y \
        --set-val NLS_ISO8859_1 y \
        --set-val SQUASHFS y \
        --set-val SQUASHFS_ZSTD y && \
    make LLVM=1 olddefconfig

# ccache: persistent cache via volume mount at /ccache
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=10G

# ─── base stage ends here ────────────────────────────────────────────────
# Everything above is independent of PKM source (toolchain, pinned kernel
# source, base kernel config). The `base` stage is the foundation for the
# fast KUnit iteration loop (make kunit-*-fast), which stages PKM source at
# runtime into a persistent build-tree volume rather than baking it into an
# image — keeping the kernel object tree incremental between runs.

# ─── pkm stage: bakes PKM source into the image (hermetic build path) ─────
FROM base AS pkm

# Cache-bust: everything below here rebuilds when source changes.
# The Makefile passes --build-arg CACHE_BUST=$(checksum) to invalidate
# Docker's layer cache when any PKM source file changes.
ARG CACHE_BUST=0
ARG ENABLE_PKM_KUNIT=0
ARG PKM_KACS_TCB_PUBKEY_HEX=""

# PKM: install the explicit slow-track scaffold into security/pkm.
COPY kernel/install-pkm-subtree.sh /usr/local/bin/install-pkm-subtree
COPY kernel/stage-kacs-core.sh /usr/local/bin/stage-kacs-core
COPY kacs/lsm.c /tmp/pkm-src/kacs/lsm.c
COPY kacs/access_check.c /tmp/pkm-src/kacs/access_check.c
COPY kacs/access_check.h /tmp/pkm-src/kacs/access_check.h
COPY kacs/access_check.rs /tmp/pkm-src/kacs/access_check.rs
COPY kacs/caap_cache.c /tmp/pkm-src/kacs/caap_cache.c
COPY kacs/caap_cache.h /tmp/pkm-src/kacs/caap_cache.h
COPY kacs/caap_cache.rs /tmp/pkm-src/kacs/caap_cache.rs
COPY kacs/kacs_rust.rs /tmp/pkm-src/kacs/kacs_rust.rs
COPY kacs/kmes_payload.rs /tmp/pkm-src/kacs/kmes_payload.rs
COPY kacs/kunit.c /tmp/pkm-src/kacs/kunit.c
COPY kacs/builtin_signing_keys.h /tmp/pkm-src/kacs/builtin_signing_keys.h
COPY kacs/token_fd.c /tmp/pkm-src/kacs/token_fd.c
COPY kacs/token_fd.h /tmp/pkm-src/kacs/token_fd.h
COPY kacs/token_runtime.h /tmp/pkm-src/kacs/token_runtime.h
COPY kacs/token_runtime.rs /tmp/pkm-src/kacs/token_runtime.rs
COPY lcs/source_device.c /tmp/pkm-src/lcs/source_device.c
COPY lcs/source_device.h /tmp/pkm-src/lcs/source_device.h
COPY lcs/kunit.c /tmp/pkm-src/lcs/kunit.c
COPY lcs/rust_ingress.rs /tmp/pkm-src/lcs/rust_ingress.rs
COPY lcs/key_fd.c /tmp/pkm-src/lcs/key_fd.c
COPY lcs/key_fd.h /tmp/pkm-src/lcs/key_fd.h
COPY lcs/transaction_fd.c /tmp/pkm-src/lcs/transaction_fd.c
COPY lcs/transaction_fd.h /tmp/pkm-src/lcs/transaction_fd.h
COPY lcs/rsi.c /tmp/pkm-src/lcs/rsi.c
COPY lcs/rsi.h /tmp/pkm-src/lcs/rsi.h
COPY kmes/kmes.c /tmp/pkm-src/kmes/kmes.c
COPY kmes/kmes.h /tmp/pkm-src/kmes/kmes.h
COPY kmes/kmes_validate.rs /tmp/pkm-src/kmes/kmes_validate.rs
COPY uapi/pkm/pkm.h /tmp/pkm-src/uapi/pkm/pkm.h
COPY uapi/pkm/syscall.h /tmp/pkm-src/uapi/pkm/syscall.h
COPY uapi/pkm/sid.h /tmp/pkm-src/uapi/pkm/sid.h
COPY uapi/pkm/sd.h /tmp/pkm-src/uapi/pkm/sd.h
COPY uapi/pkm/token.h /tmp/pkm-src/uapi/pkm/token.h
COPY uapi/pkm/access.h /tmp/pkm-src/uapi/pkm/access.h
COPY uapi/pkm/file.h /tmp/pkm-src/uapi/pkm/file.h
COPY uapi/pkm/kmes.h /tmp/pkm-src/uapi/pkm/kmes.h
COPY uapi/pkm/lcs.h /tmp/pkm-src/uapi/pkm/lcs.h
COPY crates/kacs-core/src/ /tmp/pkm-src/crates/kacs-core/src/
COPY crates/lcs-core/src/ /tmp/pkm-src/crates/lcs-core/src/
COPY kernel/crypto/ /tmp/pkm-src/kernel/crypto/
COPY kernel/scripts/update-ed25519-hacl.py /tmp/pkm-src/kernel/scripts/update-ed25519-hacl.py
COPY kernel/scripts/generate-kacs-builtin-signing-keys.py /tmp/pkm-src/kernel/scripts/generate-kacs-builtin-signing-keys.py
COPY pkm_kconfig /tmp/pkm-src/pkm_kconfig
COPY pkm_makefile /tmp/pkm-src/pkm_makefile
COPY kernel/stage-kacs-core.sh /tmp/pkm-src/kernel/stage-kacs-core.sh
COPY kernel/verify-generated-tree.sh /tmp/pkm-src/kernel/verify-generated-tree.sh
COPY kernel/verify-kernel-config.sh /tmp/pkm-src/kernel/verify-kernel-config.sh
RUN chmod +x /usr/local/bin/install-pkm-subtree /usr/local/bin/stage-kacs-core \
	/tmp/pkm-src/kernel/stage-kacs-core.sh \
	/tmp/pkm-src/kernel/verify-kernel-config.sh && \
	PKM_KACS_TCB_PUBKEY_HEX="${PKM_KACS_TCB_PUBKEY_HEX}" \
	PKM_KACS_ALLOW_EMPTY_TCB_PUBKEY="${ENABLE_PKM_KUNIT}" \
		install-pkm-subtree /tmp/pkm-src /build/linux && \
	bash /tmp/pkm-src/kernel/verify-generated-tree.sh /build/linux && \
	scripts/config --enable SECURITY_PKM && \
	scripts/config --set-str LSM "landlock,lockdown,yama,integrity,pkm" && \
	if [[ "${ENABLE_PKM_KUNIT}" == "1" ]]; then \
		scripts/config --enable KUNIT && \
		scripts/config --enable SECURITY_PKM_KUNIT; \
	fi && \
	make LLVM=1 olddefconfig && \
	bash /tmp/pkm-src/kernel/verify-kernel-config.sh /build/linux/.config && \
	rm -rf /tmp/pkm-src

# Default: build using all available cores
CMD ["bash", "-c", "make LLVM=1 CC=\"ccache clang\" -j$(nproc)"]
