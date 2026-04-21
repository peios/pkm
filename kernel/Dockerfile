FROM archlinux:latest
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
ARG KERNEL_VERSION=v6.19.6

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

# Start from Arch's kernel config
ADD https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/raw/main/config.x86_64 \
    /build/linux/.config

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
        --set-val STRICT_DEVMEM y \
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
        --set-val SQUASHFS y \
        --set-val SQUASHFS_ZSTD y && \
    make LLVM=1 olddefconfig

# Cache-bust: everything below here rebuilds when source changes.
# The Makefile passes --build-arg CACHE_BUST=$(checksum) to invalidate
# Docker's layer cache when any PKM source file changes.
ARG CACHE_BUST=0
ARG ENABLE_PKM_KUNIT=0

# PKM: install the explicit slow-track scaffold into security/pkm.
COPY kernel/install-pkm-subtree.sh /usr/local/bin/install-pkm-subtree
COPY kernel/stage-kacs-core.sh /usr/local/bin/stage-kacs-core
COPY kacs/lsm.c /tmp/pkm-src/kacs/lsm.c
COPY kacs/access_check.c /tmp/pkm-src/kacs/access_check.c
COPY kacs/access_check.h /tmp/pkm-src/kacs/access_check.h
COPY kacs/access_check.rs /tmp/pkm-src/kacs/access_check.rs
COPY kacs/kacs_rust.rs /tmp/pkm-src/kacs/kacs_rust.rs
COPY kacs/kunit.c /tmp/pkm-src/kacs/kunit.c
COPY kacs/token_fd.c /tmp/pkm-src/kacs/token_fd.c
COPY kacs/token_fd.h /tmp/pkm-src/kacs/token_fd.h
COPY kacs/token_runtime.h /tmp/pkm-src/kacs/token_runtime.h
COPY kacs/token_runtime.rs /tmp/pkm-src/kacs/token_runtime.rs
COPY crates/kacs-core/src/ /tmp/pkm-src/crates/kacs-core/src/
COPY pkm_kconfig /tmp/pkm-src/pkm_kconfig
COPY pkm_makefile /tmp/pkm-src/pkm_makefile
COPY kernel/stage-kacs-core.sh /tmp/pkm-src/kernel/stage-kacs-core.sh
RUN chmod +x /usr/local/bin/install-pkm-subtree /usr/local/bin/stage-kacs-core \
	/tmp/pkm-src/kernel/stage-kacs-core.sh && \
	install-pkm-subtree /tmp/pkm-src /build/linux && \
	rm -rf /tmp/pkm-src && \
	scripts/config --enable SECURITY_PKM && \
	scripts/config --set-str LSM "landlock,lockdown,yama,integrity,pkm" && \
	if [[ "${ENABLE_PKM_KUNIT}" == "1" ]]; then \
		scripts/config --enable KUNIT && \
		scripts/config --enable SECURITY_PKM_KUNIT; \
	fi && \
	make LLVM=1 olddefconfig

# ccache: persistent cache via volume mount at /ccache
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=10G

# Default: build using all available cores
CMD ["bash", "-c", "make LLVM=1 CC=\"ccache clang\" -j$(nproc)"]
