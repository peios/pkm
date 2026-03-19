FROM archlinux:latest

# Kernel build dependencies (C + LLVM, no Arch rust package)
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
        clang \
        llvm \
        lld \
        ccache \
    && pacman -Scc --noconfirm

# Pinned kernel version — bump deliberately, not accidentally
ARG KERNEL_VERSION=v6.19.6

# Clone kernel source at the pinned version (shallow for speed)
RUN git clone --depth 1 --branch ${KERNEL_VERSION} \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \
    /build/linux

# Install rustup and the exact Rust version the kernel requires.
# The kernel's scripts/min-tool-version.sh tells us the minimum;
# we read it from the source tree so the toolchain stays in sync
# with the pinned kernel version.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain none
ENV PATH="/root/.cargo/bin:${PATH}"

# Read the required Rust version from the kernel source and install it
RUN RUST_VERSION=$(/build/linux/scripts/min-tool-version.sh rustc) && \
    echo "Kernel requires rustc >= ${RUST_VERSION}" && \
    rustup toolchain install ${RUST_VERSION} --component rust-src && \
    rustup default ${RUST_VERSION}

# Install the exact bindgen version the kernel requires
RUN BINDGEN_VERSION=$(/build/linux/scripts/min-tool-version.sh bindgen) && \
    echo "Kernel requires bindgen >= ${BINDGEN_VERSION}" && \
    cargo install --locked --version ${BINDGEN_VERSION} bindgen-cli

# Start from Arch's kernel config
ADD https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/raw/main/config.x86_64 \
    /build/linux/.config

WORKDIR /build/linux

# Resolve new/removed config options against this kernel version
RUN make olddefconfig

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
COPY lsmod.txt /build/linux/lsmod.txt
RUN LSMOD=/build/linux/lsmod.txt make LLVM=1 localmodconfig

# Provium requirements: initramfs, 9p, vsock, virtio
# These may be stripped by localmodconfig since the build host
# doesn't necessarily have them loaded.
# Use --set-val y to force built-in (not =m modules), so initramfs
# boots work without needing module loading infrastructure.
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
        --set-val TMPFS y && \
    make LLVM=1 olddefconfig

# ccache: persistent cache via volume mount at /ccache
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=10G

# Default: build using all available cores
CMD ["bash", "-c", "make LLVM=1 CC=\"ccache clang\" -j$(nproc)"]
