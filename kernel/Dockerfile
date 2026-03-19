FROM archlinux:latest

# Kernel build dependencies (C + Rust + LLVM)
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
        rust \
        rust-src \
        clang \
        llvm \
        lld \
        ccache \
    && pacman -Scc --noconfirm

# The kernel requires a specific bindgen version
RUN cargo install --locked --version 0.69.5 bindgen-cli
ENV PATH="/root/.cargo/bin:${PATH}"

# Pinned kernel version — bump deliberately, not accidentally
ARG KERNEL_VERSION=v6.19.6

# Clone kernel source at the pinned version (shallow for speed)
RUN git clone --depth 1 --branch ${KERNEL_VERSION} \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \
    /build/linux

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

# ccache: persistent cache via volume mount at /ccache
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=10G

# Default: build using all available cores
CMD ["bash", "-c", "make LLVM=1 CC=\"ccache clang\" -j$(nproc)"]
