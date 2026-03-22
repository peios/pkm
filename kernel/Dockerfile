FROM archlinux:latest

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
        --set-val STRICT_DEVMEM y && \
    make LLVM=1 olddefconfig

# PKM syscalls: register in x86_64 syscall table
RUN printf '1000\tcommon\tkacs_open_self_token\t\tsys_kacs_open_self_token\n\
1001\tcommon\tkacs_open_process_token\t\tsys_kacs_open_process_token\n\
1002\tcommon\tkacs_create_token\t\tsys_kacs_create_token\n\
1003\tcommon\tkacs_create_session\t\tsys_kacs_create_session\n\
1004\tcommon\tkacs_set_psb\t\tsys_kacs_set_psb\n\
1010\tcommon\tkacs_open_peer_token\t\tsys_kacs_open_peer_token\n\
1011\tcommon\tkacs_impersonate_peer\t\tsys_kacs_impersonate_peer\n\
1012\tcommon\tkacs_revert\t\tsys_kacs_revert\n\
1013\tcommon\tkacs_set_impersonation_level\t\tsys_kacs_set_impersonation_level\n\
1020\tcommon\tkacs_open\t\tsys_kacs_open\n\
1021\tcommon\tkacs_get_sd\t\tsys_kacs_get_sd\n\
1022\tcommon\tkacs_set_sd\t\tsys_kacs_set_sd\n\
1023\tcommon\tkacs_access_check\t\tsys_kacs_access_check\n\
1050\tcommon\tevent_emit\t\tsys_event_emit\n' \
    >> arch/x86/entry/syscalls/syscall_64.tbl

# PKM: kernel patches
COPY kernel/patches/ /build/linux/pkm-patches/
RUN for p in pkm-patches/*.patch; do \
        [ -f "$p" ] && patch -p1 < "$p"; \
    done; \
    rm -rf pkm-patches

# PKM: copy module source into kernel tree
# Structure: security/pkm/{kacs/,events/,Kconfig,Makefile}
#
# kacs_core Rust source lives in crates/kacs-core/src/ (the Cargo crate).
# We copy it into the kernel tree, stripping #[cfg(test)] blocks and
# generating mod.rs from lib.rs (removing #![no_std] and extern crate alloc
# which the kernel parent crate provides).
RUN mkdir -p security/pkm/kacs/kacs_core
COPY kacs/lsm.c /build/linux/security/pkm/kacs/lsm.c
COPY kacs/kacs_rust.rs /build/linux/security/pkm/kacs/kacs_rust.rs
COPY crates/kacs-core/src/ /tmp/kacs-core-src/
RUN for f in /tmp/kacs-core-src/*.rs; do \
        base=$(basename "$f"); \
        if [ "$base" = "lib.rs" ]; then \
            sed '/^#!\[no_std\]/d; /^extern crate alloc;/d' "$f" \
                | sed '/^#\[cfg(test)\]/,/^}$/d' \
                > security/pkm/kacs/kacs_core/mod.rs; \
        else \
            sed '/^#\[cfg(test)\]/,/^}$/d' "$f" \
                > security/pkm/kacs/kacs_core/$base; \
        fi; \
    done && rm -rf /tmp/kacs-core-src
COPY events/ /build/linux/security/pkm/events/
COPY pkm_kconfig /build/linux/security/pkm/Kconfig
COPY pkm_makefile /build/linux/security/pkm/Makefile
RUN echo 'obj-$(CONFIG_SECURITY_PKM) += pkm/' >> security/Makefile && \
    sed -i '/endmenu/i source "security/pkm/Kconfig"' security/Kconfig && \
    scripts/config --enable SECURITY_PKM && \
    scripts/config --set-str LSM "landlock,lockdown,yama,integrity,pkm" && \
    make LLVM=1 olddefconfig

# ccache: persistent cache via volume mount at /ccache
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=10G

# Default: build using all available cores
CMD ["bash", "-c", "make LLVM=1 CC=\"ccache clang\" -j$(nproc)"]
