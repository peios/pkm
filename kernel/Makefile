SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

IMAGE       := pkm-new-kernel-builder
IMAGE_KUNIT := pkm-new-kunit-builder
OUT         := $(CURDIR)/out
OUT_KUNIT   := $(CURDIR)/out-kunit
CCACHE      := pkm-new-kernel-ccache

# Fast KUnit iteration loop (kunit-*-fast): a persistent, incremental
# kernel build tree lives in a Docker volume instead of being rebuilt from
# scratch in a fresh container every run.
IMAGE_KUNIT_BASE := pkm-new-kunit-base
OUT_KUNIT_FAST   := $(CURDIR)/out-kunit-fast
BUILDTREE        := pkm-new-kunit-buildtree

# Checksum of all PKM source files. When any file changes, the Docker
# layer cache is busted from the COPY layers onward. Layers above
# (package install, kernel clone, Rust toolchain) stay cached.
PKM_SOURCES := $(shell find $(CURDIR)/../kacs $(CURDIR)/../kmes \
	$(CURDIR)/../lcs \
	$(CURDIR)/../crates/kacs-core/src \
	$(CURDIR)/../crates/lcs-core/src \
	$(CURDIR)/crypto $(CURDIR)/scripts \
	$(CURDIR)/../README.md $(CURDIR)/../pkm_kconfig $(CURDIR)/../pkm_makefile \
	$(CURDIR)/Dockerfile $(CURDIR)/Makefile $(CURDIR)/install-pkm-subtree.sh \
	$(CURDIR)/stage-kacs-core.sh $(CURDIR)/verify-scaffold.sh $(CURDIR)/verify-generated-tree.sh \
	$(CURDIR)/verify-kernel-config.sh \
	$(CURDIR)/check-kunit-scaffold.sh $(CURDIR)/lsmod.txt \
	-type f 2>/dev/null | sort)
CACHE_BUST := $(shell cat $(PKM_SOURCES) 2>/dev/null | sha256sum | cut -c1-16)
PKM_KACS_TCB_PUBKEY_HEX ?=
PKM_DOCKER_BUILD_ARGS := --build-arg CACHE_BUST=$(CACHE_BUST)
ifneq ($(strip $(PKM_KACS_TCB_PUBKEY_HEX)),)
PKM_DOCKER_BUILD_ARGS += --build-arg PKM_KACS_TCB_PUBKEY_HEX=$(PKM_KACS_TCB_PUBKEY_HEX)
endif

.PHONY: all require-tcb-pubkey verify-scaffold image kernel boot-smoke kunit-image kunit-kernel kunit-smoke kunit-base-image kunit-kernel-fast kunit-smoke-fast kunit-clean-fast shell clean clean-all

all: kernel

require-tcb-pubkey:
	@if [[ -z "$(strip $(PKM_KACS_TCB_PUBKEY_HEX))" ]]; then \
		echo "PKM_KACS_TCB_PUBKEY_HEX is required for non-KUnit KACS builds" >&2; \
		exit 2; \
	fi

verify-scaffold:
	$(CURDIR)/verify-scaffold.sh $(CURDIR)/..

image: require-tcb-pubkey verify-scaffold
	docker build $(PKM_DOCKER_BUILD_ARGS) -t $(IMAGE) -f $(CURDIR)/Dockerfile $(CURDIR)/..

kunit-image: verify-scaffold
	docker build $(PKM_DOCKER_BUILD_ARGS) --build-arg ENABLE_PKM_KUNIT=1 -t $(IMAGE_KUNIT) -f $(CURDIR)/Dockerfile $(CURDIR)/..

kernel: image
	mkdir -p $(OUT)
	docker run --rm \
		-v $(OUT):/out \
		-v $(CCACHE):/ccache \
		$(IMAGE) \
		bash -c 'make LLVM=1 CC="ccache clang" -j$$(nproc) && cp arch/x86/boot/bzImage /out/ && cp .config /out/kernel.config && make LLVM=1 modules_install INSTALL_MOD_PATH=/out'
	@echo ""
	@echo "Kernel image: $(OUT)/bzImage"
	@echo "Kernel config: $(OUT)/kernel.config"
	@echo "Modules:      $(OUT)/lib/modules/"

kunit-kernel: kunit-image
	mkdir -p $(OUT_KUNIT)
	docker run --rm \
		-v $(OUT_KUNIT):/out \
		-v $(CCACHE):/ccache \
		$(IMAGE_KUNIT) \
		bash -c 'make LLVM=1 CC="ccache clang" -j$$(nproc) && cp arch/x86/boot/bzImage /out/ && cp .config /out/kernel.config'
	@echo ""
	@echo "KUnit kernel image: $(OUT_KUNIT)/bzImage"
	@echo "KUnit kernel config: $(OUT_KUNIT)/kernel.config"

boot-smoke:
	$(CURDIR)/check-boot-scaffold.sh

kunit-smoke: kunit-kernel
	$(CURDIR)/check-kunit-scaffold.sh

# ── Fast KUnit iteration loop ────────────────────────────────────────────
# kunit-kernel rebuilds the whole kernel in a fresh --rm container every
# run (ccache helps C, nothing helps Rust or the link). The -fast variants
# keep the kernel object tree in a persistent volume so `make` only
# recompiles what changed, and stage PKM source at runtime instead of
# rebuilding the Docker image. Non-hermetic: use kunit-smoke for trustworthy
# / CI results, kunit-smoke-fast for the inner dev loop.

kunit-base-image:
	docker build --target base -t $(IMAGE_KUNIT_BASE) -f $(CURDIR)/Dockerfile $(CURDIR)/..

kunit-kernel-fast: verify-scaffold kunit-base-image
	mkdir -p $(OUT_KUNIT_FAST)
	docker run --rm \
		--hostname pkm-kunit-fast \
		-v $(BUILDTREE):/build \
		-v $(CCACHE):/ccache \
		-v $(CURDIR)/..:/pkm-src:ro \
		-v $(OUT_KUNIT_FAST):/out \
		$(IMAGE_KUNIT_BASE) \
		bash /pkm-src/kernel/kunit-fast-build.sh
	@echo ""
	@echo "KUnit kernel image (fast): $(OUT_KUNIT_FAST)/bzImage"

kunit-smoke-fast: kunit-kernel-fast
	$(CURDIR)/check-kunit-scaffold.sh $(OUT_KUNIT_FAST)/bzImage

# Discard the persistent fast build tree. Reach for this after bumping the
# kernel version or toolchain (the base image changed but the volume still
# holds objects built against the old one), or if a fast build fails in a
# way unrelated to your change. Normal source edits never need it.
kunit-clean-fast:
	rm -rf $(OUT_KUNIT_FAST)
	docker volume rm -f $(BUILDTREE)

shell: image
	docker run --rm -it -v $(CCACHE):/ccache $(IMAGE) bash

clean:
	rm -rf $(OUT)

clean-all: clean
	docker volume rm -f $(CCACHE) $(BUILDTREE)
