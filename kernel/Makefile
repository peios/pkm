SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

IMAGE       := pkm-new-kernel-builder
IMAGE_KUNIT := pkm-new-kunit-builder
OUT         := $(CURDIR)/out
OUT_KUNIT   := $(CURDIR)/out-kunit
CCACHE      := pkm-new-kernel-ccache

# Checksum of all PKM source files. When any file changes, the Docker
# layer cache is busted from the COPY layers onward. Layers above
# (package install, kernel clone, Rust toolchain) stay cached.
PKM_SOURCES := $(shell find $(CURDIR)/../kacs $(CURDIR)/../crates/kacs-core/src \
	$(CURDIR)/../README.md $(CURDIR)/../pkm_kconfig $(CURDIR)/../pkm_makefile \
	$(CURDIR)/Dockerfile $(CURDIR)/Makefile $(CURDIR)/install-pkm-subtree.sh \
	$(CURDIR)/stage-kacs-core.sh $(CURDIR)/verify-scaffold.sh $(CURDIR)/check-kunit-scaffold.sh $(CURDIR)/lsmod.txt \
	-type f 2>/dev/null | sort)
CACHE_BUST := $(shell cat $(PKM_SOURCES) 2>/dev/null | sha256sum | cut -c1-16)

.PHONY: all verify-scaffold image kernel boot-smoke kunit-image kunit-kernel kunit-smoke shell clean clean-all

all: kernel

verify-scaffold:
	$(CURDIR)/verify-scaffold.sh $(CURDIR)/..

image: verify-scaffold
	docker build --build-arg CACHE_BUST=$(CACHE_BUST) -t $(IMAGE) -f $(CURDIR)/Dockerfile $(CURDIR)/..

kunit-image: verify-scaffold
	docker build --build-arg CACHE_BUST=$(CACHE_BUST) --build-arg ENABLE_PKM_KUNIT=1 -t $(IMAGE_KUNIT) -f $(CURDIR)/Dockerfile $(CURDIR)/..

kernel: image
	mkdir -p $(OUT)
	docker run --rm \
		-v $(OUT):/out \
		-v $(CCACHE):/ccache \
		$(IMAGE) \
		bash -c 'make LLVM=1 CC="ccache clang" -j$$(nproc) && cp arch/x86/boot/bzImage /out/ && make LLVM=1 modules_install INSTALL_MOD_PATH=/out'
	@echo ""
	@echo "Kernel image: $(OUT)/bzImage"
	@echo "Modules:      $(OUT)/lib/modules/"

kunit-kernel: kunit-image
	mkdir -p $(OUT_KUNIT)
	docker run --rm \
		-v $(OUT_KUNIT):/out \
		-v $(CCACHE):/ccache \
		$(IMAGE_KUNIT) \
		bash -c 'make LLVM=1 CC="ccache clang" -j$$(nproc) && cp arch/x86/boot/bzImage /out/'
	@echo ""
	@echo "KUnit kernel image: $(OUT_KUNIT)/bzImage"

boot-smoke:
	$(CURDIR)/check-boot-scaffold.sh

kunit-smoke: kunit-kernel
	$(CURDIR)/check-kunit-scaffold.sh

shell: image
	docker run --rm -it -v $(CCACHE):/ccache $(IMAGE) bash

clean:
	rm -rf $(OUT)

clean-all: clean
	docker volume rm -f $(CCACHE)
