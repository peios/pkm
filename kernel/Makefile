IMAGE  := pkm-kernel-builder
OUT    := $(CURDIR)/out
CCACHE := pkm-kernel-ccache

# Checksum of all PKM source files. When any file changes, the Docker
# layer cache is busted from the COPY layers onward. Layers above
# (package install, kernel clone, Rust toolchain) stay cached.
PKM_SOURCES := $(shell find $(CURDIR)/../kacs $(CURDIR)/../crates/kacs-core/src \
	$(CURDIR)/../events $(CURDIR)/../pkm_kconfig $(CURDIR)/../pkm_makefile \
	$(CURDIR)/../kernel/patches -type f 2>/dev/null | sort)
CACHE_BUST := $(shell cat $(PKM_SOURCES) 2>/dev/null | md5sum | cut -c1-12)

.PHONY: all image kernel shell clean clean-all

all: kernel

image:
	docker build --build-arg CACHE_BUST=$(CACHE_BUST) -t $(IMAGE) -f $(CURDIR)/Dockerfile $(CURDIR)/..

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

shell: image
	docker run --rm -it -v $(CCACHE):/ccache $(IMAGE) bash

clean:
	rm -rf $(OUT)

clean-all: clean
	docker volume rm -f $(CCACHE)
